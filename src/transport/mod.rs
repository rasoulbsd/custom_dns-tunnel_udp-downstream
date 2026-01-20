//! Transport adapters - pluggable transport layer
//!
//! Provides a common interface for different transport mechanisms:
//! - DNS-UDP: Traditional DNS queries over UDP
//! - DoH: DNS over HTTPS
//! - DoQ: DNS over QUIC
//! - Direct UDP: Raw UDP tunnel

pub mod dns_udp;
pub mod doh;
pub mod doq;
pub mod direct_udp;

use async_trait::async_trait;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Transport type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TransportType {
    /// DNS over UDP (traditional)
    #[serde(rename = "dns_udp", alias = "dns")]
    DnsUdp,
    /// DNS over HTTPS
    #[serde(rename = "doh", alias = "dns_over_https")]
    DoH,
    /// DNS over QUIC
    #[serde(rename = "doq", alias = "dns_over_quic")]
    DoQ,
    /// Direct UDP tunnel
    #[serde(rename = "direct_udp", alias = "udp")]
    DirectUdp,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::DnsUdp => write!(f, "dns_udp"),
            TransportType::DoH => write!(f, "doh"),
            TransportType::DoQ => write!(f, "doq"),
            TransportType::DirectUdp => write!(f, "direct_udp"),
        }
    }
}

impl std::str::FromStr for TransportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dns_udp" | "dns-udp" | "dnsudp" | "dns" => Ok(TransportType::DnsUdp),
            "doh" | "dns-over-https" => Ok(TransportType::DoH),
            "doq" | "dns-over-quic" => Ok(TransportType::DoQ),
            "direct_udp" | "direct-udp" | "udp" | "direct" => Ok(TransportType::DirectUdp),
            _ => Err(format!("Unknown transport type: {}", s)),
        }
    }
}

/// Resolver endpoint information
#[derive(Debug, Clone)]
pub struct ResolverEndpoint {
    /// Unique identifier
    pub id: u64,
    /// Transport type
    pub transport: TransportType,
    /// Address (socket addr for UDP/DoQ, URL for DoH)
    pub address: String,
    /// Parsed socket address (for UDP-based transports)
    pub socket_addr: Option<SocketAddr>,
    /// Discovered maximum label length
    pub max_label_len: u8,
    /// Discovered maximum payload size
    pub max_payload: u16,
}

impl ResolverEndpoint {
    pub fn new_dns_udp(id: u64, addr: SocketAddr) -> Self {
        Self {
            id,
            transport: TransportType::DnsUdp,
            address: addr.to_string(),
            socket_addr: Some(addr),
            max_label_len: 63,
            max_payload: 200,
        }
    }

    pub fn new_doh(id: u64, url: String) -> Self {
        Self {
            id,
            transport: TransportType::DoH,
            address: url,
            socket_addr: None,
            max_label_len: 63,
            max_payload: 2000,
        }
    }

    pub fn new_doq(id: u64, addr: SocketAddr) -> Self {
        Self {
            id,
            transport: TransportType::DoQ,
            address: addr.to_string(),
            socket_addr: Some(addr),
            max_label_len: 63,
            max_payload: 1200,
        }
    }

    pub fn new_direct_udp(id: u64, addr: SocketAddr) -> Self {
        Self {
            id,
            transport: TransportType::DirectUdp,
            address: addr.to_string(),
            socket_addr: Some(addr),
            max_label_len: 0, // Not applicable
            max_payload: 1400,
        }
    }
}

/// Result of a transport send operation
#[derive(Debug)]
pub struct SendResult {
    /// Whether the send succeeded
    pub success: bool,
    /// Round-trip time if a response was received
    pub rtt: Option<Duration>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Result of a transport receive operation
#[derive(Debug)]
pub struct RecvResult {
    /// Received data
    pub data: Vec<u8>,
    /// Source address (if applicable)
    pub source: Option<SocketAddr>,
    /// Transport-specific metadata
    pub metadata: Option<String>,
}

/// Transport adapter trait
#[async_trait]
pub trait Transport: Send + Sync + fmt::Debug {
    /// Get the transport name
    fn name(&self) -> &str;
    
    /// Get the transport type
    fn transport_type(&self) -> TransportType;
    
    /// Send a frame through this transport
    async fn send(&self, data: &[u8], endpoint: &ResolverEndpoint) -> Result<SendResult, TransportError>;
    
    /// Receive data from this transport
    /// Returns None if no data available within timeout
    async fn recv(&self, timeout: Duration) -> Result<Option<RecvResult>, TransportError>;
    
    /// Get maximum payload size for this transport
    fn max_payload_size(&self) -> usize;
    
    /// Check if this transport supports multiplexing
    fn supports_multiplexing(&self) -> bool;
    
    /// Get estimated protocol overhead in bytes
    fn estimated_overhead(&self) -> usize;
    
    /// Close the transport
    async fn close(&self) -> Result<(), TransportError>;
}

/// Transport error types
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Network I/O error
    Io(String),
    /// Connection refused or failed
    ConnectionFailed(String),
    /// Timeout waiting for response
    Timeout,
    /// Invalid response from server
    InvalidResponse(String),
    /// Transport-specific error
    Protocol(String),
    /// Transport is closed
    Closed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "I/O error: {}", e),
            TransportError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            TransportError::Timeout => write!(f, "Timeout"),
            TransportError::InvalidResponse(e) => write!(f, "Invalid response: {}", e),
            TransportError::Protocol(e) => write!(f, "Protocol error: {}", e),
            TransportError::Closed => write!(f, "Transport closed"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e.to_string())
    }
}

/// Transport registry - manages available transports
#[derive(Debug)]
pub struct TransportRegistry {
    transports: Vec<Arc<dyn Transport>>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Register a transport
    pub fn register(&mut self, transport: Arc<dyn Transport>) {
        self.transports.push(transport);
    }

    /// Get transports by type
    pub fn get_by_type(&self, transport_type: TransportType) -> Vec<Arc<dyn Transport>> {
        self.transports
            .iter()
            .filter(|t| t.transport_type() == transport_type)
            .cloned()
            .collect()
    }

    /// Get all transports
    pub fn all(&self) -> &[Arc<dyn Transport>] {
        &self.transports
    }

    /// Get first transport of a type
    pub fn get_first(&self, transport_type: TransportType) -> Option<Arc<dyn Transport>> {
        self.transports
            .iter()
            .find(|t| t.transport_type() == transport_type)
            .cloned()
    }
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export transport implementations
pub use dns_udp::DnsUdpTransport;
pub use doh::DoHTransport;
pub use doq::DoQTransport;
pub use direct_udp::DirectUdpTransport;
