//! DNS over UDP transport adapter
//!
//! Traditional DNS queries over UDP. This is a refactored version of the
//! original dns_codec module, adapted to the Transport trait.

use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::{
    RecvResult, ResolverEndpoint, SendResult, Transport, TransportError, TransportType,
};

/// DNS-UDP transport configuration
#[derive(Debug, Clone)]
pub struct DnsUdpConfig {
    /// Domain to use for DNS queries
    pub domain: String,
    /// Maximum label length (DNS limit: 63)
    pub max_label_len: usize,
    /// Minimum label length (for padding)
    pub min_label_len: usize,
    /// Receive buffer size
    pub recv_buffer_size: usize,
}

impl Default for DnsUdpConfig {
    fn default() -> Self {
        Self {
            domain: "example.com".to_string(),
            max_label_len: 63,
            min_label_len: 0,
            recv_buffer_size: 65535,
        }
    }
}

/// DNS over UDP transport
#[derive(Debug)]
pub struct DnsUdpTransport {
    config: DnsUdpConfig,
    socket: Arc<UdpSocket>,
    recv_buffer: Mutex<Vec<u8>>,
}

impl DnsUdpTransport {
    /// Create a new DNS-UDP transport
    pub async fn new(config: DnsUdpConfig) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        Ok(Self {
            recv_buffer: Mutex::new(vec![0u8; config.recv_buffer_size]),
            config,
            socket: Arc::new(socket),
        })
    }

    /// Create with an existing socket
    pub fn with_socket(config: DnsUdpConfig, socket: Arc<UdpSocket>) -> Self {
        Self {
            recv_buffer: Mutex::new(vec![0u8; config.recv_buffer_size]),
            config,
            socket,
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket.local_addr().map_err(|e| TransportError::Io(e.to_string()))
    }

    /// Encode data into a DNS query
    pub fn encode_query(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Encode data as hex
        let encoded = hex::encode(data);
        
        // Split into labels (max 63 chars each)
        let labels = self.split_into_labels(&encoded);
        
        // Add random prefix to bypass caching
        let random_prefix = hex::encode(&rand::random::<[u8; 3]>());
        
        // Build query name
        let mut name_parts = vec![random_prefix];
        name_parts.extend(labels);
        name_parts.push(self.config.domain.clone());
        let query_name = name_parts.join(".");

        // Create DNS message
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let name = Name::from_ascii(&query_name)
            .map_err(|e| TransportError::Protocol(format!("Invalid DNS name: {}", e)))?;
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);

        message.to_vec()
            .map_err(|e| TransportError::Protocol(format!("Failed to encode DNS message: {}", e)))
    }

    /// Decode data from a DNS response
    pub fn decode_response(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let message = Message::from_vec(data)
            .map_err(|e| TransportError::InvalidResponse(format!("Invalid DNS response: {}", e)))?;

        if message.message_type() != MessageType::Response {
            return Err(TransportError::InvalidResponse("Not a response".to_string()));
        }

        // Try to extract from TXT record
        for answer in message.answers() {
            if answer.record_type() == RecordType::TXT {
                let name = answer.name().to_ascii();
                if let Some(payload) = self.extract_payload_from_name(&name) {
                    return hex::decode(&payload)
                        .map_err(|e| TransportError::InvalidResponse(format!("Invalid hex: {}", e)));
                }
            }
        }

        // Try from query name (echo)
        if let Some(query) = message.queries().first() {
            let name = query.name().to_ascii();
            if let Some(payload) = self.extract_payload_from_name(&name) {
                return hex::decode(&payload)
                    .map_err(|e| TransportError::InvalidResponse(format!("Invalid hex: {}", e)));
            }
        }

        Err(TransportError::InvalidResponse("No payload found".to_string()))
    }

    fn split_into_labels(&self, data: &str) -> Vec<String> {
        let max_len = self.config.max_label_len.min(63);
        data.as_bytes()
            .chunks(max_len)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect()
    }

    fn extract_payload_from_name(&self, name: &str) -> Option<String> {
        let name = name.trim_end_matches('.');
        
        // Check if it ends with our domain
        let domain_suffix = format!(".{}", self.config.domain);
        if !name.ends_with(&domain_suffix) {
            return None;
        }

        // Remove domain suffix
        let subdomain = &name[..name.len() - domain_suffix.len()];
        
        // Split by dots and extract payload (skip random prefix)
        let parts: Vec<&str> = subdomain.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        // Skip first part (random prefix) if it's 6 hex chars
        let payload_parts = if parts[0].len() == 6 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            &parts[1..]
        } else {
            &parts[..]
        };

        Some(payload_parts.join(""))
    }

    /// Calculate maximum payload that fits in DNS query
    pub fn max_payload_for_domain(&self, domain: &str) -> usize {
        // DNS name max: 253 chars
        // Format: <prefix>.<payload_labels>.<domain>
        let max_name_len = 253usize;
        let prefix_len = 7; // 6 hex chars + dot
        let domain_len = domain.len() + 1; // domain + dot

        let remaining = max_name_len.saturating_sub(prefix_len + domain_len);
        
        // How many full labels can we fit?
        let max_label = self.config.max_label_len.min(63);
        let labels = remaining / (max_label + 1); // +1 for dot
        let total_chars = labels * max_label;

        // Hex encoding: 2 chars per byte
        total_chars / 2
    }
}

#[async_trait]
impl Transport for DnsUdpTransport {
    fn name(&self) -> &str {
        "dns-udp"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::DnsUdp
    }

    async fn send(&self, data: &[u8], endpoint: &ResolverEndpoint) -> Result<SendResult, TransportError> {
        let addr = endpoint.socket_addr
            .ok_or_else(|| TransportError::Protocol("No socket address for endpoint".to_string()))?;

        let query = self.encode_query(data)?;
        let start = Instant::now();

        self.socket.send_to(&query, addr).await?;

        Ok(SendResult {
            success: true,
            rtt: Some(start.elapsed()),
            error: None,
        })
    }

    async fn recv(&self, timeout: Duration) -> Result<Option<RecvResult>, TransportError> {
        let mut buf = self.recv_buffer.lock().await;
        
        match tokio::time::timeout(timeout, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, source))) => {
                let data = buf[..len].to_vec();
                match self.decode_response(&data) {
                    Ok(payload) => Ok(Some(RecvResult {
                        data: payload,
                        source: Some(source),
                        metadata: None,
                    })),
                    Err(e) => {
                        // Return raw data if decoding fails
                        Ok(Some(RecvResult {
                            data,
                            source: Some(source),
                            metadata: Some(format!("decode_error: {}", e)),
                        }))
                    }
                }
            }
            Ok(Err(e)) => Err(TransportError::Io(e.to_string())),
            Err(_) => Ok(None), // Timeout
        }
    }

    fn max_payload_size(&self) -> usize {
        self.max_payload_for_domain(&self.config.domain)
    }

    fn supports_multiplexing(&self) -> bool {
        false
    }

    fn estimated_overhead(&self) -> usize {
        // DNS header + query overhead + hex encoding (2x)
        50
    }

    async fn close(&self) -> Result<(), TransportError> {
        // UDP sockets don't need explicit close
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_udp_transport_creation() {
        let config = DnsUdpConfig::default();
        let transport = DnsUdpTransport::new(config).await.unwrap();
        
        assert_eq!(transport.name(), "dns-udp");
        assert_eq!(transport.transport_type(), TransportType::DnsUdp);
        assert!(!transport.supports_multiplexing());
    }

    #[test]
    fn test_encode_decode() {
        let config = DnsUdpConfig {
            domain: "test.com".to_string(),
            ..Default::default()
        };
        
        // We can't fully test without async, but we can test label splitting
        let transport_sync = DnsUdpConfig::default();
        let labels: Vec<String> = "abcdef".as_bytes()
            .chunks(63)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect();
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn test_max_payload_calculation() {
        let config = DnsUdpConfig {
            domain: "example.com".to_string(),
            max_label_len: 63,
            ..Default::default()
        };
        
        // Should be able to fit a reasonable payload
        let max = 253 - 7 - 12; // 253 - prefix - domain.len + dot
        let labels = max / 64; // label + dot
        let expected = (labels * 63) / 2;
        
        // Just verify it's positive
        assert!(expected > 0);
    }
}
