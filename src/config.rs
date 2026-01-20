use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseMode {
    /// Use DNS responses for downlink (full DNS tunnel)
    #[serde(rename = "dns")]
    Dns,
    /// Use direct UDP for downlink
    #[serde(rename = "udp")]
    Udp,
    /// Use both UDP and DNS responses (hybrid mode - best performance and reliability)
    #[serde(rename = "hybrid")]
    Hybrid,
    /// Alias for hybrid mode
    #[serde(rename = "udp/dns")]
    #[serde(alias = "dns/udp")]
    HybridAlias,
}

/// Broadcast mode for multi-record-type and multi-resolver transmission
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum BroadcastMode {
    /// Send via all record types to all resolvers (maximum redundancy)
    #[default]
    #[serde(rename = "full")]
    Full,
    /// Rotate through record types (one type per fragment)
    #[serde(rename = "rotate")]
    Rotate,
    /// Use only the first configured record type
    #[serde(rename = "single")]
    Single,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local UDP bind address
    pub local_udp: SocketAddr,
    /// UDP port for receiving responses from server (default: same as local_udp port)
    pub response_udp_port: Option<u16>,
    /// Server UDP address for UDP uplink mode (separate from DNS resolvers)
    /// Used when uplink_mode is "udp" or "hybrid"
    pub server_udp_addr: Option<SocketAddr>,
    /// Uplink mode: "dns" (DNS only), "udp" (UDP only), or "hybrid" (both UDP and DNS)
    /// Controls how client sends packets to server
    #[serde(default = "default_uplink_mode")]
    pub uplink_mode: ResponseMode,
    /// Response mode: "dns" (DNS only), "udp" (UDP only), or "hybrid" (both UDP and DNS)
    /// Controls what responses client listens for from server
    #[serde(default = "default_response_mode")]
    pub response_mode: ResponseMode,
    /// List of domains to use for DNS queries
    pub domains: Vec<String>,
    /// List of DNS resolver addresses (for DNS uplink mode)
    pub resolvers: Vec<SocketAddr>,
    /// Maximum subdomain length (default: 63, max: 63 due to DNS label limit)
    pub max_subdomain_length: usize,
    /// Minimum subdomain length (default: 0, for padding/obfuscation)
    pub min_subdomain_length: usize,
    /// Enable resolver rotation
    pub rotate_resolvers: bool,
    /// Randomize local UDP port
    pub randomize_local_port: bool,
    /// Plain mode: send raw UDP packets directly (bypass DNS encoding) for debugging
    #[serde(default)]
    pub plain_mode: bool,
    
    // === Agility / Performance Options ===
    
    /// Retry timeout in milliseconds (default: 100ms for aggressive retry)
    #[serde(default)]
    pub retry_timeout_ms: Option<u32>,
    /// Maximum retry attempts (default: 10 for aggressive retry)
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Number of UDP sockets in the query pool (default: 5)
    /// Multiple sockets with random ports help avoid rate limiting
    #[serde(default)]
    pub query_socket_pool_size: Option<usize>,

    // === Multi-Record Type Broadcast Options ===
    
    /// DNS record types to use for queries (default: ["TXT"])
    /// Options: "TXT", "A", "AAAA", "CNAME", "MX", "NS", "NULL"
    #[serde(default = "default_record_types")]
    pub record_types: Vec<String>,
    /// Broadcast mode: "full" (all types x all resolvers), "rotate", "single"
    #[serde(default)]
    pub broadcast_mode: BroadcastMode,

    // === NACK-Based Retransmission Options ===
    
    /// Enable NACK-based selective retransmission (default: true)
    #[serde(default = "default_true")]
    pub enable_nack: bool,
    /// NACK generation delay in milliseconds (default: 50ms)
    #[serde(default = "default_nack_delay")]
    pub nack_delay_ms: u64,
    /// Minimum interval between NACKs for the same packet (default: 100ms)
    #[serde(default = "default_nack_interval")]
    pub nack_interval_ms: u64,

    // === Source Port Rotation Options ===
    
    /// Interval in milliseconds to rotate source ports (0 = disabled)
    #[serde(default)]
    pub source_port_rotation_interval_ms: u64,

    // === SOCKS5 Proxy Options (for bi-directional tunneling) ===
    
    /// SOCKS5 server bind address (client-side, for local apps)
    #[serde(default)]
    pub socks5_bind: Option<SocketAddr>,
    /// Enable reverse SOCKS5 (server can initiate connections through client)
    #[serde(default)]
    pub enable_reverse_socks5: bool,
}

fn default_response_mode() -> ResponseMode {
    ResponseMode::Udp
}

fn default_uplink_mode() -> ResponseMode {
    ResponseMode::Dns
}

fn default_record_types() -> Vec<String> {
    vec!["TXT".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_nack_delay() -> u64 {
    50
}

fn default_nack_interval() -> u64 {
    100
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            local_udp: "127.0.0.1:5353".parse().unwrap(),
            response_udp_port: None,
            server_udp_addr: None,
            uplink_mode: ResponseMode::Dns,
            response_mode: ResponseMode::Udp,
            domains: vec!["example.com".to_string()],
            resolvers: vec!["8.8.8.8:53".parse().unwrap()],
            max_subdomain_length: 63,
            min_subdomain_length: 0,
            rotate_resolvers: true,
            randomize_local_port: false,
            plain_mode: false,
            // Agility options
            retry_timeout_ms: Some(100),
            max_retries: Some(10),
            query_socket_pool_size: Some(5),
            // Multi-record type broadcast
            record_types: default_record_types(),
            broadcast_mode: BroadcastMode::Full,
            // NACK options
            enable_nack: true,
            nack_delay_ms: 50,
            nack_interval_ms: 100,
            // Port rotation
            source_port_rotation_interval_ms: 0,
            // SOCKS5
            socks5_bind: None,
            enable_reverse_socks5: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// DNS server bind address
    pub dns_bind: SocketAddr,
    /// UDP query listener port (for UDP uplink mode from client)
    /// Server binds to 0.0.0.0:<udp_query_port> to receive raw UDP queries
    pub udp_query_port: Option<u16>,
    /// Target UDP address to forward packets to
    pub target_udp: Option<SocketAddr>,
    /// Client UDP port for sending responses (uses DNS query source IP, only used in UDP mode)
    pub client_udp_port: Option<u16>,
    /// Response mode: "dns" (DNS only), "udp" (UDP only), or "hybrid" (both UDP and DNS)
    #[serde(default = "default_response_mode")]
    pub response_mode: ResponseMode,
    /// List of domains to listen for
    pub domains: Vec<String>,
    /// Maximum subdomain length (default: 63, max: 63 due to DNS label limit)
    pub max_subdomain_length: usize,
    /// Minimum subdomain length (default: 0, for padding/obfuscation)
    pub min_subdomain_length: usize,
    /// Randomize DNS server port
    pub randomize_dns_port: bool,
    /// Plain mode: receive raw UDP packets directly (bypass DNS decoding) for debugging
    #[serde(default)]
    pub plain_mode: bool,

    // === Multi-Record Type Broadcast Options ===
    
    /// DNS record types to use for responses (default: ["TXT"])
    #[serde(default = "default_record_types")]
    pub record_types: Vec<String>,
    /// Broadcast mode for responses
    #[serde(default)]
    pub broadcast_mode: BroadcastMode,

    // === NACK-Based Retransmission Options ===
    
    /// Enable NACK-based selective retransmission (default: true)
    #[serde(default = "default_true")]
    pub enable_nack: bool,
    /// NACK generation delay in milliseconds (default: 50ms)
    #[serde(default = "default_nack_delay")]
    pub nack_delay_ms: u64,
    /// Minimum interval between NACKs for the same packet (default: 100ms)
    #[serde(default = "default_nack_interval")]
    pub nack_interval_ms: u64,

    // === SOCKS5 Proxy Options (for bi-directional tunneling) ===
    
    /// SOCKS5 server bind address (server-side, for remote apps)
    #[serde(default)]
    pub socks5_bind: Option<SocketAddr>,
    /// Enable reverse SOCKS5 (allow connections to be initiated from server to client)
    #[serde(default)]
    pub enable_reverse_socks5: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            udp_query_port: Some(5354),
            target_udp: None,
            client_udp_port: Some(5353),
            response_mode: ResponseMode::Udp,
            domains: vec!["example.com".to_string()],
            max_subdomain_length: 63,
            min_subdomain_length: 0,
            randomize_dns_port: false,
            plain_mode: false,
            // Multi-record type broadcast
            record_types: default_record_types(),
            broadcast_mode: BroadcastMode::Full,
            // NACK options
            enable_nack: true,
            nack_delay_ms: 50,
            nack_interval_ms: 100,
            // SOCKS5
            socks5_bind: None,
            enable_reverse_socks5: false,
        }
    }
}

pub fn load_client_config(path: Option<PathBuf>) -> anyhow::Result<ClientConfig> {
    if let Some(p) = path {
        let content = std::fs::read_to_string(p)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(ClientConfig::default())
    }
}

pub fn load_server_config(path: Option<PathBuf>) -> anyhow::Result<ServerConfig> {
    if let Some(p) = path {
        let content = std::fs::read_to_string(p)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(ServerConfig::default())
    }
}
