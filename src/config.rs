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
}

fn default_response_mode() -> ResponseMode {
    ResponseMode::Udp
}

fn default_uplink_mode() -> ResponseMode {
    ResponseMode::Dns
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            local_udp: "127.0.0.1:5353".parse().unwrap(),
            response_udp_port: None,
            server_udp_addr: None,  // Must be set when uplink_mode is "udp" or "hybrid"
            uplink_mode: ResponseMode::Dns,
            response_mode: ResponseMode::Udp,
            domains: vec!["example.com".to_string()],
            resolvers: vec!["8.8.8.8:53".parse().unwrap()],
            max_subdomain_length: 63,
            min_subdomain_length: 0,
            rotate_resolvers: true,
            randomize_local_port: false,
            plain_mode: false,
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            udp_query_port: Some(5354),  // Default port for UDP uplink queries
            target_udp: None,
            client_udp_port: Some(5353),  // Default port for sending responses to client
            response_mode: ResponseMode::Udp,
            domains: vec!["example.com".to_string()],
            max_subdomain_length: 63,
            min_subdomain_length: 0,
            randomize_dns_port: false,
            plain_mode: false,
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
