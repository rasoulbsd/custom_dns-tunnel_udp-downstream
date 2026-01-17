use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local UDP bind address
    pub local_udp: SocketAddr,
    /// UDP port for receiving responses from server (default: same as local_udp port)
    pub response_udp_port: Option<u16>,
    /// TCP listen address for shadowsocks/proxy connections (e.g., "127.0.0.1:1080")
    pub tcp_listen: Option<SocketAddr>,
    /// List of domains to use for DNS queries
    pub domains: Vec<String>,
    /// List of DNS resolver addresses
    pub resolvers: Vec<SocketAddr>,
    /// Maximum subdomain length (default: 63, max: 63 due to DNS label limit)
    pub max_subdomain_length: usize,
    /// Enable resolver rotation
    pub rotate_resolvers: bool,
    /// Randomize local UDP port
    pub randomize_local_port: bool,
    /// TCP connection timeout in seconds (default: 60)
    pub tcp_connection_timeout: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            local_udp: "127.0.0.1:5353".parse().unwrap(),
            response_udp_port: None,
            tcp_listen: Some("127.0.0.1:1080".parse().unwrap()),
            domains: vec!["example.com".to_string()],
            resolvers: vec!["8.8.8.8:53".parse().unwrap()],
            max_subdomain_length: 63,
            rotate_resolvers: true,
            randomize_local_port: false,
            tcp_connection_timeout: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// DNS server bind address
    pub dns_bind: SocketAddr,
    /// Target UDP address to forward packets to
    pub target_udp: Option<SocketAddr>,
    /// Target TCP address for forwarding TCP connections (e.g., xray core shadowsocks: "127.0.0.1:8388")
    pub tcp_target: Option<SocketAddr>,
    /// Client UDP port for sending responses (uses DNS query source IP)
    pub client_udp_port: Option<u16>,
    /// List of domains to listen for
    pub domains: Vec<String>,
    /// Maximum subdomain length (default: 63, max: 63 due to DNS label limit)
    pub max_subdomain_length: usize,
    /// Randomize DNS server port
    pub randomize_dns_port: bool,
    /// TCP connection timeout in seconds (default: 60)
    pub tcp_connection_timeout: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            target_udp: None,
            tcp_target: Some("127.0.0.1:8388".parse().unwrap()),
            client_udp_port: Some(5353),
            domains: vec!["example.com".to_string()],
            max_subdomain_length: 63,
            randomize_dns_port: false,
            tcp_connection_timeout: 60,
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
