use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local UDP bind address
    pub local_udp: SocketAddr,
    /// UDP port for receiving responses from server (default: same as local_udp port)
    pub response_udp_port: Option<u16>,
    /// List of domains to use for DNS queries
    pub domains: Vec<String>,
    /// List of DNS resolver addresses
    pub resolvers: Vec<SocketAddr>,
    /// Maximum subdomain length (default: 64)
    pub max_subdomain_length: usize,
    /// Enable resolver rotation
    pub rotate_resolvers: bool,
    /// Randomize local UDP port
    pub randomize_local_port: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            local_udp: "127.0.0.1:5353".parse().unwrap(),
            response_udp_port: None,
            domains: vec!["example.com".to_string()],
            resolvers: vec!["8.8.8.8:53".parse().unwrap()],
            max_subdomain_length: 64,
            rotate_resolvers: true,
            randomize_local_port: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// DNS server bind address
    pub dns_bind: SocketAddr,
    /// Target UDP address to forward packets to
    pub target_udp: Option<SocketAddr>,
    /// Client UDP port for sending responses (uses DNS query source IP)
    pub client_udp_port: Option<u16>,
    /// List of domains to listen for
    pub domains: Vec<String>,
    /// Maximum subdomain length (default: 64)
    pub max_subdomain_length: usize,
    /// Randomize DNS server port
    pub randomize_dns_port: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            target_udp: None,
            client_udp_port: Some(5353),
            domains: vec!["example.com".to_string()],
            max_subdomain_length: 64,
            randomize_dns_port: false,
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
