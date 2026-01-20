use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config_v2::{ClientConfigV2, ServerConfigV2};
use serde_json::Value;

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
            // Agility options
            retry_timeout_ms: Some(100),  // Aggressive: 100ms timeout
            max_retries: Some(10),         // Aggressive: 10 retries
            query_socket_pool_size: Some(5), // 5 sockets in pool
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
        let content = std::fs::read_to_string(&p)?;

        // Try to detect config version
        let value: Value = serde_json::from_str(&content)?;
        let version = value
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        if version >= 2 {
            // Parse as v2 config and convert to v1 runtime config
            let cfg_v2: ClientConfigV2 = serde_json::from_value(value)?;
            Ok(client_config_from_v2(cfg_v2))
        } else {
            // Legacy v1 format
        Ok(serde_json::from_str(&content)?)
        }
    } else {
        Ok(ClientConfig::default())
    }
}

pub fn load_server_config(path: Option<PathBuf>) -> anyhow::Result<ServerConfig> {
    if let Some(p) = path {
        let content = std::fs::read_to_string(&p)?;

        // Try to detect config version
        let value: Value = serde_json::from_str(&content)?;
        let version = value
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        if version >= 2 {
            let cfg_v2: ServerConfigV2 = serde_json::from_value(value)?;
            Ok(server_config_from_v2(cfg_v2))
        } else {
        Ok(serde_json::from_str(&content)?)
        }
    } else {
        Ok(ServerConfig::default())
    }
}

/// Convert v2 client config into the runtime ClientConfig used by the tunnel.
fn client_config_from_v2(v2: ClientConfigV2) -> ClientConfig {
    // Pick initial DNS-UDP resolvers from the v2 resolver list
    let resolvers: Vec<SocketAddr> = v2
        .resolvers
        .initial
        .iter()
        .filter(|r| r.transport == "dns_udp")
        .filter_map(|r| r.addr.parse().ok())
        .collect();

    // Fallback if none configured
    let resolvers = if resolvers.is_empty() {
        vec!["1.1.1.1:53".parse().unwrap()]
    } else {
        resolvers
    };

    // Use the default profile to infer some timing parameters
    let profile = v2.profiles.get_default();

    ClientConfig {
        local_udp: v2.local_bind,
        response_udp_port: None,
        server_udp_addr: v2
            .server
            .udp_addr
            .and_then(|s| s.parse().ok()),
        // For now, v2 uses DNS uplink + DNS downlink by default
        uplink_mode: ResponseMode::Dns,
        response_mode: ResponseMode::Dns,
        domains: v2.domains,
        resolvers,
        max_subdomain_length: v2.advanced.max_label_length.min(63),
        min_subdomain_length: v2.advanced.min_label_length,
        // Enable rotation by default in v2
        rotate_resolvers: true,
        randomize_local_port: false,
        plain_mode: v2.advanced.plain_mode,
        // Map some profile parameters into retry behaviour
        retry_timeout_ms: Some(profile.retransmit_ms as u32),
        max_retries: Some(profile.max_retries as u32),
        // Use a small socket pool by default
        query_socket_pool_size: Some(5),
    }
}

/// Convert v2 server config into the runtime ServerConfig used by the tunnel.
fn server_config_from_v2(v2: ServerConfigV2) -> ServerConfig {
    let response_mode = match v2.response_mode.as_str() {
        "dns" => ResponseMode::Dns,
        "udp" => ResponseMode::Udp,
        "hybrid" | "udp/dns" | "dns/udp" => ResponseMode::Hybrid,
        _ => default_response_mode(),
    };

    ServerConfig {
        dns_bind: v2.dns_bind,
        udp_query_port: v2.udp_query_port,
        target_udp: Some(v2.target.udp_addr),
        client_udp_port: v2.client_response_port,
        response_mode,
        domains: v2.domains,
        max_subdomain_length: v2.advanced.max_label_length.min(63),
        min_subdomain_length: v2.advanced.min_label_length,
        randomize_dns_port: false,
        plain_mode: v2.advanced.plain_mode,
    }
}
