//! Configuration v2 - New comprehensive config format
//!
//! Supports:
//! - Multiple traffic profiles
//! - Resolver database configuration
//! - Path manager settings
//! - Transport preferences
//! - Adaptive parameters

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::path::LoadBalanceStrategy;
use crate::profile::{Profile, ProfileMode};
use crate::transport::TransportType;

/// Configuration version
pub const CONFIG_VERSION: u32 = 2;

/// Full client configuration v2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigV2 {
    /// Config version
    #[serde(default = "default_version")]
    pub version: u32,
    
    /// Local bind address for application traffic
    pub local_bind: SocketAddr,
    
    /// Profiles configuration
    #[serde(default)]
    pub profiles: ProfilesConfig,
    
    /// Domains to use for DNS tunneling
    pub domains: Vec<String>,
    
    /// Resolver database configuration
    #[serde(default)]
    pub resolvers: ResolversConfig,
    
    /// Path manager configuration
    #[serde(default)]
    pub path_manager: PathManagerConfigV2,
    
    /// Server configuration
    pub server: ServerConnection,
    
    /// Advanced/low-level settings
    #[serde(default)]
    pub advanced: AdvancedConfig,
}

fn default_version() -> u32 { CONFIG_VERSION }

impl Default for ClientConfigV2 {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            local_bind: "0.0.0.0:5355".parse().unwrap(),
            profiles: ProfilesConfig::default(),
            domains: vec!["tunnel.example.com".to_string()],
            resolvers: ResolversConfig::default(),
            path_manager: PathManagerConfigV2::default(),
            server: ServerConnection::default(),
            advanced: AdvancedConfig::default(),
        }
    }
}

/// Profiles configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesConfig {
    /// Default profile name
    #[serde(default = "default_profile_name")]
    pub default: String,
    
    /// Profile definitions
    #[serde(default)]
    pub interactive: Option<ProfileDefinition>,
    
    #[serde(default)]
    pub bulk: Option<ProfileDefinition>,
    
    /// Custom profiles
    #[serde(default)]
    pub custom: HashMap<String, ProfileDefinition>,
}

fn default_profile_name() -> String { "interactive".to_string() }

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            default: "interactive".to_string(),
            interactive: Some(ProfileDefinition::interactive_defaults()),
            bulk: Some(ProfileDefinition::bulk_defaults()),
            custom: HashMap::new(),
        }
    }
}

impl ProfilesConfig {
    /// Get a profile by name
    pub fn get(&self, name: &str) -> Option<Profile> {
        match name {
            "interactive" => self.interactive.as_ref().map(|d| d.to_profile("interactive")),
            "bulk" => self.bulk.as_ref().map(|d| d.to_profile("bulk")),
            _ => self.custom.get(name).map(|d| d.to_profile(name)),
        }
    }

    /// Get the default profile
    pub fn get_default(&self) -> Profile {
        self.get(&self.default).unwrap_or_else(Profile::default)
    }
}

/// Profile definition (for config file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDefinition {
    #[serde(default)]
    pub window_packets: Option<u16>,
    
    #[serde(default)]
    pub retransmit_ms: Option<u32>,
    
    #[serde(default)]
    pub max_retries: Option<u8>,
    
    #[serde(default)]
    pub max_payload_bytes: Option<u16>,
    
    #[serde(default)]
    pub min_payload_bytes: Option<u16>,
    
    #[serde(default)]
    pub fec_enabled: Option<bool>,
    
    #[serde(default)]
    pub fec_parity_ratio: Option<f32>,
    
    #[serde(default)]
    pub redundancy_factor: Option<u8>,
    
    #[serde(default)]
    pub load_balance_strategy: Option<String>,
    
    #[serde(default)]
    pub prefer_transports: Option<Vec<String>>,
    
    #[serde(default)]
    pub adaptive_window: Option<bool>,
    
    #[serde(default)]
    pub adaptive_payload: Option<bool>,
    
    #[serde(default)]
    pub adaptive_transport: Option<bool>,
}

impl ProfileDefinition {
    pub fn interactive_defaults() -> Self {
        Self {
            window_packets: Some(8),
            retransmit_ms: Some(100),
            max_retries: Some(5),
            max_payload_bytes: Some(200),
            min_payload_bytes: None,
            fec_enabled: Some(false),
            fec_parity_ratio: None,
            redundancy_factor: Some(2),
            load_balance_strategy: Some("least_latency".to_string()),
            prefer_transports: Some(vec!["doq".to_string(), "doh".to_string(), "dns_udp".to_string()]),
            adaptive_window: Some(true),
            adaptive_payload: Some(true),
            adaptive_transport: Some(true),
        }
    }

    pub fn bulk_defaults() -> Self {
        Self {
            window_packets: Some(64),
            retransmit_ms: Some(200),
            max_retries: Some(10),
            max_payload_bytes: Some(800),
            min_payload_bytes: Some(200),
            fec_enabled: Some(true),
            fec_parity_ratio: Some(0.1),
            redundancy_factor: Some(1),
            load_balance_strategy: Some("bandwidth_first".to_string()),
            prefer_transports: Some(vec!["doq".to_string(), "direct_udp".to_string(), "doh".to_string()]),
            adaptive_window: Some(true),
            adaptive_payload: Some(true),
            adaptive_transport: Some(true),
        }
    }

    pub fn to_profile(&self, name: &str) -> Profile {
        let base = if name == "interactive" {
            Profile::interactive()
        } else if name == "bulk" {
            Profile::bulk()
        } else {
            Profile::default()
        };

        Profile {
            name: name.to_string(),
            mode: if name == "interactive" { ProfileMode::Interactive } else if name == "bulk" { ProfileMode::Bulk } else { ProfileMode::Auto },
            window_packets: self.window_packets.unwrap_or(base.window_packets),
            retransmit_ms: self.retransmit_ms.unwrap_or(base.retransmit_ms),
            max_retries: self.max_retries.unwrap_or(base.max_retries),
            max_payload_bytes: self.max_payload_bytes.unwrap_or(base.max_payload_bytes),
            min_payload_bytes: self.min_payload_bytes.unwrap_or(base.min_payload_bytes),
            fec_enabled: self.fec_enabled.unwrap_or(base.fec_enabled),
            fec_parity_ratio: self.fec_parity_ratio.unwrap_or(base.fec_parity_ratio),
            redundancy_factor: self.redundancy_factor.unwrap_or(base.redundancy_factor),
            load_balance_strategy: self.load_balance_strategy
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(base.load_balance_strategy),
            prefer_transports: self.prefer_transports
                .as_ref()
                .map(|v| v.iter().filter_map(|s| s.parse().ok()).collect())
                .unwrap_or(base.prefer_transports),
            adaptive_window: self.adaptive_window.unwrap_or(base.adaptive_window),
            adaptive_payload: self.adaptive_payload.unwrap_or(base.adaptive_payload),
            adaptive_transport: self.adaptive_transport.unwrap_or(base.adaptive_transport),
        }
    }
}

/// Resolvers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolversConfig {
    /// Path to redb database file
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    
    /// Path to watch for resolver updates
    #[serde(default)]
    pub watch_file: Option<PathBuf>,
    
    /// Initial resolvers to add
    #[serde(default)]
    pub initial: Vec<ResolverEntry>,
}

fn default_db_path() -> PathBuf { PathBuf::from("./resolvers.redb") }

impl Default for ResolversConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            watch_file: None,
            initial: vec![
                ResolverEntry {
                    addr: "1.1.1.1:53".to_string(),
                    transport: "dns_udp".to_string(),
                    tags: None,
                },
            ],
        }
    }
}

/// Single resolver entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverEntry {
    pub addr: String,
    pub transport: String,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Path manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathManagerConfigV2 {
    /// Health probe interval in milliseconds
    #[serde(default = "default_health_probe_interval")]
    pub health_probe_interval_ms: u64,
    
    /// Probe timeout in milliseconds
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_ms: u64,
    
    /// Circuit breaker failure threshold
    #[serde(default = "default_circuit_breaker_threshold")]
    pub circuit_breaker_threshold: u32,
    
    /// Circuit breaker reset time in milliseconds
    #[serde(default = "default_circuit_breaker_reset")]
    pub circuit_breaker_reset_ms: u64,
    
    /// Minimum number of healthy resolvers
    #[serde(default = "default_min_healthy")]
    pub min_healthy_resolvers: usize,
}

fn default_health_probe_interval() -> u64 { 5000 }
fn default_probe_timeout() -> u64 { 2000 }
fn default_circuit_breaker_threshold() -> u32 { 5 }
fn default_circuit_breaker_reset() -> u64 { 30000 }
fn default_min_healthy() -> usize { 2 }

impl Default for PathManagerConfigV2 {
    fn default() -> Self {
        Self {
            health_probe_interval_ms: default_health_probe_interval(),
            probe_timeout_ms: default_probe_timeout(),
            circuit_breaker_threshold: default_circuit_breaker_threshold(),
            circuit_breaker_reset_ms: default_circuit_breaker_reset(),
            min_healthy_resolvers: default_min_healthy(),
        }
    }
}

impl PathManagerConfigV2 {
    pub fn to_path_manager_config(&self) -> crate::path::PathManagerConfig {
        crate::path::PathManagerConfig {
            health_probe_interval: Duration::from_millis(self.health_probe_interval_ms),
            probe_timeout: Duration::from_millis(self.probe_timeout_ms),
            circuit_breaker_threshold: self.circuit_breaker_threshold,
            circuit_breaker_reset: Duration::from_millis(self.circuit_breaker_reset_ms),
            min_healthy_resolvers: self.min_healthy_resolvers,
            ..Default::default()
        }
    }
}

/// Server connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConnection {
    /// Server UDP address for direct UDP mode
    #[serde(default)]
    pub udp_addr: Option<String>,
    
    /// Enable direct UDP transport
    #[serde(default = "default_true")]
    pub direct_udp_enabled: bool,
}

fn default_true() -> bool { true }

impl Default for ServerConnection {
    fn default() -> Self {
        Self {
            udp_addr: None,
            direct_udp_enabled: true,
        }
    }
}

/// Advanced configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// Maximum DNS label length (max: 63)
    #[serde(default = "default_max_label")]
    pub max_label_length: usize,
    
    /// Minimum DNS label length (for padding)
    #[serde(default)]
    pub min_label_length: usize,
    
    /// Encoding type
    #[serde(default = "default_encoding")]
    pub encoding: String,
    
    /// Compression type
    #[serde(default = "default_compression")]
    pub compression: String,
    
    /// Debug mode
    #[serde(default)]
    pub debug: bool,
    
    /// Plain mode (bypass DNS encoding)
    #[serde(default)]
    pub plain_mode: bool,
}

fn default_max_label() -> usize { 63 }
fn default_encoding() -> String { "hex".to_string() }
fn default_compression() -> String { "none".to_string() }

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            max_label_length: 63,
            min_label_length: 0,
            encoding: "hex".to_string(),
            compression: "none".to_string(),
            debug: false,
            plain_mode: false,
        }
    }
}

/// Full server configuration v2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigV2 {
    /// Config version
    #[serde(default = "default_version")]
    pub version: u32,
    
    /// DNS server bind address
    pub dns_bind: SocketAddr,
    
    /// UDP query listener port
    #[serde(default)]
    pub udp_query_port: Option<u16>,
    
    /// Target to forward traffic to
    pub target: TargetConfig,
    
    /// Response mode
    #[serde(default = "default_response_mode")]
    pub response_mode: String,
    
    /// Domains to listen for
    pub domains: Vec<String>,
    
    /// Client response port
    #[serde(default)]
    pub client_response_port: Option<u16>,
    
    /// Advanced settings
    #[serde(default)]
    pub advanced: AdvancedConfig,
}

fn default_response_mode() -> String { "hybrid".to_string() }

impl Default for ServerConfigV2 {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            udp_query_port: Some(5354),
            target: TargetConfig::default(),
            response_mode: "hybrid".to_string(),
            domains: vec!["tunnel.example.com".to_string()],
            client_response_port: Some(5355),
            advanced: AdvancedConfig::default(),
        }
    }
}

/// Target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    /// Target UDP address
    pub udp_addr: SocketAddr,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            udp_addr: "127.0.0.1:8080".parse().unwrap(),
        }
    }
}

/// Load client config from file
pub fn load_client_config_v2(path: &std::path::Path) -> anyhow::Result<ClientConfigV2> {
    let content = std::fs::read_to_string(path)?;
    let config: ClientConfigV2 = serde_json::from_str(&content)?;
    Ok(config)
}

/// Load server config from file
pub fn load_server_config_v2(path: &std::path::Path) -> anyhow::Result<ServerConfigV2> {
    let content = std::fs::read_to_string(path)?;
    let config: ServerConfigV2 = serde_json::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfigV2::default();
        assert_eq!(config.version, CONFIG_VERSION);
        assert!(!config.domains.is_empty());
    }

    #[test]
    fn test_profile_config() {
        let config = ProfilesConfig::default();
        
        let interactive = config.get("interactive").unwrap();
        assert!(interactive.is_interactive());
        
        let bulk = config.get("bulk").unwrap();
        assert!(bulk.is_bulk());
    }

    #[test]
    fn test_config_serialization() {
        let config = ClientConfigV2::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: ClientConfigV2 = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.version, parsed.version);
        assert_eq!(config.domains, parsed.domains);
    }
}
