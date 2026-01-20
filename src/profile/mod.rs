//! Traffic profiles for different use cases
//!
//! Provides optimized configurations for:
//! - Interactive traffic (SSH, real-time)
//! - Bulk traffic (VPN, file transfer)

pub mod interactive;
pub mod bulk;

pub use interactive::*;
pub use bulk::*;

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::path::LoadBalanceStrategy;
use crate::transport::TransportType;

/// Profile mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileMode {
    /// Optimized for interactive, latency-sensitive traffic
    Interactive,
    /// Optimized for bulk, throughput-sensitive traffic
    Bulk,
    /// Automatically detect based on traffic patterns
    Auto,
}

impl Default for ProfileMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl std::str::FromStr for ProfileMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "interactive" | "ssh" | "realtime" => Ok(Self::Interactive),
            "bulk" | "vpn" | "transfer" => Ok(Self::Bulk),
            "auto" | "automatic" => Ok(Self::Auto),
            _ => Err(format!("Unknown profile mode: {}", s)),
        }
    }
}

/// Traffic profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile name
    pub name: String,
    
    /// Profile mode
    #[serde(default)]
    pub mode: ProfileMode,
    
    // === Window and Timing ===
    
    /// Sliding window size in packets
    #[serde(default = "default_window_packets")]
    pub window_packets: u16,
    
    /// Retransmit timeout in milliseconds
    #[serde(default = "default_retransmit_ms")]
    pub retransmit_ms: u32,
    
    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    
    // === Payload ===
    
    /// Maximum payload size per packet
    #[serde(default = "default_max_payload")]
    pub max_payload_bytes: u16,
    
    /// Minimum payload size (for padding)
    #[serde(default)]
    pub min_payload_bytes: u16,
    
    // === FEC ===
    
    /// Enable Forward Error Correction
    #[serde(default)]
    pub fec_enabled: bool,
    
    /// FEC parity ratio (0.0 - 1.0)
    #[serde(default)]
    pub fec_parity_ratio: f32,
    
    // === Path Selection ===
    
    /// Redundancy factor (how many paths to use simultaneously)
    #[serde(default = "default_redundancy")]
    pub redundancy_factor: u8,
    
    /// Load balancing strategy
    #[serde(default)]
    pub load_balance_strategy: LoadBalanceStrategy,
    
    /// Preferred transport types (in order of preference)
    #[serde(default)]
    pub prefer_transports: Vec<TransportType>,
    
    // === Adaptation ===
    
    /// Enable adaptive window sizing
    #[serde(default = "default_true")]
    pub adaptive_window: bool,
    
    /// Enable adaptive payload sizing
    #[serde(default = "default_true")]
    pub adaptive_payload: bool,
    
    /// Enable adaptive transport selection
    #[serde(default = "default_true")]
    pub adaptive_transport: bool,
}

fn default_window_packets() -> u16 { 16 }
fn default_retransmit_ms() -> u32 { 150 }
fn default_max_retries() -> u8 { 5 }
fn default_max_payload() -> u16 { 500 }
fn default_redundancy() -> u8 { 1 }
fn default_true() -> bool { true }

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            mode: ProfileMode::Auto,
            window_packets: 16,
            retransmit_ms: 150,
            max_retries: 5,
            max_payload_bytes: 500,
            min_payload_bytes: 0,
            fec_enabled: false,
            fec_parity_ratio: 0.0,
            redundancy_factor: 1,
            load_balance_strategy: LoadBalanceStrategy::default(),
            prefer_transports: vec![
                TransportType::DoQ,
                TransportType::DoH,
                TransportType::DnsUdp,
                TransportType::DirectUdp,
            ],
            adaptive_window: true,
            adaptive_payload: true,
            adaptive_transport: true,
        }
    }
}

impl Profile {
    /// Create an interactive profile (optimized for SSH-like traffic)
    pub fn interactive() -> Self {
        interactive_profile()
    }

    /// Create a bulk profile (optimized for VPN-like traffic)
    pub fn bulk() -> Self {
        bulk_profile()
    }

    /// Get retransmit timeout as Duration
    pub fn retransmit_timeout(&self) -> Duration {
        Duration::from_millis(self.retransmit_ms as u64)
    }

    /// Check if this is an interactive profile
    pub fn is_interactive(&self) -> bool {
        matches!(self.mode, ProfileMode::Interactive)
    }

    /// Check if this is a bulk profile
    pub fn is_bulk(&self) -> bool {
        matches!(self.mode, ProfileMode::Bulk)
    }

    /// Get effective window size based on current conditions
    pub fn effective_window(&self, loss_rate: f64) -> u16 {
        if !self.adaptive_window {
            return self.window_packets;
        }

        // Reduce window when loss is high
        if loss_rate > 0.1 {
            (self.window_packets as f64 * (1.0 - loss_rate)).max(2.0) as u16
        } else {
            self.window_packets
        }
    }

    /// Get effective payload size based on transport limits
    pub fn effective_payload(&self, transport_max: u16) -> u16 {
        self.max_payload_bytes.min(transport_max)
    }

    /// Should use FEC for current conditions?
    pub fn should_use_fec(&self, loss_rate: f64) -> bool {
        if !self.fec_enabled {
            return false;
        }
        
        // Enable FEC when loss exceeds threshold
        loss_rate > 0.05
    }

    /// Get preferred transport for current conditions
    pub fn preferred_transport(&self, available: &[TransportType]) -> Option<TransportType> {
        for preferred in &self.prefer_transports {
            if available.contains(preferred) {
                return Some(*preferred);
            }
        }
        available.first().copied()
    }
}

/// Profile manager
#[derive(Debug)]
pub struct ProfileManager {
    profiles: std::collections::HashMap<String, Profile>,
    default_profile: String,
}

impl ProfileManager {
    pub fn new() -> Self {
        let mut profiles = std::collections::HashMap::new();
        profiles.insert("interactive".to_string(), Profile::interactive());
        profiles.insert("bulk".to_string(), Profile::bulk());
        profiles.insert("default".to_string(), Profile::default());

        Self {
            profiles,
            default_profile: "default".to_string(),
        }
    }

    /// Add a profile
    pub fn add(&mut self, profile: Profile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Get a profile by name
    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// Get the default profile
    pub fn default_profile(&self) -> &Profile {
        self.profiles.get(&self.default_profile).unwrap_or_else(|| {
            self.profiles.values().next().unwrap()
        })
    }

    /// Set the default profile
    pub fn set_default(&mut self, name: &str) {
        if self.profiles.contains_key(name) {
            self.default_profile = name.to_string();
        }
    }

    /// List all profile names
    pub fn list(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let interactive = Profile::interactive();
        assert!(interactive.is_interactive());
        assert!(!interactive.is_bulk());
        assert!(interactive.window_packets <= 16);

        let bulk = Profile::bulk();
        assert!(!bulk.is_interactive());
        assert!(bulk.is_bulk());
        assert!(bulk.window_packets >= 32);
    }

    #[test]
    fn test_profile_manager() {
        let mut pm = ProfileManager::new();
        
        assert!(pm.get("interactive").is_some());
        assert!(pm.get("bulk").is_some());
        
        let custom = Profile {
            name: "custom".to_string(),
            ..Profile::default()
        };
        pm.add(custom);
        
        assert!(pm.get("custom").is_some());
        assert!(pm.list().contains(&"custom"));
    }

    #[test]
    fn test_effective_window() {
        let profile = Profile {
            window_packets: 16,
            adaptive_window: true,
            ..Profile::default()
        };

        // No loss
        assert_eq!(profile.effective_window(0.0), 16);
        
        // High loss
        assert!(profile.effective_window(0.5) < 16);
    }
}
