//! Bulk profile for VPN-like traffic
//!
//! Optimized for:
//! - High throughput
//! - Large transfers
//! - Bandwidth efficiency
//! - Loss tolerance with FEC

use super::{Profile, ProfileMode};
use crate::path::LoadBalanceStrategy;
use crate::transport::TransportType;

/// Create a bulk profile optimized for VPN-like traffic
pub fn bulk_profile() -> Profile {
    Profile {
        name: "bulk".to_string(),
        mode: ProfileMode::Bulk,
        
        // Large window for high throughput
        window_packets: 64,
        
        // More patient retransmit
        retransmit_ms: 200,
        max_retries: 10,
        
        // Larger payloads for efficiency
        max_payload_bytes: 800,
        min_payload_bytes: 200,
        
        // Enable FEC for loss recovery without retransmit
        fec_enabled: true,
        fec_parity_ratio: 0.1, // 10% parity
        
        // Single path to maximize bandwidth
        redundancy_factor: 1,
        
        // Prioritize throughput
        load_balance_strategy: LoadBalanceStrategy::BandwidthFirst,
        
        // Prefer high-bandwidth transports
        prefer_transports: vec![
            TransportType::DoQ,      // QUIC multiplexing
            TransportType::DirectUdp, // No DNS overhead
            TransportType::DoH,       // HTTP/2 multiplexing
            TransportType::DnsUdp,    // Fallback
        ],
        
        // Enable adaptation
        adaptive_window: true,
        adaptive_payload: true,
        adaptive_transport: true,
    }
}

/// Create an aggressive bulk profile for maximum throughput
pub fn highspeed_profile() -> Profile {
    Profile {
        name: "highspeed".to_string(),
        mode: ProfileMode::Bulk,
        
        // Maximum window
        window_packets: 128,
        
        // Patient retransmit
        retransmit_ms: 300,
        max_retries: 15,
        
        // Maximum payload
        max_payload_bytes: 1200,
        min_payload_bytes: 400,
        
        // Aggressive FEC
        fec_enabled: true,
        fec_parity_ratio: 0.15, // 15% parity
        
        redundancy_factor: 1,
        
        load_balance_strategy: LoadBalanceStrategy::BandwidthFirst,
        
        prefer_transports: vec![
            TransportType::DirectUdp,
            TransportType::DoQ,
            TransportType::DoH,
        ],
        
        adaptive_window: true,
        adaptive_payload: true,
        adaptive_transport: true,
    }
}

/// Create a balanced bulk profile
pub fn balanced_profile() -> Profile {
    Profile {
        name: "balanced".to_string(),
        mode: ProfileMode::Bulk,
        
        // Moderate window
        window_packets: 32,
        
        // Balanced retransmit
        retransmit_ms: 150,
        max_retries: 8,
        
        // Moderate payload
        max_payload_bytes: 500,
        min_payload_bytes: 100,
        
        // Light FEC
        fec_enabled: true,
        fec_parity_ratio: 0.05,
        
        redundancy_factor: 1,
        
        load_balance_strategy: LoadBalanceStrategy::WeightedRoundRobin,
        
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_profile() {
        let profile = bulk_profile();
        
        assert_eq!(profile.mode, ProfileMode::Bulk);
        assert!(profile.window_packets >= 32);
        assert!(profile.max_payload_bytes >= 500);
        assert!(profile.fec_enabled);
        assert_eq!(profile.load_balance_strategy, LoadBalanceStrategy::BandwidthFirst);
    }

    #[test]
    fn test_highspeed_profile() {
        let profile = highspeed_profile();
        let bulk = bulk_profile();
        
        // Highspeed should be more aggressive than bulk
        assert!(profile.window_packets >= bulk.window_packets);
        assert!(profile.max_payload_bytes >= bulk.max_payload_bytes);
        assert!(profile.fec_parity_ratio >= bulk.fec_parity_ratio);
    }

    #[test]
    fn test_profile_comparison() {
        let interactive = super::super::interactive::interactive_profile();
        let bulk = bulk_profile();
        
        // Bulk should have larger windows and payloads
        assert!(bulk.window_packets > interactive.window_packets);
        assert!(bulk.max_payload_bytes > interactive.max_payload_bytes);
        
        // Interactive should have faster retransmit
        assert!(interactive.retransmit_ms < bulk.retransmit_ms);
    }
}
