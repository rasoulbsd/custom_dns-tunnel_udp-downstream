//! Interactive profile for SSH-like traffic
//!
//! Optimized for:
//! - Low latency
//! - Small packets
//! - Quick retransmission
//! - Responsive feel

use super::{Profile, ProfileMode};
use crate::path::LoadBalanceStrategy;
use crate::transport::TransportType;

/// Create an interactive profile optimized for SSH-like traffic
pub fn interactive_profile() -> Profile {
    Profile {
        name: "interactive".to_string(),
        mode: ProfileMode::Interactive,
        
        // Small window for quick response
        window_packets: 8,
        
        // Aggressive retransmit for low latency
        retransmit_ms: 100,
        max_retries: 5,
        
        // Small payloads typical of interactive traffic
        max_payload_bytes: 200,
        min_payload_bytes: 0,
        
        // No FEC - retransmit is faster for small packets
        fec_enabled: false,
        fec_parity_ratio: 0.0,
        
        // Use redundant paths for reliability
        redundancy_factor: 2,
        
        // Prioritize latency
        load_balance_strategy: LoadBalanceStrategy::LeastLatency,
        
        // Prefer reliable transports
        prefer_transports: vec![
            TransportType::DoQ,    // QUIC has best latency characteristics
            TransportType::DoH,    // TCP reliability
            TransportType::DnsUdp, // Fallback
            TransportType::DirectUdp,
        ],
        
        // Enable adaptation
        adaptive_window: true,
        adaptive_payload: true,
        adaptive_transport: true,
    }
}

/// Create a stricter interactive profile for extremely latency-sensitive traffic
pub fn realtime_profile() -> Profile {
    Profile {
        name: "realtime".to_string(),
        mode: ProfileMode::Interactive,
        
        // Very small window
        window_packets: 4,
        
        // Very aggressive retransmit
        retransmit_ms: 50,
        max_retries: 3,
        
        // Tiny payloads
        max_payload_bytes: 100,
        min_payload_bytes: 0,
        
        fec_enabled: false,
        fec_parity_ratio: 0.0,
        
        // Maximum redundancy
        redundancy_factor: 3,
        
        load_balance_strategy: LoadBalanceStrategy::LeastLatency,
        
        prefer_transports: vec![
            TransportType::DirectUdp, // Lowest overhead
            TransportType::DoQ,
            TransportType::DnsUdp,
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
    fn test_interactive_profile() {
        let profile = interactive_profile();
        
        assert_eq!(profile.mode, ProfileMode::Interactive);
        assert!(profile.window_packets <= 16);
        assert!(profile.retransmit_ms <= 150);
        assert!(!profile.fec_enabled);
        assert!(profile.redundancy_factor >= 2);
        assert_eq!(profile.load_balance_strategy, LoadBalanceStrategy::LeastLatency);
    }

    #[test]
    fn test_realtime_profile() {
        let profile = realtime_profile();
        let interactive = interactive_profile();
        
        // Realtime should be more aggressive than interactive
        assert!(profile.window_packets <= interactive.window_packets);
        assert!(profile.retransmit_ms <= interactive.retransmit_ms);
    }
}
