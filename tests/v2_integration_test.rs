//! Integration tests for v2 adaptive multi-transport system

use std::sync::Arc;
use std::time::Duration;

use dns_tunnel::stream::{Frame, SendWindow, RecvWindow, RetransmitQueue};
use dns_tunnel::transport::{TransportType, ResolverEndpoint};
use dns_tunnel::path::{PathManager, PathManagerConfig, LoadBalanceStrategy, ResolverStats};
use dns_tunnel::db::ResolverDb;
use dns_tunnel::profile::{Profile, ProfileManager, ProfileMode};
use dns_tunnel::config_v2::{ClientConfigV2, ServerConfigV2};

#[test]
fn test_frame_serialization_roundtrip() {
    // Test various frame types
    let frames = vec![
        Frame::syn(1),
        Frame::data(1, 42, vec![1, 2, 3, 4, 5]),
        Frame::ack(1, 100, 0b1010101),
        Frame::fin(1, 200),
        Frame::ping(1, 300),
        Frame::pong(1, 400),
    ];

    for frame in frames {
        let bytes = frame.to_bytes();
        let parsed = Frame::from_bytes(&bytes).unwrap();
        assert_eq!(frame, parsed);
    }
}

#[test]
fn test_window_flow() {
    let mut send = SendWindow::new(4, 16);
    let mut recv = RecvWindow::new(16);

    // Send some data
    for i in 0..3 {
        let seq = send.queue(vec![i as u8]).unwrap();
        assert_eq!(seq, i);
    }

    // Receive in order
    for i in 0..3 {
        recv.receive(i, vec![i as u8]);
    }

    let data = recv.drain_ready();
    assert_eq!(data.len(), 3);

    // ACK all
    send.process_ack(2, 0);
    assert!(send.is_empty() || send.in_flight() == 0);
}

#[test]
fn test_profile_selection() {
    let pm = ProfileManager::new();

    let interactive = pm.get("interactive").unwrap();
    assert!(interactive.is_interactive());
    assert!(interactive.window_packets <= 16);
    assert!(interactive.retransmit_ms <= 150);

    let bulk = pm.get("bulk").unwrap();
    assert!(bulk.is_bulk());
    assert!(bulk.window_packets >= 32);
    assert!(bulk.fec_enabled);
}

#[test]
fn test_profile_adaptation() {
    let profile = Profile::interactive();

    // Test effective window under different loss rates
    let window_normal = profile.effective_window(0.0);
    let window_lossy = profile.effective_window(0.5);
    
    assert!(window_lossy < window_normal, "Window should shrink under loss");
}

#[tokio::test]
async fn test_resolver_db_operations() {
    let db = ResolverDb::new();

    // Add resolvers
    let id1 = db.add_resolver(TransportType::DnsUdp, "1.1.1.1:53".to_string()).await.unwrap();
    let id2 = db.add_resolver(TransportType::DoH, "https://cloudflare-dns.com/dns-query".to_string()).await.unwrap();
    let id3 = db.add_resolver(TransportType::DirectUdp, "10.0.0.1:5354".to_string()).await.unwrap();

    // Check count
    assert_eq!(db.count().await, 3);

    // Get by transport
    let dns_resolvers = db.get_by_transport(TransportType::DnsUdp).await;
    assert_eq!(dns_resolvers.len(), 1);
    assert_eq!(dns_resolvers[0].id, id1);

    // Disable one
    db.set_enabled(id2, false).await.unwrap();
    let enabled = db.get_enabled_resolvers().await;
    assert_eq!(enabled.len(), 2);

    // Get endpoints
    let endpoints = db.get_endpoints().await;
    assert_eq!(endpoints.len(), 2); // id2 is disabled
}

#[tokio::test]
async fn test_path_manager_selection() {
    let config = PathManagerConfig::default();
    let pm = PathManager::new(config);

    let endpoints = vec![
        ResolverEndpoint::new_dns_udp(1, "1.1.1.1:53".parse().unwrap()),
        ResolverEndpoint::new_dns_udp(2, "8.8.8.8:53".parse().unwrap()),
        ResolverEndpoint::new_doh(3, "https://example.com/dns-query".to_string()),
    ];

    // Test least latency selection
    let selected = pm.select(&endpoints, Some(LoadBalanceStrategy::LeastLatency), None).await;
    assert!(!selected.endpoints.is_empty());

    // Test redundant selection
    let selected = pm.select(&endpoints, Some(LoadBalanceStrategy::Redundant), None).await;
    assert!(selected.endpoints.len() >= 2);

    // Test transport preference
    let selected = pm.select(&endpoints, None, Some(TransportType::DoH)).await;
    assert_eq!(selected.endpoints.len(), 1);
    assert_eq!(selected.endpoints[0].transport, TransportType::DoH);
}

#[test]
fn test_config_v2_parsing() {
    let json = r#"{
        "version": 2,
        "local_bind": "0.0.0.0:5355",
        "profiles": {
            "default": "interactive"
        },
        "domains": ["test.example.com"],
        "resolvers": {
            "initial": [
                {"addr": "1.1.1.1:53", "transport": "dns_udp"}
            ]
        },
        "path_manager": {},
        "server": {},
        "advanced": {}
    }"#;

    let config: ClientConfigV2 = serde_json::from_str(json).unwrap();
    assert_eq!(config.version, 2);
    assert_eq!(config.domains.len(), 1);
    assert_eq!(config.resolvers.initial.len(), 1);
}

#[test]
fn test_server_config_v2_parsing() {
    let json = r#"{
        "version": 2,
        "dns_bind": "0.0.0.0:53",
        "udp_query_port": 5354,
        "target": {
            "udp_addr": "127.0.0.1:8080"
        },
        "response_mode": "hybrid",
        "domains": ["test.example.com"]
    }"#;

    let config: ServerConfigV2 = serde_json::from_str(json).unwrap();
    assert_eq!(config.version, 2);
    assert_eq!(config.udp_query_port, Some(5354));
    assert_eq!(config.response_mode, "hybrid");
}

#[test]
fn test_transport_type_serde() {
    // Serialize
    let transport = TransportType::DnsUdp;
    let json = serde_json::to_string(&transport).unwrap();
    assert!(json.contains("dns_udp"));

    // Deserialize
    let parsed: TransportType = serde_json::from_str("\"doq\"").unwrap();
    assert_eq!(parsed, TransportType::DoQ);
}

#[test]
fn test_load_balance_strategy_serde() {
    // Serialize
    let strategy = LoadBalanceStrategy::LeastLatency;
    let json = serde_json::to_string(&strategy).unwrap();
    assert!(json.contains("least_latency"));

    // Deserialize
    let parsed: LoadBalanceStrategy = serde_json::from_str("\"redundant\"").unwrap();
    assert_eq!(parsed, LoadBalanceStrategy::Redundant);
}

#[tokio::test]
async fn test_health_reporting() {
    let config = PathManagerConfig::default();
    let pm = PathManager::new(config);

    // Report success
    pm.report_success(1, Duration::from_millis(50)).await;
    pm.report_success(1, Duration::from_millis(60)).await;

    // Report failure
    pm.report_failure(2, "timeout").await;

    // Circuit should still be closed for endpoint 1
    assert!(!pm.is_circuit_open(1).await);
    
    // After many failures, circuit should open for endpoint 2
    for _ in 0..10 {
        pm.report_failure(2, "timeout").await;
    }
    assert!(pm.is_circuit_open(2).await);
}
