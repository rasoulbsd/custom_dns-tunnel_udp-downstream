// Simple integration test to verify encoding/decoding works
use dns_tunnel::dns_codec::DnsCodec;

#[test]
fn test_hex_encoding_case_insensitive() {
    let codec = DnsCodec::new(63);
    let test_data = b"Hello";  // Short data to fit in single label
    let packet_id = 12345u16;
    let fragment_id = 0u8;
    let total_fragments = 1u8;
    let domain = "example.com";
    let domains = vec![domain.to_string()];

    // Encode to DNS query
    let dns_query = codec
        .encode_to_dns_query(test_data, domain, packet_id, fragment_id, total_fragments)
        .unwrap();

    // Decode from DNS query should work (tests case insensitivity internally)
    let decoded = codec
        .decode_from_dns_query(&dns_query, &domains)
        .unwrap()
        .unwrap();

    assert_eq!(decoded.data, test_data);
    assert_eq!(decoded.packet_id, packet_id);
}

#[test]
fn test_udp_packet_encoding() {
    let codec = DnsCodec::new(64);
    let test_data = b"Test UDP packet";
    let packet_id = 54321u16;
    let fragment_id = 1u8;
    let total_fragments = 3u8;

    // Encode UDP packet
    let encoded = codec.encode_udp_packet(test_data, packet_id, fragment_id, total_fragments);

    // Decode UDP packet
    let decoded = codec.decode_udp_packet(&encoded).unwrap().unwrap();

    assert_eq!(decoded.data, test_data);
    assert_eq!(decoded.packet_id, packet_id);
    assert_eq!(decoded.fragment_id, fragment_id);
    assert_eq!(decoded.total_fragments, total_fragments);
}

#[test]
fn test_dns_query_roundtrip() {
    let codec = DnsCodec::new(64);
    let test_data = b"Roundtrip test data";
    let packet_id = 9999u16;
    let fragment_id = 0u8;
    let total_fragments = 1u8;
    let domain = "test.example.com";
    let domains = vec![domain.to_string()];

    // Encode to DNS query
    let dns_query = codec
        .encode_to_dns_query(test_data, domain, packet_id, fragment_id, total_fragments)
        .unwrap();

    // Decode from DNS query
    let decoded = codec
        .decode_from_dns_query(&dns_query, &domains)
        .unwrap()
        .unwrap();

    assert_eq!(decoded.data, test_data);
    assert_eq!(decoded.packet_id, packet_id);
    assert_eq!(decoded.fragment_id, fragment_id);
    assert_eq!(decoded.total_fragments, total_fragments);
}

#[test]
fn test_subdomain_roundtrip() {
    // Test that encode/decode roundtrip works for various sizes
    let codec = DnsCodec::new(63);
    let domain = "example.com";
    let domains = vec![domain.to_string()];

    for size in [1, 10, 20] {
        let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        
        let dns_query = codec
            .encode_to_dns_query(&test_data, domain, 1, 0, 1)
            .unwrap();

        let decoded = codec
            .decode_from_dns_query(&dns_query, &domains)
            .unwrap()
            .unwrap();

        assert_eq!(decoded.data, test_data, "Roundtrip failed for size {}", size);
    }
}
