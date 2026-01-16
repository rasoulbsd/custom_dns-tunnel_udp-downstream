// Simple integration test to verify encoding/decoding works
use dns_tunnel::dns_codec::DnsCodec;
use dns_tunnel::packet::TunnelPacket;

#[test]
fn test_hex_encoding_case_insensitive() {
    let codec = DnsCodec::new(64);
    let test_data = b"Hello, World!";
    let packet_id = 12345u16;
    let fragment_id = 0u8;
    let total_fragments = 1u8;
    let domain = "example.com";

    // Encode to DNS query
    let dns_query = codec
        .encode_to_dns_query(test_data, domain, packet_id, fragment_id, total_fragments)
        .unwrap();

    // Extract the query name
    let query_name = dns_query.queries()[0].name().to_ascii();
    let subdomain = query_name.strip_suffix(&format!(".{}", domain)).unwrap();

    // Test case insensitivity - convert to uppercase and back
    let subdomain_upper = subdomain.to_uppercase();
    let subdomain_lower = subdomain_upper.to_lowercase();

    // Decode should work with any case
    let decoded_lower = hex::decode(&subdomain_lower).unwrap();
    let decoded_upper = hex::decode(&subdomain_upper).unwrap();

    assert_eq!(decoded_lower, decoded_upper);
    assert_eq!(decoded_lower[4..], test_data);
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
fn test_subdomain_length_limit() {
    let max_length = 32;
    let codec = DnsCodec::new(max_length);
    let large_data = vec![0u8; 100]; // Large data that will exceed limit
    let domain = "example.com";

    let dns_query = codec
        .encode_to_dns_query(&large_data, domain, 1, 0, 1)
        .unwrap();

    let query_name = dns_query.queries()[0].name().to_ascii();
    let subdomain = query_name.strip_suffix(&format!(".{}", domain)).unwrap();

    // Subdomain should not exceed max length
    assert!(subdomain.len() <= max_length);
}
