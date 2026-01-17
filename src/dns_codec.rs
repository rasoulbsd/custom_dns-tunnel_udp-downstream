use crate::packet::TunnelPacket;
use anyhow::{anyhow, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use rand::Rng;

pub struct DnsCodec {
    max_subdomain_length: usize,
    max_payload_per_query: usize,
}

impl DnsCodec {
    pub fn new(max_subdomain_length: usize) -> Self {
        // DNS label limit is 63 bytes (RFC 1035)
        // Cap at 63 to ensure DNS compatibility
        let max_subdomain_length = max_subdomain_length.min(63);
        
        // Reserve space for domain name, hex encoding doubles the size
        // Hex encoding: 1 byte = 2 hex characters
        // Ensure we use even number of hex chars (truncate to even if needed)
        let max_payload = (max_subdomain_length / 2).max(16);
        
        Self {
            max_subdomain_length,
            max_payload_per_query: max_payload,
        }
    }

    /// Encode UDP packet data into DNS query
    pub fn encode_to_dns_query(
        &self,
        data: &[u8],
        domain: &str,
        packet_id: u16,
        fragment_id: u8,
        total_fragments: u8,
    ) -> Result<Message> {
        // Create packet header: packet_id (2 bytes) + fragment_id (1) + total_fragments (1) + data
        let mut packet_data = Vec::with_capacity(4 + data.len());
        packet_data.extend_from_slice(&packet_id.to_be_bytes());
        packet_data.push(fragment_id);
        packet_data.push(total_fragments);
        packet_data.extend_from_slice(data);

        // Encode to hex (case insensitive, lowercase for consistency)
        let encoded = hex::encode(&packet_data);
        
        // Ensure subdomain doesn't exceed max length
        // DNS label limit is 63 bytes (RFC 1035)
        // Hex encoding always produces even length (1 byte = 2 hex chars)
        // But we need to ensure truncation is to even length if needed
        let max_len = self.max_subdomain_length.min(63); // Cap at DNS limit
        let subdomain = if encoded.len() > max_len {
            // Truncate to even length to avoid "odd number of digits" error
            // Round down to nearest even number
            let truncate_len = (max_len / 2) * 2;
            &encoded[..truncate_len]
        } else {
            // hex::encode always produces even length, so no need to truncate
            &encoded
        };

        // Create DNS query
        let mut message = Message::new();
        message.set_id(rand::thread_rng().gen());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        // Build query name: <subdomain>.<domain>
        let query_name = format!("{}.{}", subdomain, domain);
        let name = Name::from_ascii(&query_name)
            .map_err(|e| anyhow!("Failed to create DNS name: {}", e))?;

        // Add question with any record type (we'll use TXT as default, but accept any)
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);

        Ok(message)
    }

    /// Decode DNS query to extract UDP packet data
    pub fn decode_from_dns_query(&self, message: &Message, expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        if message.queries().is_empty() {
            return Ok(None);
        }

        let query = &message.queries()[0];
        let mut query_name = query.name().to_ascii();
        
        // Remove trailing dot if present (DNS names can have trailing dot)
        if query_name.ends_with('.') {
            query_name.pop();
        }
        
        // Check if query matches any of our expected domains
        let domain_match = expected_domains.iter().any(|domain| {
            // Check if query ends with .domain or just domain, and has content before it
            (query_name.ends_with(&format!(".{}", domain)) || query_name == domain.as_str()) 
            && query_name.len() > domain.len()
        });

        if !domain_match {
            log::debug!("decode_from_dns_query: Query '{}' does not match expected domains: {:?}", 
                       query_name, expected_domains);
            return Ok(None);
        }

        // Extract subdomain (everything before the domain)
        let domain = expected_domains.iter()
            .find(|d| query_name.ends_with(&format!(".{}", d)) || query_name == d.as_str())
            .ok_or_else(|| anyhow!("Domain not found"))?;
        
        // Extract subdomain part
        let subdomain_part = if query_name == domain.as_str() {
            // No subdomain, just the domain
            return Err(anyhow!("Query has no subdomain"));
        } else {
            // Remove .domain suffix
            query_name.strip_suffix(&format!(".{}", domain))
                .ok_or_else(|| anyhow!("Invalid query format"))?
        };

        // Decode hex (case insensitive - convert to lowercase)
        let subdomain_lower = subdomain_part.to_lowercase();
        
        // Handle odd-length hex strings (shouldn't happen, but be defensive)
        let hex_to_decode = if subdomain_lower.len() % 2 == 1 {
            // Odd length - pad with '0' at the end (or truncate last char)
            // Truncating is safer as padding might decode to wrong value
            log::warn!("Odd-length hex string detected, truncating last character: {}", subdomain_lower);
            &subdomain_lower[..subdomain_lower.len() - 1]
        } else {
            &subdomain_lower
        };
        
        let decoded = hex::decode(hex_to_decode)
            .map_err(|e| anyhow!("Failed to decode hex: {} (hex: {})", e, hex_to_decode))?;

        if decoded.len() < 4 {
            return Err(anyhow!("Packet too short"));
        }

        // Extract packet metadata
        let packet_id = u16::from_be_bytes([decoded[0], decoded[1]]);
        let fragment_id = decoded[2];
        let total_fragments = decoded[3];
        let data = decoded[4..].to_vec();

        // We don't have source/dest in DNS query, so we'll use placeholder
        // The actual source will be set by the server based on the DNS query source
        Ok(Some(TunnelPacket {
            data,
            source: "0.0.0.0:0".parse().unwrap(), // Will be set by server
            destination: "0.0.0.0:0".parse().unwrap(), // Will be set by server
            packet_id,
            fragment_id,
            total_fragments,
        }))
    }

    /// Encode UDP packet data for direct UDP transmission (not DNS)
    pub fn encode_udp_packet(
        &self,
        data: &[u8],
        packet_id: u16,
        fragment_id: u8,
        total_fragments: u8,
    ) -> Vec<u8> {
        // Create packet header: packet_id (2 bytes) + fragment_id (1) + total_fragments (1) + data
        let mut packet_data = Vec::with_capacity(4 + data.len());
        packet_data.extend_from_slice(&packet_id.to_be_bytes());
        packet_data.push(fragment_id);
        packet_data.push(total_fragments);
        packet_data.extend_from_slice(data);
        packet_data
    }

    /// Decode UDP packet data from direct UDP transmission (not DNS)
    pub fn decode_udp_packet(&self, data: &[u8]) -> Result<Option<TunnelPacket>> {
        if data.len() < 4 {
            return Ok(None);
        }

        // Extract packet metadata
        let packet_id = u16::from_be_bytes([data[0], data[1]]);
        let fragment_id = data[2];
        let total_fragments = data[3];
        
        // Validate: fragment_id must be < total_fragments (0-indexed)
        // Also, total_fragments must be > 0 and reasonable (< 255)
        // Strict validation to prevent false positives from random data
        if total_fragments == 0 || total_fragments > 200 {
            log::debug!("decode_udp_packet: Invalid total_fragments: {}", total_fragments);
            return Ok(None); // Invalid - not a tunnel packet
        }
        if fragment_id >= total_fragments {
            log::debug!("decode_udp_packet: Invalid fragment_id {} >= total_fragments {}", fragment_id, total_fragments);
            return Ok(None); // Invalid - fragment_id out of range
        }
        // Additional check: packet_id should not be 0 (unlikely to be valid)
        if packet_id == 0 {
            log::debug!("decode_udp_packet: Invalid packet_id: 0");
            return Ok(None); // Invalid - packet_id 0 is reserved/unlikely
        }
        
        let packet_data = data[4..].to_vec();

        Ok(Some(TunnelPacket {
            data: packet_data,
            source: "0.0.0.0:0".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
            packet_id,
            fragment_id,
            total_fragments,
        }))
    }

    pub fn max_payload_per_query(&self) -> usize {
        self.max_payload_per_query
    }
}
