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
        
        // Calculate max payload per query
        // We need to account for:
        // 1. 4-byte header (packet_id: 2 bytes + fragment_id: 1 byte + total_fragments: 1 byte)
        // 2. Hex encoding doubles the size (1 byte = 2 hex chars)
        // 3. Max subdomain length is 63 chars
        // Formula: (payload + header) * 2 <= max_subdomain_length
        //          (payload + 4) * 2 <= 63
        //          payload + 4 <= 31
        //          payload <= 27
        // To ensure even hex length: 27 bytes payload = 54 hex chars, + 8 hex chars header = 62 hex chars (fits in 63)
        let max_total_bytes = max_subdomain_length / 2; // Max bytes that fit in subdomain (63/2 = 31)
        let header_size = 4; // packet_id (2) + fragment_id (1) + total_fragments (1)
        let max_payload = if max_total_bytes > header_size {
            max_total_bytes - header_size // 31 - 4 = 27 bytes
        } else {
            0
        }.max(16); // Minimum 16 bytes
        
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
        // Find the longest matching domain to handle cases like "tunnel.example.com" vs "example.com"
        let domain = expected_domains.iter()
            .filter(|d| {
                let domain_with_dot = format!(".{}", d);
                query_name.ends_with(&domain_with_dot) || query_name == d.as_str()
            })
            .max_by_key(|d| d.len())
            .ok_or_else(|| anyhow!("Domain not found"))?;
        
        // Extract subdomain part - remove the domain suffix
        let subdomain_part = if query_name == domain.as_str() {
            // No subdomain, just the domain
            return Err(anyhow!("Query has no subdomain"));
        } else {
            // Remove .domain suffix (with dot) - this is the most common case
            if let Some(stripped) = query_name.strip_suffix(&format!(".{}", domain)) {
                // Check if there are any remaining dots (shouldn't be, subdomain should be pure hex)
                if stripped.contains('.') {
                    // If there are dots, we might have matched the wrong domain
                    // Try to extract by finding the last dot before the domain
                    // For "subdomain.tunnel.example.com" with domain "tunnel.example.com"
                    // We want "subdomain", not "subdomain.tunnel"
                    if let Some(last_dot) = stripped.rfind('.') {
                        // Take everything after the last dot as the actual subdomain
                        &stripped[last_dot + 1..]
                    } else {
                        stripped
                    }
                } else {
                    stripped
                }
            } else if query_name.ends_with(domain) {
                // Handle case where domain doesn't have leading dot in query (unlikely but possible)
                let potential = &query_name[..query_name.len() - domain.len()];
                // Remove leading dot if present
                potential.strip_prefix('.').unwrap_or(potential)
            } else {
                return Err(anyhow!("Invalid query format: cannot extract subdomain from '{}' with domain '{}'", query_name, domain));
            }
        };
        
        // Final validation: subdomain should be pure hex (no dots, no other chars)
        if subdomain_part.contains('.') {
            return Err(anyhow!("Subdomain contains dots after extraction: '{}' (query: '{}', domain: '{}')", 
                              subdomain_part, query_name, domain));
        }

        // Decode the subdomain
        self.decode_subdomain(subdomain_part)
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
    
    /// Decode a hex subdomain string into a TunnelPacket
    fn decode_subdomain(&self, subdomain_part: &str) -> Result<Option<TunnelPacket>> {
        // Decode hex (case insensitive - convert to lowercase)
        let subdomain_lower = subdomain_part.to_lowercase();
        
        // Ensure we have a valid hex string (only 0-9, a-f)
        if !subdomain_lower.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Subdomain contains non-hex characters: {}", subdomain_lower));
        }
        
        // Handle odd-length hex strings (shouldn't happen if encoding is correct, but be defensive)
        let hex_to_decode = if subdomain_lower.len() % 2 == 1 {
            // Odd length - truncate last char (safer than padding which might decode to wrong value)
            log::warn!("Odd-length hex string detected, truncating last character: {} (len: {})", 
                      subdomain_lower, subdomain_lower.len());
            &subdomain_lower[..subdomain_lower.len() - 1]
        } else {
            &subdomain_lower
        };
        
        let decoded = hex::decode(hex_to_decode)
            .map_err(|e| anyhow!("Failed to decode hex: {} (hex: {}, len: {})", e, hex_to_decode, hex_to_decode.len()))?;

        if decoded.len() < 4 {
            return Err(anyhow!("Packet too short (decoded: {} bytes)", decoded.len()));
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
}
