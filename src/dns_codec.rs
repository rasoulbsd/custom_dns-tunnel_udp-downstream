use crate::packet::{NackPacket, PacketFlags, TunnelPacket};
use anyhow::{anyhow, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use rand::Rng;

/// Supported DNS record types for tunnel encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelRecordType {
    TXT,
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    NULL,
}

impl TunnelRecordType {
    pub fn to_dns_record_type(&self) -> RecordType {
        match self {
            TunnelRecordType::TXT => RecordType::TXT,
            TunnelRecordType::A => RecordType::A,
            TunnelRecordType::AAAA => RecordType::AAAA,
            TunnelRecordType::CNAME => RecordType::CNAME,
            TunnelRecordType::MX => RecordType::MX,
            TunnelRecordType::NS => RecordType::NS,
            TunnelRecordType::NULL => RecordType::NULL,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "TXT" => Some(TunnelRecordType::TXT),
            "A" => Some(TunnelRecordType::A),
            "AAAA" => Some(TunnelRecordType::AAAA),
            "CNAME" => Some(TunnelRecordType::CNAME),
            "MX" => Some(TunnelRecordType::MX),
            "NS" => Some(TunnelRecordType::NS),
            "NULL" => Some(TunnelRecordType::NULL),
            _ => None,
        }
    }

    pub fn all() -> Vec<TunnelRecordType> {
        vec![
            TunnelRecordType::TXT,
            TunnelRecordType::A,
            TunnelRecordType::AAAA,
            TunnelRecordType::CNAME,
            TunnelRecordType::MX,
            TunnelRecordType::NS,
        ]
    }

    /// Get the response capacity in bytes for this record type
    pub fn response_capacity(&self) -> usize {
        match self {
            TunnelRecordType::TXT => 250,   // ~255 bytes per TXT string
            TunnelRecordType::A => 64,      // Multiple A records, 4 bytes each
            TunnelRecordType::AAAA => 256,  // Multiple AAAA records, 16 bytes each
            TunnelRecordType::CNAME => 200, // Name-based encoding
            TunnelRecordType::MX => 200,    // Name-based with preference
            TunnelRecordType::NS => 200,    // Name-based encoding
            TunnelRecordType::NULL => 512,  // Raw binary (if supported)
        }
    }
}

pub struct DnsCodec {
    max_subdomain_length: usize,
    #[allow(dead_code)] // Used in smart fragmentation calculation
    min_subdomain_length: usize,
    max_payload_per_query: usize,
}

impl DnsCodec {
    pub fn new(max_subdomain_length: usize) -> Self {
        Self::new_with_min(max_subdomain_length, 0)
    }
    
    pub fn new_with_min(max_subdomain_length: usize, min_subdomain_length: usize) -> Self {
        // DNS label limit is 63 bytes (RFC 1035)
        // Cap at 63 to ensure DNS compatibility
        let original_max = max_subdomain_length;
        let max_subdomain_length = max_subdomain_length.min(63);
        if original_max > 63 {
            log::warn!("max_subdomain_length ({}) exceeds DNS label limit (63), capped to 63", original_max);
        }
        let min_subdomain_length = min_subdomain_length.min(max_subdomain_length);
        
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
        let max_total_bytes = max_subdomain_length / 2; // Max bytes that fit in subdomain
        let header_size = 4; // packet_id (2) + fragment_id (1) + total_fragments (1)
        let max_payload = if max_total_bytes > header_size {
            max_total_bytes - header_size
        } else {
            0
        };
        
        // Smart fragmentation: if min_subdomain_length is set, use it to determine preferred chunk size
        // This ensures we fragment to efficiently use available space rather than padding with zeros
        let preferred_payload = if min_subdomain_length > 0 {
            let min_total_bytes = (min_subdomain_length / 2).max(header_size);
            let min_payload = if min_total_bytes > header_size {
                min_total_bytes - header_size
            } else {
                16 // Minimum reasonable payload
            };
            // Use the larger of: min_payload (from min_subdomain_length) or 16, but cap at max_payload
            min_payload.max(16).min(max_payload.max(16))
        } else {
            max_payload.max(16) // Minimum 16 bytes
        };
        
        Self {
            max_subdomain_length,
            min_subdomain_length,
            max_payload_per_query: preferred_payload,
        }
    }

    /// Compute max payload per query based on domain length and DNS name limits.
    /// Uses multiple labels if needed to reduce fragmentation.
    pub fn max_payload_per_query_for_domain(&self, domain: &str) -> usize {
        // DNS name max length is 253 chars (without trailing dot).
        // Format: <prefix>.<payload_labels>.<domain>
        let max_name_len = 253usize;
        let max_label_len = self.max_subdomain_length.min(63);
        let prefix_len = 6usize; // random prefix label (hex)

        // Base length: prefix + dot + domain
        let base_len = prefix_len + 1 + domain.len();
        if base_len >= max_name_len {
            return 0;
        }

        // Remaining space for payload labels and their dots
        let remaining = max_name_len - base_len;
        let mut n_labels = (remaining + 1) / (max_label_len + 1);
        if n_labels == 0 {
            n_labels = 1;
        }

        let max_payload_chars = n_labels * max_label_len;

        // Convert hex chars to bytes, subtract header (4 bytes)
        let max_total_bytes = max_payload_chars / 2;
        let header_size = 4;
        if max_total_bytes > header_size {
            max_total_bytes - header_size
        } else {
            0
        }
    }

    fn split_into_labels(&self, hex_payload: &str) -> Vec<String> {
        let max_label_len = self.max_subdomain_length.min(63);
        if hex_payload.is_empty() {
            return Vec::new();
        }
        hex_payload
            .as_bytes()
            .chunks(max_label_len)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect()
    }

    fn build_name_with_prefix(&self, prefix: &str, hex_payload: &str, domain: &str) -> Result<String> {
        let mut labels = Vec::new();
        labels.push(prefix.to_string());
        labels.extend(self.split_into_labels(hex_payload));
        labels.push(domain.to_string());
        let name = labels.join(".");
        if name.len() > 253 {
            return Err(anyhow!("DNS name too long ({} chars): {}", name.len(), name));
        }
        Ok(name)
    }

    /// Encode UDP packet data into DNS query
    /// Format: <random_prefix>.<payload_hex>.<domain>
    /// Random prefix bypasses DNS caching and rate limiting
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
        
        // Ensure payload fits into DNS name length limits for this domain.
        // We allow multiple labels, so only truncate if encoded exceeds max allowed.
        let max_payload = self.max_payload_per_query_for_domain(domain);
        let max_encoded_len = (max_payload + 4) * 2; // header + payload, hex chars
        let subdomain = if max_payload > 0 && encoded.len() > max_encoded_len {
            let truncate_len = (max_encoded_len / 2) * 2; // even length
            &encoded[..truncate_len]
        } else {
            &encoded
        };

        // Generate random 6-char hex prefix (3 bytes) to bypass DNS caching
        let random_bytes: [u8; 3] = rand::thread_rng().gen();
        let random_prefix = hex::encode(random_bytes);

        // Create DNS query
        let mut message = Message::new();
        message.set_id(rand::thread_rng().gen());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        // Build query name: <random_prefix>.<payload_labels>.<domain>
        let query_name = self.build_name_with_prefix(&random_prefix, subdomain, domain)?;
        let name = Name::from_ascii(&query_name)
            .map_err(|e| anyhow!("Failed to create DNS name: {}", e))?;

        // Add question with any record type (we'll use TXT as default, but accept any)
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);

        Ok(message)
    }

    /// Decode DNS query to extract UDP packet data
    /// Handles format: <random_prefix>.<payload_hex>.<domain>
    /// The random prefix is stripped before decoding
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
        let full_subdomain = if query_name == domain.as_str() {
            // No subdomain, just the domain
            return Err(anyhow!("Query has no subdomain"));
        } else {
            // Remove .domain suffix (with dot) - this is the most common case
            if let Some(stripped) = query_name.strip_suffix(&format!(".{}", domain)) {
                stripped
            } else if query_name.ends_with(domain) {
                // Handle case where domain doesn't have leading dot in query (unlikely but possible)
                let potential = &query_name[..query_name.len() - domain.len()];
                // Remove leading dot if present
                potential.strip_prefix('.').unwrap_or(potential)
            } else {
                return Err(anyhow!("Invalid query format: cannot extract subdomain from '{}' with domain '{}'", query_name, domain));
            }
        };
        
        // Handle random prefix format: <random_prefix>.<payload_hex_labels>
        // The random prefix is 6 hex chars, so we strip the first label if it matches.
        let parts: Vec<&str> = full_subdomain.split('.').collect();
        let payload_parts = if parts.len() >= 2
            && parts[0].len() == 6
            && parts[0].chars().all(|c| c.is_ascii_hexdigit())
        {
            &parts[1..]
        } else {
            &parts[..]
        };

        let subdomain_part = payload_parts.join("");
        
        // Final validation: subdomain should be pure hex (no dots, no other chars)
        if subdomain_part.contains('.') {
            return Err(anyhow!("Subdomain contains dots after extraction: '{}' (query: '{}', domain: '{}')", 
                              subdomain_part, query_name, domain));
        }

        // Decode the subdomain
        self.decode_subdomain(&subdomain_part)
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
        
        let packet_data = data[4..].to_vec();

        Ok(Some(TunnelPacket {
            data: packet_data,
            source: "0.0.0.0:0".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
            packet_id,
            fragment_id,
            total_fragments,
            flags: PacketFlags::Data,
            session_id: 0,
        }))
    }

    /// Encode NACK packet for UDP transmission
    pub fn encode_nack_packet(&self, nack: &NackPacket) -> Vec<u8> {
        let mut packet_data = Vec::with_capacity(5 + nack.missing_bitmap.len());
        packet_data.extend_from_slice(&nack.packet_id.to_be_bytes());
        packet_data.push(0); // fragment_id = 0 for NACK
        packet_data.push(nack.total_fragments);
        packet_data.push(PacketFlags::Nack as u8); // Flags byte indicating NACK
        packet_data.extend_from_slice(&nack.missing_bitmap);
        packet_data
    }

    /// Decode NACK packet from UDP data
    pub fn decode_nack_packet(&self, data: &[u8]) -> Option<NackPacket> {
        if data.len() < 5 {
            return None;
        }
        
        let packet_id = u16::from_be_bytes([data[0], data[1]]);
        // data[2] is fragment_id (unused for NACK)
        let total_fragments = data[3];
        let flags = data[4];
        
        // Check if this is a NACK packet
        if flags != PacketFlags::Nack as u8 {
            return None;
        }
        
        let missing_bitmap = data[5..].to_vec();
        
        Some(NackPacket {
            packet_id,
            total_fragments,
            missing_bitmap,
        })
    }

    /// Check if UDP packet is a NACK
    pub fn is_nack_packet(&self, data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }
        data[4] == PacketFlags::Nack as u8
    }

    /// Encode UDP packet data into DNS response
    /// Format: <random_prefix>.<payload_hex>.<domain>
    /// Random prefix ensures uniqueness for each response
    pub fn encode_to_dns_response(
        &self,
        data: &[u8],
        domain: &str,
        packet_id: u16,
        fragment_id: u8,
        total_fragments: u8,
        query_id: u16,
    ) -> Result<Message> {
        // Create packet header: packet_id (2 bytes) + fragment_id (1) + total_fragments (1) + data
        let mut packet_data = Vec::with_capacity(4 + data.len());
        packet_data.extend_from_slice(&packet_id.to_be_bytes());
        packet_data.push(fragment_id);
        packet_data.push(total_fragments);
        packet_data.extend_from_slice(data);

        // Encode to hex (case insensitive, lowercase for consistency)
        let encoded = hex::encode(&packet_data);
        
        // Ensure payload fits into DNS name length limits for this domain.
        // We allow multiple labels, so only truncate if encoded exceeds max allowed.
        let max_payload = self.max_payload_per_query_for_domain(domain);
        let max_encoded_len = (max_payload + 4) * 2; // header + payload, hex chars
        let subdomain = if max_payload > 0 && encoded.len() > max_encoded_len {
            let truncate_len = (max_encoded_len / 2) * 2;
            &encoded[..truncate_len]
        } else {
            &encoded
        };

        // Generate random 6-char hex prefix (3 bytes) to ensure uniqueness
        let random_bytes: [u8; 3] = rand::thread_rng().gen();
        let random_prefix = hex::encode(random_bytes);

        // Create DNS response
        let mut message = Message::new();
        message.set_id(query_id);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        // Build response name: <random_prefix>.<payload_labels>.<domain>
        let response_name = self.build_name_with_prefix(&random_prefix, subdomain, domain)?;
        let name = Name::from_ascii(&response_name)
            .map_err(|e| anyhow!("Failed to create DNS name: {}", e))?;

        // Add TXT record with the subdomain as the response
        // We use TXT record type for the response
        use hickory_proto::rr::{rdata::TXT, Record};
        let mut record = Record::new();
        record.set_name(name.clone());
        record.set_record_type(RecordType::TXT);
        record.set_ttl(0); // No caching
        // TXT::new expects Vec<String>, where each string is a character string
        record.set_data(Some(hickory_proto::rr::RData::TXT(TXT::new(vec![subdomain.to_string()]))));
        message.add_answer(record);

        Ok(message)
    }

    /// Decode DNS response to extract UDP packet data
    pub fn decode_from_dns_response(&self, message: &Message, expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        // #region agent log
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
            let _ = writeln!(f, r#"{{"hypothesisId":"D2","location":"dns_codec.rs:312","message":"decode_dns_response_entry","data":{{"msg_type":"{:?}","answers_count":{},"queries_count":{},"expected_domains":"{:?}"}},"timestamp":{}}}"#, 
                message.message_type(), message.answers().len(), message.queries().len(), expected_domains,
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        }
        // #endregion
        
        // Check if this is a response
        if message.message_type() != MessageType::Response {
            return Ok(None);
        }

        // Try to extract from TXT record in answers
        for answer in message.answers() {
            // #region agent log
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                let _ = writeln!(f, r#"{{"hypothesisId":"D2","location":"dns_codec.rs:325","message":"checking_answer","data":{{"record_type":"{:?}","name":"{}"}},"timestamp":{}}}"#, 
                    answer.record_type(), answer.name().to_ascii(),
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
            }
            // #endregion
            if answer.record_type() == RecordType::TXT {
                let name = answer.name().to_ascii();
                let name_str = name.trim_end_matches('.');
                
                // Check if name matches any of our expected domains
                let domain_match = expected_domains.iter().any(|domain| {
                    (name_str.ends_with(&format!(".{}", domain)) || name_str == domain.as_str())
                        && name_str.len() > domain.len()
                });
                // #region agent log
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                    let _ = writeln!(f, r#"{{"hypothesisId":"D2","location":"dns_codec.rs:340","message":"domain_match_check","data":{{"name_str":"{}","domain_match":{}}},"timestamp":{}}}"#, 
                        name_str, domain_match,
                        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                }
                // #endregion

                if domain_match {
                    // Extract subdomain
                    let domain = expected_domains.iter()
                        .filter(|d| {
                            let domain_with_dot = format!(".{}", d);
                            name_str.ends_with(&domain_with_dot) || name_str == d.as_str()
                        })
                        .max_by_key(|d| d.len())
                        .ok_or_else(|| anyhow!("Domain not found"))?;
                    
                    let full_subdomain = if name_str == domain.as_str() {
                        return Err(anyhow!("Response has no subdomain"));
                    } else {
                        if let Some(stripped) = name_str.strip_suffix(&format!(".{}", domain)) {
                            stripped
                        } else if name_str.ends_with(domain) {
                            name_str[..name_str.len() - domain.len()].trim_start_matches('.')
                        } else {
                            return Err(anyhow!("Invalid response format"));
                        }
                    };
                    
                    // Handle random prefix format: <random_prefix>.<payload_hex_labels>
                    // The random prefix is 6 hex chars, so we strip the first label if it matches.
                    let parts: Vec<&str> = full_subdomain.split('.').collect();
                    let payload_parts = if parts.len() >= 2
                        && parts[0].len() == 6
                        && parts[0].chars().all(|c| c.is_ascii_hexdigit())
                    {
                        &parts[1..]
                    } else {
                        &parts[..]
                    };
                    let subdomain_part = payload_parts.join("");
                    
                    // Decode the subdomain
                    return self.decode_subdomain(&subdomain_part);
                }
            }
        }

        // If no TXT record found, try to extract from the query name (some DNS servers echo it)
        if !message.queries().is_empty() {
            // Use the same logic as decode_from_dns_query
            return self.decode_from_dns_query(message, expected_domains);
        }

        Ok(None)
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
            flags: PacketFlags::Data,
            session_id: 0,
        }))
    }

    // ============================================================
    // Multi-Record Type Encoding (for broadcast mode)
    // ============================================================

    /// Encode to DNS query with specified record type
    pub fn encode_to_dns_query_typed(
        &self,
        data: &[u8],
        domain: &str,
        packet_id: u16,
        fragment_id: u8,
        total_fragments: u8,
        record_type: TunnelRecordType,
    ) -> Result<Message> {
        // Create packet header: packet_id (2 bytes) + fragment_id (1) + total_fragments (1) + data
        let mut packet_data = Vec::with_capacity(4 + data.len());
        packet_data.extend_from_slice(&packet_id.to_be_bytes());
        packet_data.push(fragment_id);
        packet_data.push(total_fragments);
        packet_data.extend_from_slice(data);

        // Encode to hex
        let encoded = hex::encode(&packet_data);
        
        let max_payload = self.max_payload_per_query_for_domain(domain);
        let max_encoded_len = (max_payload + 4) * 2;
        let subdomain = if max_payload > 0 && encoded.len() > max_encoded_len {
            let truncate_len = (max_encoded_len / 2) * 2;
            &encoded[..truncate_len]
        } else {
            &encoded
        };

        // Generate random 6-char hex prefix
        let random_bytes: [u8; 3] = rand::thread_rng().gen();
        let random_prefix = hex::encode(random_bytes);

        // Create DNS query
        let mut message = Message::new();
        message.set_id(rand::thread_rng().gen());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        // Build query name
        let query_name = self.build_name_with_prefix(&random_prefix, subdomain, domain)?;
        let name = Name::from_ascii(&query_name)
            .map_err(|e| anyhow!("Failed to create DNS name: {}", e))?;

        // Add question with specified record type
        let query = Query::query(name, record_type.to_dns_record_type());
        message.add_query(query);

        Ok(message)
    }

    /// Encode to DNS response with specified record type
    pub fn encode_to_dns_response_typed(
        &self,
        data: &[u8],
        domain: &str,
        packet_id: u16,
        fragment_id: u8,
        total_fragments: u8,
        query_id: u16,
        record_type: TunnelRecordType,
    ) -> Result<Message> {
        use hickory_proto::rr::{rdata, Record, RData};
        use std::net::{Ipv4Addr, Ipv6Addr};

        // Create packet header
        let mut packet_data = Vec::with_capacity(4 + data.len());
        packet_data.extend_from_slice(&packet_id.to_be_bytes());
        packet_data.push(fragment_id);
        packet_data.push(total_fragments);
        packet_data.extend_from_slice(data);

        let encoded = hex::encode(&packet_data);
        
        let max_payload = self.max_payload_per_query_for_domain(domain);
        let max_encoded_len = (max_payload + 4) * 2;
        let subdomain = if max_payload > 0 && encoded.len() > max_encoded_len {
            let truncate_len = (max_encoded_len / 2) * 2;
            &encoded[..truncate_len]
        } else {
            &encoded
        };

        let random_bytes: [u8; 3] = rand::thread_rng().gen();
        let random_prefix = hex::encode(random_bytes);

        let mut message = Message::new();
        message.set_id(query_id);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let response_name = self.build_name_with_prefix(&random_prefix, subdomain, domain)?;
        let name = Name::from_ascii(&response_name)
            .map_err(|e| anyhow!("Failed to create DNS name: {}", e))?;

        match record_type {
            TunnelRecordType::TXT => {
                let mut record = Record::new();
                record.set_name(name.clone());
                record.set_record_type(RecordType::TXT);
                record.set_ttl(0);
                record.set_data(Some(RData::TXT(rdata::TXT::new(vec![subdomain.to_string()]))));
                message.add_answer(record);
            }
            TunnelRecordType::A => {
                // Encode data into multiple A records (4 bytes each)
                let hex_bytes = hex::decode(subdomain).unwrap_or_default();
                for chunk in hex_bytes.chunks(4) {
                    let mut ip_bytes = [0u8; 4];
                    for (i, &b) in chunk.iter().enumerate() {
                        ip_bytes[i] = b;
                    }
                    let ip = Ipv4Addr::from(ip_bytes);
                    let mut record = Record::new();
                    record.set_name(name.clone());
                    record.set_record_type(RecordType::A);
                    record.set_ttl(0);
                    record.set_data(Some(RData::A(rdata::A(ip))));
                    message.add_answer(record);
                }
            }
            TunnelRecordType::AAAA => {
                // Encode data into multiple AAAA records (16 bytes each)
                let hex_bytes = hex::decode(subdomain).unwrap_or_default();
                for chunk in hex_bytes.chunks(16) {
                    let mut ip_bytes = [0u8; 16];
                    for (i, &b) in chunk.iter().enumerate() {
                        ip_bytes[i] = b;
                    }
                    let ip = Ipv6Addr::from(ip_bytes);
                    let mut record = Record::new();
                    record.set_name(name.clone());
                    record.set_record_type(RecordType::AAAA);
                    record.set_ttl(0);
                    record.set_data(Some(RData::AAAA(rdata::AAAA(ip))));
                    message.add_answer(record);
                }
            }
            TunnelRecordType::CNAME | TunnelRecordType::NS => {
                // Encode data as name labels
                let target_name = self.build_name_with_prefix(&random_prefix, subdomain, domain)?;
                let target = Name::from_ascii(&target_name)
                    .map_err(|e| anyhow!("Failed to create target name: {}", e))?;
                let mut record = Record::new();
                record.set_name(name.clone());
                if record_type == TunnelRecordType::CNAME {
                    record.set_record_type(RecordType::CNAME);
                    record.set_data(Some(RData::CNAME(rdata::CNAME(target))));
                } else {
                    record.set_record_type(RecordType::NS);
                    record.set_data(Some(RData::NS(rdata::NS(target))));
                }
                record.set_ttl(0);
                message.add_answer(record);
            }
            TunnelRecordType::MX => {
                let target_name = self.build_name_with_prefix(&random_prefix, subdomain, domain)?;
                let target = Name::from_ascii(&target_name)
                    .map_err(|e| anyhow!("Failed to create MX target: {}", e))?;
                let mut record = Record::new();
                record.set_name(name.clone());
                record.set_record_type(RecordType::MX);
                record.set_ttl(0);
                record.set_data(Some(RData::MX(rdata::MX::new(10, target))));
                message.add_answer(record);
            }
            TunnelRecordType::NULL => {
                // NULL record - raw binary data
                let hex_bytes = hex::decode(subdomain).unwrap_or_default();
                let mut record = Record::new();
                record.set_name(name.clone());
                record.set_record_type(RecordType::NULL);
                record.set_ttl(0);
                record.set_data(Some(RData::NULL(rdata::NULL::with(hex_bytes))));
                message.add_answer(record);
            }
        }

        Ok(message)
    }

    /// Decode DNS response trying all known record types
    pub fn decode_from_dns_response_any(&self, message: &Message, expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        if message.message_type() != MessageType::Response {
            return Ok(None);
        }

        // Try each answer record
        for answer in message.answers() {
            let name = answer.name().to_ascii();
            let name_str = name.trim_end_matches('.');
            
            // Check domain match
            let domain_match = expected_domains.iter().any(|domain| {
                (name_str.ends_with(&format!(".{}", domain)) || name_str == domain.as_str())
                    && name_str.len() > domain.len()
            });

            if !domain_match {
                continue;
            }

            // Try to decode based on record type
            let result = match answer.record_type() {
                RecordType::TXT => self.decode_txt_response(answer, expected_domains),
                RecordType::A => self.decode_a_response(message, expected_domains),
                RecordType::AAAA => self.decode_aaaa_response(message, expected_domains),
                RecordType::CNAME | RecordType::NS | RecordType::MX => {
                    self.decode_name_response(answer, expected_domains)
                }
                RecordType::NULL => self.decode_null_response(answer),
                _ => continue,
            };

            if let Ok(Some(packet)) = result {
                return Ok(Some(packet));
            }
        }

        // Fallback to query-based decoding
        if !message.queries().is_empty() {
            return self.decode_from_dns_query(message, expected_domains);
        }

        Ok(None)
    }

    fn decode_txt_response(&self, answer: &hickory_proto::rr::Record, expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        use hickory_proto::rr::RData;
        
        if let Some(RData::TXT(_txt)) = answer.data() {
            let name = answer.name().to_ascii();
            let name_str = name.trim_end_matches('.');
            
            // Extract subdomain
            let domain = expected_domains.iter()
                .filter(|d| {
                    let domain_with_dot = format!(".{}", d);
                    name_str.ends_with(&domain_with_dot) || name_str == d.as_str()
                })
                .max_by_key(|d| d.len());
            
            if let Some(domain) = domain {
                let full_subdomain = if let Some(stripped) = name_str.strip_suffix(&format!(".{}", domain)) {
                    stripped
                } else {
                    return Ok(None);
                };
                
                // Strip random prefix
                let parts: Vec<&str> = full_subdomain.split('.').collect();
                let payload_parts = if parts.len() >= 2 && parts[0].len() == 6 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
                    &parts[1..]
                } else {
                    &parts[..]
                };
                let subdomain_part = payload_parts.join("");
                
                return self.decode_subdomain(&subdomain_part);
            }
        }
        Ok(None)
    }

    fn decode_a_response(&self, message: &Message, _expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        use hickory_proto::rr::RData;
        
        // Collect all A record bytes
        let mut all_bytes = Vec::new();
        for answer in message.answers() {
            if let Some(RData::A(a)) = answer.data() {
                all_bytes.extend_from_slice(&a.0.octets());
            }
        }
        
        if all_bytes.len() < 4 {
            return Ok(None);
        }
        
        // Decode as tunnel packet
        let packet_id = u16::from_be_bytes([all_bytes[0], all_bytes[1]]);
        let fragment_id = all_bytes[2];
        let total_fragments = all_bytes[3];
        let data = all_bytes[4..].to_vec();
        
        // Basic validation
        if total_fragments == 0 || total_fragments > 200 || fragment_id >= total_fragments {
            return Ok(None);
        }
        
        Ok(Some(TunnelPacket {
            data,
            source: "0.0.0.0:0".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
            packet_id,
            fragment_id,
            total_fragments,
            flags: PacketFlags::Data,
            session_id: 0,
        }))
    }

    fn decode_aaaa_response(&self, message: &Message, _expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        use hickory_proto::rr::RData;
        
        let mut all_bytes = Vec::new();
        for answer in message.answers() {
            if let Some(RData::AAAA(aaaa)) = answer.data() {
                all_bytes.extend_from_slice(&aaaa.0.octets());
            }
        }
        
        if all_bytes.len() < 4 {
            return Ok(None);
        }
        
        let packet_id = u16::from_be_bytes([all_bytes[0], all_bytes[1]]);
        let fragment_id = all_bytes[2];
        let total_fragments = all_bytes[3];
        let data = all_bytes[4..].to_vec();
        
        if total_fragments == 0 || total_fragments > 200 || fragment_id >= total_fragments {
            return Ok(None);
        }
        
        Ok(Some(TunnelPacket {
            data,
            source: "0.0.0.0:0".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
            packet_id,
            fragment_id,
            total_fragments,
            flags: PacketFlags::Data,
            session_id: 0,
        }))
    }

    fn decode_name_response(&self, answer: &hickory_proto::rr::Record, expected_domains: &[String]) -> Result<Option<TunnelPacket>> {
        use hickory_proto::rr::RData;
        
        let target_name = match answer.data() {
            Some(RData::CNAME(cname)) => cname.0.to_ascii(),
            Some(RData::NS(ns)) => ns.0.to_ascii(),
            Some(RData::MX(mx)) => mx.exchange().to_ascii(),
            _ => return Ok(None),
        };
        
        let name_str = target_name.trim_end_matches('.');
        
        // Find matching domain
        let domain = expected_domains.iter()
            .filter(|d| {
                let domain_with_dot = format!(".{}", d);
                name_str.ends_with(&domain_with_dot) || name_str == d.as_str()
            })
            .max_by_key(|d| d.len());
        
        if let Some(domain) = domain {
            let full_subdomain = if let Some(stripped) = name_str.strip_suffix(&format!(".{}", domain)) {
                stripped
            } else {
                return Ok(None);
            };
            
            // Strip random prefix
            let parts: Vec<&str> = full_subdomain.split('.').collect();
            let payload_parts = if parts.len() >= 2 && parts[0].len() == 6 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
                &parts[1..]
            } else {
                &parts[..]
            };
            let subdomain_part = payload_parts.join("");
            
            return self.decode_subdomain(&subdomain_part);
        }
        
        Ok(None)
    }

    fn decode_null_response(&self, answer: &hickory_proto::rr::Record) -> Result<Option<TunnelPacket>> {
        use hickory_proto::rr::RData;
        
        if let Some(RData::NULL(null_data)) = answer.data() {
            let data = null_data.anything().to_vec();
            if data.len() < 4 {
                return Ok(None);
            }
            
            let packet_id = u16::from_be_bytes([data[0], data[1]]);
            let fragment_id = data[2];
            let total_fragments = data[3];
            let payload = data[4..].to_vec();
            
            if total_fragments == 0 || total_fragments > 200 || fragment_id >= total_fragments {
                return Ok(None);
            }
            
            return Ok(Some(TunnelPacket {
                data: payload,
                source: "0.0.0.0:0".parse().unwrap(),
                destination: "0.0.0.0:0".parse().unwrap(),
                packet_id,
                fragment_id,
                total_fragments,
                flags: PacketFlags::Data,
                session_id: 0,
            }));
        }
        Ok(None)
    }
}
