//! DNS over HTTPS (DoH) transport adapter
//!
//! Uses HTTPS to send DNS queries, providing:
//! - TCP reliability (no packet loss)
//! - HTTP/2 multiplexing
//! - Larger payload sizes
//! - Harder to block than plain DNS

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::{
    RecvResult, ResolverEndpoint, SendResult, Transport, TransportError, TransportType,
};

/// DoH transport configuration
#[derive(Debug, Clone)]
pub struct DoHConfig {
    /// DoH server URL (e.g., "https://cloudflare-dns.com/dns-query")
    pub url: String,
    /// Domain to use for DNS queries
    pub domain: String,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum label length
    pub max_label_len: usize,
}

impl Default for DoHConfig {
    fn default() -> Self {
        Self {
            url: "https://cloudflare-dns.com/dns-query".to_string(),
            domain: "example.com".to_string(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_label_len: 63,
        }
    }
}

/// Response queue for pending responses
#[derive(Debug)]
struct ResponseQueue {
    responses: Vec<RecvResult>,
}

impl ResponseQueue {
    fn new() -> Self {
        Self { responses: Vec::new() }
    }

    fn push(&mut self, response: RecvResult) {
        self.responses.push(response);
    }

    fn pop(&mut self) -> Option<RecvResult> {
        if self.responses.is_empty() {
            None
        } else {
            Some(self.responses.remove(0))
        }
    }
}

/// DNS over HTTPS transport
/// 
/// Note: This is a stub implementation. For production use,
/// integrate with reqwest crate for HTTP/2 support.
#[derive(Debug)]
pub struct DoHTransport {
    config: DoHConfig,
    response_queue: Mutex<ResponseQueue>,
    closed: Mutex<bool>,
}

impl DoHTransport {
    /// Create a new DoH transport
    pub fn new(config: DoHConfig) -> Self {
        Self {
            config,
            response_queue: Mutex::new(ResponseQueue::new()),
            closed: Mutex::new(false),
        }
    }

    /// Encode data into a DNS wire format query
    fn encode_query(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        use hickory_proto::{
            op::{Message, MessageType, OpCode, Query},
            rr::{Name, RecordType},
        };

        // Encode payload as hex
        let encoded = hex::encode(data);
        
        // Split into labels
        let labels = self.split_into_labels(&encoded);
        
        // Add random prefix
        let random_prefix = hex::encode(&rand::random::<[u8; 3]>());
        
        // Build query name
        let mut name_parts = vec![random_prefix];
        name_parts.extend(labels);
        name_parts.push(self.config.domain.clone());
        let query_name = name_parts.join(".");

        // Create DNS message
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let name = Name::from_ascii(&query_name)
            .map_err(|e| TransportError::Protocol(format!("Invalid DNS name: {}", e)))?;
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);

        message.to_vec()
            .map_err(|e| TransportError::Protocol(format!("Failed to encode: {}", e)))
    }

    fn split_into_labels(&self, data: &str) -> Vec<String> {
        let max_len = self.config.max_label_len.min(63);
        data.as_bytes()
            .chunks(max_len)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect()
    }

    /// Decode DNS response
    fn decode_response(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        use hickory_proto::{op::Message, rr::RecordType};

        let message = Message::from_vec(data)
            .map_err(|e| TransportError::InvalidResponse(format!("Invalid DNS: {}", e)))?;

        // Extract from TXT record
        for answer in message.answers() {
            if answer.record_type() == RecordType::TXT {
                let name = answer.name().to_ascii();
                if let Some(payload) = self.extract_payload(&name) {
                    return hex::decode(&payload)
                        .map_err(|e| TransportError::InvalidResponse(format!("Bad hex: {}", e)));
                }
            }
        }

        Err(TransportError::InvalidResponse("No payload".to_string()))
    }

    fn extract_payload(&self, name: &str) -> Option<String> {
        let name = name.trim_end_matches('.');
        let domain_suffix = format!(".{}", self.config.domain);
        
        if !name.ends_with(&domain_suffix) {
            return None;
        }

        let subdomain = &name[..name.len() - domain_suffix.len()];
        let parts: Vec<&str> = subdomain.split('.').collect();
        
        if parts.is_empty() {
            return None;
        }

        // Skip random prefix
        let payload_parts = if parts[0].len() == 6 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            &parts[1..]
        } else {
            &parts[..]
        };

        Some(payload_parts.join(""))
    }
}

#[async_trait]
impl Transport for DoHTransport {
    fn name(&self) -> &str {
        "doh"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::DoH
    }

    async fn send(&self, data: &[u8], endpoint: &ResolverEndpoint) -> Result<SendResult, TransportError> {
        if *self.closed.lock().await {
            return Err(TransportError::Closed);
        }

        let _query = self.encode_query(data)?;
        let start = Instant::now();

        // TODO: Implement actual HTTP POST request using reqwest
        // For now, this is a stub that always fails
        // 
        // Example implementation with reqwest:
        // let client = reqwest::Client::builder()
        //     .timeout(self.config.request_timeout)
        //     .build()?;
        //
        // let response = client
        //     .post(&endpoint.address)
        //     .header("Content-Type", "application/dns-message")
        //     .header("Accept", "application/dns-message")
        //     .body(query)
        //     .send()
        //     .await?;
        //
        // let response_data = response.bytes().await?;
        // let payload = self.decode_response(&response_data)?;
        // 
        // Queue the response for recv()

        log::warn!("DoH transport is a stub - not implemented yet");

        Ok(SendResult {
            success: false,
            rtt: Some(start.elapsed()),
            error: Some("DoH not implemented yet".to_string()),
        })
    }

    async fn recv(&self, timeout: Duration) -> Result<Option<RecvResult>, TransportError> {
        if *self.closed.lock().await {
            return Err(TransportError::Closed);
        }

        // DoH responses are received synchronously in send()
        // and queued for recv()
        let mut queue = self.response_queue.lock().await;
        Ok(queue.pop())
    }

    fn max_payload_size(&self) -> usize {
        // DoH can handle much larger payloads than DNS-UDP
        // Limited by HTTP body size, typically 64KB+
        2048
    }

    fn supports_multiplexing(&self) -> bool {
        // HTTP/2 supports multiplexing
        true
    }

    fn estimated_overhead(&self) -> usize {
        // HTTP headers + TLS + DNS encoding
        200
    }

    async fn close(&self) -> Result<(), TransportError> {
        *self.closed.lock().await = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_config() {
        let config = DoHConfig::default();
        assert!(config.url.starts_with("https://"));
    }

    #[tokio::test]
    async fn test_doh_transport_creation() {
        let config = DoHConfig::default();
        let transport = DoHTransport::new(config);
        
        assert_eq!(transport.name(), "doh");
        assert_eq!(transport.transport_type(), TransportType::DoH);
        assert!(transport.supports_multiplexing());
        assert!(transport.max_payload_size() > 1000);
    }
}
