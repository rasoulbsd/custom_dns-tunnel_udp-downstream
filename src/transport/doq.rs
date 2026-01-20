//! DNS over QUIC (DoQ) transport adapter
//!
//! Uses QUIC to send DNS queries, providing:
//! - Built-in reliability and congestion control
//! - Multiplexed streams
//! - 0-RTT resumption
//! - Better performance than DoH for DNS

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::{
    RecvResult, ResolverEndpoint, SendResult, Transport, TransportError, TransportType,
};

/// DoQ transport configuration
#[derive(Debug, Clone)]
pub struct DoQConfig {
    /// Server address (host:port)
    pub server_addr: SocketAddr,
    /// Server name for TLS
    pub server_name: String,
    /// Domain to use for DNS queries
    pub domain: String,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Idle timeout for connection
    pub idle_timeout: Duration,
    /// Maximum label length
    pub max_label_len: usize,
}

impl Default for DoQConfig {
    fn default() -> Self {
        Self {
            server_addr: "8.8.8.8:853".parse().unwrap(),
            server_name: "dns.google".to_string(),
            domain: "example.com".to_string(),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
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

/// DNS over QUIC transport
/// 
/// Note: This is a stub implementation. For production use,
/// integrate with quinn crate for QUIC support.
#[derive(Debug)]
pub struct DoQTransport {
    config: DoQConfig,
    response_queue: Mutex<ResponseQueue>,
    closed: Mutex<bool>,
}

impl DoQTransport {
    /// Create a new DoQ transport
    pub fn new(config: DoQConfig) -> Self {
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

        // DoQ uses 2-byte length prefix
        let wire = message.to_vec()
            .map_err(|e| TransportError::Protocol(format!("Failed to encode: {}", e)))?;
        
        let mut result = Vec::with_capacity(2 + wire.len());
        result.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        result.extend_from_slice(&wire);
        
        Ok(result)
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

        // Skip 2-byte length prefix
        if data.len() < 2 {
            return Err(TransportError::InvalidResponse("Too short".to_string()));
        }
        let msg_data = &data[2..];

        let message = Message::from_vec(msg_data)
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
impl Transport for DoQTransport {
    fn name(&self) -> &str {
        "doq"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::DoQ
    }

    async fn send(&self, data: &[u8], endpoint: &ResolverEndpoint) -> Result<SendResult, TransportError> {
        if *self.closed.lock().await {
            return Err(TransportError::Closed);
        }

        let _query = self.encode_query(data)?;
        let start = Instant::now();

        // TODO: Implement actual QUIC connection using quinn
        // For now, this is a stub that always fails
        //
        // Example implementation with quinn:
        // let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        // let connection = endpoint.connect(server_addr, &server_name)?.await?;
        // let (mut send, mut recv) = connection.open_bi().await?;
        // send.write_all(&query).await?;
        // send.finish().await?;
        // let response = recv.read_to_end(65535).await?;
        // let payload = self.decode_response(&response)?;
        //
        // Queue the response for recv()

        log::warn!("DoQ transport is a stub - not implemented yet");

        Ok(SendResult {
            success: false,
            rtt: Some(start.elapsed()),
            error: Some("DoQ not implemented yet".to_string()),
        })
    }

    async fn recv(&self, timeout: Duration) -> Result<Option<RecvResult>, TransportError> {
        if *self.closed.lock().await {
            return Err(TransportError::Closed);
        }

        // DoQ responses are received synchronously in send()
        // and queued for recv()
        let mut queue = self.response_queue.lock().await;
        Ok(queue.pop())
    }

    fn max_payload_size(&self) -> usize {
        // QUIC can handle larger payloads
        // Limited by QUIC frame size (~16KB typical)
        1200
    }

    fn supports_multiplexing(&self) -> bool {
        // QUIC streams support multiplexing
        true
    }

    fn estimated_overhead(&self) -> usize {
        // QUIC headers + TLS + DNS encoding + length prefix
        50
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
    fn test_doq_config() {
        let config = DoQConfig::default();
        assert_eq!(config.server_addr.port(), 853);
    }

    #[tokio::test]
    async fn test_doq_transport_creation() {
        let config = DoQConfig::default();
        let transport = DoQTransport::new(config);
        
        assert_eq!(transport.name(), "doq");
        assert_eq!(transport.transport_type(), TransportType::DoQ);
        assert!(transport.supports_multiplexing());
    }
}
