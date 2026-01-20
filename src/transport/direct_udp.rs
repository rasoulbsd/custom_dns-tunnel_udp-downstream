//! Direct UDP transport adapter
//!
//! Raw UDP tunnel without DNS encoding. Used as:
//! - Fallback when DNS is blocked
//! - Direct connection to server when possible
//! - Higher bandwidth option

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::{
    RecvResult, ResolverEndpoint, SendResult, Transport, TransportError, TransportType,
};

/// Direct UDP transport configuration
#[derive(Debug, Clone)]
pub struct DirectUdpConfig {
    /// Local bind address
    pub bind_addr: SocketAddr,
    /// Receive buffer size
    pub recv_buffer_size: usize,
}

impl Default for DirectUdpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            recv_buffer_size: 65535,
        }
    }
}

/// Direct UDP transport
#[derive(Debug)]
pub struct DirectUdpTransport {
    config: DirectUdpConfig,
    socket: Arc<UdpSocket>,
    recv_buffer: Mutex<Vec<u8>>,
}

impl DirectUdpTransport {
    /// Create a new Direct UDP transport
    pub async fn new(config: DirectUdpConfig) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        
        Ok(Self {
            recv_buffer: Mutex::new(vec![0u8; config.recv_buffer_size]),
            config,
            socket: Arc::new(socket),
        })
    }

    /// Create with an existing socket
    pub fn with_socket(config: DirectUdpConfig, socket: Arc<UdpSocket>) -> Self {
        Self {
            recv_buffer: Mutex::new(vec![0u8; config.recv_buffer_size]),
            config,
            socket,
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket.local_addr().map_err(|e| TransportError::Io(e.to_string()))
    }

    /// Get the socket reference
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

#[async_trait]
impl Transport for DirectUdpTransport {
    fn name(&self) -> &str {
        "direct-udp"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::DirectUdp
    }

    async fn send(&self, data: &[u8], endpoint: &ResolverEndpoint) -> Result<SendResult, TransportError> {
        let addr = endpoint.socket_addr
            .ok_or_else(|| TransportError::Protocol("No socket address for endpoint".to_string()))?;

        let start = Instant::now();

        match self.socket.send_to(data, addr).await {
            Ok(sent) => {
                if sent != data.len() {
                    return Ok(SendResult {
                        success: false,
                        rtt: Some(start.elapsed()),
                        error: Some(format!("Partial send: {} of {} bytes", sent, data.len())),
                    });
                }
                Ok(SendResult {
                    success: true,
                    rtt: Some(start.elapsed()),
                    error: None,
                })
            }
            Err(e) => Ok(SendResult {
                success: false,
                rtt: Some(start.elapsed()),
                error: Some(e.to_string()),
            }),
        }
    }

    async fn recv(&self, timeout: Duration) -> Result<Option<RecvResult>, TransportError> {
        let mut buf = self.recv_buffer.lock().await;
        
        match tokio::time::timeout(timeout, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, source))) => {
                Ok(Some(RecvResult {
                    data: buf[..len].to_vec(),
                    source: Some(source),
                    metadata: None,
                }))
            }
            Ok(Err(e)) => Err(TransportError::Io(e.to_string())),
            Err(_) => Ok(None), // Timeout
        }
    }

    fn max_payload_size(&self) -> usize {
        // UDP MTU minus IP and UDP headers
        // Conservative value to avoid fragmentation
        1400
    }

    fn supports_multiplexing(&self) -> bool {
        false
    }

    fn estimated_overhead(&self) -> usize {
        // Just UDP/IP headers, no encoding
        28 // 20 IP + 8 UDP
    }

    async fn close(&self) -> Result<(), TransportError> {
        // UDP sockets don't need explicit close
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_udp_transport_creation() {
        let config = DirectUdpConfig::default();
        let transport = DirectUdpTransport::new(config).await.unwrap();
        
        assert_eq!(transport.name(), "direct-udp");
        assert_eq!(transport.transport_type(), TransportType::DirectUdp);
        assert!(!transport.supports_multiplexing());
        assert_eq!(transport.max_payload_size(), 1400);
        assert_eq!(transport.estimated_overhead(), 28);
    }

    #[tokio::test]
    async fn test_local_addr() {
        let config = DirectUdpConfig::default();
        let transport = DirectUdpTransport::new(config).await.unwrap();
        
        let addr = transport.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_send_recv_loopback() {
        // Create two transports for echo test
        let config1 = DirectUdpConfig::default();
        let transport1 = DirectUdpTransport::new(config1).await.unwrap();
        let addr1 = transport1.local_addr().unwrap();

        let config2 = DirectUdpConfig::default();
        let transport2 = DirectUdpTransport::new(config2).await.unwrap();
        let addr2 = transport2.local_addr().unwrap();

        // Send from transport1 to transport2
        let endpoint = ResolverEndpoint::new_direct_udp(1, addr2);
        let data = b"hello world";
        
        let result = transport1.send(data, &endpoint).await.unwrap();
        assert!(result.success);

        // Receive on transport2
        let recv = transport2.recv(Duration::from_millis(100)).await.unwrap();
        assert!(recv.is_some());
        let recv = recv.unwrap();
        assert_eq!(recv.data, data);
        // Source IP might be 127.0.0.1 or 0.0.0.0 depending on OS
        assert!(recv.source.is_some());
        assert_eq!(recv.source.unwrap().port(), addr1.port());
    }
}
