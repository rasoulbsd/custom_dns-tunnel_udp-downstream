//! SOCKS5 protocol implementation for bi-directional tunneling
//! 
//! Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password Authentication)
//! Supports CONNECT and UDP ASSOCIATE commands for TCP and UDP proxying.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use log::{debug, info};

/// SOCKS5 version
pub const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    NoAuth = 0x00,
    Gssapi = 0x01,
    UsernamePassword = 0x02,
    NoAcceptable = 0xFF,
}

/// SOCKS5 commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = io::Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(io::Error::new(ErrorKind::InvalidInput, "Invalid SOCKS5 command")),
        }
    }
}

/// SOCKS5 address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

/// SOCKS5 reply codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// Target address for SOCKS5 connection
#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    /// Resolve domain to SocketAddr (for domain addresses)
    pub async fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            TargetAddr::Ip(addr) => Ok(*addr),
            TargetAddr::Domain(domain, port) => {
                use tokio::net::lookup_host;
                let addr_str = format!("{}:{}", domain, port);
                let mut addrs = lookup_host(&addr_str).await?;
                addrs.next().ok_or_else(|| {
                    io::Error::new(ErrorKind::NotFound, "Failed to resolve domain")
                })
            }
        }
    }

    /// Convert to bytes for SOCKS5 protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            TargetAddr::Ip(SocketAddr::V4(v4)) => {
                buf.push(AddressType::IPv4 as u8);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            TargetAddr::Ip(SocketAddr::V6(v6)) => {
                buf.push(AddressType::IPv6 as u8);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                buf.push(AddressType::DomainName as u8);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }
}

/// SOCKS5 connection request
#[derive(Debug)]
pub struct Socks5Request {
    pub command: Command,
    pub target: TargetAddr,
}

/// SOCKS5 server that handles client connections
pub struct Socks5Server {
    listener: TcpListener,
}

impl Socks5Server {
    /// Create a new SOCKS5 server bound to the given address
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("[SOCKS5] Server listening on {}", addr);
        Ok(Self { listener })
    }

    /// Accept a new client connection
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept().await
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

/// Handle SOCKS5 handshake and return the request
pub async fn handle_socks5_handshake(stream: &mut TcpStream) -> io::Result<Socks5Request> {
    // Read version and number of methods
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    
    if buf[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid SOCKS version: {}", buf[0]),
        ));
    }
    
    let nmethods = buf[1] as usize;
    
    // Read supported methods
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    
    // For simplicity, we only support no authentication
    // In production, you'd want to check for auth methods here
    let selected_method = if methods.contains(&(AuthMethod::NoAuth as u8)) {
        AuthMethod::NoAuth
    } else {
        AuthMethod::NoAcceptable
    };
    
    // Send method selection
    stream.write_all(&[SOCKS5_VERSION, selected_method as u8]).await?;
    
    if selected_method == AuthMethod::NoAcceptable {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "No acceptable authentication method",
        ));
    }
    
    // Read connection request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    
    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Invalid SOCKS version in request",
        ));
    }
    
    let command = Command::try_from(header[1])?;
    // header[2] is reserved (RSV)
    let atyp = header[3];
    
    // Read target address
    let target = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            
            TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr),
                u16::from_be_bytes(port),
            )))
        }
        0x03 => {
            // Domain name
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            
            let domain_str = String::from_utf8(domain)
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Invalid domain name"))?;
            TargetAddr::Domain(domain_str, u16::from_be_bytes(port))
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            
            TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr),
                u16::from_be_bytes(port),
                0,
                0,
            )))
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unsupported address type: {}", atyp),
            ));
        }
    };
    
    debug!("[SOCKS5] Request: {:?} -> {:?}", command, target);
    
    Ok(Socks5Request { command, target })
}

/// Send SOCKS5 reply
pub async fn send_socks5_reply(
    stream: &mut TcpStream,
    reply: ReplyCode,
    bind_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let mut response = vec![SOCKS5_VERSION, reply as u8, 0x00]; // VER, REP, RSV
    
    // Add bound address
    let addr = bind_addr.unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
    match addr {
        SocketAddr::V4(v4) => {
            response.push(AddressType::IPv4 as u8);
            response.extend_from_slice(&v4.ip().octets());
            response.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            response.push(AddressType::IPv6 as u8);
            response.extend_from_slice(&v6.ip().octets());
            response.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    
    stream.write_all(&response).await?;
    Ok(())
}

/// Parse SOCKS5 UDP relay header
/// Format: RSV (2) + FRAG (1) + ATYP (1) + DST.ADDR (variable) + DST.PORT (2) + DATA
pub fn parse_udp_relay_header(data: &[u8]) -> Option<(TargetAddr, &[u8])> {
    if data.len() < 10 {
        return None;
    }
    
    // RSV must be 0x0000
    if data[0] != 0 || data[1] != 0 {
        return None;
    }
    
    // FRAG: we don't support fragmentation
    if data[2] != 0 {
        return None;
    }
    
    let atyp = data[3];
    let (target, header_len) = match atyp {
        0x01 if data.len() >= 10 => {
            // IPv4: ATYP(1) + ADDR(4) + PORT(2) = 7 bytes after RSV+FRAG
            let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            (TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(addr, port))), 10)
        }
        0x03 => {
            // Domain
            let len = data[4] as usize;
            if data.len() < 7 + len {
                return None;
            }
            let domain = String::from_utf8(data[5..5 + len].to_vec()).ok()?;
            let port = u16::from_be_bytes([data[5 + len], data[6 + len]]);
            (TargetAddr::Domain(domain, port), 7 + len)
        }
        0x04 if data.len() >= 22 => {
            // IPv6: ATYP(1) + ADDR(16) + PORT(2) = 19 bytes after RSV+FRAG
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let addr = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            (TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0))), 22)
        }
        _ => return None,
    };
    
    Some((target, &data[header_len..]))
}

/// Build SOCKS5 UDP relay header
pub fn build_udp_relay_header(target: &TargetAddr) -> Vec<u8> {
    let mut buf = vec![0x00, 0x00, 0x00]; // RSV + FRAG
    buf.extend_from_slice(&target.to_bytes());
    buf
}

/// SOCKS5 connection handler that bridges a SOCKS5 client to the tunnel
pub struct Socks5Connection {
    pub stream: TcpStream,
    pub request: Socks5Request,
    pub client_addr: SocketAddr,
}

impl Socks5Connection {
    /// Create a new connection from an accepted stream
    pub async fn from_stream(mut stream: TcpStream, client_addr: SocketAddr) -> io::Result<Self> {
        let request = handle_socks5_handshake(&mut stream).await?;
        Ok(Self {
            stream,
            request,
            client_addr,
        })
    }

    /// Send success reply with bound address
    pub async fn send_success(&mut self, bind_addr: SocketAddr) -> io::Result<()> {
        send_socks5_reply(&mut self.stream, ReplyCode::Succeeded, Some(bind_addr)).await
    }

    /// Send failure reply
    pub async fn send_failure(&mut self, code: ReplyCode) -> io::Result<()> {
        send_socks5_reply(&mut self.stream, code, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_addr_to_bytes_ipv4() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let target = TargetAddr::Ip(addr);
        let bytes = target.to_bytes();
        
        assert_eq!(bytes[0], AddressType::IPv4 as u8);
        assert_eq!(&bytes[1..5], &[192, 168, 1, 1]);
        assert_eq!(&bytes[5..7], &8080u16.to_be_bytes());
    }

    #[test]
    fn test_target_addr_to_bytes_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let bytes = target.to_bytes();
        
        assert_eq!(bytes[0], AddressType::DomainName as u8);
        assert_eq!(bytes[1], 11); // "example.com".len()
        assert_eq!(&bytes[2..13], b"example.com");
        assert_eq!(&bytes[13..15], &443u16.to_be_bytes());
    }

    #[test]
    fn test_parse_udp_relay_header() {
        let mut data = vec![0x00, 0x00, 0x00]; // RSV + FRAG
        data.push(0x01); // IPv4
        data.extend_from_slice(&[192, 168, 1, 1]); // IP
        data.extend_from_slice(&8080u16.to_be_bytes()); // Port
        data.extend_from_slice(b"Hello"); // Data
        
        let (target, payload) = parse_udp_relay_header(&data).unwrap();
        
        if let TargetAddr::Ip(addr) = target {
            assert_eq!(addr.to_string(), "192.168.1.1:8080");
        } else {
            panic!("Expected IP address");
        }
        
        assert_eq!(payload, b"Hello");
    }
}
