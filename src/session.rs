//! Session management for bi-directional tunnel multiplexing
//! 
//! This module provides session multiplexing over the DNS tunnel,
//! allowing multiple concurrent TCP/UDP connections to share the same tunnel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use log::{debug, info, warn};

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, waiting for SYN-ACK
    SynSent,
    /// Connection established
    Established,
    /// FIN sent, waiting for FIN-ACK
    FinWait,
    /// Connection closed
    Closed,
}

/// Session flags for protocol control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionFlags {
    /// Normal data packet
    Data = 0x00,
    /// SYN - initiate new session
    Syn = 0x01,
    /// SYN-ACK - acknowledge session initiation
    SynAck = 0x02,
    /// FIN - close session
    Fin = 0x04,
    /// FIN-ACK - acknowledge session close
    FinAck = 0x08,
    /// RST - reset session (error)
    Rst = 0x10,
    /// ACK - general acknowledgment
    Ack = 0x20,
}

impl From<u8> for SessionFlags {
    fn from(value: u8) -> Self {
        match value {
            0x00 => SessionFlags::Data,
            0x01 => SessionFlags::Syn,
            0x02 => SessionFlags::SynAck,
            0x04 => SessionFlags::Fin,
            0x08 => SessionFlags::FinAck,
            0x10 => SessionFlags::Rst,
            0x20 => SessionFlags::Ack,
            _ => SessionFlags::Data,
        }
    }
}

/// Session connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// TCP connection (SOCKS5 CONNECT)
    Tcp,
    /// UDP association (SOCKS5 UDP ASSOCIATE)
    Udp,
}

/// Session header prepended to tunnel packets
/// Format: [session_id: 4] [flags: 1] [type: 1] [data...]
#[derive(Debug, Clone)]
pub struct SessionHeader {
    pub session_id: u32,
    pub flags: SessionFlags,
    pub session_type: SessionType,
}

impl SessionHeader {
    pub const SIZE: usize = 6;

    pub fn new(session_id: u32, flags: SessionFlags, session_type: SessionType) -> Self {
        Self {
            session_id,
            flags,
            session_type,
        }
    }

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4] = self.flags as u8;
        buf[5] = match self.session_type {
            SessionType::Tcp => 0x01,
            SessionType::Udp => 0x02,
        };
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        
        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let flags = SessionFlags::from(data[4]);
        let session_type = match data[5] {
            0x01 => SessionType::Tcp,
            0x02 => SessionType::Udp,
            _ => SessionType::Tcp,
        };
        
        Some(Self {
            session_id,
            flags,
            session_type,
        })
    }
}

/// Session packet with header and data
#[derive(Debug, Clone)]
pub struct SessionPacket {
    pub header: SessionHeader,
    pub data: Vec<u8>,
    /// For SYN packets: target address to connect to
    pub target_addr: Option<SocketAddr>,
}

impl SessionPacket {
    pub fn new_syn(session_id: u32, session_type: SessionType, target_addr: SocketAddr) -> Self {
        Self {
            header: SessionHeader::new(session_id, SessionFlags::Syn, session_type),
            data: encode_socket_addr(&target_addr),
            target_addr: Some(target_addr),
        }
    }

    pub fn new_syn_ack(session_id: u32, session_type: SessionType) -> Self {
        Self {
            header: SessionHeader::new(session_id, SessionFlags::SynAck, session_type),
            data: Vec::new(),
            target_addr: None,
        }
    }

    pub fn new_data(session_id: u32, session_type: SessionType, data: Vec<u8>) -> Self {
        Self {
            header: SessionHeader::new(session_id, SessionFlags::Data, session_type),
            data,
            target_addr: None,
        }
    }

    pub fn new_fin(session_id: u32, session_type: SessionType) -> Self {
        Self {
            header: SessionHeader::new(session_id, SessionFlags::Fin, session_type),
            data: Vec::new(),
            target_addr: None,
        }
    }

    pub fn new_rst(session_id: u32, session_type: SessionType) -> Self {
        Self {
            header: SessionHeader::new(session_id, SessionFlags::Rst, session_type),
            data: Vec::new(),
            target_addr: None,
        }
    }

    /// Encode session packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SessionHeader::SIZE + self.data.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode session packet from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        let header = SessionHeader::decode(data)?;
        let payload = if data.len() > SessionHeader::SIZE {
            data[SessionHeader::SIZE..].to_vec()
        } else {
            Vec::new()
        };
        
        // Parse target address from SYN packets
        let target_addr = if header.flags == SessionFlags::Syn && !payload.is_empty() {
            decode_socket_addr(&payload)
        } else {
            None
        };
        
        Some(Self {
            header,
            data: payload,
            target_addr,
        })
    }
}

/// Encode socket address to bytes
/// Format: [type: 1] [addr: 4 or 16] [port: 2]
fn encode_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(0x01); // IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04); // IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    buf
}

/// Decode socket address from bytes
fn decode_socket_addr(data: &[u8]) -> Option<SocketAddr> {
    if data.is_empty() {
        return None;
    }
    
    match data[0] {
        0x01 if data.len() >= 7 => {
            // IPv4
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        0x04 if data.len() >= 19 => {
            // IPv6
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => None,
    }
}

/// Individual session state
#[derive(Debug)]
pub struct Session {
    pub id: u32,
    pub state: SessionState,
    pub session_type: SessionType,
    pub target_addr: Option<SocketAddr>,
    pub created_at: Instant,
    pub last_activity: Instant,
    /// Channel to send data to the session handler
    pub data_tx: mpsc::Sender<Vec<u8>>,
}

/// Session manager for multiplexing connections
pub struct SessionManager {
    sessions: HashMap<u32, Session>,
    next_session_id: AtomicU32,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(300)) // 5 minute default timeout
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: AtomicU32::new(1),
            session_timeout: timeout,
        }
    }

    /// Generate a new unique session ID
    pub fn next_id(&self) -> u32 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Create a new session
    pub fn create_session(
        &mut self,
        session_type: SessionType,
        target_addr: Option<SocketAddr>,
        data_tx: mpsc::Sender<Vec<u8>>,
    ) -> u32 {
        let id = self.next_id();
        let now = Instant::now();
        
        let session = Session {
            id,
            state: SessionState::SynSent,
            session_type,
            target_addr,
            created_at: now,
            last_activity: now,
            data_tx,
        };
        
        self.sessions.insert(id, session);
        info!("[SESSION] Created session {} ({:?}) -> {:?}", id, session_type, target_addr);
        id
    }

    /// Register an incoming session (from remote side)
    pub fn register_incoming_session(
        &mut self,
        id: u32,
        session_type: SessionType,
        target_addr: Option<SocketAddr>,
        data_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let now = Instant::now();
        
        let session = Session {
            id,
            state: SessionState::Established,
            session_type,
            target_addr,
            created_at: now,
            last_activity: now,
            data_tx,
        };
        
        self.sessions.insert(id, session);
        info!("[SESSION] Registered incoming session {} ({:?}) -> {:?}", id, session_type, target_addr);
    }

    /// Get a session by ID
    pub fn get(&self, id: u32) -> Option<&Session> {
        self.sessions.get(&id)
    }

    /// Get a mutable session by ID
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    /// Update session state
    pub fn update_state(&mut self, id: u32, state: SessionState) {
        if let Some(session) = self.sessions.get_mut(&id) {
            debug!("[SESSION] Session {} state: {:?} -> {:?}", id, session.state, state);
            session.state = state;
            session.last_activity = Instant::now();
        }
    }

    /// Mark session activity
    pub fn touch(&mut self, id: u32) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.last_activity = Instant::now();
        }
    }

    /// Close a session
    pub fn close(&mut self, id: u32) {
        if let Some(session) = self.sessions.remove(&id) {
            info!("[SESSION] Closed session {} ({:?})", id, session.session_type);
        }
    }

    /// Clean up timed-out sessions
    pub fn cleanup(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let mut closed = Vec::new();
        
        self.sessions.retain(|&id, session| {
            let elapsed = now.duration_since(session.last_activity);
            if elapsed > self.session_timeout {
                warn!("[SESSION] Session {} timed out after {:?}", id, elapsed);
                closed.push(id);
                false
            } else {
                true
            }
        });
        
        closed
    }

    /// Get number of active sessions
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a session exists
    pub fn exists(&self, id: u32) -> bool {
        self.sessions.contains_key(&id)
    }

    /// Get all session IDs
    pub fn session_ids(&self) -> Vec<u32> {
        self.sessions.keys().copied().collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_header_encode_decode() {
        let header = SessionHeader::new(12345, SessionFlags::Syn, SessionType::Tcp);
        let encoded = header.encode();
        let decoded = SessionHeader::decode(&encoded).unwrap();
        
        assert_eq!(decoded.session_id, 12345);
        assert_eq!(decoded.flags, SessionFlags::Syn);
        assert_eq!(decoded.session_type, SessionType::Tcp);
    }

    #[test]
    fn test_session_packet_encode_decode() {
        let target: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let packet = SessionPacket::new_syn(100, SessionType::Tcp, target);
        
        let encoded = packet.encode();
        let decoded = SessionPacket::decode(&encoded).unwrap();
        
        assert_eq!(decoded.header.session_id, 100);
        assert_eq!(decoded.header.flags, SessionFlags::Syn);
        assert_eq!(decoded.target_addr, Some(target));
    }

    #[test]
    fn test_socket_addr_encode_decode() {
        let addr_v4: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let encoded = encode_socket_addr(&addr_v4);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr_v4);
        
        let addr_v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let encoded = encode_socket_addr(&addr_v6);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr_v6);
    }
}
