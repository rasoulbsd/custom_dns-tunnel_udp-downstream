use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use log::{debug, error, info, warn};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_PACKET_SIZE: usize = 65507; // Max UDP packet size minus header

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpPacketFlags {
    Syn = 1,
    Ack = 2,
    Fin = 4,
    Data = 8,
    Rst = 16,
}

impl TcpPacketFlags {
    pub fn from_byte(byte: u8) -> Vec<Self> {
        let mut flags = Vec::new();
        if byte & 1 != 0 { flags.push(TcpPacketFlags::Syn); }
        if byte & 2 != 0 { flags.push(TcpPacketFlags::Ack); }
        if byte & 4 != 0 { flags.push(TcpPacketFlags::Fin); }
        if byte & 8 != 0 { flags.push(TcpPacketFlags::Data); }
        if byte & 16 != 0 { flags.push(TcpPacketFlags::Rst); }
        flags
    }

    pub fn to_byte(flags: &[Self]) -> u8 {
        let mut byte = 0u8;
        for flag in flags {
            byte |= *flag as u8;
        }
        byte
    }
}

#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub connection_id: u32,
    pub sequence: u32,
    pub data_length: u16,
    pub flags: u8,
    pub data: Vec<u8>,
}

impl TcpPacket {
    /// Serialize TCP packet to bytes
    /// Format: [4 bytes: connection_id][4 bytes: sequence][2 bytes: data_length][1 byte: flags][N bytes: data]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(11 + self.data.len());
        buf.extend_from_slice(&self.connection_id.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.data_length.to_be_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize TCP packet from bytes
    pub fn deserialize(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 11 {
            return Err(anyhow::anyhow!("Packet too short: {} bytes (need at least 11)", data.len()));
        }

        let connection_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let data_length = u16::from_be_bytes([data[8], data[9]]);
        let flags = data[10];
        
        log::debug!("Deserializing TCP packet: connection_id={}, sequence={}, data_length={}, flags={}, total_len={}", 
                   connection_id, sequence, data_length, flags, data.len());
        
        let expected_len = 11 + data_length as usize;
        if data.len() < expected_len {
            log::error!("TCP packet deserialization failed: have {} bytes, need {} bytes (data_length={}), connection_id={}, sequence={}", 
                       data.len(), expected_len, data_length, connection_id, sequence);
            return Err(anyhow::anyhow!(
                "Packet data incomplete: have {} bytes, need {} bytes (data_length={})",
                data.len(),
                expected_len,
                data_length
            ));
        }

        let packet_data = data[11..11 + data_length as usize].to_vec();

        Ok(TcpPacket {
            connection_id,
            sequence,
            data_length,
            flags,
            data: packet_data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Established,
    Closing,
    Closed,
}

#[derive(Debug)]
pub struct TcpConnection {
    pub id: u32,
    pub state: ConnectionState,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub last_activity: Instant,
    pub next_sequence: u32,
    pub expected_sequence: u32,
}

impl TcpConnection {
    pub fn new(id: u32, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            id,
            state: ConnectionState::Connecting,
            local_addr,
            remote_addr,
            last_activity: Instant::now(),
            next_sequence: 1,
            expected_sequence: 1,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > CONNECTION_TIMEOUT
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

pub struct TcpConnectionManager {
    connections: HashMap<u32, TcpConnection>,
    next_connection_id: u32,
}

impl TcpConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            next_connection_id: 1,
        }
    }

    pub fn create_connection(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> u32 {
        let id = self.next_connection_id;
        self.next_connection_id = self.next_connection_id.wrapping_add(1);
        
        let conn = TcpConnection::new(id, local_addr, remote_addr);
        self.connections.insert(id, conn);
        id
    }
    
    /// Create connection with a specific ID (for server-side when client provides ID)
    pub fn create_connection_with_id(&mut self, id: u32, local_addr: SocketAddr, remote_addr: SocketAddr) {
        let conn = TcpConnection::new(id, local_addr, remote_addr);
        self.connections.insert(id, conn);
    }

    pub fn get_connection(&mut self, id: u32) -> Option<&mut TcpConnection> {
        self.cleanup_expired();
        self.connections.get_mut(&id)
    }

    pub fn remove_connection(&mut self, id: u32) {
        self.connections.remove(&id);
    }

    pub fn cleanup_expired(&mut self) {
        let expired_ids: Vec<u32> = self.connections
            .iter()
            .filter(|(_, conn)| conn.is_expired())
            .map(|(id, _)| *id)
            .collect();
        
        for id in expired_ids {
            info!("Removing expired connection: {}", id);
            self.connections.remove(&id);
        }
    }

    pub fn get_all_connections(&self) -> Vec<u32> {
        self.connections.keys().copied().collect()
    }
}

impl Default for TcpConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract TCP packet from reassembled UDP data
pub fn extract_tcp_packet(data: &[u8]) -> anyhow::Result<TcpPacket> {
    TcpPacket::deserialize(data)
}

/// Create TCP packet for sending data
pub fn create_tcp_data_packet(connection_id: u32, sequence: u32, data: &[u8]) -> TcpPacket {
    let flags = TcpPacketFlags::to_byte(&[TcpPacketFlags::Data]);
    TcpPacket {
        connection_id,
        sequence,
        data_length: data.len() as u16,
        flags,
        data: data.to_vec(),
    }
}

/// Create TCP SYN packet
pub fn create_tcp_syn_packet(connection_id: u32) -> TcpPacket {
    TcpPacket {
        connection_id,
        sequence: 0,
        data_length: 0,
        flags: TcpPacketFlags::to_byte(&[TcpPacketFlags::Syn]),
        data: Vec::new(),
    }
}

/// Create TCP SYN-ACK packet
pub fn create_tcp_syn_ack_packet(connection_id: u32, sequence: u32) -> TcpPacket {
    TcpPacket {
        connection_id,
        sequence,
        data_length: 0,
        flags: TcpPacketFlags::to_byte(&[TcpPacketFlags::Syn, TcpPacketFlags::Ack]),
        data: Vec::new(),
    }
}

/// Create TCP ACK packet
pub fn create_tcp_ack_packet(connection_id: u32, sequence: u32) -> TcpPacket {
    TcpPacket {
        connection_id,
        sequence,
        data_length: 0,
        flags: TcpPacketFlags::to_byte(&[TcpPacketFlags::Ack]),
        data: Vec::new(),
    }
}

/// Create TCP FIN packet
pub fn create_tcp_fin_packet(connection_id: u32, sequence: u32) -> TcpPacket {
    TcpPacket {
        connection_id,
        sequence,
        data_length: 0,
        flags: TcpPacketFlags::to_byte(&[TcpPacketFlags::Fin]),
        data: Vec::new(),
    }
}

/// Create TCP RST packet
pub fn create_tcp_rst_packet(connection_id: u32) -> TcpPacket {
    TcpPacket {
        connection_id,
        sequence: 0,
        data_length: 0,
        flags: TcpPacketFlags::to_byte(&[TcpPacketFlags::Rst]),
        data: Vec::new(),
    }
}
