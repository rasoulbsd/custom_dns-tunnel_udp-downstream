use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const PACKET_TIMEOUT: Duration = Duration::from_secs(30);
const NACK_GENERATION_DELAY_MS: u64 = 50; // Generate NACK 50ms after first fragment

/// Packet flags for control messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketFlags {
    /// Normal data packet
    Data = 0x00,
    /// NACK - request retransmission of missing fragments
    Nack = 0x01,
    /// ACK - confirm receipt (optional, for future use)
    Ack = 0x02,
    /// SYN - session establishment (for SOCKS5)
    Syn = 0x04,
    /// FIN - session close
    Fin = 0x08,
    /// RST - session reset
    Rst = 0x10,
}

impl From<u8> for PacketFlags {
    fn from(value: u8) -> Self {
        match value {
            0x00 => PacketFlags::Data,
            0x01 => PacketFlags::Nack,
            0x02 => PacketFlags::Ack,
            0x04 => PacketFlags::Syn,
            0x08 => PacketFlags::Fin,
            0x10 => PacketFlags::Rst,
            _ => PacketFlags::Data, // Default to data for unknown flags
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelPacket {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub flags: PacketFlags,
    /// Session ID for multiplexed connections (0 = no session / legacy mode)
    pub session_id: u32,
}

impl TunnelPacket {
    pub fn new_data(
        data: Vec<u8>,
        packet_id: u16,
        fragment_id: u8,
        total_fragments: u8,
    ) -> Self {
        Self {
            data,
            source: "0.0.0.0:0".parse().unwrap(),
            destination: "0.0.0.0:0".parse().unwrap(),
            packet_id,
            fragment_id,
            total_fragments,
            flags: PacketFlags::Data,
            session_id: 0,
        }
    }

    pub fn is_control(&self) -> bool {
        self.flags != PacketFlags::Data
    }
}

/// NACK packet for requesting retransmission of specific fragments
#[derive(Debug, Clone)]
pub struct NackPacket {
    pub packet_id: u16,
    pub total_fragments: u8,
    /// Bitmap of missing fragment IDs (bit N = fragment N is missing)
    /// Supports up to 256 fragments (32 bytes bitmap)
    pub missing_bitmap: Vec<u8>,
}

impl NackPacket {
    /// Create a NACK packet from a list of missing fragment IDs
    pub fn new(packet_id: u16, total_fragments: u8, missing_fragments: &[u8]) -> Self {
        // Create bitmap - each byte represents 8 fragments
        let bitmap_size = ((total_fragments as usize + 7) / 8).max(1);
        let mut bitmap = vec![0u8; bitmap_size];
        
        for &frag_id in missing_fragments {
            if (frag_id as usize) < total_fragments as usize {
                let byte_idx = frag_id as usize / 8;
                let bit_idx = frag_id as usize % 8;
                if byte_idx < bitmap.len() {
                    bitmap[byte_idx] |= 1 << bit_idx;
                }
            }
        }
        
        Self {
            packet_id,
            total_fragments,
            missing_bitmap: bitmap,
        }
    }

    /// Get list of missing fragment IDs from bitmap
    pub fn get_missing_fragments(&self) -> Vec<u8> {
        let mut missing = Vec::new();
        for (byte_idx, &byte) in self.missing_bitmap.iter().enumerate() {
            for bit_idx in 0..8 {
                if byte & (1 << bit_idx) != 0 {
                    let frag_id = (byte_idx * 8 + bit_idx) as u8;
                    if frag_id < self.total_fragments {
                        missing.push(frag_id);
                    }
                }
            }
        }
        missing
    }

    /// Encode NACK packet to bytes
    /// Format: [packet_id: 2] [total_fragments: 1] [bitmap_len: 1] [bitmap: N]
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + self.missing_bitmap.len());
        data.extend_from_slice(&self.packet_id.to_be_bytes());
        data.push(self.total_fragments);
        data.push(self.missing_bitmap.len() as u8);
        data.extend_from_slice(&self.missing_bitmap);
        data
    }

    /// Decode NACK packet from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        
        let packet_id = u16::from_be_bytes([data[0], data[1]]);
        let total_fragments = data[2];
        let bitmap_len = data[3] as usize;
        
        if data.len() < 4 + bitmap_len {
            return None;
        }
        
        let missing_bitmap = data[4..4 + bitmap_len].to_vec();
        
        Some(Self {
            packet_id,
            total_fragments,
            missing_bitmap,
        })
    }
}

/// State for tracking partial packet assembly and NACK generation
#[derive(Debug)]
struct PartialPacketState {
    fragments: HashMap<u8, (Vec<u8>, Instant)>,
    total_fragments: u8,
    first_fragment_time: Instant,
    nack_sent: bool,
    last_nack_time: Option<Instant>,
}

impl PartialPacketState {
    fn new(total_fragments: u8) -> Self {
        Self {
            fragments: HashMap::new(),
            total_fragments,
            first_fragment_time: Instant::now(),
            nack_sent: false,
            last_nack_time: None,
        }
    }

    fn get_missing_fragments(&self) -> Vec<u8> {
        let mut missing = Vec::new();
        for i in 0..self.total_fragments {
            if !self.fragments.contains_key(&i) {
                missing.push(i);
            }
        }
        missing
    }

    fn should_generate_nack(&self, nack_delay_ms: u64, nack_interval_ms: u64) -> bool {
        let now = Instant::now();
        let elapsed_since_first = now.duration_since(self.first_fragment_time).as_millis() as u64;
        
        // Don't generate NACK too soon
        if elapsed_since_first < nack_delay_ms {
            return false;
        }
        
        // Check if we already have all fragments
        if self.fragments.len() == self.total_fragments as usize {
            return false;
        }
        
        // Rate limit NACK generation
        if let Some(last_nack) = self.last_nack_time {
            let elapsed_since_nack = now.duration_since(last_nack).as_millis() as u64;
            if elapsed_since_nack < nack_interval_ms {
                return false;
            }
        }
        
        true
    }
}

#[derive(Debug)]
pub struct PacketReassembler {
    // Key is just packet_id since source/dest are placeholders (0.0.0.0:0)
    fragments: HashMap<u16, PartialPacketState>,
    /// NACK generation delay in milliseconds
    nack_delay_ms: u64,
    /// Minimum interval between NACKs for same packet
    nack_interval_ms: u64,
}

impl PacketReassembler {
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
            nack_delay_ms: NACK_GENERATION_DELAY_MS,
            nack_interval_ms: 100, // Don't send NACK more than once per 100ms per packet
        }
    }

    pub fn with_nack_config(nack_delay_ms: u64, nack_interval_ms: u64) -> Self {
        Self {
            fragments: HashMap::new(),
            nack_delay_ms,
            nack_interval_ms,
        }
    }

    pub fn add_fragment(&mut self, packet: TunnelPacket) -> Option<Vec<u8>> {
        let key = packet.packet_id;
        
        // Clean up old fragments
        self.cleanup();

        let state = self.fragments
            .entry(key)
            .or_insert_with(|| PartialPacketState::new(packet.total_fragments));
        
        state.fragments.insert(packet.fragment_id, (packet.data, Instant::now()));

        // Check if we have all fragments
        if state.fragments.len() == packet.total_fragments as usize {
            let mut fragments: Vec<_> = state.fragments.iter().collect();
            fragments.sort_by_key(|(id, _)| **id);
            
            let mut reassembled = Vec::new();
            for (_, (data, _)) in fragments {
                reassembled.extend_from_slice(data);
            }

            self.fragments.remove(&key);
            Some(reassembled)
        } else {
            None
        }
    }

    /// Get missing fragments for a packet (for NACK generation)
    pub fn get_missing_fragments(&self, packet_id: u16) -> Option<(Vec<u8>, u8)> {
        self.fragments.get(&packet_id).map(|state| {
            (state.get_missing_fragments(), state.total_fragments)
        })
    }

    /// Check if NACK should be generated for any partial packets
    /// Returns list of (packet_id, NackPacket) for packets needing NACK
    pub fn check_nack_needed(&mut self) -> Vec<(u16, NackPacket)> {
        let mut nacks = Vec::new();
        
        for (&packet_id, state) in self.fragments.iter_mut() {
            if state.should_generate_nack(self.nack_delay_ms, self.nack_interval_ms) {
                let missing = state.get_missing_fragments();
                if !missing.is_empty() {
                    let nack = NackPacket::new(packet_id, state.total_fragments, &missing);
                    nacks.push((packet_id, nack));
                    state.last_nack_time = Some(Instant::now());
                    state.nack_sent = true;
                }
            }
        }
        
        nacks
    }

    /// Mark that a NACK was sent for a packet (external NACK sending)
    pub fn mark_nack_sent(&mut self, packet_id: u16) {
        if let Some(state) = self.fragments.get_mut(&packet_id) {
            state.last_nack_time = Some(Instant::now());
            state.nack_sent = true;
        }
    }

    /// Check if a packet is partially assembled (has some but not all fragments)
    pub fn has_partial_packet(&self, packet_id: u16) -> bool {
        self.fragments.contains_key(&packet_id)
    }

    /// Get number of received fragments for a packet
    pub fn get_received_count(&self, packet_id: u16) -> Option<(usize, u8)> {
        self.fragments.get(&packet_id).map(|state| {
            (state.fragments.len(), state.total_fragments)
        })
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.fragments.retain(|_, state| {
            state.fragments.retain(|_, (_, time)| now.duration_since(*time) < PACKET_TIMEOUT);
            !state.fragments.is_empty()
        });
    }
}

impl Default for PacketReassembler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn fragment_packet(data: &[u8], max_chunk_size: usize) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    let mut offset = 0;
    
    if data.is_empty() {
        return vec![Vec::new()];
    }
    
    while offset < data.len() {
        let chunk_size = (data.len() - offset).min(max_chunk_size);
        fragments.push(data[offset..offset + chunk_size].to_vec());
        offset += chunk_size;
    }
    
    fragments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nack_packet_encode_decode() {
        let missing = vec![0, 2, 5, 7];
        let nack = NackPacket::new(1234, 10, &missing);
        
        let encoded = nack.encode();
        let decoded = NackPacket::decode(&encoded).unwrap();
        
        assert_eq!(decoded.packet_id, 1234);
        assert_eq!(decoded.total_fragments, 10);
        assert_eq!(decoded.get_missing_fragments(), missing);
    }

    #[test]
    fn test_nack_packet_bitmap() {
        // Test with many fragments
        let missing = vec![0, 8, 15, 16, 31];
        let nack = NackPacket::new(100, 32, &missing);
        
        let decoded_missing = nack.get_missing_fragments();
        assert_eq!(decoded_missing, missing);
    }

    #[test]
    fn test_reassembler_missing_fragments() {
        let mut reassembler = PacketReassembler::new();
        
        // Add fragments 0 and 2, missing 1
        let packet0 = TunnelPacket::new_data(vec![1, 2, 3], 100, 0, 3);
        let packet2 = TunnelPacket::new_data(vec![7, 8, 9], 100, 2, 3);
        
        assert!(reassembler.add_fragment(packet0).is_none());
        assert!(reassembler.add_fragment(packet2).is_none());
        
        let (missing, total) = reassembler.get_missing_fragments(100).unwrap();
        assert_eq!(missing, vec![1]);
        assert_eq!(total, 3);
    }

    #[test]
    fn test_fragment_packet() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let fragments = fragment_packet(&data, 3);
        
        assert_eq!(fragments.len(), 4);
        assert_eq!(fragments[0], vec![1, 2, 3]);
        assert_eq!(fragments[1], vec![4, 5, 6]);
        assert_eq!(fragments[2], vec![7, 8, 9]);
        assert_eq!(fragments[3], vec![10]);
    }

    #[test]
    fn test_packet_flags() {
        assert_eq!(PacketFlags::from(0x00), PacketFlags::Data);
        assert_eq!(PacketFlags::from(0x01), PacketFlags::Nack);
        assert_eq!(PacketFlags::from(0x02), PacketFlags::Ack);
        assert_eq!(PacketFlags::from(0x04), PacketFlags::Syn);
    }
}
