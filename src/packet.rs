use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const PACKET_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct TunnelPacket {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    /// Indicates if this packet contains TCP data (connection_id embedded in data)
    pub is_tcp: bool,
}

#[derive(Debug)]
pub struct PacketReassembler {
    fragments: HashMap<(SocketAddr, SocketAddr, u16), HashMap<u8, (Vec<u8>, Instant)>>,
}

impl PacketReassembler {
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
        }
    }

    pub fn add_fragment(&mut self, packet: TunnelPacket) -> Option<Vec<u8>> {
        let key = (packet.source, packet.destination, packet.packet_id);
        
        // Clean up old fragments
        self.cleanup();

        let fragment_map = self.fragments.entry(key).or_insert_with(HashMap::new);
        fragment_map.insert(packet.fragment_id, (packet.data, Instant::now()));

        // Check if we have all fragments
        if fragment_map.len() == packet.total_fragments as usize {
            let mut fragments: Vec<_> = fragment_map.iter().collect();
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
    
    /// Check if reassembled data is a TCP packet (starts with connection_id)
    pub fn is_tcp_packet(data: &[u8]) -> bool {
        // TCP packet format: [4 bytes: connection_id][4 bytes: sequence][2 bytes: data_length][1 byte: flags][...]
        // Minimum size is 11 bytes
        data.len() >= 11 && data.len() <= 65507
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.fragments.retain(|_, fragments| {
            fragments.retain(|_, (_, time)| now.duration_since(*time) < PACKET_TIMEOUT);
            !fragments.is_empty()
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
    
    while offset < data.len() {
        let chunk_size = (data.len() - offset).min(max_chunk_size);
        fragments.push(data[offset..offset + chunk_size].to_vec());
        offset += chunk_size;
    }
    
    fragments
}
