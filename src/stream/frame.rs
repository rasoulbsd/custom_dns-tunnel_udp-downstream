//! Frame format for reliable transport over unreliable channels
//! 
//! Wire format (18 bytes header + payload):
//! - stream_id: u16 (2 bytes) - for multiplexing
//! - seq_num: u32 (4 bytes) - sequence number
//! - ack_num: u32 (4 bytes) - cumulative acknowledgment
//! - ack_bitmap: u64 (8 bytes) - selective ACK for 64 packets after ack_num
//! - flags: u8 (1 byte) - SYN, FIN, ACK, DATA, FEC flags
//! - payload: variable length

use std::io::{self, Read, Write};

/// Frame flags
pub mod flags {
    pub const SYN: u8 = 0b0000_0001;  // Stream initiation
    pub const FIN: u8 = 0b0000_0010;  // Stream termination
    pub const ACK: u8 = 0b0000_0100;  // Contains acknowledgment
    pub const DATA: u8 = 0b0000_1000; // Contains data payload
    pub const FEC: u8 = 0b0001_0000;  // FEC parity data
    pub const PING: u8 = 0b0010_0000; // Keepalive/probe
    pub const PONG: u8 = 0b0100_0000; // Keepalive response
}

/// Header size in bytes
pub const HEADER_SIZE: usize = 19;

/// A frame in the reliable stream protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Stream identifier for multiplexing
    pub stream_id: u16,
    /// Sequence number of this frame
    pub seq_num: u32,
    /// Cumulative acknowledgment number
    pub ack_num: u32,
    /// Selective ACK bitmap (64 packets after ack_num)
    pub ack_bitmap: u64,
    /// Frame flags
    pub flags: u8,
    /// Payload data
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new empty frame
    pub fn new(stream_id: u16) -> Self {
        Self {
            stream_id,
            seq_num: 0,
            ack_num: 0,
            ack_bitmap: 0,
            flags: 0,
            payload: Vec::new(),
        }
    }

    /// Create a data frame
    pub fn data(stream_id: u16, seq_num: u32, payload: Vec<u8>) -> Self {
        Self {
            stream_id,
            seq_num,
            ack_num: 0,
            ack_bitmap: 0,
            flags: flags::DATA,
            payload,
        }
    }

    /// Create a SYN frame (stream initiation)
    pub fn syn(stream_id: u16) -> Self {
        Self {
            stream_id,
            seq_num: 0,
            ack_num: 0,
            ack_bitmap: 0,
            flags: flags::SYN,
            payload: Vec::new(),
        }
    }

    /// Create a FIN frame (stream termination)
    pub fn fin(stream_id: u16, seq_num: u32) -> Self {
        Self {
            stream_id,
            seq_num,
            ack_num: 0,
            ack_bitmap: 0,
            flags: flags::FIN,
            payload: Vec::new(),
        }
    }

    /// Create an ACK-only frame
    pub fn ack(stream_id: u16, ack_num: u32, ack_bitmap: u64) -> Self {
        Self {
            stream_id,
            seq_num: 0,
            ack_num,
            ack_bitmap,
            flags: flags::ACK,
            payload: Vec::new(),
        }
    }

    /// Create a PING frame (keepalive)
    pub fn ping(stream_id: u16, seq_num: u32) -> Self {
        Self {
            stream_id,
            seq_num,
            ack_num: 0,
            ack_bitmap: 0,
            flags: flags::PING,
            payload: Vec::new(),
        }
    }

    /// Create a PONG frame (keepalive response)
    pub fn pong(stream_id: u16, ack_num: u32) -> Self {
        Self {
            stream_id,
            seq_num: 0,
            ack_num,
            ack_bitmap: 0,
            flags: flags::PONG,
            payload: Vec::new(),
        }
    }

    /// Add ACK information to the frame
    pub fn with_ack(mut self, ack_num: u32, ack_bitmap: u64) -> Self {
        self.ack_num = ack_num;
        self.ack_bitmap = ack_bitmap;
        self.flags |= flags::ACK;
        self
    }

    /// Check if frame has SYN flag
    pub fn is_syn(&self) -> bool {
        self.flags & flags::SYN != 0
    }

    /// Check if frame has FIN flag
    pub fn is_fin(&self) -> bool {
        self.flags & flags::FIN != 0
    }

    /// Check if frame has ACK flag
    pub fn is_ack(&self) -> bool {
        self.flags & flags::ACK != 0
    }

    /// Check if frame has DATA flag
    pub fn is_data(&self) -> bool {
        self.flags & flags::DATA != 0
    }

    /// Check if frame has FEC flag
    pub fn is_fec(&self) -> bool {
        self.flags & flags::FEC != 0
    }

    /// Check if frame is a PING
    pub fn is_ping(&self) -> bool {
        self.flags & flags::PING != 0
    }

    /// Check if frame is a PONG
    pub fn is_pong(&self) -> bool {
        self.flags & flags::PONG != 0
    }

    /// Serialize frame to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&self.seq_num.to_be_bytes());
        buf.extend_from_slice(&self.ack_num.to_be_bytes());
        buf.extend_from_slice(&self.ack_bitmap.to_be_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize frame from bytes
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame too short: {} bytes, need at least {}", data.len(), HEADER_SIZE),
            ));
        }

        let stream_id = u16::from_be_bytes([data[0], data[1]]);
        let seq_num = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let ack_num = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        let ack_bitmap = u64::from_be_bytes([
            data[10], data[11], data[12], data[13],
            data[14], data[15], data[16], data[17],
        ]);
        let flags = data[18];
        let payload = data[HEADER_SIZE..].to_vec();

        Ok(Self {
            stream_id,
            seq_num,
            ack_num,
            ack_bitmap,
            flags,
            payload,
        })
    }

    /// Get the total size of the frame when serialized
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }
}

/// Check if a sequence number is acknowledged by the SACK bitmap
pub fn is_sacked(base_ack: u32, seq: u32, bitmap: u64) -> bool {
    if seq <= base_ack {
        return true; // Cumulatively acknowledged
    }
    let offset = seq.wrapping_sub(base_ack);
    if offset == 0 || offset > 64 {
        return false; // Out of bitmap range
    }
    // Bit 0 = base_ack + 1, bit 1 = base_ack + 2, etc.
    bitmap & (1u64 << (offset - 1)) != 0
}

/// Set a sequence number as acknowledged in the SACK bitmap
pub fn set_sacked(base_ack: u32, seq: u32, bitmap: &mut u64) {
    if seq <= base_ack {
        return; // Already cumulatively acked
    }
    let offset = seq.wrapping_sub(base_ack);
    if offset > 0 && offset <= 64 {
        *bitmap |= 1u64 << (offset - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let frame = Frame::data(1, 42, vec![1, 2, 3, 4, 5]);
        let bytes = frame.to_bytes();
        let parsed = Frame::from_bytes(&bytes).unwrap();
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_frame_with_ack() {
        let frame = Frame::data(1, 10, vec![0xAB])
            .with_ack(5, 0b1010);
        
        assert!(frame.is_data());
        assert!(frame.is_ack());
        assert_eq!(frame.ack_num, 5);
        assert_eq!(frame.ack_bitmap, 0b1010);
    }

    #[test]
    fn test_sack_operations() {
        let base_ack = 100;
        let mut bitmap = 0u64;

        // Set some packets as acked
        set_sacked(base_ack, 101, &mut bitmap);
        set_sacked(base_ack, 103, &mut bitmap);
        set_sacked(base_ack, 105, &mut bitmap);

        // Verify
        assert!(is_sacked(base_ack, 100, bitmap)); // cumulative
        assert!(is_sacked(base_ack, 101, bitmap)); // bit 0
        assert!(!is_sacked(base_ack, 102, bitmap)); // not set
        assert!(is_sacked(base_ack, 103, bitmap)); // bit 2
        assert!(!is_sacked(base_ack, 104, bitmap)); // not set
        assert!(is_sacked(base_ack, 105, bitmap)); // bit 4
    }

    #[test]
    fn test_frame_flags() {
        assert!(Frame::syn(1).is_syn());
        assert!(Frame::fin(1, 0).is_fin());
        assert!(Frame::ack(1, 0, 0).is_ack());
        assert!(Frame::data(1, 0, vec![]).is_data());
        assert!(Frame::ping(1, 0).is_ping());
        assert!(Frame::pong(1, 0).is_pong());
    }
}
