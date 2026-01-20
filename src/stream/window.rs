//! Sliding window implementation for flow control and congestion management
//!
//! Implements:
//! - Configurable window size
//! - RTT estimation with smoothed RTT and variance
//! - RTO (Retransmission Timeout) calculation
//! - AIMD congestion control

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Minimum RTO value (100ms)
pub const MIN_RTO_MS: u64 = 100;
/// Maximum RTO value (10 seconds)
pub const MAX_RTO_MS: u64 = 10_000;
/// Initial RTO value (1 second)
pub const INITIAL_RTO_MS: u64 = 1000;
/// Alpha for SRTT calculation (1/8)
const SRTT_ALPHA: f64 = 0.125;
/// Beta for RTTVAR calculation (1/4)
const RTTVAR_BETA: f64 = 0.25;

/// RTT estimator using Jacobson/Karels algorithm
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT
    srtt: Option<Duration>,
    /// RTT variance
    rttvar: Option<Duration>,
    /// Calculated RTO
    rto: Duration,
    /// Minimum RTO
    min_rto: Duration,
    /// Maximum RTO
    max_rto: Duration,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: Duration::from_millis(INITIAL_RTO_MS),
            min_rto: Duration::from_millis(MIN_RTO_MS),
            max_rto: Duration::from_millis(MAX_RTO_MS),
        }
    }

    /// Create with custom RTO bounds
    pub fn with_bounds(min_rto_ms: u64, max_rto_ms: u64) -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: Duration::from_millis(min_rto_ms.max(INITIAL_RTO_MS).min(max_rto_ms)),
            min_rto: Duration::from_millis(min_rto_ms),
            max_rto: Duration::from_millis(max_rto_ms),
        }
    }

    /// Update RTT estimate with a new sample
    pub fn update(&mut self, rtt: Duration) {
        match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
                let diff = if rtt > srtt {
                    rtt - srtt
                } else {
                    srtt - rtt
                };
                let new_rttvar = Duration::from_secs_f64(
                    (1.0 - RTTVAR_BETA) * rttvar.as_secs_f64() + RTTVAR_BETA * diff.as_secs_f64()
                );
                
                // SRTT = (1 - alpha) * SRTT + alpha * R
                let new_srtt = Duration::from_secs_f64(
                    (1.0 - SRTT_ALPHA) * srtt.as_secs_f64() + SRTT_ALPHA * rtt.as_secs_f64()
                );

                self.srtt = Some(new_srtt);
                self.rttvar = Some(new_rttvar);
            }
            _ => {
                // First sample
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
        }

        // RTO = SRTT + 4 * RTTVAR
        self.recalculate_rto();
    }

    fn recalculate_rto(&mut self) {
        if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            let rto = srtt + rttvar * 4;
            self.rto = rto.max(self.min_rto).min(self.max_rto);
        }
    }

    /// Get current RTO
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Get smoothed RTT
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Get RTT variance
    pub fn rttvar(&self) -> Option<Duration> {
        self.rttvar
    }

    /// Back off RTO (double it) after a timeout
    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(self.max_rto);
    }

    /// Reset RTT estimator
    pub fn reset(&mut self) {
        self.srtt = None;
        self.rttvar = None;
        self.rto = Duration::from_millis(INITIAL_RTO_MS);
    }
}

/// Congestion control state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow start: exponential growth
    SlowStart,
    /// Congestion avoidance: linear growth
    CongestionAvoidance,
    /// Fast recovery after packet loss
    FastRecovery,
}

/// AIMD congestion controller
#[derive(Debug, Clone)]
pub struct CongestionController {
    /// Current congestion window (in packets)
    cwnd: f64,
    /// Slow start threshold
    ssthresh: f64,
    /// Current state
    state: CongestionState,
    /// Maximum window size
    max_window: u32,
    /// Minimum window size
    min_window: u32,
    /// Packets acknowledged since last window increase
    ack_count: u32,
}

impl CongestionController {
    pub fn new(initial_window: u32, max_window: u32) -> Self {
        Self {
            cwnd: initial_window as f64,
            ssthresh: (max_window / 2) as f64,
            state: CongestionState::SlowStart,
            max_window,
            min_window: 1,
            ack_count: 0,
        }
    }

    /// Get current window size
    pub fn window(&self) -> u32 {
        (self.cwnd as u32).max(self.min_window).min(self.max_window)
    }

    /// Get current state
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// Called when a packet is acknowledged
    pub fn on_ack(&mut self) {
        match self.state {
            CongestionState::SlowStart => {
                // Exponential growth: increase by 1 for each ACK
                self.cwnd += 1.0;
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                // Linear growth: increase by 1/cwnd for each ACK
                self.cwnd += 1.0 / self.cwnd;
            }
            CongestionState::FastRecovery => {
                // In fast recovery, inflate window
                self.cwnd += 1.0;
            }
        }
        self.cwnd = self.cwnd.min(self.max_window as f64);
    }

    /// Called when a packet loss is detected (via timeout or 3 dup acks)
    pub fn on_loss(&mut self, is_timeout: bool) {
        if is_timeout {
            // Timeout: severe congestion, reset to slow start
            self.ssthresh = (self.cwnd / 2.0).max(2.0);
            self.cwnd = self.min_window as f64;
            self.state = CongestionState::SlowStart;
        } else {
            // Fast retransmit: moderate congestion
            self.ssthresh = (self.cwnd / 2.0).max(2.0);
            self.cwnd = self.ssthresh + 3.0; // +3 for the 3 dup acks
            self.state = CongestionState::FastRecovery;
        }
    }

    /// Exit fast recovery (after retransmitted packet is acked)
    pub fn exit_fast_recovery(&mut self) {
        if self.state == CongestionState::FastRecovery {
            self.cwnd = self.ssthresh;
            self.state = CongestionState::CongestionAvoidance;
        }
    }

    /// Reset the controller
    pub fn reset(&mut self, initial_window: u32) {
        self.cwnd = initial_window as f64;
        self.ssthresh = (self.max_window / 2) as f64;
        self.state = CongestionState::SlowStart;
        self.ack_count = 0;
    }
}

/// Entry in the send window
#[derive(Debug, Clone)]
pub struct SendEntry {
    /// Sequence number
    pub seq_num: u32,
    /// Frame data
    pub data: Vec<u8>,
    /// Time first sent
    pub first_sent: Instant,
    /// Time last sent (for retransmission)
    pub last_sent: Instant,
    /// Number of transmissions
    pub transmit_count: u32,
    /// Has been acknowledged
    pub acked: bool,
}

/// Sliding window for sending
#[derive(Debug)]
pub struct SendWindow {
    /// Window entries indexed by sequence number
    entries: BTreeMap<u32, SendEntry>,
    /// Next sequence number to use
    next_seq: u32,
    /// Oldest unacknowledged sequence number
    send_una: u32,
    /// Window size in packets
    window_size: u32,
    /// RTT estimator
    rtt: RttEstimator,
    /// Congestion controller
    congestion: CongestionController,
}

impl SendWindow {
    pub fn new(window_size: u32, max_window: u32) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_seq: 0,
            send_una: 0,
            window_size,
            rtt: RttEstimator::new(),
            congestion: CongestionController::new(window_size.min(4), max_window),
        }
    }

    /// Check if window has space for more packets
    pub fn can_send(&self) -> bool {
        let in_flight = self.next_seq.wrapping_sub(self.send_una);
        in_flight < self.effective_window()
    }

    /// Get effective window size (minimum of configured and congestion window)
    pub fn effective_window(&self) -> u32 {
        self.window_size.min(self.congestion.window())
    }

    /// Get number of packets in flight
    pub fn in_flight(&self) -> u32 {
        self.next_seq.wrapping_sub(self.send_una)
    }

    /// Queue a frame for sending, returns the sequence number
    pub fn queue(&mut self, data: Vec<u8>) -> Option<u32> {
        if !self.can_send() {
            return None;
        }

        let seq = self.next_seq;
        let now = Instant::now();
        
        self.entries.insert(seq, SendEntry {
            seq_num: seq,
            data,
            first_sent: now,
            last_sent: now,
            transmit_count: 1,
            acked: false,
        });

        self.next_seq = self.next_seq.wrapping_add(1);
        Some(seq)
    }

    /// Get a frame by sequence number for retransmission
    pub fn get_for_retransmit(&mut self, seq: u32) -> Option<&mut SendEntry> {
        self.entries.get_mut(&seq).filter(|e| !e.acked)
    }

    /// Mark a frame as retransmitted
    pub fn mark_retransmitted(&mut self, seq: u32) {
        if let Some(entry) = self.entries.get_mut(&seq) {
            entry.last_sent = Instant::now();
            entry.transmit_count += 1;
        }
    }

    /// Process an ACK
    pub fn process_ack(&mut self, ack_num: u32, ack_bitmap: u64) {
        let mut new_acks = 0;
        let mut rtt_sample = None;

        // Process cumulative ACK
        while self.send_una <= ack_num && self.entries.contains_key(&self.send_una) {
            if let Some(entry) = self.entries.remove(&self.send_una) {
                if !entry.acked && entry.transmit_count == 1 {
                    // Only use RTT sample if packet was not retransmitted
                    rtt_sample = Some(entry.first_sent.elapsed());
                }
                new_acks += 1;
            }
            self.send_una = self.send_una.wrapping_add(1);
        }

        // Process selective ACKs
        for i in 0..64u32 {
            if ack_bitmap & (1u64 << i) != 0 {
                let seq = ack_num.wrapping_add(i + 1);
                if let Some(entry) = self.entries.get_mut(&seq) {
                    if !entry.acked {
                        entry.acked = true;
                        new_acks += 1;
                    }
                }
            }
        }

        // Update RTT estimate
        if let Some(rtt) = rtt_sample {
            self.rtt.update(rtt);
        }

        // Update congestion window
        for _ in 0..new_acks {
            self.congestion.on_ack();
        }
    }

    /// Called when a timeout occurs
    pub fn on_timeout(&mut self) {
        self.rtt.backoff();
        self.congestion.on_loss(true);
    }

    /// Get current RTO
    pub fn rto(&self) -> Duration {
        self.rtt.rto()
    }

    /// Get entries that need retransmission
    pub fn get_timed_out(&self) -> Vec<u32> {
        let rto = self.rtt.rto();
        let now = Instant::now();
        
        self.entries
            .iter()
            .filter(|(_, e)| !e.acked && now.duration_since(e.last_sent) >= rto)
            .map(|(seq, _)| *seq)
            .collect()
    }

    /// Get next sequence number
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Get oldest unacknowledged sequence number
    pub fn send_una(&self) -> u32 {
        self.send_una
    }

    /// Check if all sent data has been acknowledged
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get RTT statistics
    pub fn rtt_stats(&self) -> (Option<Duration>, Option<Duration>, Duration) {
        (self.rtt.srtt(), self.rtt.rttvar(), self.rtt.rto())
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.entries.clear();
        self.next_seq = 0;
        self.send_una = 0;
        self.rtt.reset();
        self.congestion.reset(self.window_size.min(4));
    }
}

/// Entry in the receive window
#[derive(Debug, Clone)]
pub struct RecvEntry {
    /// Sequence number
    pub seq_num: u32,
    /// Frame data
    pub data: Vec<u8>,
    /// Time received
    pub received_at: Instant,
}

/// Sliding window for receiving
#[derive(Debug)]
pub struct RecvWindow {
    /// Received but not yet delivered entries
    entries: BTreeMap<u32, RecvEntry>,
    /// Next expected sequence number
    next_expected: u32,
    /// Window size
    window_size: u32,
    /// Highest sequence number seen
    highest_seen: u32,
}

impl RecvWindow {
    pub fn new(window_size: u32) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_expected: 0,
            window_size,
            highest_seen: 0,
        }
    }

    /// Check if a sequence number is within the receive window
    pub fn in_window(&self, seq: u32) -> bool {
        let lower = self.next_expected;
        let upper = self.next_expected.wrapping_add(self.window_size);
        
        if lower <= upper {
            seq >= lower && seq < upper
        } else {
            // Wrapped around
            seq >= lower || seq < upper
        }
    }

    /// Receive a frame
    pub fn receive(&mut self, seq: u32, data: Vec<u8>) -> bool {
        if !self.in_window(seq) {
            return false;
        }

        // Already have this one
        if self.entries.contains_key(&seq) {
            return false;
        }

        self.entries.insert(seq, RecvEntry {
            seq_num: seq,
            data,
            received_at: Instant::now(),
        });

        if seq > self.highest_seen || (seq < self.next_expected && self.highest_seen > self.next_expected) {
            self.highest_seen = seq;
        }

        true
    }

    /// Get in-order data ready for delivery
    pub fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();

        while let Some(entry) = self.entries.remove(&self.next_expected) {
            result.push(entry.data);
            self.next_expected = self.next_expected.wrapping_add(1);
        }

        result
    }

    /// Get ACK number (next expected sequence)
    pub fn ack_num(&self) -> u32 {
        // Cumulative ACK: everything before this has been received
        if self.next_expected == 0 {
            0
        } else {
            self.next_expected.wrapping_sub(1)
        }
    }

    /// Get SACK bitmap for out-of-order packets
    pub fn sack_bitmap(&self) -> u64 {
        let mut bitmap = 0u64;
        let base = self.next_expected;

        for (&seq, _) in &self.entries {
            let offset = seq.wrapping_sub(base);
            if offset > 0 && offset <= 64 {
                bitmap |= 1u64 << (offset - 1);
            }
        }

        bitmap
    }

    /// Get next expected sequence number
    pub fn next_expected(&self) -> u32 {
        self.next_expected
    }

    /// Check if window has any out-of-order packets
    pub fn has_gaps(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.entries.clear();
        self.next_expected = 0;
        self.highest_seen = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_estimator() {
        let mut rtt = RttEstimator::new();
        
        // First sample
        rtt.update(Duration::from_millis(100));
        assert!(rtt.srtt().is_some());
        
        // More samples
        rtt.update(Duration::from_millis(120));
        rtt.update(Duration::from_millis(90));
        
        let srtt = rtt.srtt().unwrap();
        assert!(srtt.as_millis() > 80 && srtt.as_millis() < 130);
    }

    #[test]
    fn test_congestion_controller() {
        let mut cc = CongestionController::new(4, 64);
        
        assert_eq!(cc.state(), CongestionState::SlowStart);
        
        // Slow start
        for _ in 0..10 {
            cc.on_ack();
        }
        assert!(cc.window() > 4);
        
        // Loss
        let window_before = cc.window();
        cc.on_loss(true);
        assert!(cc.window() < window_before);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_send_window() {
        let mut sw = SendWindow::new(4, 16);
        
        // Queue some packets
        assert!(sw.can_send());
        let seq1 = sw.queue(vec![1, 2, 3]).unwrap();
        let seq2 = sw.queue(vec![4, 5, 6]).unwrap();
        
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
        assert_eq!(sw.in_flight(), 2);
        
        // ACK first packet
        sw.process_ack(0, 0);
        assert_eq!(sw.send_una(), 1);
    }

    #[test]
    fn test_recv_window() {
        let mut rw = RecvWindow::new(16);
        
        // Receive in order
        assert!(rw.receive(0, vec![1]));
        assert!(rw.receive(1, vec![2]));
        
        let ready = rw.drain_ready();
        assert_eq!(ready.len(), 2);
        
        // Receive out of order
        assert!(rw.receive(3, vec![4])); // gap at 2
        assert!(rw.receive(4, vec![5]));
        
        let ready = rw.drain_ready();
        assert!(ready.is_empty()); // waiting for seq 2
        
        assert!(rw.has_gaps());
        assert!(rw.sack_bitmap() != 0); // Should have SACK bits set
        
        // Fill the gap
        assert!(rw.receive(2, vec![3]));
        let ready = rw.drain_ready();
        assert_eq!(ready.len(), 3); // 2, 3, 4
    }
}
