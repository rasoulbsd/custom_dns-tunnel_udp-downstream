//! Retransmission queue with timers and RTO management
//!
//! Manages:
//! - Pending transmissions
//! - Timeout detection
//! - Retry counting
//! - Backoff strategies

use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;
use std::time::{Duration, Instant};

use super::frame::Frame;

/// Maximum number of retransmissions before giving up
pub const MAX_RETRANSMISSIONS: u32 = 10;

/// A pending transmission entry
#[derive(Debug, Clone)]
pub struct PendingTransmission {
    /// The frame to transmit
    pub frame: Frame,
    /// Deadline for this transmission (when RTO expires)
    pub deadline: Instant,
    /// Number of transmissions so far
    pub transmit_count: u32,
    /// Time of first transmission
    pub first_sent: Instant,
    /// Time of last transmission
    pub last_sent: Instant,
    /// Current RTO for this transmission
    pub rto: Duration,
}

impl PendingTransmission {
    pub fn new(frame: Frame, rto: Duration) -> Self {
        let now = Instant::now();
        Self {
            frame,
            deadline: now + rto,
            transmit_count: 1,
            first_sent: now,
            last_sent: now,
            rto,
        }
    }

    /// Update for retransmission with exponential backoff
    pub fn retransmit(&mut self) {
        self.transmit_count += 1;
        self.last_sent = Instant::now();
        // Exponential backoff
        self.rto = (self.rto * 2).min(Duration::from_secs(60));
        self.deadline = self.last_sent + self.rto;
    }

    /// Check if this transmission has exceeded max retries
    pub fn exceeded_max_retries(&self) -> bool {
        self.transmit_count >= MAX_RETRANSMISSIONS
    }

    /// Check if this transmission has timed out
    pub fn is_timed_out(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Get time until deadline
    pub fn time_until_deadline(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// Entry in the timeout heap
#[derive(Debug, Clone, Eq, PartialEq)]
struct TimeoutEntry {
    deadline: Instant,
    seq_num: u32,
    stream_id: u16,
}

impl Ord for TimeoutEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior
        other.deadline.cmp(&self.deadline)
    }
}

impl PartialOrd for TimeoutEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Retransmission queue managing pending transmissions
#[derive(Debug)]
pub struct RetransmitQueue {
    /// Pending transmissions by (stream_id, seq_num)
    pending: HashMap<(u16, u32), PendingTransmission>,
    /// Timeout heap for efficient deadline checking
    timeouts: BinaryHeap<TimeoutEntry>,
    /// Default RTO for new transmissions
    default_rto: Duration,
    /// Maximum retransmissions
    max_retransmissions: u32,
}

impl RetransmitQueue {
    pub fn new(default_rto: Duration, max_retransmissions: u32) -> Self {
        Self {
            pending: HashMap::new(),
            timeouts: BinaryHeap::new(),
            default_rto,
            max_retransmissions,
        }
    }

    /// Add a frame to the retransmit queue
    pub fn add(&mut self, frame: Frame, rto: Option<Duration>) {
        let key = (frame.stream_id, frame.seq_num);
        let rto = rto.unwrap_or(self.default_rto);
        let pending = PendingTransmission::new(frame, rto);
        
        self.timeouts.push(TimeoutEntry {
            deadline: pending.deadline,
            seq_num: pending.frame.seq_num,
            stream_id: pending.frame.stream_id,
        });
        
        self.pending.insert(key, pending);
    }

    /// Remove a frame from the queue (when acknowledged)
    pub fn remove(&mut self, stream_id: u16, seq_num: u32) -> Option<PendingTransmission> {
        self.pending.remove(&(stream_id, seq_num))
    }

    /// Check if a frame is pending
    pub fn is_pending(&self, stream_id: u16, seq_num: u32) -> bool {
        self.pending.contains_key(&(stream_id, seq_num))
    }

    /// Get a pending transmission
    pub fn get(&self, stream_id: u16, seq_num: u32) -> Option<&PendingTransmission> {
        self.pending.get(&(stream_id, seq_num))
    }

    /// Get timed-out transmissions that need retransmission
    /// Returns frames that should be retransmitted and frames that have exceeded max retries
    pub fn get_timed_out(&mut self) -> (Vec<Frame>, Vec<Frame>) {
        let now = Instant::now();
        let mut to_retransmit = Vec::new();
        let mut failed = Vec::new();

        // Process timeout heap
        while let Some(entry) = self.timeouts.peek() {
            if entry.deadline > now {
                break;
            }

            let entry = self.timeouts.pop().unwrap();
            let key = (entry.stream_id, entry.seq_num);

            if let Some(pending) = self.pending.get_mut(&key) {
                // Check if this is a stale timeout entry
                if pending.deadline != entry.deadline {
                    // Deadline was updated, this entry is stale
                    continue;
                }

                if pending.transmit_count >= self.max_retransmissions {
                    // Exceeded max retries
                    if let Some(p) = self.pending.remove(&key) {
                        failed.push(p.frame);
                    }
                } else {
                    // Need retransmission
                    pending.retransmit();
                    to_retransmit.push(pending.frame.clone());
                    
                    // Re-add to timeout heap with new deadline
                    self.timeouts.push(TimeoutEntry {
                        deadline: pending.deadline,
                        seq_num: pending.frame.seq_num,
                        stream_id: pending.frame.stream_id,
                    });
                }
            }
        }

        (to_retransmit, failed)
    }

    /// Get time until next timeout
    pub fn next_timeout(&self) -> Option<Duration> {
        self.timeouts.peek().map(|e| {
            e.deadline.saturating_duration_since(Instant::now())
        })
    }

    /// Get number of pending transmissions
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Clear all pending transmissions for a stream
    pub fn clear_stream(&mut self, stream_id: u16) {
        self.pending.retain(|(sid, _), _| *sid != stream_id);
        // Note: stale entries in timeouts heap will be cleaned up lazily
    }

    /// Clear all pending transmissions
    pub fn clear(&mut self) {
        self.pending.clear();
        self.timeouts.clear();
    }

    /// Update RTO for a specific pending transmission
    pub fn update_rto(&mut self, stream_id: u16, seq_num: u32, new_rto: Duration) {
        if let Some(pending) = self.pending.get_mut(&(stream_id, seq_num)) {
            pending.rto = new_rto;
            pending.deadline = pending.last_sent + new_rto;
            
            // Add new timeout entry (old one becomes stale)
            self.timeouts.push(TimeoutEntry {
                deadline: pending.deadline,
                seq_num,
                stream_id,
            });
        }
    }

    /// Get statistics about pending transmissions
    pub fn stats(&self) -> RetransmitStats {
        let mut total_retransmits = 0u64;
        let mut max_retransmits = 0u32;
        let mut oldest_pending = None;

        for pending in self.pending.values() {
            total_retransmits += pending.transmit_count as u64;
            max_retransmits = max_retransmits.max(pending.transmit_count);
            
            match oldest_pending {
                None => oldest_pending = Some(pending.first_sent),
                Some(t) if pending.first_sent < t => oldest_pending = Some(pending.first_sent),
                _ => {}
            }
        }

        RetransmitStats {
            pending_count: self.pending.len(),
            total_retransmits,
            max_retransmits,
            oldest_pending_age: oldest_pending.map(|t| t.elapsed()),
        }
    }
}

/// Statistics about the retransmit queue
#[derive(Debug, Clone)]
pub struct RetransmitStats {
    /// Number of pending transmissions
    pub pending_count: usize,
    /// Total number of retransmissions across all pending
    pub total_retransmits: u64,
    /// Maximum retransmit count for any single packet
    pub max_retransmits: u32,
    /// Age of the oldest pending transmission
    pub oldest_pending_age: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::frame::Frame;
    use std::thread::sleep;

    #[test]
    fn test_retransmit_queue() {
        let mut queue = RetransmitQueue::new(Duration::from_millis(50), 3);

        let frame = Frame::data(1, 0, vec![1, 2, 3]);
        queue.add(frame.clone(), None);

        assert_eq!(queue.len(), 1);
        assert!(queue.is_pending(1, 0));

        // Not timed out yet
        let (retransmit, failed) = queue.get_timed_out();
        assert!(retransmit.is_empty());
        assert!(failed.is_empty());

        // Wait for timeout
        sleep(Duration::from_millis(60));

        let (retransmit, failed) = queue.get_timed_out();
        assert_eq!(retransmit.len(), 1);
        assert!(failed.is_empty());

        // Remove when acked
        let removed = queue.remove(1, 0);
        assert!(removed.is_some());
        assert!(queue.is_empty());
    }

    #[test]
    fn test_max_retries() {
        // Use longer timeouts to avoid race conditions
        let mut queue = RetransmitQueue::new(Duration::from_millis(50), 2);

        let frame = Frame::data(1, 0, vec![1]);
        queue.add(frame, None);

        // First timeout - retransmit (transmit_count becomes 2)
        sleep(Duration::from_millis(60));
        let (retransmit, failed) = queue.get_timed_out();
        assert_eq!(retransmit.len(), 1, "First timeout should retransmit");
        assert!(failed.is_empty());

        // Second timeout - exceeded max (transmit_count was already 2)
        sleep(Duration::from_millis(120)); // backoff doubles to 100ms
        let (retransmit, failed) = queue.get_timed_out();
        assert!(retransmit.is_empty(), "Should not retransmit after max");
        assert_eq!(failed.len(), 1, "Should report as failed");
    }
}
