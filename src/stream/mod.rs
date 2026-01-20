//! Stream layer - provides reliable transport over unreliable transports
//! 
//! This module implements:
//! - Frame format with sequence numbers, ACKs, and flags
//! - Sliding window for flow control
//! - Retransmission with RTO calculation
//! - Optional FEC (Forward Error Correction)

pub mod frame;
pub mod window;
pub mod retransmit;
pub mod fec;

pub use frame::*;
pub use window::*;
pub use retransmit::*;
