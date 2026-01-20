//! Adaptive Multi-Transport DNS Tunnel
//!
//! A high-performance DNS tunnel with:
//! - Multiple transport adapters (DNS-UDP, DoH, DoQ, Direct UDP)
//! - Reliable stream layer with ACK, SACK, and retransmission
//! - Intelligent path management with health monitoring
//! - Traffic profiles for interactive (SSH) and bulk (VPN) workloads
//! - Persistent resolver database with hot-reload

// === Original modules (v1 compatibility) ===
pub mod config;
pub mod dns_codec;
pub mod packet;
pub mod utils;

// === New v2 modules ===
pub mod stream;
pub mod transport;
pub mod path;
pub mod db;
pub mod profile;
pub mod config_v2;

// === Re-exports for v1 compatibility ===
pub use config::*;
pub use dns_codec::*;
pub use packet::*;
pub use utils::*;

// === Re-exports for v2 ===
pub use config_v2::{ClientConfigV2, ServerConfigV2};
pub use stream::{Frame, SendWindow, RecvWindow, RetransmitQueue};
pub use transport::{Transport, TransportType, TransportRegistry, ResolverEndpoint};
pub use path::{PathManager, LoadBalanceStrategy, ResolverStats};
pub use db::ResolverDb;
pub use profile::{Profile, ProfileMode, ProfileManager};
