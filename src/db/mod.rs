//! Resolver database using redb
//!
//! Provides persistent storage for resolver information:
//! - Resolver endpoints
//! - Health statistics
//! - Discovered limits
//!
//! Supports hot-reload from external sources (file, socket)

pub mod resolver;

pub use resolver::*;

use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::transport::{ResolverEndpoint, TransportType};
use crate::path::ResolverStats;

/// Database error types
#[derive(Debug, Clone)]
pub enum DbError {
    /// I/O error
    Io(String),
    /// Serialization error
    Serialization(String),
    /// Key not found
    NotFound(u64),
    /// Database is closed
    Closed,
    /// Invalid data
    InvalidData(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Io(e) => write!(f, "I/O error: {}", e),
            DbError::Serialization(e) => write!(f, "Serialization error: {}", e),
            DbError::NotFound(id) => write!(f, "Resolver not found: {}", id),
            DbError::Closed => write!(f, "Database closed"),
            DbError::InvalidData(e) => write!(f, "Invalid data: {}", e),
        }
    }
}

impl std::error::Error for DbError {}

/// Resolver record stored in database
#[derive(Debug, Clone)]
pub struct ResolverRecord {
    /// Unique identifier
    pub id: u64,
    /// Transport type
    pub transport: TransportType,
    /// Address (socket addr or URL)
    pub address: String,
    /// Whether the resolver is enabled
    pub enabled: bool,
    /// User-defined tags
    pub tags: Vec<String>,
    /// Time added
    pub added_at: u64,
    /// Time last updated
    pub updated_at: u64,
}

impl ResolverRecord {
    pub fn new(id: u64, transport: TransportType, address: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id,
            transport,
            address,
            enabled: true,
            tags: Vec::new(),
            added_at: now,
            updated_at: now,
        }
    }

    pub fn to_endpoint(&self) -> ResolverEndpoint {
        match self.transport {
            TransportType::DnsUdp => {
                let addr = self.address.parse().unwrap_or_else(|_| "0.0.0.0:53".parse().unwrap());
                ResolverEndpoint::new_dns_udp(self.id, addr)
            }
            TransportType::DoH => {
                ResolverEndpoint::new_doh(self.id, self.address.clone())
            }
            TransportType::DoQ => {
                let addr = self.address.parse().unwrap_or_else(|_| "0.0.0.0:853".parse().unwrap());
                ResolverEndpoint::new_doq(self.id, addr)
            }
            TransportType::DirectUdp => {
                let addr = self.address.parse().unwrap_or_else(|_| "0.0.0.0:5354".parse().unwrap());
                ResolverEndpoint::new_direct_udp(self.id, addr)
            }
        }
    }
}

/// Stats record stored in database
#[derive(Debug, Clone)]
pub struct StatsRecord {
    /// Resolver ID
    pub id: u64,
    /// Smoothed RTT in milliseconds
    pub rtt_ms: f64,
    /// Loss rate
    pub loss_rate: f64,
    /// Success count
    pub success_count: u64,
    /// Failure count
    pub failure_count: u64,
    /// Health score
    pub health_score: f64,
    /// Max label length
    pub max_label_len: u8,
    /// Max payload
    pub max_payload: u16,
    /// Rate limit QPS
    pub rate_limit_qps: Option<u32>,
    /// Last updated timestamp
    pub updated_at: u64,
}

impl StatsRecord {
    pub fn from_stats(stats: &ResolverStats) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: stats.id,
            rtt_ms: stats.rtt_ms,
            loss_rate: stats.loss_rate,
            success_count: stats.success_count,
            failure_count: stats.failure_count,
            health_score: stats.health_score,
            max_label_len: stats.max_label_len,
            max_payload: stats.max_payload,
            rate_limit_qps: stats.rate_limit_qps,
            updated_at: now,
        }
    }
}

/// In-memory resolver database
/// 
/// Note: This is a simplified in-memory implementation.
/// For production, integrate with redb crate for persistence.
#[derive(Debug)]
pub struct ResolverDb {
    resolvers: RwLock<std::collections::HashMap<u64, ResolverRecord>>,
    stats: RwLock<std::collections::HashMap<u64, StatsRecord>>,
    next_id: RwLock<u64>,
}

impl ResolverDb {
    /// Create a new in-memory database
    pub fn new() -> Self {
        Self {
            resolvers: RwLock::new(std::collections::HashMap::new()),
            stats: RwLock::new(std::collections::HashMap::new()),
            next_id: RwLock::new(1),
        }
    }

    /// Open or create a database file
    /// 
    /// Note: This is a stub. For production, use redb::Database::create()
    pub async fn open(_path: &Path) -> Result<Self, DbError> {
        // TODO: Implement redb persistence
        // let db = redb::Database::create(path)?;
        Ok(Self::new())
    }

    /// Add a new resolver
    pub async fn add_resolver(&self, transport: TransportType, address: String) -> Result<u64, DbError> {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let record = ResolverRecord::new(id, transport, address);
        
        let mut resolvers = self.resolvers.write().await;
        resolvers.insert(id, record);

        Ok(id)
    }

    /// Add a resolver with specific ID
    pub async fn add_resolver_with_id(&self, id: u64, transport: TransportType, address: String) -> Result<(), DbError> {
        let record = ResolverRecord::new(id, transport, address);
        
        let mut resolvers = self.resolvers.write().await;
        resolvers.insert(id, record);

        // Update next_id if needed
        let mut next_id = self.next_id.write().await;
        if id >= *next_id {
            *next_id = id + 1;
        }

        Ok(())
    }

    /// Remove a resolver
    pub async fn remove_resolver(&self, id: u64) -> Result<(), DbError> {
        let mut resolvers = self.resolvers.write().await;
        let mut stats = self.stats.write().await;

        if resolvers.remove(&id).is_none() {
            return Err(DbError::NotFound(id));
        }
        stats.remove(&id);

        Ok(())
    }

    /// Get a resolver by ID
    pub async fn get_resolver(&self, id: u64) -> Result<ResolverRecord, DbError> {
        let resolvers = self.resolvers.read().await;
        resolvers.get(&id).cloned().ok_or(DbError::NotFound(id))
    }

    /// Get all resolvers
    pub async fn get_all_resolvers(&self) -> Vec<ResolverRecord> {
        let resolvers = self.resolvers.read().await;
        resolvers.values().cloned().collect()
    }

    /// Get enabled resolvers
    pub async fn get_enabled_resolvers(&self) -> Vec<ResolverRecord> {
        let resolvers = self.resolvers.read().await;
        resolvers.values()
            .filter(|r| r.enabled)
            .cloned()
            .collect()
    }

    /// Get resolvers by transport type
    pub async fn get_by_transport(&self, transport: TransportType) -> Vec<ResolverRecord> {
        let resolvers = self.resolvers.read().await;
        resolvers.values()
            .filter(|r| r.transport == transport && r.enabled)
            .cloned()
            .collect()
    }

    /// Update resolver
    pub async fn update_resolver(&self, record: ResolverRecord) -> Result<(), DbError> {
        let mut resolvers = self.resolvers.write().await;
        if !resolvers.contains_key(&record.id) {
            return Err(DbError::NotFound(record.id));
        }
        resolvers.insert(record.id, record);
        Ok(())
    }

    /// Enable/disable resolver
    pub async fn set_enabled(&self, id: u64, enabled: bool) -> Result<(), DbError> {
        let mut resolvers = self.resolvers.write().await;
        let record = resolvers.get_mut(&id).ok_or(DbError::NotFound(id))?;
        record.enabled = enabled;
        record.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(())
    }

    /// Update stats for a resolver
    pub async fn update_stats(&self, stats: StatsRecord) -> Result<(), DbError> {
        let mut db_stats = self.stats.write().await;
        db_stats.insert(stats.id, stats);
        Ok(())
    }

    /// Get stats for a resolver
    pub async fn get_stats(&self, id: u64) -> Option<StatsRecord> {
        let stats = self.stats.read().await;
        stats.get(&id).cloned()
    }

    /// Get healthy resolvers (above minimum score)
    pub async fn get_healthy(&self, min_score: f64) -> Vec<ResolverRecord> {
        let resolvers = self.resolvers.read().await;
        let stats = self.stats.read().await;

        resolvers.values()
            .filter(|r| r.enabled)
            .filter(|r| {
                stats.get(&r.id)
                    .map(|s| s.health_score >= min_score)
                    .unwrap_or(true) // Include resolvers without stats
            })
            .cloned()
            .collect()
    }

    /// Get resolver endpoints
    pub async fn get_endpoints(&self) -> Vec<ResolverEndpoint> {
        let resolvers = self.resolvers.read().await;
        resolvers.values()
            .filter(|r| r.enabled)
            .map(|r| r.to_endpoint())
            .collect()
    }

    /// Get resolver count
    pub async fn count(&self) -> usize {
        let resolvers = self.resolvers.read().await;
        resolvers.len()
    }

    /// Clear all data
    pub async fn clear(&self) {
        let mut resolvers = self.resolvers.write().await;
        let mut stats = self.stats.write().await;
        resolvers.clear();
        stats.clear();
    }
}

impl Default for ResolverDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolver_db() {
        let db = ResolverDb::new();

        // Add resolver
        let id = db.add_resolver(TransportType::DnsUdp, "1.1.1.1:53".to_string()).await.unwrap();
        assert_eq!(id, 1);

        // Get resolver
        let record = db.get_resolver(id).await.unwrap();
        assert_eq!(record.address, "1.1.1.1:53");
        assert!(record.enabled);

        // Get all
        let all = db.get_all_resolvers().await;
        assert_eq!(all.len(), 1);

        // Disable
        db.set_enabled(id, false).await.unwrap();
        let enabled = db.get_enabled_resolvers().await;
        assert!(enabled.is_empty());

        // Remove
        db.remove_resolver(id).await.unwrap();
        assert!(db.get_resolver(id).await.is_err());
    }

    #[tokio::test]
    async fn test_resolver_to_endpoint() {
        let record = ResolverRecord::new(1, TransportType::DnsUdp, "8.8.8.8:53".to_string());
        let endpoint = record.to_endpoint();
        
        assert_eq!(endpoint.id, 1);
        assert_eq!(endpoint.transport, TransportType::DnsUdp);
        assert_eq!(endpoint.socket_addr, Some("8.8.8.8:53".parse().unwrap()));
    }
}
