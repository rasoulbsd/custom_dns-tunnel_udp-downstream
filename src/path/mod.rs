//! Path manager - intelligent path selection and load balancing
//!
//! Manages:
//! - Health monitoring of resolvers
//! - Multi-factor path scoring
//! - Load balancing strategies
//! - Circuit breaker for failing paths

pub mod health;
pub mod scorer;
pub mod circuit;

pub use health::*;
pub use scorer::*;
pub use circuit::*;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::transport::{ResolverEndpoint, TransportType};
use crate::db::ResolverDb;

/// Load balancing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin weighted by health score
    WeightedRoundRobin,
    /// Always pick lowest latency
    LeastLatency,
    /// Pick highest bandwidth/payload capacity
    BandwidthFirst,
    /// Send to multiple resolvers (redundant)
    Redundant,
    /// Random selection weighted by score
    WeightedRandom,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::WeightedRoundRobin
    }
}

impl std::str::FromStr for LoadBalanceStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "weighted_round_robin" | "wrr" | "round_robin" => Ok(Self::WeightedRoundRobin),
            "least_latency" | "latency" | "fastest" => Ok(Self::LeastLatency),
            "bandwidth_first" | "bandwidth" | "throughput" => Ok(Self::BandwidthFirst),
            "redundant" | "multi" | "spam" => Ok(Self::Redundant),
            "weighted_random" | "random" => Ok(Self::WeightedRandom),
            _ => Err(format!("Unknown load balance strategy: {}", s)),
        }
    }
}

/// Path manager configuration
#[derive(Debug, Clone)]
pub struct PathManagerConfig {
    /// Health probe interval
    pub health_probe_interval: Duration,
    /// Probe timeout
    pub probe_timeout: Duration,
    /// Circuit breaker threshold (consecutive failures)
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker reset time
    pub circuit_breaker_reset: Duration,
    /// Minimum healthy resolvers required
    pub min_healthy_resolvers: usize,
    /// Default load balance strategy
    pub default_strategy: LoadBalanceStrategy,
    /// Redundancy factor (for redundant mode)
    pub redundancy_factor: usize,
}

impl Default for PathManagerConfig {
    fn default() -> Self {
        Self {
            health_probe_interval: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(2),
            circuit_breaker_threshold: 5,
            circuit_breaker_reset: Duration::from_secs(30),
            min_healthy_resolvers: 2,
            default_strategy: LoadBalanceStrategy::WeightedRoundRobin,
            redundancy_factor: 2,
        }
    }
}

/// Path selection result
#[derive(Debug, Clone)]
pub struct SelectedPath {
    /// Selected resolver endpoints
    pub endpoints: Vec<ResolverEndpoint>,
    /// Strategy used
    pub strategy: LoadBalanceStrategy,
    /// Selection reason
    pub reason: String,
}

/// Path manager - coordinates health, scoring, and selection
#[derive(Debug)]
pub struct PathManager {
    config: PathManagerConfig,
    health: Arc<RwLock<HealthMonitor>>,
    scorer: PathScorer,
    circuits: Arc<RwLock<HashMap<u64, CircuitBreaker>>>,
    round_robin_index: Arc<RwLock<usize>>,
}

impl PathManager {
    /// Create a new path manager
    pub fn new(config: PathManagerConfig) -> Self {
        let scorer = PathScorer::new(ScorerConfig::default());
        
        Self {
            health: Arc::new(RwLock::new(HealthMonitor::new(HealthConfig {
                probe_interval: config.health_probe_interval,
                probe_timeout: config.probe_timeout,
                ..Default::default()
            }))),
            scorer,
            circuits: Arc::new(RwLock::new(HashMap::new())),
            round_robin_index: Arc::new(RwLock::new(0)),
            config,
        }
    }

    /// Select paths based on strategy and current health
    pub async fn select(
        &self,
        candidates: &[ResolverEndpoint],
        strategy: Option<LoadBalanceStrategy>,
        prefer_transport: Option<TransportType>,
    ) -> SelectedPath {
        let strategy = strategy.unwrap_or(self.config.default_strategy);
        
        // Filter by transport preference if specified
        let filtered: Vec<&ResolverEndpoint> = if let Some(transport) = prefer_transport {
            candidates.iter().filter(|e| e.transport == transport).collect()
        } else {
            candidates.iter().collect()
        };

        if filtered.is_empty() {
            return SelectedPath {
                endpoints: vec![],
                strategy,
                reason: "No candidates available".to_string(),
            };
        }

        // Filter out circuit-broken resolvers
        let healthy: Vec<&ResolverEndpoint> = {
            let circuits = self.circuits.read().await;
            filtered.iter()
                .filter(|e| {
                    circuits.get(&e.id)
                        .map(|cb| cb.is_closed())
                        .unwrap_or(true)
                })
                .copied()
                .collect()
        };

        if healthy.is_empty() {
            // All circuits open, try half-open on first candidate
            return SelectedPath {
                endpoints: vec![filtered[0].clone()],
                strategy,
                reason: "All circuits open, attempting recovery".to_string(),
            };
        }

        // Get health stats for scoring
        let health = self.health.read().await;
        let mut scored: Vec<(&ResolverEndpoint, f64)> = healthy.iter()
            .map(|e| {
                let stats = health.get_stats(e.id);
                let score = self.scorer.compute_score(stats.as_ref(), false);
                (*e, score)
            })
            .collect();

        // Sort by score (descending)
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let endpoints = match strategy {
            LoadBalanceStrategy::WeightedRoundRobin => {
                let mut idx = self.round_robin_index.write().await;
                *idx = (*idx + 1) % scored.len();
                vec![scored[*idx].0.clone()]
            }
            LoadBalanceStrategy::LeastLatency => {
                // Re-sort by RTT
                let mut by_rtt: Vec<_> = scored.iter()
                    .map(|(e, _)| {
                        let stats = health.get_stats(e.id);
                        let rtt = stats.map(|s| s.rtt_ms).unwrap_or(f64::MAX);
                        (*e, rtt)
                    })
                    .collect();
                by_rtt.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                vec![by_rtt[0].0.clone()]
            }
            LoadBalanceStrategy::BandwidthFirst => {
                // Sort by max_payload
                let mut by_bandwidth: Vec<_> = scored.iter()
                    .map(|(e, _)| (*e, e.max_payload as usize))
                    .collect();
                by_bandwidth.sort_by(|a, b| b.1.cmp(&a.1));
                vec![by_bandwidth[0].0.clone()]
            }
            LoadBalanceStrategy::Redundant => {
                // Take top N by score
                let count = self.config.redundancy_factor.min(scored.len());
                scored[..count].iter().map(|(e, _)| (*e).clone()).collect()
            }
            LoadBalanceStrategy::WeightedRandom => {
                // Weighted random selection
                let total_score: f64 = scored.iter().map(|(_, s)| *s).sum();
                let mut r = rand::random::<f64>() * total_score;
                for (endpoint, score) in &scored {
                    r -= score;
                    if r <= 0.0 {
                        return SelectedPath {
                            endpoints: vec![(*endpoint).clone()],
                            strategy,
                            reason: format!("Weighted random selection (score: {:.2})", score),
                        };
                    }
                }
                vec![scored[0].0.clone()]
            }
        };

        SelectedPath {
            endpoints,
            strategy,
            reason: format!("Selected {} endpoint(s)", scored.len()),
        }
    }

    /// Report a successful transmission
    pub async fn report_success(&self, endpoint_id: u64, rtt: Duration) {
        // Update health stats
        let mut health = self.health.write().await;
        health.record_success(endpoint_id, rtt);

        // Reset circuit breaker
        let mut circuits = self.circuits.write().await;
        if let Some(cb) = circuits.get_mut(&endpoint_id) {
            cb.record_success();
        }
    }

    /// Report a failed transmission
    pub async fn report_failure(&self, endpoint_id: u64, error: &str) {
        // Update health stats
        let mut health = self.health.write().await;
        health.record_failure(endpoint_id);

        // Update circuit breaker
        let mut circuits = self.circuits.write().await;
        let cb = circuits.entry(endpoint_id).or_insert_with(|| {
            CircuitBreaker::new(CircuitBreakerConfig {
                failure_threshold: self.config.circuit_breaker_threshold,
                reset_timeout: self.config.circuit_breaker_reset,
                ..Default::default()
            })
        });
        cb.record_failure();
    }

    /// Get health statistics for an endpoint
    pub async fn get_health(&self, endpoint_id: u64) -> Option<ResolverStats> {
        let health = self.health.read().await;
        health.get_stats(endpoint_id)
    }

    /// Get all health statistics
    pub async fn get_all_health(&self) -> Vec<ResolverStats> {
        let health = self.health.read().await;
        health.get_all_stats()
    }

    /// Check if an endpoint's circuit is open
    pub async fn is_circuit_open(&self, endpoint_id: u64) -> bool {
        let circuits = self.circuits.read().await;
        circuits.get(&endpoint_id)
            .map(|cb| cb.is_open())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_path_manager_creation() {
        let config = PathManagerConfig::default();
        let pm = PathManager::new(config);
        
        let candidates = vec![
            ResolverEndpoint::new_dns_udp(1, "1.1.1.1:53".parse().unwrap()),
            ResolverEndpoint::new_dns_udp(2, "8.8.8.8:53".parse().unwrap()),
        ];

        let selected = pm.select(&candidates, None, None).await;
        assert!(!selected.endpoints.is_empty());
    }

    #[tokio::test]
    async fn test_redundant_selection() {
        let config = PathManagerConfig {
            redundancy_factor: 2,
            ..Default::default()
        };
        let pm = PathManager::new(config);
        
        let candidates = vec![
            ResolverEndpoint::new_dns_udp(1, "1.1.1.1:53".parse().unwrap()),
            ResolverEndpoint::new_dns_udp(2, "8.8.8.8:53".parse().unwrap()),
            ResolverEndpoint::new_dns_udp(3, "9.9.9.9:53".parse().unwrap()),
        ];

        let selected = pm.select(&candidates, Some(LoadBalanceStrategy::Redundant), None).await;
        assert_eq!(selected.endpoints.len(), 2);
    }
}
