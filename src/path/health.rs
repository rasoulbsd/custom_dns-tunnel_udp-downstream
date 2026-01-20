//! Health monitoring for resolvers
//!
//! Tracks:
//! - RTT (round-trip time)
//! - Loss rate
//! - Success/failure counts
//! - Discovered limits (max label, payload, rate limit)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::transport::TransportType;

/// Health monitoring configuration
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between health probes
    pub probe_interval: Duration,
    /// Timeout for health probes
    pub probe_timeout: Duration,
    /// Number of samples for RTT smoothing
    pub rtt_samples: usize,
    /// Window for loss rate calculation
    pub loss_window: usize,
    /// Minimum samples before stats are reliable
    pub min_samples: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(2),
            rtt_samples: 10,
            loss_window: 20,
            min_samples: 3,
        }
    }
}

/// Statistics for a single resolver
#[derive(Debug, Clone)]
pub struct ResolverStats {
    /// Resolver ID
    pub id: u64,
    /// Transport type
    pub transport: TransportType,
    /// Smoothed RTT in milliseconds
    pub rtt_ms: f64,
    /// RTT variance
    pub rtt_var_ms: f64,
    /// Loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Total successful transmissions
    pub success_count: u64,
    /// Total failed transmissions
    pub failure_count: u64,
    /// Time of last successful transmission
    pub last_success: Option<Instant>,
    /// Time of last failure
    pub last_failure: Option<Instant>,
    /// Computed health score (0.0 - 1.0)
    pub health_score: f64,
    /// Discovered maximum label length
    pub max_label_len: u8,
    /// Discovered maximum payload size
    pub max_payload: u16,
    /// Discovered rate limit (queries per second)
    pub rate_limit_qps: Option<u32>,
    /// Whether stats are reliable (enough samples)
    pub reliable: bool,
}

impl ResolverStats {
    pub fn new(id: u64, transport: TransportType) -> Self {
        Self {
            id,
            transport,
            rtt_ms: 0.0,
            rtt_var_ms: 0.0,
            loss_rate: 0.0,
            success_count: 0,
            failure_count: 0,
            last_success: None,
            last_failure: None,
            health_score: 1.0,
            max_label_len: 63,
            max_payload: 200,
            rate_limit_qps: None,
            reliable: false,
        }
    }

    /// Total transmissions
    pub fn total(&self) -> u64 {
        self.success_count + self.failure_count
    }

    /// Success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.total() == 0 {
            1.0
        } else {
            self.success_count as f64 / self.total() as f64
        }
    }

    /// Time since last success
    pub fn time_since_success(&self) -> Option<Duration> {
        self.last_success.map(|t| t.elapsed())
    }

    /// Time since last failure
    pub fn time_since_failure(&self) -> Option<Duration> {
        self.last_failure.map(|t| t.elapsed())
    }
}

/// Internal tracking data for a resolver
#[derive(Debug)]
struct ResolverTracker {
    stats: ResolverStats,
    rtt_history: Vec<f64>,
    recent_results: Vec<bool>, // true = success, false = failure
    config: HealthConfig,
}

impl ResolverTracker {
    fn new(id: u64, transport: TransportType, config: HealthConfig) -> Self {
        Self {
            stats: ResolverStats::new(id, transport),
            rtt_history: Vec::new(),
            recent_results: Vec::new(),
            config,
        }
    }

    fn record_success(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f64() * 1000.0;
        
        // Update RTT history
        self.rtt_history.push(rtt_ms);
        if self.rtt_history.len() > self.config.rtt_samples {
            self.rtt_history.remove(0);
        }

        // Update smoothed RTT
        let sum: f64 = self.rtt_history.iter().sum();
        self.stats.rtt_ms = sum / self.rtt_history.len() as f64;

        // Update RTT variance
        if self.rtt_history.len() > 1 {
            let variance: f64 = self.rtt_history.iter()
                .map(|r| (r - self.stats.rtt_ms).powi(2))
                .sum::<f64>() / (self.rtt_history.len() - 1) as f64;
            self.stats.rtt_var_ms = variance.sqrt();
        }

        // Update recent results
        self.recent_results.push(true);
        if self.recent_results.len() > self.config.loss_window {
            self.recent_results.remove(0);
        }

        // Update loss rate
        let failures = self.recent_results.iter().filter(|r| !**r).count();
        self.stats.loss_rate = failures as f64 / self.recent_results.len() as f64;

        // Update counts
        self.stats.success_count += 1;
        self.stats.last_success = Some(Instant::now());

        // Update reliability flag
        self.stats.reliable = self.stats.total() >= self.config.min_samples as u64;
    }

    fn record_failure(&mut self) {
        // Update recent results
        self.recent_results.push(false);
        if self.recent_results.len() > self.config.loss_window {
            self.recent_results.remove(0);
        }

        // Update loss rate
        let failures = self.recent_results.iter().filter(|r| !**r).count();
        self.stats.loss_rate = failures as f64 / self.recent_results.len() as f64;

        // Update counts
        self.stats.failure_count += 1;
        self.stats.last_failure = Some(Instant::now());

        // Update reliability flag
        self.stats.reliable = self.stats.total() >= self.config.min_samples as u64;
    }

    fn update_limits(&mut self, max_label_len: u8, max_payload: u16, rate_limit: Option<u32>) {
        self.stats.max_label_len = max_label_len;
        self.stats.max_payload = max_payload;
        self.stats.rate_limit_qps = rate_limit;
    }

    fn update_score(&mut self, score: f64) {
        self.stats.health_score = score;
    }
}

/// Health monitor - tracks health of all resolvers
#[derive(Debug)]
pub struct HealthMonitor {
    config: HealthConfig,
    trackers: HashMap<u64, ResolverTracker>,
}

impl HealthMonitor {
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            trackers: HashMap::new(),
        }
    }

    /// Register a resolver for monitoring
    pub fn register(&mut self, id: u64, transport: TransportType) {
        if !self.trackers.contains_key(&id) {
            self.trackers.insert(id, ResolverTracker::new(id, transport, self.config.clone()));
        }
    }

    /// Record a successful transmission
    pub fn record_success(&mut self, id: u64, rtt: Duration) {
        if let Some(tracker) = self.trackers.get_mut(&id) {
            tracker.record_success(rtt);
        }
    }

    /// Record a failed transmission
    pub fn record_failure(&mut self, id: u64) {
        if let Some(tracker) = self.trackers.get_mut(&id) {
            tracker.record_failure();
        }
    }

    /// Update discovered limits for a resolver
    pub fn update_limits(&mut self, id: u64, max_label_len: u8, max_payload: u16, rate_limit: Option<u32>) {
        if let Some(tracker) = self.trackers.get_mut(&id) {
            tracker.update_limits(max_label_len, max_payload, rate_limit);
        }
    }

    /// Update health score for a resolver
    pub fn update_score(&mut self, id: u64, score: f64) {
        if let Some(tracker) = self.trackers.get_mut(&id) {
            tracker.update_score(score);
        }
    }

    /// Get stats for a resolver
    pub fn get_stats(&self, id: u64) -> Option<ResolverStats> {
        self.trackers.get(&id).map(|t| t.stats.clone())
    }

    /// Get stats for all resolvers
    pub fn get_all_stats(&self) -> Vec<ResolverStats> {
        self.trackers.values().map(|t| t.stats.clone()).collect()
    }

    /// Get healthy resolvers (above minimum score threshold)
    pub fn get_healthy(&self, min_score: f64) -> Vec<ResolverStats> {
        self.trackers.values()
            .filter(|t| t.stats.health_score >= min_score)
            .map(|t| t.stats.clone())
            .collect()
    }

    /// Remove a resolver from monitoring
    pub fn remove(&mut self, id: u64) {
        self.trackers.remove(&id);
    }

    /// Clear all monitoring data
    pub fn clear(&mut self) {
        self.trackers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_stats() {
        let mut stats = ResolverStats::new(1, TransportType::DnsUdp);
        assert_eq!(stats.total(), 0);
        assert_eq!(stats.success_rate(), 1.0);
        
        stats.success_count = 8;
        stats.failure_count = 2;
        assert_eq!(stats.total(), 10);
        assert_eq!(stats.success_rate(), 0.8);
    }

    #[test]
    fn test_health_monitor() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);

        monitor.register(1, TransportType::DnsUdp);
        
        // Record some successes
        monitor.record_success(1, Duration::from_millis(50));
        monitor.record_success(1, Duration::from_millis(60));
        monitor.record_success(1, Duration::from_millis(40));

        let stats = monitor.get_stats(1).unwrap();
        assert_eq!(stats.success_count, 3);
        assert!(stats.rtt_ms > 40.0 && stats.rtt_ms < 60.0);
        assert_eq!(stats.loss_rate, 0.0);

        // Record a failure
        monitor.record_failure(1);
        
        let stats = monitor.get_stats(1).unwrap();
        assert_eq!(stats.failure_count, 1);
        assert!(stats.loss_rate > 0.0);
    }
}
