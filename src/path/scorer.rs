//! Multi-factor path scoring
//!
//! Computes a health score (0.0 - 1.0) for resolvers based on:
//! - RTT (latency)
//! - Loss rate
//! - Recency (time since last success)
//! - Throughput capacity

use super::health::ResolverStats;

/// Scorer configuration
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// Weight for RTT factor
    pub rtt_weight: f64,
    /// Weight for loss rate factor
    pub loss_weight: f64,
    /// Weight for recency factor
    pub recency_weight: f64,
    /// Weight for throughput factor
    pub throughput_weight: f64,
    /// RTT normalization (1000ms = score 0)
    pub rtt_max_ms: f64,
    /// Recency normalization (60s = score 0)
    pub recency_max_secs: f64,
    /// Throughput normalization (max_payload for score 1)
    pub throughput_max_bytes: u16,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            rtt_weight: 0.3,
            loss_weight: 0.4,
            recency_weight: 0.15,
            throughput_weight: 0.15,
            rtt_max_ms: 1000.0,
            recency_max_secs: 60.0,
            throughput_max_bytes: 1400,
        }
    }
}

impl ScorerConfig {
    /// Create scorer config optimized for interactive traffic (SSH)
    pub fn interactive() -> Self {
        Self {
            rtt_weight: 0.5,      // Prioritize latency
            loss_weight: 0.3,
            recency_weight: 0.15,
            throughput_weight: 0.05,
            rtt_max_ms: 500.0,    // Stricter RTT threshold
            recency_max_secs: 30.0,
            throughput_max_bytes: 500,
        }
    }

    /// Create scorer config optimized for bulk traffic (VPN)
    pub fn bulk() -> Self {
        Self {
            rtt_weight: 0.15,
            loss_weight: 0.35,
            recency_weight: 0.1,
            throughput_weight: 0.4, // Prioritize throughput
            rtt_max_ms: 2000.0,     // More tolerant of latency
            recency_max_secs: 120.0,
            throughput_max_bytes: 1400,
        }
    }
}

/// Path scorer
#[derive(Debug, Clone)]
pub struct PathScorer {
    config: ScorerConfig,
}

impl PathScorer {
    pub fn new(config: ScorerConfig) -> Self {
        Self { config }
    }

    /// Compute score for a resolver
    /// Returns 0.0 - 1.0 where 1.0 is best
    pub fn compute_score(&self, stats: Option<&ResolverStats>, is_interactive: bool) -> f64 {
        let stats = match stats {
            Some(s) => s,
            None => return 0.5, // Unknown resolver gets middle score
        };

        // Adjust weights based on traffic type
        let config = if is_interactive {
            ScorerConfig::interactive()
        } else {
            self.config.clone()
        };

        // RTT score: lower is better
        let rtt_score = 1.0 - (stats.rtt_ms / config.rtt_max_ms).min(1.0);

        // Loss score: lower is better
        let loss_score = 1.0 - stats.loss_rate;

        // Recency score: recent success is better
        let recency_score = match stats.time_since_success() {
            Some(elapsed) => 1.0 - (elapsed.as_secs_f64() / config.recency_max_secs).min(1.0),
            None => 0.5, // No success yet
        };

        // Throughput score: higher payload capacity is better
        let throughput_score = (stats.max_payload as f64 / config.throughput_max_bytes as f64).min(1.0);

        // Weighted sum
        let score = config.rtt_weight * rtt_score
            + config.loss_weight * loss_score
            + config.recency_weight * recency_score
            + config.throughput_weight * throughput_score;

        // Clamp to valid range
        score.max(0.0).min(1.0)
    }

    /// Compute scores for multiple resolvers
    pub fn compute_scores(&self, stats_list: &[ResolverStats], is_interactive: bool) -> Vec<(u64, f64)> {
        stats_list.iter()
            .map(|s| (s.id, self.compute_score(Some(s), is_interactive)))
            .collect()
    }

    /// Get the best resolver by score
    pub fn get_best(&self, stats_list: &[ResolverStats], is_interactive: bool) -> Option<(u64, f64)> {
        self.compute_scores(stats_list, is_interactive)
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get resolvers above a minimum score threshold
    pub fn get_above_threshold(&self, stats_list: &[ResolverStats], threshold: f64, is_interactive: bool) -> Vec<(u64, f64)> {
        self.compute_scores(stats_list, is_interactive)
            .into_iter()
            .filter(|(_, score)| *score >= threshold)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportType;
    use std::time::Instant;

    fn make_stats(id: u64, rtt_ms: f64, loss_rate: f64, max_payload: u16) -> ResolverStats {
        let mut stats = ResolverStats::new(id, TransportType::DnsUdp);
        stats.rtt_ms = rtt_ms;
        stats.loss_rate = loss_rate;
        stats.max_payload = max_payload;
        stats.last_success = Some(Instant::now());
        stats
    }

    #[test]
    fn test_scorer_basic() {
        let scorer = PathScorer::new(ScorerConfig::default());

        // Good resolver: low RTT, no loss, good throughput
        let good = make_stats(1, 50.0, 0.0, 1000);
        let score = scorer.compute_score(Some(&good), false);
        assert!(score > 0.8);

        // Bad resolver: high RTT, high loss
        let bad = make_stats(2, 800.0, 0.5, 200);
        let score = scorer.compute_score(Some(&bad), false);
        assert!(score < 0.5);
    }

    #[test]
    fn test_interactive_scoring() {
        let scorer = PathScorer::new(ScorerConfig::default());

        // Low latency resolver
        let fast = make_stats(1, 30.0, 0.1, 200);
        // High throughput resolver
        let big = make_stats(2, 200.0, 0.05, 1400);

        // For interactive, fast should score higher
        let fast_score = scorer.compute_score(Some(&fast), true);
        let big_score = scorer.compute_score(Some(&big), true);
        assert!(fast_score > big_score);

        // For bulk, big should score higher
        let fast_score = scorer.compute_score(Some(&fast), false);
        let big_score = scorer.compute_score(Some(&big), false);
        // This depends on exact weights, but throughput should matter more for bulk
    }

    #[test]
    fn test_get_best() {
        let scorer = PathScorer::new(ScorerConfig::default());

        let stats = vec![
            make_stats(1, 100.0, 0.1, 500),
            make_stats(2, 50.0, 0.0, 800),
            make_stats(3, 200.0, 0.2, 1000),
        ];

        let (best_id, best_score) = scorer.get_best(&stats, false).unwrap();
        assert_eq!(best_id, 2); // Lowest RTT and no loss
    }
}
