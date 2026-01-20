//! Circuit breaker for failing resolvers
//!
//! Prevents cascading failures by temporarily stopping requests
//! to consistently failing resolvers.
//!
//! States:
//! - Closed: Normal operation, requests flow through
//! - Open: Requests blocked, resolver considered dead
//! - Half-Open: One probe request allowed to test recovery

use std::time::{Duration, Instant};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Blocking all requests
    Open,
    /// Testing if resolver recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to open circuit
    pub failure_threshold: u32,
    /// Time to wait before trying half-open
    pub reset_timeout: Duration,
    /// Number of successes in half-open to close circuit
    pub half_open_successes: u32,
    /// Maximum consecutive failures in half-open before re-opening
    pub half_open_failures: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            half_open_successes: 2,
            half_open_failures: 1,
        }
    }
}

/// Circuit breaker for a single resolver
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure: Option<Instant>,
    last_state_change: Instant,
    total_trips: u64,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure: None,
            last_state_change: Instant::now(),
            total_trips: 0,
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        // Check if we should transition from Open to HalfOpen
        if self.state == CircuitState::Open {
            if let Some(last_failure) = self.last_failure {
                if last_failure.elapsed() >= self.config.reset_timeout {
                    return CircuitState::HalfOpen;
                }
            }
        }
        self.state
    }

    /// Check if circuit is closed (allowing requests)
    pub fn is_closed(&self) -> bool {
        matches!(self.state(), CircuitState::Closed | CircuitState::HalfOpen)
    }

    /// Check if circuit is open (blocking requests)
    pub fn is_open(&self) -> bool {
        self.state() == CircuitState::Open
    }

    /// Check if circuit is half-open (testing)
    pub fn is_half_open(&self) -> bool {
        self.state() == CircuitState::HalfOpen
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes += 1;

        match self.state() {
            CircuitState::HalfOpen => {
                // Transition from actual state, not computed
                if self.state == CircuitState::Open {
                    // First success in half-open
                    self.state = CircuitState::HalfOpen;
                    self.last_state_change = Instant::now();
                    self.consecutive_successes = 1;
                }
                
                if self.consecutive_successes >= self.config.half_open_successes {
                    self.state = CircuitState::Closed;
                    self.last_state_change = Instant::now();
                    log::info!("Circuit breaker closed after successful recovery");
                }
            }
            _ => {}
        }
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        self.consecutive_successes = 0;
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());

        match self.state() {
            CircuitState::Closed => {
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.state = CircuitState::Open;
                    self.last_state_change = Instant::now();
                    self.total_trips += 1;
                    log::warn!("Circuit breaker opened after {} consecutive failures", self.consecutive_failures);
                }
            }
            CircuitState::HalfOpen => {
                if self.consecutive_failures >= self.config.half_open_failures {
                    self.state = CircuitState::Open;
                    self.last_state_change = Instant::now();
                    log::warn!("Circuit breaker re-opened during half-open test");
                }
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Manually reset the circuit breaker
    pub fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.last_failure = None;
        self.last_state_change = Instant::now();
    }

    /// Get time until circuit might transition to half-open
    pub fn time_until_half_open(&self) -> Option<Duration> {
        if self.state == CircuitState::Open {
            self.last_failure.map(|t| {
                self.config.reset_timeout.saturating_sub(t.elapsed())
            })
        } else {
            None
        }
    }

    /// Get total number of times circuit has tripped
    pub fn total_trips(&self) -> u64 {
        self.total_trips
    }

    /// Get time since last state change
    pub fn time_in_state(&self) -> Duration {
        self.last_state_change.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_circuit_breaker_basic() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_millis(100),
            half_open_successes: 2,
            half_open_failures: 1,
        };
        let mut cb = CircuitBreaker::new(config);

        assert!(cb.is_closed());
        assert_eq!(cb.state(), CircuitState::Closed);

        // Record failures until threshold
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_closed());

        cb.record_failure();
        assert!(cb.is_open());
        assert_eq!(cb.total_trips(), 1);
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(50),
            half_open_successes: 1,
            half_open_failures: 1,
        };
        let mut cb = CircuitBreaker::new(config);

        // Trip the circuit
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());

        // Wait for reset timeout
        sleep(Duration::from_millis(60));

        // Should be half-open now
        assert!(cb.is_half_open());

        // Success in half-open closes circuit
        cb.record_success();
        assert!(cb.is_closed());
    }

    #[test]
    fn test_circuit_breaker_half_open_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(50),
            half_open_successes: 2,
            half_open_failures: 1,
        };
        let mut cb = CircuitBreaker::new(config);

        // Trip the circuit
        cb.record_failure();
        cb.record_failure();

        // Wait for reset
        sleep(Duration::from_millis(60));
        assert!(cb.is_half_open());

        // Failure in half-open re-opens
        cb.record_failure();
        assert!(cb.is_open());
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig::default();
        let mut cb = CircuitBreaker::new(config);

        // Trip the circuit
        for _ in 0..5 {
            cb.record_failure();
        }
        assert!(cb.is_open());

        // Manual reset
        cb.reset();
        assert!(cb.is_closed());
    }
}
