use std::time::Instant;

/// Token-bucket rate limiter bounding how many packets the relay accepts per
/// second. This caps storm amplification: each accepted source packet is fanned
/// out to every output interface, so without a ceiling a broadcast storm on an
/// input interface is faithfully amplified across all outputs.
///
/// The bucket holds up to `burst` tokens and refills at `rate` tokens/sec.
/// Each relayed source packet consumes one token; when the bucket is empty the
/// packet is dropped. Construction is skipped entirely when no limit is set, so
/// the unlimited hotpath pays nothing.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// Create a limiter of `rate` packets/sec with a burst capacity of `burst`
    /// (the most packets that can pass back-to-back after an idle period).
    pub fn new(rate: u32, burst: u32) -> Self {
        let burst = burst.max(1) as f64;
        RateLimiter {
            rate: rate as f64,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    /// Refill based on elapsed time, then try to consume one token. Returns
    /// true if the packet is allowed, false if it should be dropped.
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;

        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_burst_then_blocks() {
        // rate=0 means no refill; the bucket starts full at `burst`.
        let mut rl = RateLimiter::new(0, 3);
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow()); // bucket drained, no refill
    }

    #[test]
    fn burst_floors_at_one() {
        let mut rl = RateLimiter::new(0, 0);
        assert!(rl.allow());
        assert!(!rl.allow());
    }
}
