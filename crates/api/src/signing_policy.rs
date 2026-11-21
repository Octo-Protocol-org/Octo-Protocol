//! Startup policy for locally built Stellar transactions.

use std::time::{SystemTime, UNIX_EPOCH};

pub const MIN_BASE_FEE_STROOPS: i64 = 100;
pub const DEFAULT_MAX_TIME_WINDOW_SECONDS: u64 = 300;
pub const DEFAULT_FEE_PERCENTILE: u8 = 50;
pub const DEFAULT_FEE_CEILING_STROOPS: i64 = 10_000;
const MAX_TIME_WINDOW_SECONDS: u64 = 86_400;
const SUPPORTED_FEE_PERCENTILES: [u8; 11] = [10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 99];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningPolicy {
    max_time_window_seconds: u64,
    fee_percentile: u8,
    fee_ceiling_stroops: i64,
}

impl SigningPolicy {
    pub fn new(
        max_time_window_seconds: u64,
        fee_percentile: u8,
        fee_ceiling_stroops: i64,
    ) -> Result<Self, String> {
        if !(1..=MAX_TIME_WINDOW_SECONDS).contains(&max_time_window_seconds) {
            return Err(format!(
                "STELLAR_TX_MAX_AGE_SECS must be between 1 and {MAX_TIME_WINDOW_SECONDS}"
            ));
        }
        if !SUPPORTED_FEE_PERCENTILES.contains(&fee_percentile) {
            let supported = SUPPORTED_FEE_PERCENTILES
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",");
            return Err(format!(
                "STELLAR_FEE_PERCENTILE must be one of {supported}"
            ));
        }
        if fee_ceiling_stroops < MIN_BASE_FEE_STROOPS {
            return Err(format!(
                "STELLAR_FEE_CEILING_STROOPS must be at least {MIN_BASE_FEE_STROOPS}"
            ));
        }
        Ok(Self {
            max_time_window_seconds,
            fee_percentile,
            fee_ceiling_stroops,
        })
    }

    pub fn max_time_window_seconds(self) -> u64 {
        self.max_time_window_seconds
    }

    pub fn max_time(self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(self.max_time_window_seconds)
    }

    pub fn fee_percentile(self) -> u8 {
        self.fee_percentile
    }

    pub fn fee_ceiling_stroops(self) -> i64 {
        self.fee_ceiling_stroops
    }
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self {
            max_time_window_seconds: DEFAULT_MAX_TIME_WINDOW_SECONDS,
            fee_percentile: DEFAULT_FEE_PERCENTILE,
            fee_ceiling_stroops: DEFAULT_FEE_CEILING_STROOPS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_short_and_keep_a_valid_network_fee_floor() {
        let policy = SigningPolicy::default();
        assert_eq!(policy.max_time_window_seconds(), 300);
        assert_eq!(policy.fee_percentile(), 50);
        assert_eq!(policy.fee_ceiling_stroops(), 10_000);
        assert!(policy.max_time() > 0);
    }

    #[test]
    fn accepts_supported_horizon_percentiles_and_valid_bounds() {
        assert!(SigningPolicy::new(60, 95, 500).is_ok());
    }

    #[test]
    fn accepts_every_supported_fee_percentile() {
        for percentile in SUPPORTED_FEE_PERCENTILES {
            assert!(SigningPolicy::new(300, percentile, 500).is_ok());
        }
    }

    #[test]
    fn accepts_inclusive_time_window_and_fee_ceiling_limits() {
        assert!(SigningPolicy::new(1, 50, 100).is_ok());
        assert!(SigningPolicy::new(86_400, 50, 100).is_ok());
    }

    #[test]
    fn rejects_unbounded_or_invalid_signing_settings() {
        assert!(SigningPolicy::new(0, 50, 500).is_err());
        assert!(SigningPolicy::new(86_401, 50, 500).is_err());
        assert!(SigningPolicy::new(300, 75, 500).is_err());
        assert!(SigningPolicy::new(300, 50, 99).is_err());
    }

    #[test]
    fn boundary_errors_name_the_offending_variable() {
        let err = SigningPolicy::new(86_401, 50, 100).unwrap_err();
        assert!(err.contains("STELLAR_TX_MAX_AGE_SECS"), "{err}");
        let err = SigningPolicy::new(300, 50, 99).unwrap_err();
        assert!(err.contains("STELLAR_FEE_CEILING_STROOPS"), "{err}");
    }
}
