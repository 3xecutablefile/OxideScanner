use crate::error::{OxideScannerError, Result};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitPolicy {
    pub max_operations: u32,
    pub period: Duration,
    pub burst_capacity: Option<u32>,
}

impl RateLimitPolicy {
    pub fn new(max_operations: u32, period: Duration) -> Self {
        Self {
            max_operations,
            period,
            burst_capacity: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_burst(max_operations: u32, period: Duration, burst_capacity: u32) -> Self {
        Self {
            max_operations,
            period,
            burst_capacity: Some(burst_capacity),
        }
    }

    #[allow(dead_code)]
    pub fn to_quota(&self) -> Result<governor::Quota> {
        use governor::Quota;
        use std::num::NonZeroU32;

        let max_ops = NonZeroU32::new(self.max_operations).ok_or_else(|| {
            OxideScannerError::config("Rate limit max_operations must be greater than 0")
        })?;

        let quota = if let Some(burst) = self.burst_capacity {
            let burst_ops = NonZeroU32::new(burst).ok_or_else(|| {
                OxideScannerError::config("Rate limit burst_capacity must be greater than 0")
            })?;
            Quota::with_period(self.period)
                .unwrap()
                .allow_burst(burst_ops)
        } else {
            Quota::with_period(self.period)
                .unwrap()
                .allow_burst(max_ops)
        };

        Ok(quota)
    }
}
