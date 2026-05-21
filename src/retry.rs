use crate::error::OxideScannerError;
use std::time::Duration;

type Result<T> = std::result::Result<T, OxideScannerError>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

impl RetryConfig {
    #[allow(dead_code)]
    pub fn new(max_retries: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }

    pub fn from_env() -> Result<Self> {
        let max_retries = if let Ok(max_retries) = std::env::var("OXIDE_RETRY_MAX_ATTEMPTS") {
            max_retries
                .parse::<u32>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_RETRY_MAX_ATTEMPTS value"))?
        } else {
            3
        };

        let base_delay = if let Ok(delay) = std::env::var("OXIDE_RETRY_BASE_DELAY_MS") {
            let ms = delay.parse::<u64>().map_err(|_| {
                OxideScannerError::config("Invalid OXIDE_RETRY_BASE_DELAY_MS value")
            })?;
            Duration::from_millis(ms)
        } else {
            Duration::from_millis(100)
        };

        let max_delay = if let Ok(delay) = std::env::var("OXIDE_RETRY_MAX_DELAY_MS") {
            let ms = delay
                .parse::<u64>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_RETRY_MAX_DELAY_MS value"))?;
            Duration::from_millis(ms)
        } else {
            Duration::from_secs(5)
        };

        Ok(Self {
            max_retries,
            base_delay,
            max_delay,
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        })
    }

    #[allow(dead_code)]
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    #[allow(dead_code)]
    pub fn with_jitter_factor(mut self, factor: f64) -> Self {
        self.jitter_factor = factor;
        self
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.base_delay, Duration::from_millis(100));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_retry_config_new() {
        let config = RetryConfig::new(5, Duration::from_secs(1), Duration::from_secs(10));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.base_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(10));
    }
}
