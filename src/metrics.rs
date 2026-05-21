use crate::error::{OxideScannerError, Result};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_port: u16,
    pub export_interval: Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prometheus_port: 9090,
            export_interval: Duration::from_secs(30),
        }
    }
}

impl MetricsConfig {
    pub fn from_env() -> Result<Self> {
        let enabled = if let Ok(enabled) = std::env::var("OXIDE_METRICS_ENABLED") {
            enabled
                .parse::<bool>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_METRICS_ENABLED value"))?
        } else {
            false
        };

        let prometheus_port = if let Ok(port) = std::env::var("OXIDE_METRICS_PORT") {
            port.parse::<u16>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_METRICS_PORT value"))?
        } else {
            9090
        };

        let export_interval = if let Ok(interval) = std::env::var("OXIDE_METRICS_INTERVAL") {
            let secs = interval
                .parse::<u64>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_METRICS_INTERVAL value"))?;
            Duration::from_secs(secs)
        } else {
            Duration::from_secs(30)
        };

        Ok(Self {
            enabled,
            prometheus_port,
            export_interval,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.prometheus_port, 9090);
        assert_eq!(config.export_interval.as_secs(), 30);
    }

    #[test]
    fn test_metrics_config_from_env() {
        env::set_var("OXIDE_METRICS_ENABLED", "true");
        env::set_var("OXIDE_METRICS_PORT", "8080");
        env::set_var("OXIDE_METRICS_INTERVAL", "60");

        let config = MetricsConfig::from_env().unwrap();
        assert!(config.enabled);
        assert_eq!(config.prometheus_port, 8080);
        assert_eq!(config.export_interval.as_secs(), 60);
        env::remove_var("OXIDE_METRICS_ENABLED");
        env::remove_var("OXIDE_METRICS_PORT");
        env::remove_var("OXIDE_METRICS_INTERVAL");
    }
}
