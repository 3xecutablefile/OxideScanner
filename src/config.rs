use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::logging::LogConfig;
use crate::metrics::MetricsConfig;
use crate::rate_limit::RateLimitPolicy;
use crate::retry::RetryConfig;
use crate::validation;
use inquire::{Confirm, Select, Text};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    Tcp,
    Udp,
    Both,
}

impl ScanMode {
    pub fn label(&self) -> &str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Both => "TCP + UDP",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target: String,
    pub json_mode: bool,
    pub scan_mode: ScanMode,
    pub port_limit: u16,
    pub scan_timeout: Duration,
    pub exploit_timeout: Duration,
    pub threads: usize,
    pub shutdown_timeout: Duration,
    pub enable_rate_limiting: bool,
    pub scanner_rate_limit: RateLimitPolicy,
    pub external_tools_rate_limit: RateLimitPolicy,
    pub exploit_queries_rate_limit: RateLimitPolicy,
    pub logging: LogConfig,
    pub metrics: MetricsConfig,
    pub retry: RetryConfig,
    pub nse_script: Option<String>,
}

impl Config {
    pub fn from_args(args: &[String]) -> Result<Self> {
        if args.len() < 2 {
            return Err(OxideScannerError::config("Target argument required"));
        }

        let target = validation::validate_target(&args[1])?;
        let json_mode = args.contains(&"--json".to_string());
        let has_any_flags = args.len() > 2;
        let interactive = std::io::stdin().is_terminal() && !json_mode;

        let scan_mode = if args.contains(&"--udp".to_string()) {
            ScanMode::Udp
        } else if args.contains(&"--both".to_string()) {
            ScanMode::Both
        } else if !has_any_flags && interactive {
            Self::prompt_scan_mode()?
        } else {
            ScanMode::Tcp
        };

        let port_limit = if args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.ends_with('k'))
        {
            Self::parse_port_limit_flag(args)?
        } else if let Some(limit) = Self::parse_numeric_port_flag(args)? {
            limit
        } else if interactive {
            Self::prompt_port_limit()?
        } else {
            constants::ports::DEFAULT_LIMIT
        };

        let scan_timeout =
            Self::parse_timeout_arg(args, "--scan-timeout", constants::DEFAULT_SCAN_TIMEOUT_MS)?;
        let exploit_timeout = Self::parse_timeout_arg(
            args,
            "--exploit-timeout",
            constants::DEFAULT_EXPLOIT_TIMEOUT_SECS * 1000,
        )?;

        let nse_script = if let Some(script) = Self::parse_string_arg(args, "--script") {
            Some(script)
        } else if !has_any_flags && interactive {
            Self::prompt_nse_script()?
        } else {
            None
        };

        let env_config = Self::from_env()?;

        let threads = Self::parse_thread_arg(args, env_config.threads)?;
        let shutdown_timeout = Self::parse_timeout_arg(
            args,
            "--shutdown-timeout",
            env_config.shutdown_timeout.as_millis() as u64,
        )?;
        let enable_rate_limiting =
            !args.contains(&"--no-rate-limit".to_string()) && env_config.enable_rate_limiting;

        let logging = LogConfig::from_env()?;
        let metrics = MetricsConfig::from_env()?;
        let retry = RetryConfig::from_env()?;

        Ok(Config {
            target,
            json_mode,
            scan_mode,
            port_limit,
            scan_timeout,
            exploit_timeout,
            threads,
            shutdown_timeout,
            enable_rate_limiting,
            scanner_rate_limit: env_config.scanner_rate_limit,
            external_tools_rate_limit: env_config.external_tools_rate_limit,
            exploit_queries_rate_limit: env_config.exploit_queries_rate_limit,
            logging,
            metrics,
            retry,
            nse_script,
        })
    }

    fn prompt_scan_mode() -> Result<ScanMode> {
        let options = vec!["TCP", "UDP", "TCP + UDP"];
        let selection = Select::new("Select scan mode", options)
            .with_starting_cursor(0)
            .prompt()
            .map_err(|e| OxideScannerError::config(format!("Scan mode prompt failed: {}", e)))?;
        match selection {
            "UDP" => Ok(ScanMode::Udp),
            "TCP + UDP" => Ok(ScanMode::Both),
            _ => Ok(ScanMode::Tcp),
        }
    }

    fn prompt_nse_script() -> Result<Option<String>> {
        let yes = Confirm::new("Run NSE scripts?")
            .with_default(false)
            .prompt()
            .map_err(|e| OxideScannerError::config(format!("NSE prompt failed: {}", e)))?;
        if !yes {
            return Ok(None);
        }

        let categories = vec![
            "vuln        Check for specific known vulnerabilities",
            "safe        Not designed to crash services or exploit holes",
            "default     Default set (-sC) — speed, usefulness, reliability",
            "discovery   Query registries, SNMP, directory services, etc.",
            "exploit     Actively exploit a vulnerability",
            "auth        Authentication credentials (or bypassing them)",
            "brute       Brute-force to guess authentication credentials",
            "intrusive   May crash target, use significant resources",
            "dos         May cause a denial of service",
            "broadcast   Discover hosts by broadcasting on local network",
            "external    May send data to third-party services",
            "fuzzer      Send unexpected/randomized fields in packets",
            "malware     Test if target is infected by malware/backdoors",
            "info        General information gathering",
            "version     Version detection extension (auto, not selectable)",
            "Custom      Type your own",
        ];

        let selection = Select::new("Select NSE script category", categories)
            .with_starting_cursor(0)
            .prompt()
            .map_err(|e| OxideScannerError::config(format!("NSE prompt failed: {}", e)))?;

        if selection == "Custom      (Type your own)" {
            let custom = Text::new("Enter NSE category/filter:")
                .with_help_message("Examples: http-*, ssh-auth-methods, or a custom glob")
                .prompt()
                .map_err(|e| OxideScannerError::config(format!("NSE prompt failed: {}", e)))?;
            Ok(Some(custom))
        } else {
            let cat = selection.split_whitespace().next().unwrap_or("vuln").to_string();
            Ok(Some(cat))
        }
    }

    fn parse_timeout_arg(args: &[String], flag: &str, default_ms: u64) -> Result<Duration> {
        for (i, arg) in args.iter().enumerate() {
            if arg == flag {
                if i + 1 >= args.len() {
                    return Err(OxideScannerError::config(format!(
                        "Missing timeout value for {}",
                        flag
                    )));
                }

                let timeout_ms = args[i + 1].parse::<u64>().map_err(|_| {
                    OxideScannerError::config(format!(
                        "Invalid timeout value for {}: {}",
                        flag,
                        args[i + 1]
                    ))
                })?;

                let validated_ms = timeout_ms;
                return Ok(Duration::from_millis(validated_ms));
            }
        }
        Ok(Duration::from_millis(default_ms))
    }

    fn parse_numeric_port_flag(args: &[String]) -> Result<Option<u16>> {
        for (i, arg) in args.iter().enumerate() {
            if arg == "--ports" {
                if i + 1 >= args.len() {
                    return Err(OxideScannerError::config(
                        "Missing port count value for --ports flag",
                    ));
                }

                let port_count = args[i + 1].parse::<u16>().map_err(|_| {
                    OxideScannerError::config(format!("Invalid port count: {}", args[i + 1]))
                })?;

                if port_count < 1 {
                    return Err(OxideScannerError::config(
                        "Port count must be at least 1",
                    ));
                }

                return Ok(Some(port_count));
            }
        }

        for arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                let num_str = &arg[1..];
                if let Ok(num) = num_str.parse::<u16>() {
                    if num >= 1 {
                        return Ok(Some(num));
                    }
                }
            }
        }

        Ok(None)
    }

    fn parse_port_limit_flag(args: &[String]) -> Result<u16> {
        for arg in args {
            if arg.starts_with('-') && arg.ends_with('k') {
                let num_str = &arg[1..arg.len() - 1];
                if let Ok(num) = num_str.parse::<u16>() {
                    if (1..=constants::ports::MAX_K_VALUE).contains(&num) {
                        return Ok(num * constants::ports::DEFAULT_LIMIT);
                    } else {
                        return Err(OxideScannerError::config(format!(
                            "Port limit must be between 1k and {}k",
                            constants::ports::MAX_K_VALUE
                        )));
                    }
                } else {
                    return Err(OxideScannerError::config(format!(
                        "Invalid port limit format: {}",
                        arg
                    )));
                }
            }
        }
        Ok(constants::ports::MAX)
    }

    fn prompt_port_limit() -> Result<u16> {
        let port_options = vec!["1000 (top ports)", "5000", "10000", "65535 (all)", "Custom"];
        let selection = Select::new("Number of ports to scan", port_options)
            .with_starting_cursor(0)
            .prompt()
            .map_err(|e| OxideScannerError::config(format!("Port prompt failed: {}", e)))?;

        match selection {
            "1000 (top ports)" => Ok(1000),
            "5000" => Ok(5000),
            "10000" => Ok(10000),
            "65535 (all)" => Ok(constants::ports::MAX),
            _ => {
                let input = Text::new("Enter port count or range (e.g. 2300 or 1-2300):")
                    .prompt()
                    .map_err(|e| OxideScannerError::config(format!("Port input failed: {}", e)))?;

                let input = input.trim().to_lowercase();
                if input == "all" {
                    Ok(constants::ports::MAX)
                } else if let Ok(num) = input.parse::<u16>() {
                    validation::validate_port_limit(num)
                } else if let Some(num_str) = input.strip_prefix("1-").or_else(|| input.strip_prefix("0-")) {
                    if let Ok(num) = num_str.parse::<u16>() {
                        validation::validate_port_limit(num)
                    } else {
                        Err(OxideScannerError::config(format!(
                            "Invalid port range: {}. Use a number like 2300", input
                        )))
                    }
                } else {
                    Err(OxideScannerError::config(format!(
                        "Invalid port number: {}. Use e.g. 2300 or 1-2300", input
                    )))
                }
            }
        }
    }

    fn parse_string_arg(args: &[String], flag: &str) -> Option<String> {
        for (i, arg) in args.iter().enumerate() {
            if arg == flag {
                if i + 1 < args.len() {
                    let val = args[i + 1].trim().to_string();
                    if !val.is_empty() && !val.starts_with('-') {
                        return Some(val);
                    }
                }
            }
        }
        None
    }

    fn parse_thread_arg(args: &[String], default: usize) -> Result<usize> {
        for (i, arg) in args.iter().enumerate() {
            if arg == "--threads" {
                if i + 1 >= args.len() {
                    return Err(OxideScannerError::config("Missing connection count value"));
                }

                let threads = args[i + 1].parse::<usize>().map_err(|_| {
                    OxideScannerError::config(format!("Invalid connection count: {}", args[i + 1]))
                })?;

                if threads == 0 {
                    return Ok(constants::MAX_CONCURRENT_CONNS);
                }

                return Ok(threads);
            }
        }
        Ok(default)
    }

    fn from_env() -> Result<Self> {
        let threads = if let Ok(threads) = std::env::var("OXIDE_THREADS") {
            threads
                .parse::<usize>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_THREADS value"))?
        } else {
            constants::MAX_CONCURRENT_CONNS
        };

        let shutdown_timeout = if let Ok(timeout) = std::env::var("OXIDE_SHUTDOWN_TIMEOUT") {
            let secs = timeout
                .parse::<u64>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_SHUTDOWN_TIMEOUT value"))?;
            Duration::from_secs(secs)
        } else {
            Duration::from_secs(30)
        };

        let enable_rate_limiting = if let Ok(enabled) = std::env::var("OXIDE_ENABLE_RATE_LIMIT") {
            enabled
                .parse::<bool>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_ENABLE_RATE_LIMIT value"))?
        } else {
            true
        };

        let scanner_rate_limit = RateLimitPolicy::new(
            std::env::var("OXIDE_SCANNER_RATE_LIMIT")
                .unwrap_or_else(|_| "50".to_string())
                .parse::<u32>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_SCANNER_RATE_LIMIT value"))?,
            Duration::from_secs(1),
        );

        let external_tools_rate_limit = RateLimitPolicy::new(
            std::env::var("OXIDE_EXTERNAL_TOOLS_RATE_LIMIT")
                .unwrap_or_else(|_| "5".to_string())
                .parse::<u32>()
                .map_err(|_| {
                    OxideScannerError::config("Invalid OXIDE_EXTERNAL_TOOLS_RATE_LIMIT value")
                })?,
            Duration::from_secs(1),
        );

        let exploit_queries_rate_limit = RateLimitPolicy::new(
            std::env::var("OXIDE_EXPLOIT_QUERIES_RATE_LIMIT")
                .unwrap_or_else(|_| "2".to_string())
                .parse::<u32>()
                .map_err(|_| {
                    OxideScannerError::config("Invalid OXIDE_EXPLOIT_QUERIES_RATE_LIMIT value")
                })?,
            Duration::from_secs(1),
        );

        let logging = LogConfig::from_env()?;
        let metrics = MetricsConfig::from_env()?;
        let retry = RetryConfig::from_env()?;

        Ok(Config {
            target: String::new(),
            json_mode: false,
            scan_mode: ScanMode::Tcp,
            port_limit: 1000,
            scan_timeout: Duration::from_millis(constants::DEFAULT_SCAN_TIMEOUT_MS),
            exploit_timeout: Duration::from_secs(constants::DEFAULT_EXPLOIT_TIMEOUT_SECS),
            threads,
            shutdown_timeout,
            enable_rate_limiting,
            scanner_rate_limit,
            external_tools_rate_limit,
            exploit_queries_rate_limit,
            logging,
            metrics,
            retry,
            nse_script: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_args_basic() {
        let args = vec![
            "oxidescanner".to_string(),
            "127.0.0.1".to_string(),
            "-5k".to_string(),
            "--json".to_string(),
        ];

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.target, "127.0.0.1");
        assert!(config.json_mode);
        assert_eq!(config.port_limit, 5000);
    }

    #[test]
    fn test_config_from_args_with_timeouts() {
        let args = vec![
            "oxidescanner".to_string(),
            "example.com".to_string(),
            "-5k".to_string(),
            "--scan-timeout".to_string(),
            "50".to_string(),
            "--exploit-timeout".to_string(),
            "15000".to_string(),
        ];

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.target, "example.com");
        assert_eq!(config.scan_timeout.as_millis(), 50);
        assert_eq!(config.exploit_timeout.as_millis(), 15000);
    }

    #[test]
    fn test_config_invalid_target() {
        let args = vec!["oxidescanner".to_string(), String::new()];

        let result = Config::from_args(&args);
        assert!(result.is_err());
    }
}
