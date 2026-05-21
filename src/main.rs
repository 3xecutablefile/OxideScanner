mod config;
mod constants;
mod error;
mod exploit;
mod external;
mod logging;
mod metrics;
mod rate_limit;
mod retry;
mod scanner;
mod shutdown;
mod utils;
mod validation;

use colored::*;
use error::{OxideScannerError, Result};
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        process::exit(0);
    }

    let config = match config::Config::from_args(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{} {}", "ERROR".red().bold(), e);
            process::exit(1);
        }
    };

    if let Err(e) = run(config).await {
        eprintln!("{} {}", "✗".red().bold(), e);
        process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "{}",
        "usage: oxscan <target> [port-options] [--json] [--scan-timeout MS] [--exploit-timeout MS] [--threads N]"
            .red()
            .bold()
    );
    eprintln!("Port Options:");
    eprintln!("  -Nk                 Scan N*1000 ports (e.g., -1k=1000, -5k=5000, -30k=30000)");
    eprintln!("  -N                  Scan N ports directly (e.g., -1000, -5000)");
    eprintln!("  --ports N           Scan N ports (e.g., --ports 1000)");
    eprintln!("  (no flag)           Scan top 1000 ports (most common)");
    eprintln!("Other Options:");
    eprintln!("  --json              Output in JSON format");
    eprintln!("  --scan-timeout MS   TCP connection timeout in milliseconds (default: 1000)");
    eprintln!("  --exploit-timeout MS Exploit search timeout in milliseconds (default: 10000)");
    eprintln!("  --threads N         Max concurrent connections (default: 200)");
    eprintln!("Examples:");
    eprintln!("  oxscan 127.0.0.1                    # Scan top 1000 ports");
    eprintln!("  oxscan example.com -1k              # Scan top 1000 ports");
    eprintln!("  oxscan example.com -5k              # Scan top 5000 ports");
    eprintln!("  oxscan example.com -500             # Scan first 500 ports");
    eprintln!("  oxscan example.com --ports 1000     # Scan 1000 ports");
    eprintln!("  oxscan example.com -65535           # Scan all ports");
    eprintln!("  oxscan 192.168.1.1 --json          # Output in JSON format");
}

async fn run(config: config::Config) -> Result<()> {
    crate::utils::check_dependencies()?;
    let target_addrs = utils::resolve_target(&config.target)?;

    if !config.json_mode {
        print_scan_start(&config);
    }

    let results = scanner::fast_scan(&target_addrs, &config).await?;

    if results.open.is_empty() {
        if !config.json_mode {
            println!("{} No open ports found", "WARNING".yellow());
        }
        return Ok(());
    }

    let open_ports: Vec<scanner::Port> = results.open;
    let services = scanner::detect_services(&config.target, &open_ports, &config).await?;

    if !config.json_mode {
        scanner::print_service_detection_results(&services);
    }

    if services.is_empty() {
        if !config.json_mode {
            println!("{} No services detected", "WARNING".yellow());
        }
        return Ok(());
    }

    let results = exploit::search_exploits(&services, &config).await?;
    output_results(&results, &services, &config)?;

    Ok(())
}

fn print_scan_start(config: &config::Config) {
    println!(
        "  {}  scanning {} ports",
        config.target.bright_cyan().bold(),
        if config.port_limit == constants::ports::MAX {
            "all".to_string()
        } else {
            format!("top {}", config.port_limit)
        }
    );
}

fn output_results(
    exploit_results: &[exploit::PortResult],
    services: &[scanner::Port],
    config: &config::Config,
) -> Result<()> {
    if config.json_mode {
        let json_output = serde_json::to_string_pretty(exploit_results)
            .map_err(|e| OxideScannerError::parse(format!("Failed to serialize JSON: {}", e)))?;
        println!("{}", json_output);
    } else {
        exploit::print_results(exploit_results, services);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_usage_doesnt_panic() {
        print_usage();
    }

    #[test]
    fn test_print_scan_start() {
        let config = config::Config::from_args(&[
            "oxscan".to_string(),
            "127.0.0.1".to_string(),
            "-5k".to_string(),
        ])
        .unwrap();

        print_scan_start(&config);
    }
}
