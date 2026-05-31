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
use config::ScanMode;
use error::{OxideScannerError, Result};
use serde::Serialize;
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
    eprintln!("Scan Mode:");
    eprintln!("  (none)              TCP scan (default)");
    eprintln!("  --udp               UDP scan");
    eprintln!("  --both              TCP + UDP scan");
    eprintln!("Other Options:");
    eprintln!("  --json              Output in JSON format");
    eprintln!("  --scan-timeout MS   Connection timeout in milliseconds (default: 1000)");
    eprintln!("  --exploit-timeout MS Exploit search timeout in milliseconds (default: 10000)");
    eprintln!("  --threads N         Max concurrent connections (default: 200)");
    eprintln!("  --script CATEGORY   Run nmap NSE scripts (e.g., --script vuln)");
    eprintln!("Examples:");
    eprintln!("  oxscan 127.0.0.1                    # TCP scan top 1000 ports");
    eprintln!("  oxscan example.com -1k              # TCP scan top 1000 ports");
    eprintln!("  oxscan example.com -5k              # TCP scan top 5000 ports");
    eprintln!("  oxscan example.com -500             # Scan first 500 ports");
    eprintln!("  oxscan example.com --ports 1000     # Scan 1000 ports");
    eprintln!("  oxscan example.com -65535           # Scan all ports");
    eprintln!("  oxscan 192.168.1.1 --json          # Output in JSON format");
    eprintln!("  oxscan scanme.nmap.org --udp       # UDP scan");
    eprintln!("  oxscan scanme.nmap.org --both      # TCP + UDP scan");
    eprintln!("  oxscan scanme.nmap.org --script vuln  # Run NSE vulnerability scripts");
}

async fn run(config: config::Config) -> Result<()> {
    crate::utils::check_dependencies()?;
    let target_addrs = utils::resolve_target(&config.target)?;

    let (tcp_results, udp_results) = match config.scan_mode {
        ScanMode::Udp => {
            if !config.json_mode {
                println!("  {}  scanning top {} UDP ports", config.target.bright_cyan().bold(), 
                    if config.port_limit == constants::ports::MAX { "all".to_string() } else { format!("{}", config.port_limit) });
            }
            let results = scanner::udp_fast_scan(&target_addrs, &config).await?;
            (None, Some(results))
        }
        ScanMode::Both => {
            if !config.json_mode {
                println!("  {}  scanning top {} TCP ports", config.target.bright_cyan().bold(),
                    if config.port_limit == constants::ports::MAX { "all".to_string() } else { format!("{}", config.port_limit) });
            }
            let tcp = scanner::fast_scan(&target_addrs, &config).await?;
            if !config.json_mode {
                println!("  {}  scanning top {} UDP ports", config.target.bright_cyan().bold(),
                    if config.port_limit == constants::ports::MAX { "all".to_string() } else { format!("{}", config.port_limit) });
            }
            let udp = scanner::udp_fast_scan(&target_addrs, &config).await?;
            (Some(tcp), Some(udp))
        }
        ScanMode::Tcp => {
            if !config.json_mode {
                print_scan_start(&config);
            }
            let results = scanner::fast_scan(&target_addrs, &config).await?;
            (Some(results), None)
        }
    };

    let tcp_open: Vec<scanner::Port> = tcp_results.as_ref().map(|r| r.open.clone()).unwrap_or_default();
    let udp_open: Vec<scanner::Port> = udp_results.as_ref().map(|r| r.open.clone()).unwrap_or_default();

    if tcp_open.is_empty() && udp_open.is_empty() {
        if !config.json_mode {
            println!("{} No open ports found", "WARNING".yellow());
        }
        return Ok(());
    }

    let mut services = Vec::new();
    if !tcp_open.is_empty() {
        let svc = scanner::detect_services(&config.target, &tcp_open, false, &config).await?;
        services.extend(svc);
    }
    if !udp_open.is_empty() {
        let svc = scanner::detect_services(&config.target, &udp_open, true, &config).await?;
        services.extend(svc);
    }
    services.sort_by_key(|p| p.port);

    if !config.json_mode {
        scanner::print_service_detection_results(&services);
    }

    if services.is_empty() {
        if !config.json_mode {
            println!("{} No services detected", "WARNING".yellow());
        }
        return Ok(());
    }

    let os_result = scanner::detect_os(&config.target, &services, &config).await;
    if !config.json_mode {
        if let Some(ref os) = os_result {
            println!("  {}", "os".bright_magenta().bold());
            println!("    {}  ({}%)", os.distro_label(), (os.confidence * 100.0) as u8);
            println!();
        }
    }

    let all_open: Vec<scanner::Port> = tcp_open.into_iter().chain(udp_open).collect();
    if let Some(ref script) = config.nse_script {
        let nse_results = scanner::run_nse_scripts(&config.target, &all_open, script, &config).await;
        if !config.json_mode {
            scanner::print_nse_results(&nse_results);
        }
    }

    let exploit_results = exploit::search_exploits(&services, &config).await?;
    output_results(&exploit_results, &services, &os_result, &config)?;

    Ok(())
}

fn print_scan_start(config: &config::Config) {
    println!(
        "  {}  scanning top {} ports",
        config.target.bright_cyan().bold(),
        if config.port_limit == constants::ports::MAX {
            "all".to_string()
        } else {
            format!("{}", config.port_limit)
        }
    );
}

#[derive(Serialize)]
struct OutputData<'a> {
    services: &'a [scanner::Port],
    os: Option<&'a scanner::OsResult>,
    exploits: &'a [exploit::PortResult],
}

fn output_results(
    exploit_results: &[exploit::PortResult],
    services: &[scanner::Port],
    os_result: &Option<scanner::OsResult>,
    config: &config::Config,
) -> Result<()> {
    if config.json_mode {
        let data = OutputData {
            services,
            os: os_result.as_ref(),
            exploits: exploit_results,
        };
        let json_output = serde_json::to_string_pretty(&data)
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
