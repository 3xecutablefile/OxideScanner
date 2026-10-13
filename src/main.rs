mod config;
mod constants;
mod error;
mod exploit;
mod external;
mod hacktricks;
mod hacktricks_settings;
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
use external::nmap_nse::NseResult;
use serde::Serialize;
use std::env;
use std::io::IsTerminal;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        process::exit(0);
    }

    if matches!(args[1].as_str(), "--setup-hacktricks" | "--reset-hacktricks") {
        let result = if args.len() != 2 {
            Err(OxideScannerError::config(
                "Use --setup-hacktricks or --reset-hacktricks alone, without a target or scan flags",
            ))
        } else if args[1] == "--setup-hacktricks" {
            hacktricks_settings::setup()
        } else {
            hacktricks_settings::reset()
        };
        match result {
            Ok(()) => {
                if args[1] == "--reset-hacktricks" {
                    println!("HackTricks stored key removed; reference search disabled unless overridden by OXIDE_HACKTRICKS_API_KEY.");
                }
            }
            Err(error) => {
                eprintln!("{} {}", "ERROR".red().bold(), error);
                process::exit(1);
            }
        }
        return;
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
    eprintln!("  --no-scripts        Skip automatic NSE checks");
    eprintln!("  --script SELECTOR   Optional override (default: auto)");
    eprintln!("  Interactive NSE: yes/no; matching scripts are selected automatically");
    eprintln!("HackTricks References (optional; requires a Brave Search API key):");
    eprintln!("  oxscan --setup-hacktricks  Configure once using a hidden key prompt");
    eprintln!("  oxscan --reset-hacktricks  Remove the saved key and remember opt-out");
    eprintln!("  No configured key: reference search stays disabled; no Docker needed");
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
    eprintln!("  oxscan 127.0.0.1 --no-scripts       # Skip NSE checks");
}

async fn run(config: config::Config) -> Result<()> {
    crate::utils::check_dependencies()?;
    let target_addrs = utils::resolve_target(&config.target)?;
    let interactive = !config.json_mode
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal();
    let (api_key, settings_error) = match hacktricks_settings::load_for_scan(interactive) {
        Ok(key) => (key, None),
        Err(error) => {
            eprintln!("{} HackTricks references disabled: {}", "WARNING".yellow(), error);
            (None, Some(error.to_string()))
        }
    };

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
    let nse = collect_nse_results(&all_open, &config).await;
    if api_key.is_some() && !config.json_mode {
        println!("  {}  searching service references", "hacktricks".bright_cyan().bold());
    }
    let mut references = hacktricks::collect_references(
        &services, &nse.results, api_key.as_ref().map(hacktricks_settings::ApiKey::as_str),
    ).await;
    if let Some(error) = settings_error {
        references.status = "unavailable".to_string();
        references.errors.push(error);
    }

    let exploit_results = if services.is_empty() {
        Vec::new()
    } else {
        exploit::search_exploits(&services, &config).await?
    };
    output_results(&exploit_results, &services, &os_result, &nse, &references, &config)?;

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
struct NseReport {
    status: &'static str,
    selection: Option<String>,
    results: Vec<NseResult>,
    error: Option<String>,
}

impl NseReport {
    fn record_result(&mut self, protocol: &str, result: Result<Vec<NseResult>>) {
        match result {
            Ok(results) => {
                self.status = if self.error.is_some() { "partial" } else { "completed" };
                self.results.extend(results);
            }
            Err(error) => {
                self.status = if matches!(self.status, "completed" | "partial") {
                    "partial"
                } else {
                    "failed"
                };
                let message = format!("{}: {}", protocol, error);
                match &mut self.error {
                    Some(errors) => {
                        errors.push('\n');
                        errors.push_str(&message);
                    }
                    None => self.error = Some(message),
                }
            }
        }
    }
}

async fn collect_nse_results(ports: &[scanner::Port], config: &config::Config) -> NseReport {
    let mut report = NseReport {
        status: "disabled",
        selection: config.nse_script.clone(),
        results: Vec::new(),
        error: None,
    };
    let Some(selection) = config.nse_script.as_deref() else {
        return report;
    };
    if ports.is_empty() {
        report.status = "skipped_no_open_ports";
        return report;
    }
    if !config.json_mode {
        println!(
            "  {}  checking discovered services",
            "nse".bright_yellow().bold()
        );
    }
    // Separate passes preserve TCP findings if UDP requires unavailable privileges.
    for protocol in ["tcp", "udp"] {
        let protocol_ports: Vec<_> = ports.iter()
            .filter(|port| port.protocol == protocol).cloned().collect();
        if protocol_ports.is_empty() {
            continue;
        }
        let result = scanner::run_nse_scripts(
            &config.target, &protocol_ports, selection, config,
        ).await;
        report.record_result(protocol, result);
    }
    if let Some(error) = &report.error {
        eprintln!("{} NSE checks failed: {}", "WARNING".yellow(), error);
    }
    if !config.json_mode {
        if report.status == "completed" && report.results.is_empty() {
            println!("    No NSE script findings returned.\n");
        } else {
            scanner::print_nse_results(&report.results);
        }
    }
    report
}

#[derive(Serialize)]
struct OutputData<'a> {
    target: &'a str,
    services: &'a [scanner::Port],
    os: Option<&'a scanner::OsResult>,
    exploits: &'a [exploit::PortResult],
    nse: &'a NseReport,
    hacktricks: &'a hacktricks::HackTricksReport,
}

fn output_results(
    exploit_results: &[exploit::PortResult],
    services: &[scanner::Port],
    os_result: &Option<scanner::OsResult>,
    nse: &NseReport,
    references: &hacktricks::HackTricksReport,
    config: &config::Config,
) -> Result<()> {
    if config.json_mode {
        let data = OutputData {
            target: &config.target,
            services,
            os: os_result.as_ref(),
            exploits: exploit_results,
            nse,
            hacktricks: references,
        };
        let json_output = serde_json::to_string_pretty(&data)
            .map_err(|e| OxideScannerError::parse(format!("Failed to serialize JSON: {}", e)))?;
        println!("{}", json_output);
    } else {
        exploit::print_results(exploit_results, services);
        hacktricks::print_references(references);
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
            "--json".to_string(),
        ])
        .unwrap();

        print_scan_start(&config);
    }

    #[tokio::test]
    async fn test_nse_report_selection_and_json() {
        let mut config = config::Config::from_args(&[
            "oxscan".to_string(),
            "127.0.0.1".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        let report = collect_nse_results(&[], &config).await;
        assert_eq!(report.status, "skipped_no_open_ports");

        config.nse_script = None;
        let disabled = collect_nse_results(&[scanner::Port::new(80)], &config).await;
        assert_eq!(disabled.status, "disabled");

        let nse = NseReport {
            status: "completed",
            selection: Some(constants::DEFAULT_NSE_SCRIPTS.to_string()),
            results: vec![NseResult {
                host: Some("127.0.0.1".to_string()),
                scope: "port".to_string(),
                port: Some(53),
                protocol: Some("udp".to_string()),
                script_id: "dns-nsid".to_string(),
                output: "first\nsecond".to_string(),
            }],
            error: None,
        };
        let references = hacktricks::collect_references(&[], &nse.results, None).await;
        let output = OutputData {
            target: "127.0.0.1",
            services: &[],
            os: None,
            exploits: &[],
            nse: &nse,
            hacktricks: &references,
        };
        let json = serde_json::to_value(output).unwrap();
        assert_eq!(json["nse"]["status"], "completed");
        assert_eq!(json["nse"]["results"][0]["protocol"], "udp");
        assert_eq!(json["nse"]["results"][0]["output"], "first\nsecond");
        assert_eq!(json["hacktricks"]["status"], "disabled");
        assert_eq!(json["hacktricks"]["requests"], 0);
        assert_eq!(json["target"], "127.0.0.1");
        let empty = serde_json::to_value(OutputData {
            target: "127.0.0.1",
            services: &[],
            os: None,
            exploits: &[],
            nse: &report,
            hacktricks: &references,
        })
        .unwrap();
        assert_eq!(empty["services"], serde_json::json!([]));
        assert_eq!(empty["nse"]["status"], "skipped_no_open_ports");

        let mut partial = disabled;
        partial.record_result("tcp", Ok(nse.results.clone()));
        partial.record_result("udp", Err(OxideScannerError::external_tool(
            "nmap", "UDP scan requires privileges",
        )));
        assert_eq!(partial.status, "partial");
        assert_eq!(partial.results.len(), 1);
        assert!(partial.error.as_ref().unwrap().contains("UDP scan requires privileges"));

        let mut failed = report;
        failed.record_result("tcp", Err(OxideScannerError::timeout(60000)));
        failed.record_result("udp", Err(OxideScannerError::timeout(60000)));
        assert_eq!(failed.status, "failed");
        assert!(failed.error.as_ref().unwrap().contains("tcp:"));
        assert!(failed.error.as_ref().unwrap().contains("udp:"));
        failed.record_result("tcp", Ok(Vec::new()));
        assert_eq!(failed.status, "partial");
    }
}
