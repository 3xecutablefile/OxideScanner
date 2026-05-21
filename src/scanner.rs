use crate::config::Config;
use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::external::nmap::NmapDetector;
use crate::utils;
use atty;
use colored::*;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub product: String,
    pub version: String,
}

impl Port {
    pub fn new(port: u16) -> Self {
        Self { port, service: String::new(), product: String::new(), version: String::new() }
    }

    pub fn with_service(port: u16, service: String, product: String, version: String) -> Self {
        Self { port, service, product, version }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Clone, Debug)]
pub struct ScanResults {
    pub open: Vec<Port>,
    pub filtered: Vec<u16>,
    pub closed: usize,
}

struct ProgressReporter {
    scanned: Arc<AtomicUsize>,
    total: usize,
    start_time: Instant,
    json_mode: bool,
}

impl ProgressReporter {
    fn new(total: usize, json_mode: bool) -> Self {
        Self {
            scanned: Arc::new(AtomicUsize::new(0)),
            total,
            start_time: Instant::now(),
            json_mode,
        }
    }

    fn scanned_counter(&self) -> Arc<AtomicUsize> {
        self.scanned.clone()
    }

    fn start_reporting(&self) -> Option<thread::JoinHandle<()>> {
        if self.json_mode || !atty::is(atty::Stream::Stdout) {
            return None;
        }

        let scanned = Arc::clone(&self.scanned);
        let total = self.total;
        let start_time = self.start_time;

        Some(thread::spawn(move || loop {
            let scanned = scanned.load(Ordering::Relaxed);
            let percent = if total > 0 { (scanned * 100) / total } else { 100 };
            let bar = utils::progress_bar(percent, constants::progress::DEFAULT_WIDTH);

            print!(
                "\r[{}] {:3}% | {}/{} scanned | {:.1}s",
                bar,
                percent,
                scanned,
                total,
                start_time.elapsed().as_secs_f32()
            );

            if let Err(e) = std::io::stdout().flush() {
                eprintln!("Failed to flush stdout: {}", e);
                break;
            }

            if scanned >= total {
                break;
            }
            thread::sleep(Duration::from_millis(constants::PROGRESS_UPDATE_INTERVAL_MS));
        }))
    }
}

pub async fn fast_scan(target_addrs: &[SocketAddr], config: &Config) -> Result<ScanResults> {
    let ports: Vec<u16> = utils::get_port_list(config.port_limit);
    let total = ports.len();

    if total == 0 {
        return Ok(ScanResults { open: Vec::new(), filtered: Vec::new(), closed: 0 });
    }

    let progress = ProgressReporter::new(total, config.json_mode);
    let progress_handle = progress.start_reporting();
    let scanned = progress.scanned_counter();

    let semaphore = Arc::new(Semaphore::new(config.threads));
    let addrs_arc = Arc::new(target_addrs.to_vec());
    let scan_timeout = config.scan_timeout;

    let mut handles = Vec::with_capacity(total);

    for &port in &ports {
        let sem = semaphore.clone();
        let addrs = addrs_arc.clone();
        let timeout = scan_timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            (port, tcp_connect_addrs(&addrs, port, timeout).await)
        }));
    }

    let mut open = Vec::new();
    let mut filtered = Vec::new();
    let mut closed = 0usize;

    for handle in handles {
        let (port, status) = handle.await.unwrap_or((0, PortStatus::Filtered));
        scanned.fetch_add(1, Ordering::Relaxed);
        match status {
            PortStatus::Open => open.push(Port::new(port)),
            PortStatus::Filtered => filtered.push(port),
            PortStatus::Closed => closed += 1,
        }
    }

    if let Some(handle) = progress_handle {
        if let Err(e) = handle.join() {
            eprintln!("Progress reporter thread panicked: {:?}", e);
        }
    }

    open.sort_by_key(|p| p.port);
    filtered.sort();

    let results = ScanResults { open, filtered, closed };

    if !config.json_mode {
        print_scan_summary(&results);
    }

    Ok(results)
}

async fn tcp_connect_addrs(addrs: &[SocketAddr], port: u16, timeout: Duration) -> PortStatus {
    for base in addrs {
        let mut socket_addr = *base;
        socket_addr.set_port(port);

        match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
            Ok(Ok(_)) => return PortStatus::Open,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return PortStatus::Closed;
            }
            _ => continue,
        }
    }
    PortStatus::Filtered
}

pub async fn detect_services(target: &str, ports: &[Port], _config: &Config) -> Result<Vec<Port>> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }

    let nmap_detector = NmapDetector::new().map_err(|e| {
        OxideScannerError::service_detection(format!("Failed to initialize nmap: {}", e))
    })?;

    let port_numbers: Vec<u16> = ports.iter().map(|p| p.port).collect();
    let timeout = Some(Duration::from_secs(constants::NMAP_TIMEOUT_SECS));

    let nmap_services = nmap_detector
        .detect_services(target, &port_numbers, timeout)
        .await
        .map_err(|e| {
            OxideScannerError::service_detection(format!("Service detection failed: {}", e))
        })?;

    let mut detected_ports: Vec<Port> = nmap_services
        .into_iter()
        .map(|ns| Port::with_service(ns.port, ns.service, ns.product, ns.version))
        .collect();

    detected_ports.sort_by_key(|p| p.port);

    Ok(detected_ports)
}

fn print_scan_summary(results: &ScanResults) {
    let open_s = if results.open.len() == 1 { "" } else { "s" };
    let filtered_s = if results.filtered.len() == 1 { "" } else { "s" };
    println!(
        "\n  {} open port{}  {} filtered port{}  {} closed",
        results.open.len().to_string().bright_green().bold(),
        open_s,
        results.filtered.len().to_string().bright_yellow().bold(),
        filtered_s,
        results.closed.to_string().dimmed(),
    );

    if !results.open.is_empty() {
        println!("\n  {}", "open".bright_green().bold());
        for port in &results.open {
            println!("    {}/tcp", port.port.to_string().bright_cyan());
        }
    }

    if !results.filtered.is_empty() {
        println!("\n  {}", "filtered".bright_yellow().bold());
        for port in &results.filtered {
            println!("    {}/tcp", port.to_string().bright_yellow());
        }
    }

    if !results.open.is_empty() {
        println!();
    }
}

pub fn print_service_detection_results(ports: &[Port]) {
    if ports.is_empty() {
        return;
    }

    println!("  {}", "svc".bright_cyan().bold());
    for port in ports {
        let line = if !port.product.is_empty() {
            format!(
                "    {}/tcp  {} {} {}",
                port.port.to_string().bright_cyan(),
                port.service,
                port.product,
                port.version
            )
        } else {
            format!("    {}/tcp  {}", port.port.to_string().bright_cyan(), port.service)
        };
        println!("{}", line);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_new() {
        let port = Port::new(80);
        assert_eq!(port.port, 80);
        assert!(port.service.is_empty());
        assert!(port.product.is_empty());
        assert!(port.version.is_empty());
    }

    #[test]
    fn test_port_with_service() {
        let port = Port::with_service(
            80,
            "http".to_string(),
            "Apache".to_string(),
            "2.4.41".to_string(),
        );
        assert_eq!(port.port, 80);
        assert_eq!(port.service, "http");
        assert_eq!(port.product, "Apache");
        assert_eq!(port.version, "2.4.41");
        assert!(!port.service.is_empty() || !port.product.is_empty());
    }

    #[test]
    fn test_progress_reporter() {
        let reporter = ProgressReporter::new(100, false);
        assert_eq!(reporter.total, 100);
        assert!(!reporter.json_mode);

        let counter = reporter.scanned_counter();
        counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(reporter.scanned.load(Ordering::Relaxed), 1);
    }
}
