use crate::config::Config;
use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::external::nmap::{NmapDetector, NmapService};
use crate::external::nmap_nse::{NseResult, NseRunner};
use crate::external::ExternalTool;
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
    pub protocol: String,
    pub service: String,
    pub product: String,
    pub version: String,
}

impl Port {
    pub fn new(port: u16) -> Self {
        Self { port, protocol: "tcp".to_string(), service: String::new(), product: String::new(), version: String::new() }
    }

    pub fn new_udp(port: u16) -> Self {
        Self { port, protocol: "udp".to_string(), service: String::new(), product: String::new(), version: String::new() }
    }

    pub fn with_service(port: u16, service: String, product: String, version: String) -> Self {
        Self { port, protocol: "tcp".to_string(), service, product, version }
    }

    pub fn with_service_udp(port: u16, service: String, product: String, version: String) -> Self {
        Self { port, protocol: "udp".to_string(), service, product, version }
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
        print_scan_summary(&results, "tcp");
    }

    Ok(results)
}

async fn tcp_connect_addrs(addrs: &[SocketAddr], port: u16, timeout: Duration) -> PortStatus {
    for base in addrs {
        let mut socket_addr = *base;
        socket_addr.set_port(port);

        match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
            Ok(Ok(_)) => return PortStatus::Open,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused
                       || e.kind() == std::io::ErrorKind::ConnectionReset => {
                return PortStatus::Closed;
            }
            _ => continue,
        }
    }
    PortStatus::Filtered
}

pub async fn detect_services(target: &str, ports: &[Port], is_udp: bool, _config: &Config) -> Result<Vec<Port>> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }

    let timeout = Duration::from_secs(constants::NMAP_TIMEOUT_SECS);
    let detector = NmapDetector::new().map_err(|e| {
        OxideScannerError::service_detection(format!("Failed to initialize nmap: {}", e))
    })?;

    let mut handles = Vec::new();
    for port in ports {
        let detector = detector.clone();
        let target = target.to_string();
        let port_num = port.port;
        handles.push(tokio::spawn(async move {
            detector
                .detect_services(&target, &[port_num], Some(timeout), is_udp)
                .await
        }));
    }

    let mut all_services: Vec<NmapService> = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(svcs)) => all_services.extend(svcs),
            Ok(Err(e)) => {
                eprintln!(
                    "  {} Service detection on port {} failed: {}",
                    "WARNING".yellow(),
                    ports[i].port,
                    e
                );
            }
            Err(e) => {
                eprintln!(
                    "  {} Service detection task for port {} panicked: {}",
                    "WARNING".yellow(),
                    ports[i].port,
                    e
                );
            }
        }
    }

    all_services.sort_by_key(|s| s.port);

    let mut detected_ports: Vec<Port> = all_services
        .into_iter()
        .map(|ns| {
            if is_udp {
                Port::with_service_udp(ns.port, ns.service, ns.product, ns.version)
            } else {
                Port::with_service(ns.port, ns.service, ns.product, ns.version)
            }
        })
        .collect();

    detected_ports.sort_by_key(|p| p.port);

    Ok(detected_ports)
}

fn print_scan_summary(results: &ScanResults, proto: &str) {
    let ports_label = if results.open.len() == 1 { "port" } else { "ports" };
    let filtered_label = if results.filtered.len() == 1 { "port" } else { "ports" };
    println!(
        "\n  {} open {} {}  {} filtered {}  {} closed",
        results.open.len().to_string().bright_green().bold(),
        proto,
        ports_label,
        results.filtered.len().to_string().bright_yellow().bold(),
        filtered_label,
        results.closed.to_string().dimmed(),
    );

    if !results.open.is_empty() {
        println!("\n  {}", "open".bright_green().bold());
        for port in &results.open {
            println!("    {}/{}", port.port.to_string().bright_cyan(), proto);
        }
    }

    if results.filtered.len() <= 10 {
        if !results.filtered.is_empty() {
            println!("\n  {}", "filtered".bright_yellow().bold());
            for port in &results.filtered {
                println!("    {}/{}", port.to_string().bright_yellow(), proto);
            }
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
        let proto = &port.protocol;
        let line = if !port.product.is_empty() {
            format!(
                "    {}/{}  {} {} {}",
                port.port.to_string().bright_cyan(),
                proto,
                port.service,
                port.product,
                port.version
            )
        } else {
            format!("    {}/{}  {}", port.port.to_string().bright_cyan(), proto, port.service)
        };
        println!("{}", line);
    }
    println!();
}

#[derive(Debug, Clone, Serialize)]
pub struct OsResult {
    pub name: String,
    pub distro: String,
    pub confidence: f32,
    pub source: String,
}

impl OsResult {
    pub fn distro_label(&self) -> String {
        if self.distro.is_empty() {
            self.name.clone()
        } else {
            format!("{}, {}", self.name, self.distro)
        }
    }
}

pub fn infer_os_from_services(services: &[Port]) -> Option<OsResult> {
    let os_keywords = [
        ("Ubuntu", "Linux", "Ubuntu"),
        ("Debian", "Linux", "Debian"),
        ("CentOS", "Linux", "CentOS"),
        ("Red Hat", "Linux", "RHEL"),
        ("FreeBSD", "FreeBSD", ""),
        ("Windows", "Windows", "Windows"),
        ("Microsoft", "Windows", "Windows"),
        ("macOS", "macOS", ""),
        ("Darwin", "macOS", ""),
        ("SUSE", "Linux", "SUSE"),
        ("Fedora", "Linux", "Fedora"),
        ("Arch", "Linux", "Arch"),
        ("Alpine", "Linux", "Alpine"),
    ];

    for service in services {
        let combined = format!("{} {} {}", service.service, service.product, service.version);
        for &(keyword, os_family, distro) in &os_keywords {
            if combined.contains(keyword) {
                return Some(OsResult {
                    name: os_family.to_string(),
                    distro: distro.to_string(),
                    confidence: 0.85,
                    source: "service_banner".to_string(),
                });
            }
        }
    }
    None
}

pub async fn detect_os(target: &str, services: &[Port], _config: &Config) -> Option<OsResult> {
    let banner_os = infer_os_from_services(services);

    let ports: Vec<u16> = services.iter().map(|p| p.port).collect();
    if ports.is_empty() {
        return banner_os;
    }

    let nmap_os = try_nmap_os_detection(target, &ports).await;

    nmap_os.or(banner_os)
}

async fn try_nmap_os_detection(target: &str, ports: &[u16]) -> Option<OsResult> {
    let detector = NmapDetector::new().ok()?;
    let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    let port_str = port_list.join(",");

    let args = vec![
        "-O".to_string(),
        "-sV".to_string(),
        "--version-intensity".to_string(),
        constants::NMAP_VERSION_INTENSITY.to_string(),
        "-p".to_string(),
        port_str,
        "-oX".to_string(),
        "-".to_string(),
        "--open".to_string(),
        "--disable-arp-ping".to_string(),
        "-Pn".to_string(),
        target.to_string(),
    ];

    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let timeout = Duration::from_secs(constants::NMAP_TIMEOUT_SECS);

    let output = detector.execute_with_timeout(&args_str, timeout).await.ok()?;

    if !output.status.success() {
        return None;
    }

    let xml_content = String::from_utf8_lossy(&output.stdout);
    let xml_clean: String = xml_content
        .lines()
        .filter(|line| !line.trim().starts_with("<!DOCTYPE"))
        .collect::<Vec<_>>()
        .join("\n");

    let doc = roxmltree::Document::parse(&xml_clean).ok()?;
    let root = doc.root_element();

    for host in root.children() {
        if host.tag_name().name() != "host" {
            continue;
        }
        for osmatch in host.children() {
            if osmatch.tag_name().name() != "osmatch" {
                continue;
            }
            let name = osmatch.attribute("name")?.to_string();
            let accuracy: u8 = osmatch.attribute("accuracy")?.parse().ok()?;

            let mut osclass_str = String::new();
            for osclass in osmatch.children() {
                if osclass.tag_name().name() == "osclass" {
                    let parts: Vec<&str> = [
                        osclass.attribute("vendor"),
                        osclass.attribute("osfamily"),
                        osclass.attribute("osgen"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();
                    osclass_str = parts.join(" ");
                    break;
                }
            }

            let (os_family, distro) = if osclass_str.contains("Windows") {
                ("Windows".to_string(), osclass_str)
            } else if osclass_str.contains("Linux") || osclass_str.contains("linux") {
                (name.clone(), String::new())
            } else {
                (name.clone(), String::new())
            };

            return Some(OsResult {
                name: os_family,
                distro,
                confidence: accuracy as f32 / 100.0,
                source: "nmap_os_detection".to_string(),
            });
        }
    }
    None
}

pub async fn udp_fast_scan(target_addrs: &[SocketAddr], config: &Config) -> Result<ScanResults> {
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
            (port, udp_connect_addrs(&addrs, port, timeout).await)
        }));
    }

    let mut open = Vec::new();
    let mut filtered = Vec::new();
    let mut closed = 0usize;

    for handle in handles {
        let (port, status) = handle.await.unwrap_or((0, PortStatus::Filtered));
        scanned.fetch_add(1, Ordering::Relaxed);
        match status {
            PortStatus::Open => open.push(Port::new_udp(port)),
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
        print_scan_summary(&results, "udp");
    }

    Ok(results)
}

async fn udp_connect_addrs(addrs: &[SocketAddr], port: u16, timeout: Duration) -> PortStatus {
    for base in addrs {
        let mut socket_addr = *base;
        socket_addr.set_port(port);

        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => continue,
        };

        if socket.connect(socket_addr).await.is_err() {
            continue;
        }

        if socket.send(&[0x00]).await.is_err() {
            continue;
        }

        let mut buf = [0u8; 1024];
        match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
            Ok(Ok(_)) => return PortStatus::Open,
            _ => continue,
        }
    }
    PortStatus::Filtered
}



pub async fn run_nse_scripts(
    target: &str,
    ports: &[Port],
    script_category: &str,
    _config: &Config,
) -> Vec<NseResult> {
    let runner = match NseRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} NSE runner init failed: {}", "WARNING".yellow(), e);
            return Vec::new();
        }
    };

    let port_numbers: Vec<u16> = ports.iter().map(|p| p.port).collect();
    let timeout = Duration::from_secs(constants::NMAP_TIMEOUT_SECS * 2);

    match runner.run_scripts(target, &port_numbers, script_category, timeout).await {
        Ok(results) => results,
        Err(e) => {
            eprintln!("{} NSE execution failed: {}", "WARNING".yellow(), e);
            Vec::new()
        }
    }
}

pub fn print_nse_results(results: &[NseResult]) {
    if results.is_empty() {
        return;
    }

    println!("  {}", "nse".bright_yellow().bold());
    for result in results {
        println!(
            "    {}/tcp  {}",
            result.port.to_string().bright_cyan(),
            result.script_id.bright_white()
        );
        for line in result.output.lines().take(5) {
            println!("      {}", line.dimmed());
        }
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
