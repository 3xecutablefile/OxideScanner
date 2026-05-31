use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::external::{BaseTool, ExternalTool};
use crate::validation;
use roxmltree::Document;
use serde::Serialize;
use std::process::Output;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct NmapService {
    pub port: u16,
    pub service: String,
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NmapOsResult {
    pub name: String,
    pub accuracy: u8,
    pub osclass: Option<String>,
}

#[derive(Clone)]
pub struct NmapDetector {
    pub base_tool: BaseTool,
}

impl NmapDetector {
    pub fn new() -> Result<Self> {
        let base_tool = BaseTool::new("nmap")?;
        Ok(Self { base_tool })
    }

    pub async fn detect_services(
        &self,
        target: &str,
        ports: &[u16],
        timeout: Option<Duration>,
        is_udp: bool,
    ) -> Result<Vec<NmapService>> {
        let timeout = timeout.unwrap_or(Duration::from_secs(constants::NMAP_TIMEOUT_SECS));

        let validated_target = validation::validate_target(target)?;
        let port_list = self.format_port_list(ports)?;
        let validated_port_list = validation::validate_port_list(&port_list)?;

        let args = self.build_nmap_args(&validated_target, &validated_port_list, is_udp);
        let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = self.execute_with_timeout(&args_str, timeout).await?;

        self.parse_nmap_output(&output)
    }

    fn format_port_list(&self, ports: &[u16]) -> Result<String> {
        if ports.is_empty() {
            return Err(OxideScannerError::validation("Port list cannot be empty"));
        }

        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();

        Ok(port_strings.join(","))
    }

    fn build_nmap_args(&self, target: &str, port_list: &str, is_udp: bool) -> Vec<String> {
        let mut args = Vec::new();

        if is_udp {
            args.push("-sUV".to_string());
        } else {
            args.push("-sV".to_string());
        }

        args.push("--version-intensity".to_string());
        args.push(constants::NMAP_VERSION_INTENSITY.to_string());
        args.push("-p".to_string());
        args.push(port_list.to_string());
        args.push("-oX".to_string());
        args.push("-".to_string());
        args.push("--open".to_string());
        args.push("--disable-arp-ping".to_string());
        args.push("-Pn".to_string());
        args.push(target.to_string());

        args
    }

    fn parse_nmap_output(&self, output: &Output) -> Result<Vec<NmapService>> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OxideScannerError::external_tool(
                "nmap",
                format!("Command failed: {}", stderr),
            ));
        }

        let xml_content = String::from_utf8_lossy(&output.stdout);
        let xml_clean = self.clean_xml_content(&xml_content);

        self.parse_nmap_xml(&xml_clean)
    }

    fn clean_xml_content(&self, xml_content: &str) -> String {
        xml_content
            .lines()
            .filter(|line| !line.trim().starts_with("<!DOCTYPE"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn parse_nmap_xml(&self, xml_content: &str) -> Result<Vec<NmapService>> {
        let doc = Document::parse(xml_content)
            .map_err(|e| OxideScannerError::parse(format!("Failed to parse nmap XML: {}", e)))?;

        let root = doc.root_element();
        if root.tag_name().name() != "nmaprun" {
            return Err(OxideScannerError::parse(
                "Invalid nmap XML format".to_string(),
            ));
        }

        let mut services = Vec::new();

        for host in root.children() {
            if host.tag_name().name() != "host" {
                continue;
            }

            for ports_elem in host.children() {
                if ports_elem.tag_name().name() != "ports" {
                    continue;
                }

                for port_elem in ports_elem.children() {
                    if port_elem.tag_name().name() != "port" {
                        continue;
                    }

                    if let Some(service) = self.parse_port_element(&port_elem)? {
                        services.push(service);
                    }
                }
            }
        }

        services.sort_by_key(|s| s.port);
        Ok(services)
    }

    fn parse_port_element(&self, port_elem: &roxmltree::Node) -> Result<Option<NmapService>> {
        let port_id = port_elem
            .attribute("portid")
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|&p| p > 0);

        let port_id = match port_id {
            Some(p) => p,
            None => return Ok(None),
        };

        let mut service_name = "unknown".to_string();
        let mut product = String::new();
        let mut version = String::new();

        for service_elem in port_elem.children() {
            if service_elem.tag_name().name() != "service" {
                continue;
            }

            service_name = service_elem
                .attribute("name")
                .unwrap_or("unknown")
                .to_string();

            product = service_elem.attribute("product").unwrap_or("").to_string();

            version = service_elem.attribute("version").unwrap_or("").to_string();

            break;
        }

        Ok(Some(NmapService {
            port: port_id,
            service: service_name,
            product,
            version,
        }))
    }

    pub fn parse_os_xml(&self, xml_content: &str) -> Option<NmapOsResult> {
        let xml_clean: String = xml_content
            .lines()
            .filter(|line| !line.trim().starts_with("<!DOCTYPE"))
            .collect::<Vec<_>>()
            .join("\n");

        let doc = Document::parse(&xml_clean).ok()?;
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

                let osclass = osmatch
                    .children()
                    .find(|c| c.tag_name().name() == "osclass")
                    .and_then(|oc| {
                        let vendor = oc.attribute("vendor")?;
                        let family = oc.attribute("osfamily")?;
                        let gen = oc.attribute("osgen").unwrap_or("");
                        Some(format!("{} {} {}", vendor, family, gen).trim().to_string())
                    });

                return Some(NmapOsResult {
                    name,
                    accuracy,
                    osclass,
                });
            }
        }
        None
    }
}

impl ExternalTool for NmapDetector {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output> {
        self.base_tool.execute_command(args, timeout).await
    }

    fn name(&self) -> &str {
        "nmap"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_port_list() {
        let detector = NmapDetector::new().unwrap();
        let ports = vec![22, 80, 443];
        let result = detector.format_port_list(&ports).unwrap();
        assert_eq!(result, "22,80,443");
    }

    #[test]
    fn test_format_empty_port_list() {
        let detector = NmapDetector::new().unwrap();
        let ports = vec![];
        let result = detector.format_port_list(&ports);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_nmap_args_tcp() {
        let detector = NmapDetector::new().unwrap();
        let args = detector.build_nmap_args("127.0.0.1", "80,443", false);
        assert!(args.contains(&"-sV".to_string()));
        assert!(!args.contains(&"-sUV".to_string()));
    }

    #[test]
    fn test_build_nmap_args_udp() {
        let detector = NmapDetector::new().unwrap();
        let args = detector.build_nmap_args("127.0.0.1", "53,161", true);
        assert!(args.contains(&"-sUV".to_string()));
        assert!(!args.contains(&"-sV".to_string()));
    }
}
