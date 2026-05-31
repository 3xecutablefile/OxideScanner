use crate::error::{OxideScannerError, Result};
use crate::external::{BaseTool, ExternalTool};
use crate::validation;
use roxmltree::Document;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct NseResult {
    pub port: u16,
    pub script_id: String,
    pub output: String,
}

pub struct NseRunner {
    base_tool: BaseTool,
}

impl NseRunner {
    pub fn new() -> Result<Self> {
        let base_tool = BaseTool::new("nmap")?;
        Ok(Self { base_tool })
    }

    pub async fn run_scripts(
        &self,
        target: &str,
        ports: &[u16],
        script_category: &str,
        timeout: Duration,
    ) -> Result<Vec<NseResult>> {
        let validated_target = validation::validate_target(target)?;

        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let port_list = port_strings.join(",");

        let args = vec![
            "--script".to_string(),
            script_category.to_string(),
            "-sV".to_string(),
            "-p".to_string(),
            port_list,
            "-oX".to_string(),
            "-".to_string(),
            "--open".to_string(),
            "--disable-arp-ping".to_string(),
            "-Pn".to_string(),
            validated_target,
        ];

        let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self.execute_with_timeout(&args_str, timeout).await?;

        self.parse_nse_output(&output)
    }

    fn parse_nse_output(&self, output: &std::process::Output) -> Result<Vec<NseResult>> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OxideScannerError::external_tool(
                "nmap_nse",
                format!("Command failed: {}", stderr),
            ));
        }

        let xml_content = String::from_utf8_lossy(&output.stdout);
        let xml_clean: String = xml_content
            .lines()
            .filter(|line| !line.trim().starts_with("<!DOCTYPE"))
            .collect::<Vec<_>>()
            .join("\n");

        self.parse_nse_xml(&xml_clean)
    }

    fn parse_nse_xml(&self, xml_content: &str) -> Result<Vec<NseResult>> {
        let doc = Document::parse(xml_content)
            .map_err(|e| OxideScannerError::parse(format!("Failed to parse NSE XML: {}", e)))?;

        let root = doc.root_element();
        if root.tag_name().name() != "nmaprun" {
            return Err(OxideScannerError::parse("Invalid nmap XML format".to_string()));
        }

        let mut results = Vec::new();

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

                    let port_id = port_elem
                        .attribute("portid")
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(0);

                    for child in port_elem.children() {
                        if child.tag_name().name() != "script" {
                            continue;
                        }

                        let script_id = child.attribute("id").unwrap_or("unknown").to_string();
                        let script_output = child.attribute("output").unwrap_or("").to_string();

                        results.push(NseResult {
                            port: port_id,
                            script_id,
                            output: script_output,
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

impl ExternalTool for NseRunner {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<std::process::Output> {
        self.base_tool.execute_command(args, timeout).await
    }

    fn name(&self) -> &str {
        "nmap_nse"
    }
}
