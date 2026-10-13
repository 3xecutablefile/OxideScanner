use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::external::{BaseTool, ExternalTool};
use crate::validation;
use roxmltree::{Document, Node, ParsingOptions};
use serde::Serialize;
use std::net::IpAddr;
use std::process::Output;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct NseResult {
    pub host: Option<String>,
    pub scope: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
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
        tcp_ports: &[u16],
        udp_ports: &[u16],
        script_selection: &str,
        timeout: Duration,
    ) -> Result<Vec<NseResult>> {
        let args = Self::build_nmap_args(target, tcp_ports, udp_ports, script_selection)?;
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.execute_with_timeout(&args_str, timeout).await?;

        Self::parse_nse_output(&output)
    }

    fn build_nmap_args(
        target: &str,
        tcp_ports: &[u16],
        udp_ports: &[u16],
        script_selection: &str,
    ) -> Result<Vec<String>> {
        let validated_target = validation::validate_target(target)?;
        if validated_target.starts_with('-') || validated_target.chars().any(char::is_control) {
            return Err(OxideScannerError::validation(
                "NSE target cannot start with '-' or contain control characters",
            ));
        }
        if script_selection.trim().is_empty() || script_selection.contains('\0') {
            return Err(OxideScannerError::validation(
                "NSE script selection cannot be blank or contain NUL",
            ));
        }
        if tcp_ports.is_empty() && udp_ports.is_empty() {
            return Err(OxideScannerError::validation(
                "NSE requires at least one TCP or UDP port",
            ));
        }

        let mut args = Vec::new();
        let mut port_lists = Vec::new();
        for (flag, protocol, ports) in [("-sT", "T", tcp_ports), ("-sU", "U", udp_ports)] {
            if ports.is_empty() {
                continue;
            }
            if ports.contains(&0) {
                return Err(OxideScannerError::validation("NSE ports must be nonzero"));
            }
            let mut ports = ports.to_vec();
            ports.sort_unstable();
            ports.dedup();
            let port_list = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            port_lists.push(format!(
                "{}:{}",
                protocol,
                validation::validate_port_list(&port_list)?
            ));
            args.push(flag.to_string());
        }

        args.extend([
            "-sV".to_string(),
            "--version-intensity".to_string(),
            constants::NMAP_VERSION_INTENSITY.to_string(),
            "--script".to_string(),
            script_selection.to_string(),
            "--script-timeout".to_string(),
            format!("{}s", constants::NMAP_TIMEOUT_SECS),
            "-p".to_string(),
            port_lists.join(","),
            "-oX".to_string(),
            "-".to_string(),
            "--open".to_string(),
            "--disable-arp-ping".to_string(),
            "-Pn".to_string(),
            validated_target,
        ]);

        Ok(args)
    }

    fn parse_nse_output(output: &Output) -> Result<Vec<NseResult>> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OxideScannerError::external_tool(
                "nmap_nse",
                format!("Command failed ({}): {}", output.status, stderr),
            ));
        }

        let xml_content = std::str::from_utf8(&output.stdout)
            .map_err(|e| OxideScannerError::parse(format!("NSE XML is not UTF-8: {}", e)))?;
        Self::parse_nse_xml(xml_content)
    }

    fn parse_nse_xml(xml_content: &str) -> Result<Vec<NseResult>> {
        // Nmap emits a DOCTYPE; parse it without stripping lines from script output.
        let options = ParsingOptions {
            allow_dtd: true,
            ..ParsingOptions::default()
        };
        let doc = Document::parse_with_options(xml_content, options)
            .map_err(|e| OxideScannerError::parse(format!("Failed to parse NSE XML: {}", e)))?;

        let root = doc.root_element();
        if root.tag_name().name() != "nmaprun" {
            return Err(OxideScannerError::parse(
                "Invalid nmap XML format".to_string(),
            ));
        }

        let mut results = Vec::new();

        for script in root
            .descendants()
            .filter(|node| node.has_tag_name("script"))
        {
            let parent = script.parent().expect("Script element has a parent");
            let script_id = script.attribute("id").unwrap_or("unknown").to_string();
            let (scope, port, protocol) = match parent.tag_name().name() {
                "port" => {
                    let port_id = parent.attribute("portid").unwrap_or("");
                    let port = port_id
                        .parse::<u16>()
                        .ok()
                        .filter(|&p| p != 0 && port_id.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or_else(|| {
                            OxideScannerError::parse(format!(
                                "NSE script '{}': invalid or missing portid {:?}",
                                script_id, port_id
                            ))
                        })?;
                    let protocol = match parent.attribute("protocol") {
                        Some(protocol @ ("tcp" | "udp")) => protocol,
                        protocol => {
                            return Err(OxideScannerError::parse(format!(
                                "NSE script '{}' on port {}: invalid or missing protocol {:?}",
                                script_id, port, protocol
                            )));
                        }
                    };
                    ("port", Some(port), Some(protocol.to_string()))
                }
                "hostscript" => ("host", None, None),
                "prescript" => ("pre", None, None),
                "postscript" => ("post", None, None),
                _ => continue,
            };
            let host = script
                .ancestors()
                .find(|node| node.has_tag_name("host"))
                .and_then(|host| {
                    host.children()
                        .filter(|node| {
                            node.has_tag_name("address")
                                && matches!(node.attribute("addrtype"), Some("ipv4" | "ipv6"))
                        })
                        .find_map(|address| address.attribute("addr")?.parse::<IpAddr>().ok())
                })
                .map(|address| address.to_string());
            let mut output = script.attribute("output").unwrap_or("").to_string();
            if output.is_empty() {
                Self::render_script_structure(script, 0, &mut output);
            }
            results.push(NseResult {
                host,
                scope: scope.to_string(),
                port,
                protocol,
                script_id,
                output,
            });
        }

        Ok(results)
    }

    fn render_script_structure(node: Node<'_, '_>, depth: usize, output: &mut String) {
        for child in node
            .children()
            .filter(|child| child.has_tag_name("table") || child.has_tag_name("elem"))
        {
            output.push_str(&"  ".repeat(depth));
            if let Some(key) = child.attribute("key") {
                output.push_str(key);
                output.push(':');
            } else if child.has_tag_name("table") {
                output.push_str("[]");
            }
            if child.has_tag_name("table") {
                output.push('\n');
                Self::render_script_structure(child, depth + 1, output);
            } else {
                if child.attribute("key").is_some() {
                    output.push(' ');
                }
                for text in child.descendants().filter(Node::is_text) {
                    output.push_str(text.text().unwrap_or(""));
                }
                output.push('\n');
            }
        }
    }
}

impl ExternalTool for NseRunner {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output> {
        self.base_tool.execute_command(args, timeout).await
    }

    fn name(&self) -> &str {
        "nmap_nse"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_udp_and_mixed_args() {
        for (tcp, udp, scans, ports, selection) in [
            (
                vec![443, 80, 443],
                vec![],
                vec!["-sT"],
                "T:80,443",
                "safe and (default or vuln)",
            ),
            (
                vec![],
                vec![161, 53, 53],
                vec!["-sU"],
                "U:53,161",
                "dns-recursion,snmp-info",
            ),
            (
                vec![443, 53, 80, 80],
                vec![53, 53],
                vec!["-sT", "-sU"],
                "T:53,80,443,U:53",
                "safe and (default or vuln)",
            ),
        ] {
            let args = NseRunner::build_nmap_args("example.com", &tcp, &udp, selection).unwrap();
            let mut expected: Vec<String> = scans.into_iter().map(str::to_string).collect();
            expected.extend([
                "-sV".to_string(),
                "--version-intensity".to_string(),
                constants::NMAP_VERSION_INTENSITY.to_string(),
                "--script".to_string(),
                selection.to_string(),
                "--script-timeout".to_string(),
                format!("{}s", constants::NMAP_TIMEOUT_SECS),
                "-p".to_string(),
                ports.to_string(),
                "-oX".to_string(),
                "-".to_string(),
                "--open".to_string(),
                "--disable-arp-ping".to_string(),
                "-Pn".to_string(),
                "example.com".to_string(),
            ]);
            assert_eq!(args, expected);
        }
    }

    #[test]
    fn invalid_arguments() {
        for target in [
            "",
            "--script=all",
            "-iLtargets",
            "bad host",
            "bad\n",
            "bad\r",
            "bad\0",
        ] {
            assert!(NseRunner::build_nmap_args(target, &[80], &[], "safe").is_err());
        }
        assert!(NseRunner::build_nmap_args(&"a".repeat(254), &[80], &[], "safe").is_err());
        for selection in ["", " \t\r\n", "safe\0"] {
            assert!(NseRunner::build_nmap_args("localhost", &[80], &[], selection).is_err());
        }
        for (tcp, udp) in [(vec![], vec![]), (vec![0], vec![53]), (vec![80], vec![0])] {
            assert!(NseRunner::build_nmap_args("localhost", &tcp, &udp, "safe").is_err());
        }
    }

    #[test]
    fn all_script_scopes_and_output() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <prescript><script id="broadcast-listener" output="">
    <table key="discovery"><elem key="address">192.0.2.10</elem>
      <table><elem>alpha &amp; beta</elem><elem key="note">first&#10;second</elem></table>
    </table><elem key="empty"/>
  </script></prescript>
  <host><status state="up"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/>
        <script id="http-title" output="&#10;  &lt;Title&gt; &amp; &quot;quotes&quot; — café&#10;&#9;last line&#10;">
          <elem key="title">Do not replace the output attribute</elem>
        </script>
        <script id="http-headers" output="  No headers found.  "/>
      </port>
      <port protocol="udp" portid="53"><state state="open"/><service name="domain"/>
        <script id="dns-recursion" output="Recursion appears to be disabled"/>
      </port>
    </ports>
    <hostscript><script id="smb-os-discovery" output="Host details"/></hostscript>
  </host>
  <host><address addr="2001:db8::1" addrtype="ipv6"/>
    <ports><port protocol="tcp" portid="443"><script id="ssl-cert">
      <table key="subject"><elem key="commonName">example.org</elem></table>
    </script></port></ports>
  </host>
  <host><address addr="not-an-ip" addrtype="ipv4"/>
    <hostscript><script id="empty-script" output=""/></hostscript>
  </host>
  <postscript><script id="ssh-hostkey" output="No duplicates found"/></postscript>
  <runstats><finished exit="success"/></runstats>
</nmaprun>"#;
        let results = NseRunner::parse_nse_xml(xml).unwrap();
        let contexts: Vec<_> = results
            .iter()
            .map(|result| {
                (
                    result.host.as_deref(),
                    result.scope.as_str(),
                    result.port,
                    result.protocol.as_deref(),
                    result.script_id.as_str(),
                )
            })
            .collect();
        let ipv4 = Some("192.0.2.10");
        let ipv6 = Some("2001:db8::1");
        assert_eq!(
            contexts,
            vec![
                (None, "pre", None, None, "broadcast-listener"),
                (ipv4, "port", Some(80), Some("tcp"), "http-title"),
                (ipv4, "port", Some(80), Some("tcp"), "http-headers"),
                (ipv4, "port", Some(53), Some("udp"), "dns-recursion"),
                (ipv4, "host", None, None, "smb-os-discovery"),
                (ipv6, "port", Some(443), Some("tcp"), "ssl-cert"),
                (None, "host", None, None, "empty-script"),
                (None, "post", None, None, "ssh-hostkey"),
            ]
        );
        assert_eq!(results[0].output,
            "discovery:\n  address: 192.0.2.10\n  []\n    alpha & beta\n    note: first\nsecond\nempty: \n");
        assert_eq!(
            results[1].output,
            "\n  <Title> & \"quotes\" — café\n\tlast line\n"
        );
        assert_eq!(results[2].output, "  No headers found.  ");
        assert_eq!(results[3].output, "Recursion appears to be disabled");
        assert_eq!(results[4].output, "Host details");
        assert_eq!(results[5].output, "subject:\n  commonName: example.org\n");
        assert_eq!(results[6].output, "");
        assert_eq!(results[7].output, "No duplicates found");
    }

    #[test]
    fn malformed_xml_and_script_ports() {
        for xml in ["", "<nmaprun>", "<other/>", "<nmaprun>&unknown;</nmaprun>"] {
            assert!(matches!(
                NseRunner::parse_nse_xml(xml),
                Err(OxideScannerError::Parse(_))
            ));
        }
        for (attributes, expected) in [
            (r#"protocol="tcp""#, "portid"),
            (r#"portid="0" protocol="tcp""#, "portid"),
            (r#"portid="65536" protocol="tcp""#, "portid"),
            (r#"portid="oops" protocol="tcp""#, "portid"),
            (r#"portid="+80" protocol="tcp""#, "portid"),
            (r#"portid="80""#, "protocol"),
            (r#"portid="80" protocol="""#, "protocol"),
            (r#"portid="80" protocol="icmp""#, "protocol"),
        ] {
            let xml = format!(
                r#"<nmaprun><host><ports><port {}><script id="broken" output="keep"/></port></ports></host></nmaprun>"#,
                attributes
            );
            let error = NseRunner::parse_nse_xml(&xml).unwrap_err();
            assert!(matches!(error, OxideScannerError::Parse(_)));
            assert!(error.to_string().contains("broken"));
            assert!(error.to_string().contains(expected));
        }
        assert!(NseRunner::parse_nse_xml("<nmaprun/>").unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn command_failure_and_invalid_utf8_remain_errors() {
        use std::os::unix::process::ExitStatusExt;

        let mut output = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"<nmaprun/>".to_vec(),
            stderr: b"UDP scan requires privileges".to_vec(),
        };
        let error = NseRunner::parse_nse_output(&output).unwrap_err();
        assert!(matches!(error, OxideScannerError::ExternalTool { .. }));
        assert!(error.to_string().contains("UDP scan requires privileges"));
        output.status = std::process::ExitStatus::from_raw(0);
        assert!(NseRunner::parse_nse_output(&output).unwrap().is_empty());
        output.stdout = vec![0xff];
        assert!(matches!(
            NseRunner::parse_nse_output(&output),
            Err(OxideScannerError::Parse(_))
        ));
    }
}
