
use crate::error::{OxideScannerError, Result};
use crate::external::{BaseTool, ExternalTool};
use serde::{Deserialize, Serialize};
use std::process::Output;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct Exploit {
    pub title: String,
    pub url: String,
    pub cvss: Option<f32>,
    pub path: String,
}

#[derive(Debug)]
pub struct ExploitSearcher {
    base_tool: BaseTool,
}

#[derive(Debug, Deserialize)]
struct SearchsploitExploit {
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "EDB-ID")]
    edb_id: String,
    #[serde(rename = "Path")]
    path: String,
}

#[derive(Debug, Deserialize)]
struct SearchsploitResponse {
    #[serde(rename = "RESULTS_EXPLOIT")]
    results_exploit: Vec<SearchsploitExploit>,
}

impl ExploitSearcher {
    pub fn new() -> Result<Self> {
        let base_tool = BaseTool::new("searchsploit")?;
        Ok(ExploitSearcher { base_tool })
    }

    pub async fn search_with_strategy(
        &self,
        query: &str,
        timeout: Duration,
    ) -> Result<Vec<Exploit>> {
        let args = vec!["--json", "--id", query];
        let output = self.execute_with_timeout(&args, timeout).await?;
        
        match self.parse_searchsploit_output(&output) {
            Ok(exploits) => Ok(exploits),
            Err(e) => Err(e),
        }
    }

    fn parse_searchsploit_output(&self, output: &Output) -> Result<Vec<Exploit>> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OxideScannerError::external_tool(
                "searchsploit",
                format!("Command failed: {}", stderr),
            ));
        }

        let text = String::from_utf8_lossy(&output.stdout);

        match self.parse_json_output(&text) {
            Ok(exploits) => Ok(exploits),
            Err(_) => {
                self.parse_text_output(&text)
            }
        }
    }

    fn parse_json_output(&self, text: &str) -> Result<Vec<Exploit>> {
        let response: SearchsploitResponse = serde_json::from_str(text)
            .map_err(|e| OxideScannerError::external_tool("searchsploit", format!("JSON parsing failed: {}", e)))?;

        let mut exploits = Vec::new();

        for exploit_data in response.results_exploit {
            let cvss_score = self.extract_cvss(&exploit_data.title);
            let url = format!("https://www.exploit-db.com/exploits/{}", exploit_data.edb_id);

            let exploit = Exploit {
                title: exploit_data.title,
                url,
                cvss: cvss_score,
                path: exploit_data.path,
            };

            exploits.push(exploit);
        }

        Ok(exploits)
    }

    fn parse_text_output(&self, text: &str) -> Result<Vec<Exploit>> {
        let mut exploits = Vec::new();

        for line in text.lines() {
            if self.should_skip_line(line) {
                continue;
            }

            if let Some(exploit) = self.parse_exploit_line(line)? {
                exploits.push(exploit);
            }
        }

        Ok(exploits)
    }

    fn should_skip_line(&self, line: &str) -> bool {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return true;
        }
        if !trimmed.contains("|") {
            return true;
        }

        false
    }

    fn parse_exploit_line(&self, line: &str) -> Result<Option<Exploit>> {
        let parts: Vec<&str> = line.split('|').collect();
        
        if parts.len() < 2 {
            return Ok(None);
        }

        let title = parts[0].trim();
        let path = parts[1].trim();

        if title.is_empty() || title.starts_with('#') {
            return Ok(None);
        }

        let cvss_score = self.extract_cvss(title);
        let url = format!("https://www.exploit-db.com/exploit {}", path);

        Ok(Some(Exploit {
            title: title.to_string(),
            url,
            cvss: cvss_score,
            path: path.to_string(),
        }))
    }

    fn extract_cvss(&self, title: &str) -> Option<f32> {
        let cvss_pattern = regex::Regex::new(r"(?i)cvss[:\s]*(\d+\.?\d*)").ok()?;
        cvss_pattern.captures(title)
            .and_then(|caps| caps.get(1))
            .and_then(|m| m.as_str().parse::<f32>().ok())
    }
}

impl ExternalTool for ExploitSearcher {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output> {
        self.base_tool.execute_command(args, timeout).await
    }

    fn name(&self) -> &str {
        "searchsploit"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cvss() {
        let searcher = ExploitSearcher::new().unwrap();

        assert_eq!(searcher.extract_cvss("Remote Code Execution"), None);
        assert_eq!(searcher.extract_cvss("SQL Injection"), None);
        assert_eq!(searcher.extract_cvss("Some random exploit"), None);
    }

    #[test]
    fn test_should_skip_line() {
        let searcher = ExploitSearcher::new().unwrap();

        assert!(searcher.should_skip_line("----"));
        assert!(!searcher.should_skip_line("Exploit Title | Path"));
        assert!(searcher.should_skip_line(""));
        assert!(searcher.should_skip_line("  # Comment"));
        assert!(!searcher.should_skip_line("Some exploit title | /path/to/exploit"));
    }

    #[test]
    fn test_parse_exploit_line() {
        let searcher = ExploitSearcher::new().unwrap();

        let line = "Test Exploit | /path/to/exploit.txt | Description";
        let result = searcher.parse_exploit_line(line).unwrap().unwrap();

        assert_eq!(result.title, "Test Exploit");
        assert_eq!(result.path, "/path/to/exploit.txt");
        assert_eq!(
            result.url,
            "https://www.exploit-db.com/exploit /path/to/exploit.txt"
        );
    }
}
