pub mod nmap;
pub mod searchsploit;

use crate::error::{OxideScannerError, Result};
use std::process::Output;
use std::time::Duration;

#[allow(async_fn_in_trait)]
pub trait ExternalTool {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output>;

    #[allow(dead_code)]
    fn name(&self) -> &str;
}

#[derive(Debug)]
pub struct BaseTool {
    pub name: &'static str,
    pub binary_path: String,
}

impl BaseTool {
    pub fn new(name: &'static str) -> Result<Self> {
        let binary_path = Self::find_binary(name)?;
        Ok(Self { name, binary_path })
    }

    fn find_binary(name: &str) -> Result<String> {
        use std::process::Command;

        let output = Command::new("which")
            .arg(name)
            .output()
            .map_err(|e| OxideScannerError::external_tool("which", e.to_string()))?;

        if !output.status.success() {
            return Err(OxideScannerError::external_tool(
                name,
                "Tool not found in PATH".to_string(),
            ));
        }

        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            return Err(OxideScannerError::external_tool(
                name,
                "Tool path is empty".to_string(),
            ));
        }

        Ok(path)
    }

    pub async fn execute_command(
        &self,
        args: &[&str],
        timeout_duration: Duration,
    ) -> Result<Output> {
        use tokio::process::Command;
        use tokio::time::timeout as tokio_timeout;

        let mut cmd = Command::new(&self.binary_path);
        cmd.args(args);

        let output = tokio_timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| OxideScannerError::timeout(timeout_duration.as_millis() as u64))?;

        let output =
            output.map_err(|e| OxideScannerError::external_tool(self.name, e.to_string()))?;

        Ok(output)
    }
}

impl ExternalTool for BaseTool {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output> {
        self.execute_command(args, timeout).await
    }

    fn name(&self) -> &str {
        self.name
    }
}
