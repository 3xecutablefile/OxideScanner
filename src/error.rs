use std::io;

#[derive(Debug, thiserror::Error)]
pub enum OxideScannerError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("External tool error: {tool} failed with {message}")]
    ExternalTool { tool: String, message: String },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Parsing error: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Timeout error: operation timed out after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    #[error("Service detection failed: {0}")]
    ServiceDetection(String),


    #[error("Target resolution failed: {0}")]
    TargetResolution(String),
}

impl OxideScannerError {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn external_tool(tool: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ExternalTool {
            tool: tool.into(),
            message: message.into(),
        }
    }

    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    pub fn timeout(duration_ms: u64) -> Self {
        Self::Timeout { duration_ms }
    }

    pub fn service_detection(msg: impl Into<String>) -> Self {
        Self::ServiceDetection(msg.into())
    }


    pub fn target_resolution(msg: impl Into<String>) -> Self {
        Self::TargetResolution(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, OxideScannerError>;
