use crate::error::{OxideScannerError, Result};

pub fn validate_target(target: &str) -> Result<String> {
    if target.is_empty() {
        return Err(OxideScannerError::validation("Target cannot be empty"));
    }

    if target.len() > crate::constants::validation::MAX_TARGET_LENGTH {
        return Err(OxideScannerError::validation("Target too long"));
    }

    if target.contains(' ') || target.contains('\t') || target.contains('\n') {
        return Err(OxideScannerError::validation("Target contains invalid characters"));
    }

    Ok(target.to_string())
}

pub fn validate_port_limit(limit: u16) -> Result<u16> {
    if limit == 0 {
        return Err(OxideScannerError::validation("Port limit must be greater than 0"));
    }

    if limit > crate::constants::ports::MAX {
        return Err(OxideScannerError::validation("Port limit exceeds maximum"));
    }

    Ok(limit)
}

pub fn validate_port_list(port_list: &str) -> Result<String> {
    if port_list.is_empty() {
        return Err(OxideScannerError::validation("Port list cannot be empty"));
    }

    for part in port_list.split(',') {
        let part = part.trim();
        
        if part.is_empty() {
            return Err(OxideScannerError::validation("Invalid port format"));
        }

        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(OxideScannerError::validation("Invalid port range format"));
            }

            let start: u16 = range_parts[0]
                .parse()
                .map_err(|_| OxideScannerError::validation("Invalid start port"))?;
            let end: u16 = range_parts[1]
                .parse()
                .map_err(|_| OxideScannerError::validation("Invalid end port"))?;

            if start > end {
                return Err(OxideScannerError::validation("Start port cannot be greater than end port"));
            }
        } else {
            let _: u16 = part
                .parse()
                .map_err(|_| OxideScannerError::validation("Invalid port number"))?;
        }
    }

    Ok(port_list.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_target() {
        assert!(validate_target("127.0.0.1").is_ok());
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("").is_err());
        assert!(validate_target("invalid..hostname").is_ok());
    }

    #[test]
    fn test_validate_port_limit() {
        assert!(validate_port_limit(1000).is_ok());
        assert!(validate_port_limit(65535).is_ok());
        assert!(validate_port_limit(0).is_err());
        assert!(validate_port_limit(u16::MAX).is_ok());
    }

    #[test]
    fn test_validate_port_list() {
        assert!(validate_port_list("80,443,8080").is_ok());
        assert!(validate_port_list("1-1000").is_ok());
        assert!(validate_port_list("").is_err());
        assert!(validate_port_list("80,443,").is_err());
        assert!(validate_port_list("invalid").is_err());
    }
}
