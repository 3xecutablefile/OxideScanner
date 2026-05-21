use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::validation;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::Command;

pub fn check_dependencies() -> Result<()> {
    let required_tools = vec![
        ("searchsploit", "Exploit database search tool"),
        ("nmap", "Network scanning and service detection"),
    ];

    let mut missing = Vec::new();

    for (tool, description) in required_tools {
        if !check_binary_in_path(tool) {
            missing.push(format!("{} ({})", tool, description));
        }
    }

    if !missing.is_empty() {
        return Err(OxideScannerError::external_tool(
            "dependency_check",
            format!(
                "Missing required tools:\n  {}\n\nInstall with:\n  sudo apt install nmap  # Debian/Ubuntu\n  sudo pacman -S nmap  # Arch\n  brew install nmap  # macOS\n\n  # Install searchsploit from exploit-db:\n  git clone https://github.com/offensive-security/exploitdb.git\n  sudo cp exploitdb/searchsploit /usr/local/bin/\n  sudo cp -r exploitdb/exploits /opt/",
                missing.join("\n  ")
            )
        ));
    }

    Ok(())
}

pub fn check_binary_in_path(bin: &str) -> bool {
    match Command::new("which").arg(bin).output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

pub fn resolve_target(target: &str) -> Result<Vec<SocketAddr>> {
    let validated_target = validation::validate_target(target)?;

    let base = format!("{}:0", validated_target);
    match base.to_socket_addrs() {
        Ok(iter) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if addrs.is_empty() {
                Err(OxideScannerError::target_resolution(format!(
                    "could not resolve target: {}",
                    target
                )))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => Err(OxideScannerError::target_resolution(format!(
            "resolve error: {}",
            e
        ))),
    }
}

pub fn get_port_list(limit: u16) -> Vec<u16> {
    let validated_limit = validation::validate_port_limit(limit).unwrap_or(limit);

    if validated_limit == constants::ports::MAX {
        (constants::ports::MIN..=constants::ports::MAX).collect()
    } else {
        (constants::ports::MIN..=validated_limit).collect()
    }
}

pub fn progress_bar(percent: usize, width: usize) -> String {
    let filled = (percent * width) / 100;
    let mut bar = String::with_capacity(width);

    for i in 0..width {
        if i < filled {
            bar.push('█');
        } else {
            bar.push('░');
        }
    }

    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar() {
        let bar = progress_bar(50, 40);
        let filled_count = bar.chars().filter(|&c| c == '█').count();
        let empty_count = bar.chars().filter(|&c| c == '░').count();
        assert_eq!(filled_count, 20);
        assert_eq!(empty_count, 20);
        assert_eq!(filled_count + empty_count, 40);
    }
}
