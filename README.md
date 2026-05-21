# OxideScanner

A rust-based scanner with built in exploit searching.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)]()


### Important
**Only scan systems you own or have explicit permission to test.**

## Quick Start

### Installation
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
./install.sh
```

### Basic Usage


Common options

| Option | Description | Example |
|--------|-------------|---------|
| `-Nk` | Scan N×1000 ports | `-1k` = 1000, `-5k` = 5000 |
| `-N` | Scan N ports | `-1000` = exactly 1000 ports |
| `--ports N` | Scan port count | `--ports 1000` |
| `--json` | JSON output | `--json` |
| `--threads N` | Worker threads | `--threads 8` |
| `--scan-timeout MS` | TCP timeout | `--scan-timeout 50` |

Command Syntax
```bash
oxscan <target> [options]
```

Configuration
```bash
export OXIDE_THREADS=8                    # Parallel scanning
export OXIDE_SCAN_TIMEOUT=50              # Connection timeout
export OXIDE_LOG_LEVEL=info               # Logging level
export OXIDE_ENABLE_RATE_LIMIT=true       # Enable rate limiting
```

## Installation Options

### Automated
```bash
git clone https://github.com/3xecutablefile/OxideScanner.git
cd OxideScanner
chmod +x install.sh
./install.sh
```

### Manual Build
```bash
# Prerequisites
sudo apt install nmap ruby git        
brew install nmap ruby git            

# Build from source
git clone https://github.com/3xecutablefile/OxideScanner.git
cd OxideScanner
cargo build --release
sudo cp target/release/oxscan /usr/local/bin/
```



## Example

```bash
oxscan scanme.nmap.org
```
### Output:
```
================================================================
Port 80 | http Apache httpd 2.4.7 | Risk: 136.5 | 17 exploits
----------------------------------------------------------------
   [9.8] Apache + PHP Remote Code Execution
    Path: php/remote/29290.c

   [8.1] Apache Memory Information Leak
    Path: linux/web-apps/42745.py
    ...
    15 more exploits available
================================================================

Summary:
  Total exploits: 17
  High-risk services: 1
  Services analyzed: 1
```

## Architecture


### Core Components

- **scanner** - High-performance parallel port scanning
- **exploit** - Exploit database integration and risk scoring
- **external** - Nmap and searchsploit tool abstractions
- **utils** - Networking utilities and target resolution




## Changelog

### v1.0.1 (2025-11-11)
- Fixed searchsploit JSON parsing with correct field mappings
- Added intelligent query filtering for targeted exploit search
- Improved performance by filtering generic service queries
- Enhanced documentation with comprehensive examples
- Cleaned codebase and removed unused dependencies

### v1.0.0
- Initial release with basic port scanning and exploit integration

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/3xecutablefile/OxideScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/3xecutablefile/OxideScanner/discussions)

## Author

**3xecutablefile**  
*random kid*

[![GitHub](https://img.shields.io/badge/GitHub-3xecutablefile-blue.svg)](https://github.com/3xecutablefile)

---

<div align="center">

**Fast Port Scanning with Smart Exploit Discovery**

[Star Repository](https://github.com/3xecutablefile/OxideScanner) • [Report Issues](https://github.com/3xecutablefile/OxideScanner/issues) • [Request Features](https://github.com/3xecutablefile/OxideScanner/discussions)

</div>
