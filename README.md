# OxideScanner

A rust-based scanner with built in exploit searching.

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)]()


### Important
**Only scan systems you own or have explicit permission to test.**

## Quick Start

### Installation
```bash
git clone https://github.com/3xecutablefile/OxideScanner.git
cd OxideScanner
./install.sh
```

### Basic Usage

Run `oxscan <target>` for interactive prompts. For NSE, answer only **yes or no**; matching scripts are selected automatically.

Common options

| Option | Description | Example |
|--------|-------------|---------|
| `-Nk` | Scan N×1000 ports | `-1k` = 1000, `-5k` = 5000 |
| `-N` | Scan N ports | `-1000` = exactly 1000 ports |
| `--ports N` | Scan port count | `--ports 1000` |
| `--udp` | UDP scan mode | `--udp` |
| `--both` | TCP + UDP scan | `--both` |
| `--no-scripts` | Skip automatic NSE checks | `--no-scripts` |
| `--script SELECTOR` | Optional manual override; no selection required | `--script auto` |
| `--json` | JSON output | `--json` |
| `--threads N` | Worker threads | `--threads 8` |
| `--scan-timeout MS` | Connection timeout | `--scan-timeout 50` |
| `--exploit-timeout MS` | Exploit search timeout | `--exploit-timeout 5000` |

Command Syntax
```bash
oxscan <target> [options]
```

### Automatic NSE Checks

NSE is Nmap's Lua scripting engine. OxideScanner first discovers open ports and uses Nmap service probes to identify the service, product, and version. When NSE is enabled, it runs a service-detection/script pass against the discovered TCP and UDP ports. Nmap's own host and service rules decide which checks apply, including services on nonstandard ports.

- **Interactive:** one `Run automatic NSE checks?` confirmation, default **yes**. There is no category menu.
- **Noninteractive or `--json`:** checks run automatically. Use `--no-scripts` to skip them.
- **Automatic selection:** `safe and (default or vuln)` selects Nmap's safe-tagged default and vulnerability checks. The installed Nmap script database determines the available checks; this is not every NSE script or comprehensive vulnerability coverage.
- **Existing overrides:** `--script <selector>` remains supported; `--script auto` uses the automatic selection. Combining `--script` with `--no-scripts` is an error.
- **Timing:** each script has a 30-second limit; each protocol's NSE subprocess has a 60-second limit. Process failures and overall timeouts are included in the report. An individual script can time out or return no output while Nmap itself completes, so an empty result is not proof that every check passed.
- **UDP:** the NSE pass uses Nmap's UDP scan mode, which requires appropriate OS privileges. TCP and UDP run in separate passes so a UDP failure does not discard TCP findings.

Console output retains full script text. JSON includes an `nse` object with `status`, `selection`, `results`, and `error`. Status is `disabled`, `skipped_no_open_ports`, `completed`, `partial`, or `failed`; partial reports retain results from the successful protocol. Each result includes its host, scope (`port`, `host`, `pre`, or `post`), optional port/protocol, script ID, and output. Reports are emitted even when no open ports or services are found.

```bash
oxscan 127.0.0.1                         # Interactive yes/no NSE choice
oxscan 127.0.0.1 --json                  # Automatic NSE, machine-readable findings
oxscan 127.0.0.1 --json --no-scripts     # Skip NSE
```

NSE output provides evidence from checks; Searchsploit results are product/version matches that still need verification. Details on script selection: [Nmap NSE usage](https://nmap.org/book/nse-usage.html).

### Optional HackTricks Reference Search

OxideScanner can search HackTricks automatically after service detection and NSE. It returns related articles, short search snippets, and suggested follow-up checks in both terminal and JSON reports. References are guidance and do not change exploit risk scores.

**This uses a Brave Search API key**, available from the [Brave Search API dashboard](https://api-dashboard.search.brave.com/). HackTricks itself does not require a search API key. Requests use Brave's Web Search endpoint and accept only HTTPS links on `hacktricks.wiki`, `book.hacktricks.wiki`, or `cloud.hacktricks.wiki`.

Configure it once:

```bash
oxscan --setup-hacktricks
```

The terminal asks whether to enable references, then accepts the key through a hidden input. Enter a blank key or answer no to keep the feature disabled. Ordinary interactive scans also offer this setup once if no previous choice exists. The choice is remembered; subsequent scans reuse the saved key without prompting. API authentication is checked when a search request is made, not during setup.

- **No configured key:** no reference searches or guidance are activated. JSON records `hacktricks.status` as `disabled`.
- **JSON/noninteractive runs:** never prompt for a key. Use a saved credential or `OXIDE_HACKTRICKS_API_KEY`.
- **Linux/macOS storage:** `$XDG_CONFIG_HOME/oxidescanner/hacktricks.json` when XDG_CONFIG_HOME is absolute, otherwise `$HOME/.config/oxidescanner/hacktricks.json`. The key is stored as plaintext in an owner-only file (`0600`) inside a private directory (`0700`), using atomic replacement. Unsafe links, permissions, and permissive macOS ACLs are rejected. Credentials stay outside scan configuration and reports.
- **Environment override:** `OXIDE_HACKTRICKS_API_KEY` takes precedence and is never persisted. Setting it to an empty value disables references for that invocation, even if a key was saved.
- **Reset:** `oxscan --reset-hacktricks` removes the stored key and remembers opt-out. It can recover a safely owned settings file with corrupt JSON. An environment override still takes precedence.
- **Setup/reset require no target, Nmap, or Searchsploit.** Setup needs an interactive terminal; do not combine these commands with scan flags.

```bash
oxscan 127.0.0.1 --json                        # Uses the configured key, if any
OXIDE_HACKTRICKS_API_KEY= oxscan 127.0.0.1 --json # Disable references for this run
oxscan --reset-hacktricks                      # Remove the saved key
```

#### Matching And Request Limits

The service map covers HTTP(S), SSH, FTP, DNS, SMB, LDAP, MySQL, PostgreSQL, SQL Server, Redis, MongoDB, RDP, SNMP, SMTP, IMAP, POP3, NFS, VNC, MQTT, and AMQP. It matches service names rather than assuming a port identifies its protocol, so recognized services on nonstandard ports work too.

Recognized product names can refine a query. Explicit NSE observations about SMB signing, anonymous FTP, DNS recursion, and legacy TLS protocols receive priority. Negative/error output does not become a positive observation. Finding-specific guidance inspects at most 64 KiB per NSE result; the original NSE output remains available in the report.

Outbound queries contain canonical service/product names and fixed observation terms. Target IPs, hostnames, raw banners, raw NSE output, and version strings are not sent to Brave. Duplicate queries share a request while retaining all associated host/port/protocol contexts. An empty product-specific search can fall back to its general service query.

Each scan allows at most **8 requests**, including fallbacks; **3 accepted links per query**; **10 seconds per request**; and **30 seconds for the search stage**. Requests are spaced at least 1.05 seconds apart. Responses are limited to 1 MiB, redirects are rejected, and operator proxy environment settings are honored. Invalid credentials, exhausted quota, and network failures leave scan results intact.

Search results are reused within a run, not cached to disk. Persistent storage of Brave results requires a [plan granting storage rights](https://brave.com/search/api/). This implementation uses native Rust HTTPS: **no Docker, browser, Node.js, or local HackTricks installation**.

#### JSON Reference Reports

The report includes the requested `target` and a separate `hacktricks` object:

- `status`: `disabled`, `skipped_no_context`, `completed`, `no_results`, `partial`, `unavailable`, or `budget_exhausted`.
- `provider`, `checked_at`, `requests`, `skipped_queries`, and sanitized `errors`.
- `lookups`: query, source contexts, suggested `next_steps`, links/snippets, and per-query `status`/`error`. Per-query status distinguishes `completed`, `no_results`, `failed`, and `skipped`.

Dates indicate when a lookup was made, not when an article was published. Follow-up suggestions are authored by OxideScanner; returned article titles and snippets come from search results. Source material remains attributable through its article URL.

Implementation references: [HackTricks search source](https://github.com/HackTricks-wiki/hacktricks/blob/master/theme/ht_searcher.js), [HackTricks attribution guidance](https://hacktricks.wiki/en/welcome/hacktricks-values-and-faq.html), [Brave Web Search API](https://api-dashboard.search.brave.com/api-reference/web/search/get), and [Brave rate limits](https://api-dashboard.search.brave.com/documentation/guides/rate-limiting).

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

### Development Checks

```bash
cargo test --locked --all-targets -- --test-threads=1
cargo build --release --locked
python3 tests/cli_smoke.py
```

The unit tests include loopback HTTP fixtures, credential persistence checks, and NSE/XML regression cases. They do not need a Brave key, Nmap, or Searchsploit. The optional Python 3 smoke check exercises the release CLI and hidden prompts on Linux/macOS, using temporary settings and dummy external tools; its native probe touches only loopback TCP port 1. Environment-reading tests run serially because some older tests modify process-wide environment variables. `Cargo.lock` is tracked for reproducible dependency resolution. The release build and checks were verified with Rust 1.97.1 on macOS; use a current stable toolchain.



## Example

```bash
oxscan scanme.nmap.org
```
### Output:
```
  scanme.nmap.org  scanning top 1000 ports

  2 open tcp ports  1 filtered port  997 closed

  open
    22/tcp
    80/tcp

  filtered
    25/tcp

  svc
    22/tcp  ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
    80/tcp  http Apache httpd 2.4.7

  os
    Linux, Ubuntu  (85%)

  ◆ critical  80/tcp  http Apache httpd 2.4.7  17 exploits
    1. Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution 
       /opt/homebrew/opt/exploitdb/share/exploitdb/exploits/php/remote/29290.c
    ...
    17 exploits total
```

## Architecture


### Core Components

- **scanner** - High-performance parallel port scanning (TCP + UDP)
- **exploit** - Exploit database integration and risk scoring
- **external** - Nmap, NSE, and searchsploit tool abstractions
- **config** - CLI args + interactive prompts with arrow-key selection
- **validation** - Input validation and sanitization
- **utils** - Networking utilities and target resolution




## Changelog

### v1.0.2 (2026-05-31)
- Added UDP scan mode (`--udp`, `--both`)
- Added NSE script execution (`--script CATEGORY`)
- Interactive arrow-key prompts via inquire (no flags needed)
- Per-port concurrent service detection (one nmap per port, async)
- Automatic OS detection (banner inference + nmap -O fallback)
- Auto-lookup NSE categories in interactive menu
- Port range input support (e.g. `1-2300`)

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
