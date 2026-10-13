# OxideScanner Handoff

## Session And Scope

- Date: 2026-10-01. Starting commit: `f32a512`; working tree was clean.
- Initial request: read the codebase. Follow-up: identify useful revamps and make NSE automatic to reduce manual pentesting work.
- Read all Rust modules, README, manifest, installer, and ignore rules (external/support modules reviewed with delegated readers).
- Clarification: interactive NSE must be a yes/no decision, not a category or script selection. Subsequent request: explain what else the tool needs after completing this work.
- Completed: automatic NSE selection, yes/no prompt, correct TCP/UDP handling, complete console/JSON NSE results, documentation, and regression checks.
- Current request: implement optional, one-time API key setup and automatic live HackTricks reference search, test, commit, and push. Implementation and checks are complete; publication is authorized. Check Git history/status for the resulting commit and remote state. Using Brave Search as the documented key-backed provider; HackTricks' public search itself is keyless. No Docker/browser runtime. Earlier screenshot text removal remains blocked on its separate UI source path.
- Before publication, incorporated upstream `a5b41b2` (README clone URL correction) with a fast-forward; the feature changes are based on that commit.

## Completed HackTricks Integration

- `src/hacktricks_settings.rs`: standalone `--setup-hacktricks` / `--reset-hacktricks`, first-scan optional consent, hidden key entry, remembered opt-out, and reuse. `OXIDE_HACKTRICKS_API_KEY` overrides storage without persisting; a blank environment value explicitly disables references. JSON/non-TTY scans never prompt.
- Per-user path: absolute `$XDG_CONFIG_HOME/oxidescanner/hacktricks.json`, otherwise `$HOME/.config/oxidescanner/hacktricks.json`. Versioned settings use `api_key: null` for opt-out. Credentials are plaintext in private 0700/0600 storage. Descriptor-relative libc operations protect writes; links/unsafe ownership/permissions are rejected. macOS ACL checks reject extended entries on private storage and unsafe write grants on ancestors. Reset can replace corrupt payloads after filesystem safety checks.
- `src/hacktricks.rs`: native reqwest/Rustls GETs to `https://api.search.brave.com/res/v1/web/search`, with a sensitive `X-Subscription-Token` header and no redirects. Operator proxy environment settings are honored. Canonical service/product terms and known NSE observations produce `site:hacktricks.wiki` queries. No raw versions, banners, target addresses, hostnames, or arbitrary NSE text is sent.
- Covers 20 service families, with special positive-evidence rules for SMB signing, anonymous FTP, DNS recursion, and legacy TLS. Known script evidence over 64 KiB is omitted from special matching while original NSE output remains available. Query deduplication preserves all source contexts; empty product-specific queries fall back to a general service query within the same budget.
- Limits: 8 HTTP attempts, 10 s/request, 30 s/search stage, 1.05 s minimum spacing, 1 MiB/response, 3 accepted result links/query. Exact HTTPS hostname allowlist: `hacktricks.wiki`, `book.hacktricks.wiki`, `cloud.hacktricks.wiki`. Remote terminal controls are removed and credential echoes are rejected, including in successful responses.
- Main JSON now includes requested `target` and `hacktricks: {status, provider, checked_at, requests, skipped_queries, lookups, errors}`. Each lookup preserves status/error, source contexts, original scanner-authored next-step suggestions, and attributed result links/snippets. Disabled/missing credentials produce no requests or reference guidance. Settings errors become `unavailable`, not an intentional opt-out. References never contribute to exploit risk scores.
- Stage statuses: disabled, skipped_no_context, completed, no_results, partial, unavailable, budget_exhausted. Per-query statuses: completed, no_results, failed, skipped. No persistent search cache; Brave storage rights depend on subscription. Only per-run query reuse is implemented.
- Added direct reqwest (Rustls, JSON) and Unix libc dependencies. `Cargo.lock` is now tracked. Existing Nmap argument and Searchsploit parser helpers are static/pure so unit tests no longer require installed external tools.
- `tests/cli_smoke.py`: stdlib Python smoke check for release CLI, temporary settings, fake keys and dummy tools. Checks hidden setup, reuse, opt-out, JSON/non-TTY behavior, permissions, env override, reset and corrupt-file recovery. No Brave calls; native scan probe is limited to localhost TCP port 1.

### Research Sources

- HackTricks public search implementation: https://github.com/HackTricks-wiki/hacktricks/blob/master/theme/ht_searcher.js
- Attribution/usage: https://hacktricks.wiki/en/welcome/hacktricks-values-and-faq.html
- Brave endpoint, fields and authentication: https://api-dashboard.search.brave.com/api-reference/web/search/get
- Search operators: https://api-dashboard.search.brave.com/documentation/resources/search-operators
- Rate limits: https://api-dashboard.search.brave.com/documentation/guides/rate-limiting
- Storage rights: https://brave.com/search/api/
- Reviewed HackTricks SMB, web, SSH, DNS and FTP guides plus Nmap `smb2-security-mode` and `ftp-anon` output documentation. The official public index is keyless; the API credential is explicitly labelled as Brave's, not a fictitious HackTricks key.

## Completed Automatic NSE Changes

- `constants.rs`: automatic selection is `safe and (default or vuln)`; NSE's own service/host rules choose applicable scripts.
- `config.rs`: interactive `Run automatic NSE checks?` confirmation, default yes. Noninteractive/JSON defaults to automatic checks. `--no-scripts` disables them; existing `--script` overrides remain optional, with `auto` as an alias. Conflicting, blank, or missing script arguments fail validation.
- `external/nmap_nse.rs`: protocol-qualified port lists, deduplication, explicit TCP/UDP flags, light service detection, 30-second per-script limit, argument validation, and pure parser/argument helpers. Parses port, host, pre-, and post-scan script output; preserves host/protocol attribution and full output, with a readable fallback for structured-only results. Malformed XML/ports/protocols and failed commands remain errors.
- `scanner.rs`: NSE returns `Result<Vec<NseResult>>`; console displays correct protocols and all output lines. `exploit.rs` also prints the actual protocol.
- `main.rs`: separate TCP/UDP NSE passes preserve successful findings if another protocol fails (notably UDP privilege errors). JSON adds `nse: {status, selection, results, error}`. Status is `disabled`, `skipped_no_open_ports`, `completed`, `partial`, or `failed`. No-open-port/no-service scans now still produce JSON. A stage's completed status refers to the Nmap process, not proof that every script ran or passed.
- `external/mod.rs`: `kill_on_drop(true)` terminates the direct child when its execution future times out. Each protocol's NSE pass retains the existing 60-second overall timeout.
- `README.md` and CLI help describe automatic selection and opt-out behavior. No new dependencies.
- Public API changes: `NseRunner::run_scripts` now accepts separate TCP/UDP slices; `scanner::run_nse_scripts` returns `Result`. `NseResult` now has `host`, `scope`, optional `port` and `protocol`, `script_id`, and `output`.

## Project

Rust 2021 CLI, package `oxidescanner` version 1.0.1, binary `oxscan`, MIT license. Uses Tokio for sockets/processes, inquire for terminal prompts, serde/serde_json for reports, roxmltree for Nmap XML, colored for terminal output, regex for title-based CVSS extraction, and reqwest/Rustls for optional reference search. Nmap and Searchsploit must be installed on PATH for actual scans; standalone key setup/reset does not require them. `tests/cli_smoke.py` provides release CLI coverage. No CI configuration is tracked.

`src/lib.rs` exports all modules; `src/main.rs` independently declares them again. Consequently module tests run in both the library and binary targets.

## Runtime Map

1. `src/config.rs`: validates the target, parses CLI flags and `OXIDE_*` environment settings, and prompts on an interactive terminal. TCP/UDP/both modes; port counts; timeouts; connection concurrency; NSE selector.
2. `src/main.rs::run`: checks dependencies, resolves the target, runs TCP and/or UDP scans (sequentially in both mode), fingerprints open ports, detects OS, runs enabled NSE checks, looks up exploit records, and prints results.
3. `src/utils.rs`: PATH checks using `which`, synchronous DNS via `ToSocketAddrs`, port list creation, progress-bar rendering. Port lists are sequential `1..=N`, despite "top ports" wording.
4. `src/scanner.rs`: one Tokio task per port behind a semaphore. TCP uses connect success/refusal/timeout classification; UDP sends a single zero byte and only calls a responding port open. Service detection launches one Nmap process per open port without a concurrency cap. OS detection always attempts Nmap `-O -sV`, then falls back to case-sensitive banner keywords with fixed 85% confidence.
5. `src/external/mod.rs`: `ExternalTool` trait and `BaseTool`, executable resolution, subprocess output capture, timeouts. Arguments bypass the shell. Initially timeout did not explicitly kill subprocesses.
6. `src/external/nmap.rs`: service detection arguments and XML parser; separate unused OS XML parser.
7. `src/external/nmap_nse.rs`: Nmap NSE invocation and script-output parsing; updated as described above.
8. `src/external/searchsploit.rs`: one `searchsploit --json --id QUERY` per lookup, JSON parser with text fallback, CVSS inferred from titles.
9. `src/exploit.rs`: builds product/version queries, deduplicates them, searches sequentially, scores and sorts matches. Searchsploit records are potential matches, not verified vulnerabilities.

## Data And Defaults

- `Port`: port number, protocol string, service, product, version.
- `ScanResults`: open ports, filtered port numbers, closed count.
- `OsResult`: name, distro, confidence, source.
- `PortResult`: one service port, matching exploit records, heuristic risk score.
- Initial JSON report: `services`, `os`, `exploits`; omitted NSE and discovery counts. Early exits printed no JSON.
- Defaults (`src/constants.rs`): 1000 ports, 200 concurrent socket connections, 1000 ms socket timeout, 10 s Searchsploit timeout, 30 s Nmap timeout, version intensity 1, NSE process timeout 60 s.
- Risk score: `(2 * min(exploit_count, 10) + sum(CVSS_or_5)) * service_multiplier`; thresholds 15/30/50. This is an unbounded aggregate heuristic, not a CVSS score.

## Support Modules

- `logging.rs`, `metrics.rs`, `retry.rs`, `shutdown.rs`: configuration types, no running logging/exporter/retry/shutdown implementation.
- `rate_limit.rs`: policy to governor quota conversion; no limiter in the scan flow. The conversion sets burst capacity but replenishes only one operation per period, and zero period can panic.
- `error.rs`: thiserror enum for config, tool, validation, parsing, IO, timeout, service detection, and target resolution; shared `Result<T>` alias.
- `validation.rs`: basic nonempty/length/whitespace target check and numeric port validation. Does not fully validate host syntax; port-list validation accepts port zero.
- Config reads `OXIDE_THREADS`, shutdown timeout, rate-limit policies, logging, metrics, and retry settings. README's `OXIDE_SCAN_TIMEOUT` is not implemented. `OXIDE_THREADS=0` can stall semaphore acquisition.

## Findings To Keep In View

- Both OS XML parsers expect `host > osmatch`; normal Nmap XML uses `host > os > osmatch`, so Nmap OS results are missed.
- UDP discovery is IPv4-bound, never reports closed ports, and misses services that ignore the generic payload; silence is ambiguous.
- TCP returns on the first refused resolved address, potentially missing an open service at another address.
- Unbounded parallel Nmap service processes are separate from the socket semaphore.
- Search query deduplication keeps only the first matching port; repeated services lose per-port attribution. Literal `unknown`/`httpd` query exclusions are bypassed by an earlier return.
- Searchsploit text fallback can parse a table header as an exploit and constructs malformed URLs. Some errors collapse into empty results.
- Package version remains 1.0.1 while README includes a 1.0.2 changelog.
- `install.sh` supports Linux/macOS, installs dependencies, release-builds, and copies the binary; its Linux Searchsploit path assumes apt/sudo or a Git clone, and destination chmod sometimes targets a directory.
- Current stable Rust is recommended; the previous README's 1.70 minimum was not supported by the resolved dependencies and has been replaced with the verified toolchain information.

## Verification

Baseline command:

```sh
cargo test --locked --all-targets -- --test-threads=1
```

Baseline passed: 26 library tests and 28 binary tests, zero failures. After the NSE changes, the same command passed **34 library tests and 37 binary tests**, zero failures. Module tests are duplicated across these targets; these are not 71 unique tests. Five pre-existing dead-code warnings remain. Tests are serial because logging/metrics tests mutate process-global environment variables. Several older parser/argument tests require Nmap/Searchsploit on PATH even though they do not execute scans; both tools are available locally. New NSE parser/argument checks do not require either executable.

`cargo build --release --locked` passed; executable: `target/release/oxscan`. `git diff --check` passed. A Python stdlib pseudo-terminal check launched the release executable and verified yes, no, and Enter/default confirmation inputs, with no category menu. It deliberately supplied invalid `--threads` to stop configuration before any scanning.

No live-target scans or end-to-end NSE network checks were performed. Protocol handling, XML parsing, error retention, report serialization, and partial-result status were checked with regression fixtures. Tests/build create ignored `target/` artifacts; source changes remain uncommitted.

### Final HackTricks Verification

- `cargo test --locked --all-targets -- --test-threads=1`: **55 library + 58 binary tests passed**. These targets repeat module tests; counts are not unique test cases.
- `cargo build --release --locked`: passed. Binary is `target/release/oxscan`, built with Rust 1.97.1 on macOS.
- `python3 tests/cli_smoke.py`: all 6 smoke scenarios passed; temporary files/processes were cleaned up.
- `git diff --check`: passed. Five existing dead-code warnings remain.
- The first integrated run exposed three older parser tests requiring Searchsploit, which is no longer present on the current PATH. Refactoring the pure helpers removed that dependency; all tests now pass without it.
- HTTP success/error/quota/timeout/redirect/oversize/secret-echo behaviors were tested against loopback fixtures. Live Brave authentication/search was not exercised with a real key. macOS ACL behavior was tested with actual ACL fixtures. Linux runtime/cross-compilation is not verified in this session.
- A read-only optional `cargo metadata --offline` attempt could not enumerate every target's dependency metadata because an Android-specific crate was not cached. It does not affect the successful macOS tests/release build; no broader MSRV is claimed.

## Suggested Next Priorities

1. Fix discovery correctness: genuine common-port ordering, UDP protocol probes/ambiguous states, IPv6 resolution/sockets, and the OS XML nesting bug.
2. Improve service detection: bounded/batched Nmap workers, deeper retry for unidentified services, and reuse fingerprint results to avoid repeat probing for OS/NSE.
3. Make findings actionable: evidence, confidence, vulnerability state, affected host/port, remediation, and verification steps; distinguish NSE observations from Searchsploit candidates. Fix per-port attribution after query deduplication.
4. Add complete saved scan records: target, scan options, phase outcomes, raw evidence, timestamps, and resume/diff support before expanding multi-target scans.
5. Wire up actual concurrency/rate limits, cancellation, retry behavior, and optional-dependency degradation; existing configuration alone does not implement these.
6. Build controlled local integration fixtures for HTTP/TLS, SSH, TCP/UDP, timeout, malformed output, and missing-tool paths.

Release build command: `cargo build --release --locked`.
