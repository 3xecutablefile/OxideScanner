//! Live HackTricks guidance via Brave Search; references never contribute to risk scores.

use crate::{external::nmap_nse::NseResult, scanner::Port};
use reqwest::{header::HeaderValue, Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::Write;
use std::time::Duration;
use tokio::time::{sleep_until, timeout_at, Instant};

const ENDPOINT: &str = "https://api.search.brave.com/res/v1/web/search";
const SITE: &str = "site:hacktricks.wiki";
const NSE_OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Serialize)]
pub struct HackTricksReport {
    pub status: String,
    pub provider: &'static str,
    pub checked_at: Option<String>,
    /// HTTP attempts, including failed requests and canonical fallbacks.
    pub requests: usize,
    /// Distinct planned queries left unattempted when this stage stops.
    pub skipped_queries: usize,
    pub lookups: Vec<ReferenceLookup>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceLookup {
    pub query: String,
    /// pending during planning; completed, no_results, failed, or skipped on return.
    pub status: String,
    pub error: Option<String>,
    pub contexts: Vec<ReferenceContext>,
    pub next_steps: Vec<String>,
    pub results: Vec<ReferenceLink>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReferenceContext {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub basis: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceLink {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

struct ServiceSpec {
    aliases: &'static [&'static str],
    term: &'static str,
    steps: [&'static str; 2],
}

const SERVICES: &[ServiceSpec] = &[
    ServiceSpec {
        aliases: &["http", "https", "ssl/http", "ssl/https", "http-proxy"],
        term: "HTTP",
        steps: [
            "Review authentication on exposed routes and administrative interfaces.",
            "Check proxy access rules and TLS configuration where applicable.",
        ],
    },
    ServiceSpec {
        aliases: &["ssh"],
        term: "SSH",
        steps: [
            "Review allowed authentication methods and privileged-account access.",
            "Compare enabled algorithms with the server's current security baseline.",
        ],
    },
    ServiceSpec {
        aliases: &["ftp", "ftps", "ssl/ftp"],
        term: "FTP",
        steps: [
            "Check anonymous access and directory read/write permissions.",
            "Verify that credentials and file transfers require encrypted transport.",
        ],
    },
    ServiceSpec {
        aliases: &["dns", "domain"],
        term: "DNS",
        steps: [
            "Review which clients may use recursion and request zone transfers.",
            "Check whether exposed records disclose internal infrastructure.",
        ],
    },
    ServiceSpec {
        aliases: &["smb", "microsoft-ds", "netbios-ssn"],
        term: "SMB",
        steps: [
            "Review signing requirements and supported SMB dialects.",
            "Check guest access and share permissions against intended access.",
        ],
    },
    ServiceSpec {
        aliases: &["ldap", "ldaps", "ssl/ldap"],
        term: "LDAP",
        steps: [
            "Review anonymous bind permissions and directory access rules.",
            "Verify transport protection and signing requirements for binds.",
        ],
    },
    ServiceSpec {
        aliases: &["mysql"],
        term: "MySQL",
        steps: [
            "Review remote-account grants and network access restrictions.",
            "Check authentication and encrypted connection requirements.",
        ],
    },
    ServiceSpec {
        aliases: &["postgresql", "postgres"],
        term: "PostgreSQL",
        steps: [
            "Review client authentication rules and role privileges.",
            "Verify that remote connections use the intended TLS policy.",
        ],
    },
    ServiceSpec {
        aliases: &["ms-sql-s", "mssql"],
        term: "Microsoft SQL Server",
        steps: [
            "Review exposed instances, login policy, and privileged roles.",
            "Check encrypted connections and unnecessary server features.",
        ],
    },
    ServiceSpec {
        aliases: &["redis"],
        term: "Redis",
        steps: [
            "Review bind addresses, protected mode, and authentication.",
            "Check ACLs for administrative and file-related commands.",
        ],
    },
    ServiceSpec {
        aliases: &["mongodb"],
        term: "MongoDB",
        steps: [
            "Verify authentication and least-privilege database roles.",
            "Review exposed listeners and transport encryption.",
        ],
    },
    ServiceSpec {
        aliases: &["rdp", "ms-wbt-server"],
        term: "RDP",
        steps: [
            "Verify Network Level Authentication and permitted login groups.",
            "Review remote access restrictions and TLS configuration.",
        ],
    },
    ServiceSpec {
        aliases: &["snmp"],
        term: "SNMP",
        steps: [
            "Review SNMP versions and authentication settings.",
            "Restrict management access and check read/write permissions.",
        ],
    },
    ServiceSpec {
        aliases: &["smtp", "smtps", "submission", "ssl/smtp"],
        term: "SMTP",
        steps: [
            "Review relay restrictions and authentication requirements.",
            "Check TLS policy and unnecessary account-discovery responses.",
        ],
    },
    ServiceSpec {
        aliases: &["imap", "imaps", "ssl/imap"],
        term: "IMAP",
        steps: [
            "Verify that mailbox authentication requires encrypted transport.",
            "Review supported authentication methods and account access controls.",
        ],
    },
    ServiceSpec {
        aliases: &["pop", "pop3", "pop3s", "ssl/pop3"],
        term: "POP3",
        steps: [
            "Check TLS requirements before mailbox authentication.",
            "Review legacy authentication methods and account access controls.",
        ],
    },
    ServiceSpec {
        aliases: &["nfs", "nfs-acl"],
        term: "NFS",
        steps: [
            "Review exported paths and allowed client networks.",
            "Check root squashing and read/write permissions on exports.",
        ],
    },
    ServiceSpec {
        aliases: &["vnc"],
        term: "VNC",
        steps: [
            "Review remote desktop authentication and transport protection.",
            "Restrict access to intended management clients.",
        ],
    },
    ServiceSpec {
        aliases: &["mqtt", "mqtts"],
        term: "MQTT",
        steps: [
            "Review anonymous connections and topic ACLs.",
            "Verify TLS and permissions for publishing and subscribing.",
        ],
    },
    ServiceSpec {
        aliases: &["amqp", "amqps"],
        term: "AMQP",
        steps: [
            "Review broker authentication and virtual-host permissions.",
            "Check TLS policy and access to broker management interfaces.",
        ],
    },
];

fn canonical_service(name: &str) -> Option<&'static ServiceSpec> {
    SERVICES.iter().find(|spec| {
        spec.aliases
            .iter()
            .any(|alias| name.trim().eq_ignore_ascii_case(alias))
    })
}

fn product_hint(service: &str, product: &str) -> Option<&'static str> {
    // Only a bounded, token-delimited prefix selects a literal; no banner text is sent.
    let product = product.trim();
    if product.len() > 128 {
        return None;
    }
    [
        ("SSH", "OpenSSH"),
        ("SSH", "Dropbear"),
        ("HTTP", "Apache httpd"),
        ("HTTP", "nginx"),
        ("HTTP", "Microsoft IIS"),
        ("SMB", "Samba"),
        ("FTP", "vsftpd"),
        ("FTP", "ProFTPD"),
        ("MySQL", "MySQL"),
        ("PostgreSQL", "PostgreSQL"),
        ("Redis", "Redis"),
        ("MongoDB", "MongoDB"),
    ]
    .into_iter()
    .find_map(|(family, hint)| {
        let prefix = product.get(..hint.len())?;
        let boundary = product[hint.len()..].chars().next();
        (family == service
            && prefix.eq_ignore_ascii_case(hint)
            && boundary.is_none_or(|c| c.is_ascii_whitespace() || matches!(c, '/' | '_')))
        .then_some(hint)
    })
}

struct PlannedLookup {
    lookup: ReferenceLookup,
    fallback: Option<String>,
    attempted: bool,
}

fn finish_lookup(mut entry: PlannedLookup) -> ReferenceLookup {
    if !entry.attempted {
        entry.lookup.status = "skipped".to_string();
    }
    entry.lookup
}

fn service_query(term: &str) -> String {
    format!("{SITE} {term} security enumeration")
}

fn lookup(query: String, context: ReferenceContext, steps: &[&str]) -> ReferenceLookup {
    ReferenceLookup {
        query,
        status: "pending".to_string(),
        error: None,
        contexts: vec![context],
        next_steps: steps.iter().map(|step| (*step).to_string()).collect(),
        results: Vec::new(),
    }
}

fn merge_contexts(destination: &mut ReferenceLookup, source: ReferenceLookup) {
    destination.contexts.extend(source.contexts);
    destination.contexts.sort();
    destination.contexts.dedup();
    for step in source.next_steps {
        if !destination.next_steps.contains(&step) {
            destination.next_steps.push(step);
        }
    }
}

fn nse_error(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        [
            "error",
            "failed",
            "script execution failed",
            "timed out",
            "timeout",
        ]
        .iter()
        .any(|prefix| {
            line.get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                && line
                    .as_bytes()
                    .get(prefix.len())
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        })
    })
}

fn plan_queries(services: &[Port], nse: &[NseResult]) -> Vec<PlannedLookup> {
    let mut planned = BTreeMap::<(u8, String), PlannedLookup>::new();
    let mut add = |priority, entry: ReferenceLookup, fallback| {
        let key = (priority, entry.query.clone());
        match planned.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut existing) => {
                // Identical canonical queries have identical suggestions; sort contexts once below.
                existing.get_mut().lookup.contexts.extend(entry.contexts);
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(PlannedLookup {
                    lookup: entry,
                    fallback,
                    attempted: false,
                });
            }
        }
    };

    for result in nse {
        // Check length before inspecting or copying evidence; large outputs keep service guidance.
        if result.output.len() > NSE_OUTPUT_LIMIT
            || !matches!(
                result.script_id.as_str(),
                "smb2-security-mode" | "ftp-anon" | "dns-recursion" | "ssl-enum-ciphers"
            )
            || nse_error(&result.output)
        {
            continue;
        }
        let mut observation = |term: &str, description: &str, steps: &[&str]| {
            add(
                0,
                lookup(
                    format!("{SITE} {term}"),
                    ReferenceContext {
                        host: result.host.clone(),
                        port: result.port,
                        protocol: result.protocol.clone(),
                        basis: format!("nse:{}", result.script_id),
                        description: description.to_string(),
                    },
                    steps,
                ),
                None,
            );
        };
        let exact_line = |expected: &str| result.output.lines().any(|line| line.trim() == expected);
        match result.script_id.as_str() {
            "smb2-security-mode" => {
                for (state, term, description) in [
                    (
                        "Message signing enabled but not required",
                        "SMB signing enabled not required",
                        "NSE reports that SMB signing is enabled but not required.",
                    ),
                    (
                        "Message signing is disabled and not required!",
                        "SMB signing disabled not required",
                        "NSE reports that SMB signing is disabled and not required.",
                    ),
                ] {
                    if exact_line(state) {
                        observation(
                            term,
                            description,
                            &[
                                "Confirm the effective SMB signing policy on the reported host.",
                                "Review client compatibility before requiring signing.",
                            ],
                        );
                    }
                }
            }
            "ftp-anon"
                if result
                    .output
                    .trim_start()
                    .lines()
                    .next()
                    .is_some_and(|line| {
                        line.trim_end() == "Anonymous FTP login allowed (FTP code 230)"
                    }) =>
            {
                observation(
                    "FTP anonymous login permissions",
                    "NSE reports that anonymous FTP login is allowed.",
                    &[
                        "Review which directories anonymous users can read or write.",
                        "Disable anonymous login if it is not required.",
                    ],
                );
            }
            "dns-recursion" if exact_line("Recursion appears to be enabled") => {
                observation(
                    "DNS recursion access control",
                    "NSE reports that DNS recursion appears to be enabled.",
                    &[
                        "Confirm whether recursion is available outside trusted client networks.",
                        "Review resolver access controls for the reported endpoint.",
                    ],
                );
            }
            "ssl-enum-ciphers" => {
                for legacy in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"] {
                    if exact_line(&format!("{legacy}:")) {
                        observation(&format!("TLS {legacy} legacy protocol configuration"), &format!("NSE lists a {legacy} protocol section."), &[
                            "Confirm the negotiated protocol and affected listener configuration.",
                            "Review client compatibility before disabling legacy protocols.",
                        ]);
                    }
                }
            }
            _ => {}
        }
    }

    for service in services {
        let Some(spec) = canonical_service(&service.service) else {
            continue;
        };
        let canonical = service_query(spec.term);
        let query = match product_hint(spec.term, &service.product) {
            Some(hint) if !hint.eq_ignore_ascii_case(spec.term) => {
                service_query(&format!("{} {hint}", spec.term))
            }
            _ => canonical.clone(),
        };
        let fallback = (query != canonical).then_some(canonical);
        // Port has no host field. Do not borrow a host from unrelated NSE results.
        add(
            1,
            lookup(
                query,
                ReferenceContext {
                    host: None,
                    port: Some(service.port),
                    protocol: Some(service.protocol.clone()),
                    basis: "service".to_string(),
                    description: format!("Recognized {} service.", spec.term),
                },
                &spec.steps,
            ),
            fallback,
        );
    }
    planned
        .into_values()
        .map(|mut entry| {
            entry.lookup.contexts.sort();
            entry.lookup.contexts.dedup();
            entry
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Limits {
    attempts: usize,
    body_bytes: usize,
    request_timeout: Duration,
    overall_timeout: Duration,
    spacing: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            attempts: 8,
            body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(10),
            overall_timeout: Duration::from_secs(30),
            spacing: Duration::from_millis(1050),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Failure {
    Auth,
    Quota,
    Redirect,
    Http,
    Transport,
    Timeout,
    Oversize,
    Malformed,
}

impl Failure {
    fn message(&self) -> &'static str {
        // Never include response bodies, URLs, header values, or reqwest errors.
        match self {
            Self::Auth => "Brave Search authentication rejected (401/403).",
            Self::Quota => "Brave Search quota or rate limit reached (429).",
            Self::Redirect => "Brave Search redirect rejected.",
            Self::Http => "Brave Search returned an unsuccessful HTTP status.",
            Self::Transport => "Brave Search transport failed.",
            Self::Timeout => "Brave Search request timed out.",
            Self::Oversize => "Brave Search response exceeded the size limit.",
            Self::Malformed => "Brave Search returned a malformed response.",
        }
    }
}

fn build_client(key: &str, limits: Limits, loopback_test: bool) -> Result<Client, &'static str> {
    let mut token =
        HeaderValue::from_str(key).map_err(|_| "Invalid Brave Search API key header.")?;
    token.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("X-Subscription-Token", token);
    let builder = Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never()) // Hidden transport retries would bypass the attempt budget.
        .https_only(true)
        .timeout(limits.request_timeout)
        .connect_timeout(limits.request_timeout);
    // Production retains reqwest's operator-configured proxy discovery and verified TLS.
    let builder = if cfg!(test) && loopback_test {
        builder.no_proxy().https_only(false)
    } else {
        builder
    };
    builder
        .build()
        .map_err(|_| "Could not initialize Brave Search HTTPS client.")
}

#[derive(Deserialize)]
struct SearchResponse {
    #[serde(rename = "type")]
    kind: Option<String>,
    web: Option<WebResults>,
}

#[derive(Deserialize)]
struct WebResults {
    results: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct SearchHit {
    title: String,
    url: String,
    #[serde(default)]
    description: String,
}

async fn fetch(
    client: &Client,
    endpoint: &str,
    query: &str,
    limit: usize,
    key: &str,
) -> Result<Vec<ReferenceLink>, Failure> {
    let transport = |error: reqwest::Error| {
        if error.is_timeout() {
            Failure::Timeout
        } else {
            Failure::Transport
        }
    };
    let mut response = client
        .get(endpoint)
        .query(&[
            ("q", query),
            ("count", "5"),
            ("result_filter", "web"),
            ("search_lang", "en"),
            ("spellcheck", "false"),
            ("text_decorations", "false"),
        ])
        .send()
        .await
        .map_err(transport)?;
    match response.status().as_u16() {
        401 | 403 => return Err(Failure::Auth),
        429 => return Err(Failure::Quota),
        300..=399 => return Err(Failure::Redirect),
        200..=299 => {}
        _ => return Err(Failure::Http),
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Failure::Oversize);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(Failure::Oversize);
        }
        body.extend_from_slice(&chunk);
    }
    let decoded: SearchResponse = serde_json::from_slice(&body).map_err(|_| Failure::Malformed)?;
    let web = match decoded.web {
        Some(web) => web,
        None if decoded.kind.as_deref() == Some("search") => return Ok(Vec::new()),
        None => return Err(Failure::Malformed),
    };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    let had_results = !web.results.is_empty();
    let mut valid_shape = false;
    for value in web.results {
        let Ok(hit) = serde_json::from_value::<SearchHit>(value) else {
            continue;
        };
        valid_shape = true;
        let Some(url) = accepted_url(&hit.url) else {
            continue;
        };
        // Check before truncation and after cleaning/URL normalization. Reject entire hits:
        // rewriting a credential-bearing URL could leave a misleading or still-sensitive link.
        if [&hit.title, &hit.description, &hit.url, &url]
            .into_iter()
            .any(|field| secret_bearing(field, key))
            || [&hit.url, &url].into_iter().any(|field| {
                decoded_url(field).is_some_and(|decoded| secret_bearing(&decoded, key))
            })
        {
            continue;
        }
        let title = clean_text(&hit.title, 160);
        if title.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        results.push(ReferenceLink {
            title,
            url,
            snippet: clean_text(&hit.description, 320),
        });
        if results.len() == 3 {
            break;
        }
    }
    if had_results && !valid_shape {
        Err(Failure::Malformed)
    } else {
        Ok(results)
    }
}

fn secret_bearing(text: &str, key: &str) -> bool {
    let key = key.trim();
    !key.is_empty() && (text.contains(key) || clean_text(text, usize::MAX).contains(key))
}

fn invisible(c: char) -> bool {
    matches!(c, '\u{00ad}' | '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}')
}

fn accepted_url(raw: &str) -> Option<String> {
    if raw.len() > 4096
        || raw.contains('\\')
        || raw
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || invisible(c))
    {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    if let Some((_, port)) = authority.split_once(':') {
        if port != "443" {
            return None;
        }
    }
    // Reject encoded terminal/control bytes too; never decode the returned URL or its anchor.
    if decoded_url(raw)?
        .chars()
        .any(|c| c.is_control() || invisible(c))
    {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || !matches!(
            url.host_str()?,
            "hacktricks.wiki" | "book.hacktricks.wiki" | "cloud.hacktricks.wiki"
        )
    {
        return None;
    }
    Some(url.to_string())
}

fn decoded_url(raw: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = (bytes.next()? as char).to_digit(16)?;
            let low = (bytes.next()? as char).to_digit(16)?;
            decoded.push((high * 16 + low) as u8);
        } else {
            decoded.push(byte);
        }
    }
    Some(String::from_utf8_lossy(&decoded).into_owned())
}

fn clean_text(text: &str, limit: usize) -> String {
    let mut chars = text.chars().peekable();
    let mut output = String::new();
    let mut length = 0;
    let mut space = false;
    while let Some(c) = chars.next() {
        let escape = match c {
            '\u{1b}' => chars.next(),
            '\u{9b}' => Some('['),
            '\u{9d}' => Some(']'),
            _ => None,
        };
        if c == '\u{1b}' || matches!(c, '\u{9b}' | '\u{9d}') {
            match escape {
                Some('[') => {
                    for code in chars.by_ref() {
                        if ('@'..='~').contains(&code) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(code) = chars.next() {
                        if matches!(code, '\u{7}' | '\u{9c}') {
                            break;
                        }
                        if code == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if c.is_whitespace() {
            space = !output.is_empty();
            continue;
        }
        if c.is_control() || invisible(c) {
            continue;
        }
        if space && length < limit {
            output.push(' ');
            length += 1;
        }
        space = false;
        if length == limit {
            break;
        }
        output.push(c);
        length += 1;
    }
    output.trim_end().to_string()
}

/// Collect optional live guidance. An absent/blank key returns before query planning or I/O.
pub async fn collect_references(
    services: &[Port],
    nse: &[NseResult],
    api_key: Option<&str>,
) -> HackTricksReport {
    collect_at(services, nse, api_key, ENDPOINT, Limits::default()).await
}

// Endpoint and limits are private; only this module's local-server tests override them.
async fn collect_at(
    services: &[Port],
    nse: &[NseResult],
    api_key: Option<&str>,
    endpoint: &str,
    limits: Limits,
) -> HackTricksReport {
    let mut report = HackTricksReport {
        status: "disabled".to_string(),
        provider: "brave",
        checked_at: None,
        requests: 0,
        skipped_queries: 0,
        lookups: Vec::new(),
        errors: Vec::new(),
    };
    let Some(key) = api_key.filter(|key| !key.trim().is_empty()) else {
        return report;
    };
    let deadline = Instant::now() + limits.overall_timeout;
    let mut planned = plan_queries(services, nse);
    if planned.is_empty() {
        report.status = "skipped_no_context".to_string();
        return report;
    }
    let loopback_test = cfg!(test)
        && Url::parse(endpoint)
            .is_ok_and(|url| url.scheme() == "http" && url.host_str() == Some("127.0.0.1"));
    let client = match build_client(key, limits, loopback_test) {
        Ok(client) => client,
        Err(error) => {
            report.status = "unavailable".to_string();
            report.skipped_queries = planned.len();
            report.lookups = planned.into_iter().map(finish_lookup).collect();
            report.errors.push(error.to_string());
            return report;
        }
    };
    let mut queue: VecDeque<usize> = (0..planned.len()).collect();
    let mut last_start = None;
    let mut successes = 0;
    let mut exhausted = false;
    while let Some(index) = queue.pop_front() {
        if planned[index].attempted {
            continue;
        }
        if report.requests == limits.attempts || Instant::now() >= deadline {
            exhausted = true;
            break;
        }
        if let Some(start) = last_start {
            let next = start + limits.spacing;
            if next >= deadline {
                exhausted = true;
                break;
            }
            sleep_until(next).await;
        }
        if Instant::now() >= deadline {
            exhausted = true;
            break;
        }
        let now = Instant::now();
        last_start = Some(now);
        planned[index].attempted = true;
        report.requests += 1;
        report.checked_at.get_or_insert_with(|| {
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
        let outcome = timeout_at(
            deadline.min(now + limits.request_timeout),
            fetch(
                &client,
                endpoint,
                &planned[index].lookup.query,
                limits.body_bytes,
                key,
            ),
        )
        .await
        .unwrap_or(Err(Failure::Timeout));
        match outcome {
            Ok(results) => {
                successes += 1;
                let empty = results.is_empty();
                planned[index].lookup.results = results;
                planned[index].lookup.status =
                    if empty { "no_results" } else { "completed" }.to_string();
                if empty {
                    if let Some(query) = planned[index].fallback.take() {
                        let mut fallback = planned[index].lookup.clone();
                        fallback.query = query;
                        fallback.status = "pending".to_string();
                        fallback.error = None;
                        let position = planned
                            .iter()
                            .position(|entry| entry.lookup.query == fallback.query);
                        let position = if let Some(position) = position {
                            merge_contexts(&mut planned[position].lookup, fallback);
                            position
                        } else {
                            planned.push(PlannedLookup {
                                lookup: fallback,
                                fallback: None,
                                attempted: false,
                            });
                            planned.len() - 1
                        };
                        if !planned[position].attempted {
                            queue.push_front(position);
                        }
                    }
                }
            }
            Err(error) => {
                let message = error.message().to_string();
                planned[index].lookup.status = "failed".to_string();
                planned[index].lookup.error = Some(message.clone());
                if !report.errors.contains(&message) {
                    report.errors.push(message);
                }
                // A bad credential or exhausted provider quota affects every remaining query.
                if matches!(error, Failure::Auth | Failure::Quota) {
                    break;
                }
                if Instant::now() >= deadline {
                    exhausted = true;
                    break;
                }
            }
        }
    }
    report.skipped_queries = planned.iter().filter(|entry| !entry.attempted).count();
    report.lookups = planned.into_iter().map(finish_lookup).collect();
    report.status = if exhausted {
        report
            .errors
            .push("Brave Search scan request/time budget exhausted.".to_string());
        "budget_exhausted"
    } else if successes == 0 {
        "unavailable"
    } else if !report.errors.is_empty() {
        "partial"
    } else if report.lookups.iter().all(|entry| entry.results.is_empty()) {
        "no_results"
    } else {
        "completed"
    }
    .to_string();
    report
}

/// Print guidance only; disabled reports produce no terminal output.
pub fn print_references(report: &HackTricksReport) {
    let _ = write_references(&mut std::io::stdout().lock(), report);
}

fn write_references(writer: &mut impl Write, report: &HackTricksReport) -> std::io::Result<()> {
    if report.status == "disabled" {
        return Ok(());
    }
    writeln!(
        writer,
        "\nHackTricks Guidance (Brave): {} | {} requests | {} skipped queries",
        clean_text(&report.status, 40),
        report.requests,
        report.skipped_queries
    )?;
    for entry in &report.lookups {
        writeln!(
            writer,
            "  [{}] {}",
            clean_text(&entry.status, 40),
            clean_text(&entry.query, 200)
        )?;
        if let Some(error) = &entry.error {
            writeln!(writer, "    {}", clean_text(error, 200))?;
        }
        for context in &entry.contexts {
            let endpoint = match (context.port, context.protocol.as_deref()) {
                (Some(port), Some(protocol)) => format!("{port}/{}", clean_text(protocol, 24)),
                (Some(port), None) => port.to_string(),
                (None, Some(protocol)) => clean_text(protocol, 24),
                (None, None) => "host context".to_string(),
            };
            writeln!(
                writer,
                "    {} | {} | {}",
                context
                    .host
                    .as_deref()
                    .map(|host| clean_text(host, 160))
                    .unwrap_or_else(|| "host unspecified".to_string()),
                endpoint,
                clean_text(&context.description, 320)
            )?;
        }
        for step in &entry.next_steps {
            writeln!(writer, "    Next: {}", clean_text(step, 320))?;
        }
        for link in &entry.results {
            if let Some(url) = accepted_url(&link.url) {
                writeln!(
                    writer,
                    "    {}\n      {}\n      {}",
                    clean_text(&link.title, 160),
                    url,
                    clean_text(&link.snippet, 320)
                )?;
            }
        }
    }
    for error in &report.errors {
        writeln!(writer, "  {}", clean_text(error, 200))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::thread::{self, JoinHandle};

    const KEY: &str = "fixture-key-never-a-real-credential";
    const GOOD: &str = r#"{"web":{"results":[{"title":"Reference","url":"https://book.hacktricks.wiki/en/network-services/example.html#review","description":"Review configuration."}]}}"#;
    const EMPTY: &str = r#"{"web":{"results":[]}}"#;

    fn port(number: u16, protocol: &str, service: &str, product: &str) -> Port {
        Port {
            port: number,
            protocol: protocol.into(),
            service: service.into(),
            product: product.into(),
            version: "10.20.30.40 tenant.private https://secret.invalid".into(),
        }
    }

    fn nse(script: &str, output: &str) -> NseResult {
        NseResult {
            host: Some("192.0.2.7".into()),
            scope: "host".into(),
            port: None,
            protocol: None,
            script_id: script.into(),
            output: output.into(),
        }
    }

    fn limits() -> Limits {
        Limits {
            request_timeout: Duration::from_secs(2),
            overall_timeout: Duration::from_secs(5),
            spacing: Duration::from_millis(2),
            ..Limits::default()
        }
    }

    fn reply(status: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    }

    struct MockServer {
        endpoint: String,
        received: Arc<Mutex<Vec<(Instant, String)>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl MockServer {
        fn new(responses: Vec<String>) -> Self {
            Self::delayed(
                responses
                    .into_iter()
                    .map(|body| (Duration::ZERO, body))
                    .collect(),
            )
        }

        fn delayed(responses: Vec<(Duration, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/search", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let received = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let log = Arc::clone(&received);
            let stopped = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                let mut responses = VecDeque::from(responses);
                while !stopped.load(Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => panic!("local listener: {error}"),
                    };
                    // macOS accepted sockets can inherit the listener's nonblocking mode.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(200)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_millis(200)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n")
                        && request.len() < 16384
                    {
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(count) => request.extend_from_slice(&buffer[..count]),
                        }
                    }
                    if request.is_empty() {
                        continue;
                    }
                    log.lock()
                        .unwrap()
                        .push((Instant::now(), String::from_utf8(request).unwrap()));
                    let (delay, response) = responses.pop_front().unwrap_or_else(|| {
                        (
                            Duration::ZERO,
                            reply("500 Unexpected request", "unexpected request"),
                        )
                    });
                    thread::sleep(delay);
                    // The bounded reader deliberately closes oversized/timed-out responses early.
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self {
                endpoint,
                received,
                stop,
                thread: Some(thread),
            }
        }

        fn queries(&self) -> Vec<String> {
            self.received
                .lock()
                .unwrap()
                .iter()
                .map(|(_, request)| {
                    let path = request
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    let url = Url::parse(&format!("http://localhost{path}")).unwrap();
                    let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
                    assert_eq!(pairs.len(), 6);
                    for (name, expected) in [
                        ("count", "5"),
                        ("result_filter", "web"),
                        ("search_lang", "en"),
                        ("spellcheck", "false"),
                        ("text_decorations", "false"),
                    ] {
                        assert_eq!(pairs.get(name).unwrap(), expected);
                    }
                    assert!(request
                        .to_ascii_lowercase()
                        .contains(&format!("x-subscription-token: {KEY}")));
                    pairs["q"].clone()
                })
                .collect()
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    #[test]
    fn canonical_planning_is_private_deterministic_and_preserves_contexts() {
        let mut services = vec![
            port(8443, "tcp", " SSL/HTTP ", "nginx 1.2 tenant.private"),
            port(8080, "tcp", "sSL/hTtPs", "NGINX/1.2"),
            port(8080, "udp", "http-proxy", "nginx"),
            port(2222, "tcp", "ssh", "OpenSSH_9.8p1 tenant.private"),
            port(22, "tcp", "unknown", "OpenSSH"),
            port(443, "tcp", "https://secret.invalid", "nginx"),
            port(8888, "tcp", "http", "nginx.tenant.private"),
        ];
        services.push(services[0].clone());
        let planned = plan_queries(&services, &[]);
        let queries: Vec<_> = planned
            .iter()
            .map(|entry| entry.lookup.query.as_str())
            .collect();
        assert_eq!(
            queries,
            [
                "site:hacktricks.wiki HTTP nginx security enumeration",
                "site:hacktricks.wiki HTTP security enumeration",
                "site:hacktricks.wiki SSH OpenSSH security enumeration"
            ]
        );
        assert_eq!(planned[0].lookup.contexts.len(), 3);
        assert!(planned
            .iter()
            .all(|entry| entry.lookup.status == "pending" && entry.lookup.error.is_none()));
        assert!(planned
            .iter()
            .flat_map(|entry| &entry.lookup.contexts)
            .all(|context| context.host.is_none()));
        assert_eq!(
            planned[0]
                .lookup
                .contexts
                .iter()
                .filter(|context| context.port == Some(8080))
                .count(),
            2
        );
        assert_eq!(product_hint("SSH", "OpenSSHevil"), None);
        assert_eq!(product_hint("HTTP", "https://nginx"), None);
        assert_eq!(product_hint("SSH", "OpenSSH_9.8p1"), Some("OpenSSH"));
        let serialized = serde_json::to_string(
            &planned
                .iter()
                .map(|entry| &entry.lookup)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(!serialized.contains("tenant.private"));
        assert!(!serialized.contains("10.20.30.40"));
        services.reverse();
        assert_eq!(
            serialized,
            serde_json::to_string(
                &plan_queries(&services, &[])
                    .iter()
                    .map(|entry| &entry.lookup)
                    .collect::<Vec<_>>()
            )
            .unwrap()
        );
        for spec in SERVICES {
            for alias in spec.aliases {
                let result = plan_queries(&[port(65432, "udp", alias, "")], &[]);
                assert_eq!(result[0].lookup.query, service_query(spec.term));
                assert_eq!(result[0].lookup.contexts[0].port, Some(65432));
                assert_eq!(
                    result[0].lookup.contexts[0].protocol.as_deref(),
                    Some("udp")
                );
            }
        }
        assert!(plan_queries(&[port(22, "tcp", "unknown", "OpenSSH")], &[]).is_empty());
    }

    #[test]
    fn observations_require_positive_evidence_and_keep_source_attribution() {
        let mut observations = vec![
            nse(
                "smb2-security-mode",
                "3:1:1:\n  Message signing enabled but not required",
            ),
            nse(
                "ftp-anon",
                "Anonymous FTP login allowed (FTP code 230)\nfiles",
            ),
            nse("dns-recursion", "Recursion appears to be enabled"),
            nse(
                "ssl-enum-ciphers",
                "  TLSv1.0:\n    ciphers:\n  TLSv1.1:\n    ciphers:\n  TLSv1.2:",
            ),
            nse(
                "smb2-security-mode",
                "Message signing is disabled and not required!",
            ),
        ];
        observations[1].scope = "port".into();
        observations[1].port = Some(2121);
        observations[1].protocol = Some("tcp".into());
        observations.push(observations[0].clone());
        let mut other_host = observations[0].clone();
        other_host.host = Some("192.0.2.8".into());
        observations.push(other_host);
        let planned = plan_queries(&[port(1445, "tcp", "smb", "")], &observations);
        assert_eq!(planned.len(), 7);
        assert_eq!(planned.last().unwrap().lookup.contexts[0].basis, "service");
        let smb = planned
            .iter()
            .find(|entry| entry.lookup.query.contains("enabled not required"))
            .unwrap();
        assert_eq!(smb.lookup.contexts.len(), 2);
        assert!(smb
            .lookup
            .contexts
            .iter()
            .all(|context| context.port.is_none() && context.protocol.is_none()));
        let disabled = planned
            .iter()
            .find(|entry| entry.lookup.query.contains("disabled not required"))
            .unwrap();
        assert_eq!(
            disabled.lookup.contexts[0].description,
            "NSE reports that SMB signing is disabled and not required."
        );
        assert!(disabled.lookup.contexts[0].port.is_none());
        assert_eq!(plan_queries(&[], &[nse("smb2-security-mode", "Message signing enabled but not required\nMessage signing is disabled and not required!")]).len(), 2);
        let ftp = planned
            .iter()
            .find(|entry| entry.lookup.query.contains("anonymous"))
            .unwrap();
        assert_eq!(ftp.lookup.contexts[0].port, Some(2121));
        assert_eq!(ftp.lookup.contexts[0].host.as_deref(), Some("192.0.2.7"));
        for (script, output) in [
            ("smb2-security-mode", "Message signing enabled and required"),
            (
                "smb2-security-mode",
                "NOT: Message signing enabled but not required",
            ),
            (
                "smb2-security-mode",
                "ERROR: failed\nMessage signing enabled but not required",
            ),
            (
                "smb2-security-mode",
                "NOT: Message signing is disabled and not required!",
            ),
            (
                "smb2-security-mode",
                "eRrOr: failed\nMessage signing is disabled and not required!",
            ),
            ("ftp-anon", "Anonymous FTP login denied (FTP code 530)"),
            (
                "ftp-anon",
                "Anonymous FTP login allowed (FTP code 230) is false",
            ),
            (
                "ftp-anon",
                "ERROR: Anonymous FTP login allowed (FTP code 230)",
            ),
            ("dns-recursion", "Recursion appears to be disabled"),
            ("dns-recursion", "NOT: Recursion appears to be enabled"),
            (
                "dns-recursion",
                "Script execution failed\nRecursion appears to be enabled",
            ),
            (
                "ssl-enum-ciphers",
                "TLSv1.0: not supported\nTLSv1.1: disabled\nTLSv1.2:",
            ),
            ("ssl-enum-ciphers", "ERROR: failed\nTLSv1.0:"),
            (
                "tenant.private-arbitrary-script",
                "Recursion appears to be enabled",
            ),
        ] {
            assert!(
                plan_queries(&[], &[nse(script, output)]).is_empty(),
                "{script}: {output}"
            );
        }
        let negative = nse("ftp-anon", "Anonymous FTP login denied (FTP code 530)");
        assert_eq!(
            plan_queries(&[port(21, "tcp", "ftp", "")], &[negative]).len(),
            1
        );
        let positive = "Recursion appears to be enabled\n";
        let mut bounded = nse(
            "dns-recursion",
            &format!(
                "{positive}{}",
                "x".repeat(NSE_OUTPUT_LIMIT - positive.len())
            ),
        );
        assert_eq!(plan_queries(&[], std::slice::from_ref(&bounded)).len(), 1);
        bounded.output.push('x');
        assert!(plan_queries(&[], std::slice::from_ref(&bounded)).is_empty());
        let generic = plan_queries(&[port(5353, "udp", "dns", "")], &[bounded]);
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].lookup.query, service_query("DNS"));
        assert!(!nse_error("errorless output"));
    }

    #[test]
    fn https_allowlist_and_terminal_cleaning_handle_unicode_and_anchors() {
        assert_eq!(
            accepted_url("HTTPS://BOOK.HACKTRICKS.WIKI:443/en/a#one").as_deref(),
            Some("https://book.hacktricks.wiki/en/a#one")
        );
        assert!(accepted_url("https://cloud.hacktricks.wiki/en/a#two").is_some());
        for url in [
            "http://hacktricks.wiki/",
            "javascript:alert(1)",
            "https://hacktricks.wiki.evil.test/",
            "https://evil-hacktricks.wiki/",
            "https://hacktricks.wiki@evil.test/",
            "https://@hacktricks.wiki/",
            "https://x:password@hacktricks.wiki/",
            "https://hacktricks.wiki:444/",
            "https://hacktricks.wiki:/",
            "https://hacktricks.wiki:0443/",
            "https://hacktricks.wiki./",
            "https://hacktricks.wiki\\@evil.test/",
            " https://hacktricks.wiki/",
            "https://hacktricks.wiki/\nfoo",
            "https://hacktricks.wiki/%0afoo",
            "https://hacktricks.wiki/%1B[31m",
            "https://hacktricks.wiki/%E2%80%AEtxt",
            "https://hacktricks.wiki/\u{202e}txt",
        ] {
            assert!(accepted_url(url).is_none(), "{url:?}");
        }
        let text = "  \x1b[31mCafé\x1b[0m\t雪\n\x1b]8;;https://evil.test\x07link\x1b]8;;\x07\u{202e}\u{200b}\0 \u{9b}32m✓\u{9b}0m  ";
        assert_eq!(clean_text(text, 160), "Café 雪 link ✓");
        assert_eq!(clean_text(&"雪".repeat(400), 160).chars().count(), 160);
        assert_eq!(clean_text(&"é".repeat(400), 320).chars().count(), 320);
        assert_eq!(clean_text("test", 0), "");
    }

    #[tokio::test]
    async fn disabled_no_context_and_invalid_headers_never_send_requests() {
        let mock = MockServer::new(vec![]);
        let service = [port(2222, "tcp", "ssh", "OpenSSH")];
        for key in [None, Some(""), Some(" \t\r\n")] {
            let report = collect_at(&service, &[], key, &mock.endpoint, limits()).await;
            assert_eq!(report.status, "disabled");
            assert_eq!(report.requests, 0);
            assert_eq!(report.skipped_queries, 0);
            assert!(
                report.lookups.is_empty()
                    && report.errors.is_empty()
                    && report.checked_at.is_none()
            );
            let mut printed = Vec::new();
            write_references(&mut printed, &report).unwrap();
            assert!(printed.is_empty());
            assert_eq!(serde_json::to_value(&report).unwrap()["provider"], "brave");
        }
        let report = collect_at(
            &[port(22, "tcp", "unknown", "OpenSSH")],
            &[nse("dns-recursion", "Recursion appears to be disabled")],
            Some(KEY),
            &mock.endpoint,
            limits(),
        )
        .await;
        assert_eq!(report.status, "skipped_no_context");
        assert_eq!(report.requests, 0);
        assert!(report.checked_at.is_none());
        let bad_key = format!("{KEY}\r\nInjected: header");
        let report = collect_at(&service, &[], Some(&bad_key), &mock.endpoint, limits()).await;
        assert_eq!(report.status, "unavailable");
        assert_eq!(report.errors, ["Invalid Brave Search API key header."]);
        assert_eq!(report.lookups[0].status, "skipped");
        assert!(report.lookups[0].error.is_none());
        assert!(!serde_json::to_string(&report).unwrap().contains(KEY));
        assert_eq!(report.requests, 0);
        assert!(mock.received.lock().unwrap().is_empty());
        assert!(build_client(KEY, limits(), false)
            .unwrap()
            .get(&mock.endpoint)
            .send()
            .await
            .is_err());
        assert!(mock.received.lock().unwrap().is_empty());
        assert_eq!(
            collect_references(&service, &[], None).await.status,
            "disabled"
        );
    }

    #[tokio::test]
    async fn successful_search_filters_hits_limits_text_and_sends_only_fixed_parameters() {
        let encoded: String = KEY.bytes().map(|byte| format!("%{byte:02X}")).collect();
        let hidden = format!("{}\u{200b}\x1b[0m{}", &KEY[..8], &KEY[8..]);
        let body = serde_json::json!({"web": {"results": [
            null, {}, {"title": 7, "url": "https://hacktricks.wiki/wrong-shape"},
            {"title": format!("\x1b]0;{KEY}\x07Visible"), "url": "https://hacktricks.wiki/raw-title"},
            {"title": hidden, "url": "https://hacktricks.wiki/clean-title"},
            {"title": "Raw snippet", "url": "https://hacktricks.wiki/raw-snippet", "description": format!("{}{KEY}", "x".repeat(400))},
            {"title": "Clean snippet", "url": "https://hacktricks.wiki/clean-snippet", "description": hidden},
            {"title": "Credential URL", "url": format!("https://hacktricks.wiki/{KEY}")},
            {"title": "Encoded credential URL", "url": format!("https://hacktricks.wiki/?credential={encoded}")},
            {"title": "Normalized credential URL", "url": format!("https://hacktricks.wiki/{encoded}/../safe")},
            {"title": "bad", "url": "https://hacktricks.wiki.evil.test/a"},
            {"title": "\u{1b}", "url": "https://hacktricks.wiki/a#one"},
            {"title": format!("\u{1b}[31m{}\u{1b}[0m", "雪".repeat(200)), "url": "https://hacktricks.wiki/a#one", "description": "é".repeat(400)},
            {"title": "duplicate", "url": "https://HACKTRICKS.WIKI:443/a#one"},
            {"title": "different section", "url": "https://hacktricks.wiki/a#two"},
            {"title": "cloud", "url": "https://cloud.hacktricks.wiki/"},
            {"title": "fourth", "url": "https://book.hacktricks.wiki/four"}
        ]}}).to_string();
        let mock = MockServer::new(vec![reply("200 OK", &body)]);
        let report = collect_at(
            &[port(8443, "tcp", "https", "nginx tenant.private")],
            &[],
            Some(KEY),
            &mock.endpoint,
            limits(),
        )
        .await;
        assert_eq!(report.status, "completed");
        assert_eq!(report.lookups[0].status, "completed");
        assert!(report.lookups[0].error.is_none());
        assert_eq!(report.requests, 1);
        assert_eq!(report.skipped_queries, 0);
        assert!(report.checked_at.is_some());
        let hits = &report.lookups[0].results;
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].title.chars().count(), 160);
        assert_eq!(hits[0].snippet.chars().count(), 320);
        assert!(hits[0].url.ends_with("#one") && hits[1].url.ends_with("#two"));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(KEY) && !serialized.contains(&encoded));
        let mut printed = Vec::new();
        write_references(&mut printed, &report).unwrap();
        let printed = String::from_utf8(printed).unwrap();
        assert!(!printed.contains(KEY) && !printed.contains(&encoded));
        assert_eq!(
            mock.queries(),
            ["site:hacktricks.wiki HTTP nginx security enumeration"]
        );
    }

    #[tokio::test]
    async fn empty_enriched_searches_share_one_canonical_fallback_and_all_contexts() {
        for (canonical_body, status) in [(GOOD, "completed"), (EMPTY, "no_results")] {
            let mock = MockServer::new(vec![
                reply("200 OK", EMPTY),
                reply("200 OK", canonical_body),
                reply("200 OK", EMPTY),
            ]);
            let services = [
                port(2222, "tcp", "ssh", "Dropbear"),
                port(2222, "udp", "ssh", "OpenSSH"),
                port(22, "tcp", "ssh", ""),
            ];
            let report = collect_at(&services, &[], Some(KEY), &mock.endpoint, limits()).await;
            assert_eq!(report.status, status);
            assert_eq!(report.requests, 3);
            assert_eq!(report.skipped_queries, 0);
            let canonical = report
                .lookups
                .iter()
                .find(|entry| entry.query == service_query("SSH"))
                .unwrap();
            assert_eq!(canonical.contexts.len(), 3);
            assert_eq!(canonical.status, status);
            assert!(report.lookups.iter().all(|entry| entry.error.is_none()));
            assert!(report
                .lookups
                .iter()
                .filter(|entry| entry.query != canonical.query)
                .all(|entry| entry.status == "no_results"));
            assert_eq!(
                mock.queries(),
                [
                    service_query("SSH Dropbear"),
                    service_query("SSH"),
                    service_query("SSH OpenSSH")
                ]
            );
        }
        let filtered =
            r#"{"web":{"results":[{"title":"Other","url":"https://example.invalid/"}]}}"#;
        let mock = MockServer::new(vec![reply("200 OK", filtered), reply("200 OK", GOOD)]);
        let report = collect_at(
            &[port(2222, "tcp", "ssh", "OpenSSH")],
            &[],
            Some(KEY),
            &mock.endpoint,
            limits(),
        )
        .await;
        assert_eq!(report.status, "completed");
        assert_eq!(report.requests, 2);
        assert!(report.lookups[0].results.is_empty());
        assert_eq!(report.lookups[0].status, "no_results");
        assert_eq!(report.lookups[1].status, "completed");
        assert_eq!(report.lookups[1].results.len(), 1);
        assert_eq!(mock.queries().len(), 2);
    }

    #[tokio::test]
    async fn failures_are_sanitized_and_preserve_prior_results() {
        let oversized = "x".repeat(Limits::default().body_bytes + 1);
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n", oversized.len());
        for (failure, response, stops) in [
            (Failure::Auth, reply("401 Unauthorized", KEY), true),
            (Failure::Auth, reply("403 Forbidden", KEY), true),
            (Failure::Quota, reply("429 Too Many Requests", KEY), true),
            (Failure::Http, reply("503 Unavailable", KEY), false),
            (Failure::Malformed, reply("200 OK", &format!("{{{KEY}")), false),
            (Failure::Malformed, reply("200 OK", r#"{"web":{"results":{}}}"#), false),
            (Failure::Malformed, reply("200 OK", r#"{"web":{"results":[null,17,{}, {"title":false,"url":"https://hacktricks.wiki/"}, {"title":"Wrong URL type","url":17}, {"title":"Wrong snippet type","url":"https://hacktricks.wiki/","description":false}]}}"#), false),
            (Failure::Oversize, reply("200 OK", &oversized), false),
            (Failure::Oversize, chunked, false),
            (Failure::Redirect, format!("HTTP/1.1 302 Found\r\nLocation: /follow?{KEY}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), false),
            (Failure::Transport, format!("HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\n{KEY}"), false),
        ] {
            let mock = MockServer::new(vec![reply("200 OK", GOOD), response.clone(), reply("200 OK", GOOD)]);
            let services = [port(21, "tcp", "ftp", ""), port(80, "tcp", "http", ""), port(22, "tcp", "ssh", "")];
            let report = collect_at(&services, &[], Some(KEY), &mock.endpoint, limits()).await;
            assert_eq!(report.status, "partial", "{failure:?}");
            assert_eq!(report.errors, [failure.message()], "response bytes={}, chunked={}, requests={}", response.len(), response.contains("chunked"), mock.queries().len());
            assert_eq!(report.requests, if stops { 2 } else { 3 });
            assert_eq!(report.skipped_queries, usize::from(stops));
            assert_eq!(report.lookups[0].results.len(), 1);
            assert_eq!(report.lookups[0].status, "completed");
            assert_eq!(report.lookups[1].status, "failed");
            assert_eq!(report.lookups[1].error.as_deref(), Some(failure.message()));
            assert_eq!(report.lookups[2].status, if stops { "skipped" } else { "completed" });
            assert!(report.lookups[2].error.is_none());
            assert_eq!(report.lookups[2].results.len(), usize::from(!stops));
            assert!(!serde_json::to_string(&report).unwrap().contains(KEY));
            let mut printed = Vec::new();
            write_references(&mut printed, &report).unwrap();
            assert!(!String::from_utf8(printed).unwrap().contains(KEY));
            assert_eq!(mock.queries().len(), report.requests);

            let only_failure = MockServer::new(vec![response]);
            let report = collect_at(&services[..1], &[], Some(KEY), &only_failure.endpoint, limits()).await;
            assert_eq!(report.status, "unavailable", "{failure:?}");
            assert_eq!(report.lookups[0].status, "failed");
            assert_eq!(report.lookups[0].error.as_deref(), Some(failure.message()));
            assert_eq!(report.requests, 1);
            assert!(!serde_json::to_string(&report).unwrap().contains(KEY));
        }
    }

    #[tokio::test]
    async fn attempt_budget_counts_fallbacks_and_does_not_mark_finished_work_exhausted() {
        let services: Vec<_> = SERVICES
            .iter()
            .take(10)
            .map(|spec| port(50000, "tcp", spec.aliases[0], ""))
            .collect();
        for (count, expected) in [(8, "no_results"), (10, "budget_exhausted")] {
            let mock = MockServer::new(vec![reply("200 OK", EMPTY); 8]);
            let report =
                collect_at(&services[..count], &[], Some(KEY), &mock.endpoint, limits()).await;
            assert_eq!(report.requests, 8);
            assert_eq!(
                report.status,
                expected,
                "{:?}; {:?}",
                report.errors,
                mock.queries()
            );
            assert_eq!(report.skipped_queries, count - 8);
            assert!(report.lookups[..8]
                .iter()
                .all(|entry| entry.status == "no_results" && entry.error.is_none()));
            assert!(report.lookups[8..]
                .iter()
                .all(|entry| entry.status == "skipped" && entry.error.is_none()));
            assert_eq!(mock.queries().len(), 8);
        }
        let mock = MockServer::new(vec![reply("200 OK", EMPTY)]);
        let report = collect_at(
            &[port(2222, "tcp", "ssh", "OpenSSH")],
            &[],
            Some(KEY),
            &mock.endpoint,
            Limits {
                attempts: 1,
                ..limits()
            },
        )
        .await;
        assert_eq!(report.status, "budget_exhausted");
        assert_eq!(report.requests, 1);
        assert_eq!(report.skipped_queries, 1);
        assert_eq!(report.lookups[1].query, service_query("SSH"));
        assert_eq!(report.lookups[0].status, "no_results");
        assert_eq!(report.lookups[1].status, "skipped");
        assert!(report.lookups[1].error.is_none());
    }

    #[tokio::test]
    async fn request_and_overall_deadlines_return_reports_with_completed_results() {
        let services = [port(80, "tcp", "http", ""), port(22, "tcp", "ssh", "")];
        for (request_timeout, overall_timeout, expected) in [
            (Duration::from_millis(40), Duration::from_secs(2), "partial"),
            (
                Duration::from_secs(2),
                Duration::from_millis(80),
                "budget_exhausted",
            ),
        ] {
            let mock = MockServer::delayed(vec![
                (Duration::ZERO, reply("200 OK", GOOD)),
                (Duration::from_millis(160), reply("200 OK", GOOD)),
            ]);
            let start = Instant::now();
            let report = collect_at(
                &services,
                &[],
                Some(KEY),
                &mock.endpoint,
                Limits {
                    request_timeout,
                    overall_timeout,
                    ..limits()
                },
            )
            .await;
            assert_eq!(report.status, expected);
            assert_eq!(report.requests, 2);
            assert_eq!(report.lookups[0].results.len(), 1);
            assert_eq!(report.lookups[0].status, "completed");
            assert_eq!(report.lookups[1].status, "failed");
            assert_eq!(
                report.lookups[1].error.as_deref(),
                Some(Failure::Timeout.message())
            );
            assert!(report
                .errors
                .iter()
                .any(|message| message == Failure::Timeout.message()));
            assert!(start.elapsed() < Duration::from_secs(1));
        }
    }

    #[tokio::test]
    async fn production_spacing_is_enforced_and_observations_go_first() {
        let defaults = Limits::default();
        assert_eq!(defaults.attempts, 8);
        assert_eq!(defaults.body_bytes, 1024 * 1024);
        assert_eq!(defaults.request_timeout, Duration::from_secs(10));
        assert_eq!(defaults.overall_timeout, Duration::from_secs(30));
        assert_eq!(defaults.spacing, Duration::from_millis(1050));
        let mock = MockServer::new(vec![reply("200 OK", GOOD); 2]);
        let report = collect_at(
            &[port(80, "tcp", "http", "")],
            &[nse(
                "smb2-security-mode",
                "Message signing enabled but not required",
            )],
            Some(KEY),
            &mock.endpoint,
            defaults,
        )
        .await;
        assert_eq!(report.status, "completed");
        let queries = mock.queries();
        assert!(queries[0].contains("signing"));
        assert_eq!(queries[1], service_query("HTTP"));
        let received = mock.received.lock().unwrap();
        assert!(received[1].0.duration_since(received[0].0) >= Duration::from_secs(1));
    }
}
