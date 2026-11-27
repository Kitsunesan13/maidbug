# MaidBug

Automated reconnaissance, attack-surface mapping, and vulnerability triage pipeline written in Bash. MaidBug orchestrates standard security utilities into a checkpointed, multi-stage workflow designed for unattended execution and structured manual review.

> **Disclaimer:** This tool is intended strictly for authorized security assessments, penetration testing, and bug bounty programs within explicitly defined scopes. Always ensure you have permission before scanning any target.

## Key Features

- **Wildcard-Aware DNS Validation:** Filters dead subdomains and wildcard DNS responses (`dnsx`) before port scanning or HTTP probing.
- **Flexible Port & Service Discovery:** Supports `naabu` (SYN/connect with CDN exclusion) or `rustscan` (`-Rs` for environments without raw-socket privileges), followed by `nmap -sV` fingerprinting on non-web ports.
- **Session Freshness Check & Multi-Identity Diffing:** Verifies whether provided session headers (`-H`) are still active at startup, and supports 3-way access control comparison (anonymous vs. low-privilege `-H` vs. high-privilege `-A`) using JSON key-structure comparison and response-size heuristics.
- **GraphQL & JS Asset Analysis:** Probes common GraphQL endpoints for enabled introspection (dumping schemas and extracting query/mutation fields) and scans JavaScript bundles plus `.js.map` sourcemaps via `trufflehog`, mapping findings back to their source URLs.
- **False-Positive Reduction:** Re-verifies raw `nuclei` matches independently before marking them as verified, applies two-probe soft-404 baseline filtering, and deduplicates endpoint paths prior to parameter fuzzing.
- **Checkpoint & Resume Support:** Tracks completed stages per target and configuration fingerprint so interrupted runs can be resumed cleanly with `-r`.
- **Consolidated Triage Output:** Aggregates high-signal leads across all stages into `09_PRIORITY_REVIEW.txt` alongside `FINAL_SUMMARY.txt`.

## Pipeline Stages

| Stage | Description | Tools Used |
| --- | --- | --- |
| **0.5** | Session header freshness check (when `-H` is provided) | `curl` |
| **1.0** | Subdomain enumeration, scope filtering, and wildcard DNS removal | `subfinder`, `dnsx` |
| **1.5** | Subdomain takeover candidate detection | `nuclei` (`-tags takeover`) |
| **2.0** | Port scanning | `naabu` or `rustscan` (`-Rs`) |
| **2.5** | Service/version fingerprinting on non-web ports | `nmap` |
| **3.0** | HTTP liveness probing and WAF-block separation (`403`/`406`/`429`/`503`) | `httpx-toolkit` |
| **3.5** | Quick-win CORS, configuration, and exposure checks | `nuclei` |
| **3.6** | GraphQL endpoint detection and schema introspection | `curl`, `jq`, `nuclei` |
| **3.7** | Visual screenshot triage *(opt-in: `-S`)* | `gowitness` |
| **4.0** | Web crawling (optional headless `-L`) and path-deduplicated parameter discovery | `katana`, `arjun` |
| **4.5** | Two-probe soft-404 baseline filtering | `curl` |
| **4.55** | Archived URL discovery and live validation *(opt-in: `-g`)* | `gau`, `uro`, `curl` |
| **4.6** | Heuristic endpoint triage for IDOR, auth, and admin paths | `grep`, `curl` |
| **4.7** | Three-way access control diffing *(opt-in: `-A`)* | `curl`, `jq` |
| **5.0** | JavaScript and sourcemap secret scanning | `curl`, `trufflehog` |
| **6.0** | Tech-stack-aware template scanning with two-pass verification | `nuclei` |
| **6.5** | Custom nuclei template directory scan *(opt-in: `-t <dir>`)* | `nuclei` |
| **7.0** | Active parameter fuzzing (DAST) with two-pass verification | `nuclei` |
| **7.5** | Reflected parameter filtering and XSS verification *(opt-in: `-x`)* | `kxss`, `dalfox` |
| **8.0** | Directory and content discovery *(opt-in: `-f`)* | `ffuf` |

## Prerequisites

### Core Dependencies (Required)

- `bash` (4.0+), `curl`, `jq`
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [naabu](https://github.com/projectdiscovery/naabu) *(or*[*RustScan*](https://github.com/bee-san/RustScan)*when using `-Rs`)*
- [httpx](https://github.com/projectdiscovery/httpx) *(invoked as `httpx-toolkit`)*
- [katana](https://github.com/projectdiscovery/katana)
- [arjun](https://github.com/s0md3v/Arjun)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [trufflehog](https://github.com/trufflesecurity/trufflehog)

### Optional Dependencies (Feature-Dependent)

- [dnsx](https://github.com/projectdiscovery/dnsx) — DNS resolution and wildcard filtering
- `nmap` — Service/version detection on non-web ports
- [gowitness](https://github.com/sensepost/gowitness) — Required for `-S`
- `chromium` / `google-chrome` — Required for `-L` (headless crawling)
- [gau](https://github.com/lc/gau) & [uro](https://github.com/s0md3v/uro) — Required for `-g`
- [kxss](https://github.com/Emoe/kxss) & [dalfox](https://github.com/hahwul/dalfox) — Required for `-x`
- [ffuf](https://github.com/ffuf/ffuf) & [SecLists](https://github.com/danielmiessler/SecLists) — Required for `-f`

## Installation

```
git clone https://github.com/<your-username>/maidbug.git
cd maidbug
chmod +x mb.sh
```

Ensure `$HOME/go/bin` and `/usr/local/bin` are in your `PATH`, and add `output/` to your `.gitignore` so scan logs and session headers are never committed.

## Usage

```
./mb.sh -u <target> [options]
```

### Common Examples

**Standard balanced scan:**

```
./mb.sh -u example.com
```

**Stealth scan with authenticated session cookie, historical URLs, and XSS pipeline:**

```
./mb.sh -u app.example.com -s example.com -m stealth -g -x \
  -H "Cookie: session=your_user_token"
```

**Access control comparison (low-privilege user `-H` vs. admin `-A`):**

```
./mb.sh -u app.example.com -m balanced \
  -H "Authorization: Bearer <low_priv_token>" \
  -A "Authorization: Bearer <admin_token>"
```

**Resume an interrupted run:**

```
./mb.sh -u app.example.com -m stealth -g -x -r \
  -H "Cookie: session=your_user_token"
```

### Options Reference

| Flag | Description |
| --- | --- |
| `-u <target>` | **Required.** Target domain (e.g., `example.com`). |
| `-s <scope>` | Scope anchor regex if different from `-u` (default: same as `-u`). |
| `-m <mode>` | Request pacing: `stealth` \| `balanced` \| `brawler` (default: `balanced`). |
| `-p <power>` | Resource profile: `mobile` \| `desktop` \| `vps` (default: `desktop`). |
| `-d <depth>` | Crawl depth: `everest` (depth 5) \| `mariana` (depth 8) (default: `everest`). |
| `-H <header>` | Custom HTTP header for primary identity (repeatable). |
| `-A <header>` | Custom HTTP header for high-privilege identity used in Stage 4.7 diffing (repeatable). |
| `-Rs` | Use `rustscan` instead of `naabu` for port scanning. |
| `-r` | Resume previous run matching the exact target + configuration fingerprint. |
| `-f <mode>` | Enable `ffuf` content discovery: `silent` \| `vortex` \| `brutal`. |
| `-S` | Enable screenshot capture via `gowitness`. |
| `-L` | Enable headless browser crawling (`katana -hl`). |
| `-t <dir>` | Run an additional `nuclei` scan using custom templates from `<dir>`. |
| `-g` | Enable historical URL discovery (`gau` + `uro`) with soft-404 validation. |
| `-x` | Enable reflected XSS pipeline (`kxss` + `dalfox`). |
| `-h` | Display help message and exit. |

## Output Structure

Results are saved under `output/<target>_<MODE>-<POWER>-<DEPTH>/`:

- `09_PRIORITY_REVIEW.txt` — Consolidated starting point ranking verified secrets, access-control anomalies, critical/high findings, confirmed XSS, GraphQL introspection, and high-interest endpoints.
- `FINAL_SUMMARY.txt` — High-level run metrics, runtime, and verified medium+ findings.
- `01_subfinder_subdomains.txt` — DNS-validated, non-wildcard subdomains.
- `02_port_scan_results.txt` & `02_5_nmap_service_versions.txt` — Open ports and non-web service fingerprints.
- `03_httpx_live_hosts.txt` & `03_httpx_waf_blocked.txt` — Active HTTP hosts and WAF-blocked targets.
- `03_6_graphql_endpoints.txt` & `03_6_graphql_schemas/` — Detected GraphQL endpoints and dumped schemas.
- `04_katana_endpoints_filtered.txt` — Parameterized and API endpoints.
- `04_6_interesting_endpoints.txt` — Heuristic IDOR, auth, and admin path triage.
- `04_7_access_control_diff.txt` — Multi-identity access control anomalies.
- `05_trufflehog_verified_secrets.txt` — Live-verified secrets mapped to their source JS/sourcemap URLs.
- `06_*_verified.jsonl` & `07_*_verified.jsonl` — Two-pass verified Nuclei findings with full request/response pairs.
- `run.log` — Detailed execution log and error diagnostics.
