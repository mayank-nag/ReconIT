<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/version-1.0.0-orange?style=for-the-badge" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/OSINT-passive-blueviolet?style=for-the-badge" alt="Passive OSINT">
</p>

<h1 align="center"> VENOM</h1>
<h3 align="center"><em>One domain in. Everything out.</em></h3>

<p align="center">
  Automated OSINT Reconnaissance Framework that spreads recursively across subdomains, historical records,<br>
  community reputation, and technology fingerprints — then delivers a single, structured intelligence report.
</p>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Module Reference](#module-reference)
  - [Phase 1 — Root Scan](#phase-1--root-scan)
  - [Phase 2 — Subdomain Spread](#phase-2--subdomain-spread)
  - [Phase 3 — Surface Crawl](#phase-3--surface-crawl)
  - [Phase 4 — Threat Intel & Reputation](#phase-4--threat-intel--reputation)
  - [Phase 5 — AI Analysis & Report Generation](#phase-5--ai-analysis--report-generation)
- [Risk Scoring](#risk-scoring)
- [Output & Reports](#output--reports)
- [API Keys](#api-keys)
- [Project Structure](#project-structure)
- [Comparison](#comparison)
- [Legal & Ethical Use](#legal--ethical-use)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**Venom** is a Python-based automated OSINT reconnaissance framework built for security researchers, bug bounty hunters, students, and authorized penetration testers.

Feed it a single root domain. It spreads — recursively outward across subdomains, historical records, community reputation, technology fingerprints, and known CVEs — and produces a unified intelligence report with interactive visualizations and an AI-generated analyst narrative.

**All reconnaissance is passive.** Data is gathered exclusively from publicly available sources. No active exploitation, injection, or brute-force credential attacks are performed.

---

## Key Features

| Category | Capability |
|---|---|
| 🔍 **Recursive Recon** | Subdomains discovered via Certificate Transparency, DNS brute-force, and SSL SANs — each recursed through the full scan pipeline |
| 🧠 **AI Analyst** | Rule-based intelligence engine that generates executive summaries, technical narratives, and prioritized remediation roadmaps |
| 🛡️ **CVE Correlation** | Detected technologies matched against a curated CVE database and the CIRCL/NVD API for known vulnerabilities |
| 🔑 **GitHub Dorking** | Automated secret-hunting queries for leaked API keys, credentials, environment files, and internal endpoints |
| 📊 **Risk Scoring** | Quantitative 0–100 risk score with configurable scoring rules and severity bands (LOW / MEDIUM / HIGH / CRITICAL) |
| 🌐 **Interactive Graph** | NetworkX + PyVis visualization of the target's domain structure — colour-coded by risk |
| 📄 **Multi-Format Reports** | JSON (machine-readable) + HTML dashboard (human-readable) + interactive graph |
| 🕰️ **Historical Analysis** | Wayback Machine integration for archived snapshot analysis and deleted-page discovery |
| 🛡️ **Reputation Check** | VirusTotal, Google Safe Browsing, and AbuseIPDB threat intelligence correlation |
| 📧 **Email Harvesting** | Extracts and deduplicates email addresses from crawled page content |
| 📎 **Metadata Extraction** | EXIF, PDF, and document metadata analysis for author enumeration and GPS data leaks |
| ⚡ **Async Concurrency** | `asyncio` + `httpx` for high-performance parallel scanning |
| 🎨 **Rich Terminal UI** | Colour-coded, styled terminal output powered by the `rich` library |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          VENOM CORE                              │
│                                                                  │
│  Input: domain.com                                               │
│         │                                                        │
│         ▼                                                        │
│   ┌─────────────┐                                               │
│   │ Orchestrator │  ← manages phase order, concurrency           │
│   └──────┬──────┘                                               │
│          │                                                       │
│    ┌─────┴───────────────────────────────┐                      │
│    │                                     │                      │
│    ▼                                     ▼                      │
│  Phase 1: Root Scan                Phase 2: Spread              │
│  (WHOIS, DNS, SSL, Tech)           (Subdomain enum,             │
│                                     recursive Phase 1)          │
│    │                                     │                      │
│    └──────────────┬──────────────────────┘                      │
│                   ▼                                              │
│              Phase 3: Surface Crawl                             │
│              (Pages, Files, Emails, Metadata)                   │
│                   │                                              │
│                   ▼                                              │
│              Phase 4: Threat Intel & Reputation                 │
│              (Wayback, VirusTotal, CVE Matching,                │
│               GitHub Dorking)                                   │
│                   │                                              │
│                   ▼                                              │
│              Phase 5: AI Analysis & Reports                     │
│              (Analyst Narrative + JSON + HTML + Graph)           │
└──────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- **Python 3.10** or higher
- **pip** package manager
- **Git** (to clone the repository)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/mayank-nag/ReconIT.git
cd ReconIT

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys (optional — enhances scan coverage)
cp config.yaml.example config.yaml   # or create config.yaml manually
# Edit config.yaml with your API keys
```

### Dependencies

| Package | Purpose |
|---|---|
| `requests`, `httpx`, `aiohttp` | HTTP clients (sync + async) |
| `dnspython` | DNS record resolution |
| `python-whois` | WHOIS domain lookups |
| `beautifulsoup4`, `lxml` | HTML parsing and crawling |
| `cryptography` | SSL/TLS certificate inspection |
| `networkx`, `pyvis` | Graph building and interactive visualization |
| `Jinja2` | HTML report templating |
| `PyYAML` | Configuration file parsing |
| `exifread`, `PyPDF2`, `Pillow` | Document and image metadata extraction |
| `rich` | Styled terminal output |
| `tqdm` | Progress bars |

---

## Quick Start

```bash
# Basic scan
python venom.py --target example.com

# Full scan with all optional modules
python venom.py --target example.com --full

# Infrastructure-only scan (skip crawling)
python venom.py --target example.com --no-crawl

# Custom crawl depth and output directory
python venom.py --target example.com --depth 2 --output ./reports/

# JSON-only output with verbose logging
python venom.py --target example.com --format json --verbose
```

### Example Terminal Output

```
╔══════════════════════════════════════════════════════╗
║  __      __  ______   _   _    ___    __  __         ║
║  \ \    / / |  ____| | \ | |  / _ \  |  \/  |       ║
║   \ \  / /  | |__    |  \| | | | | | | \  / |       ║
║    \ \/ /   |  __|   | . ` | | | | | | |\/| |       ║
║     \  /    | |____  | |\  | | |_| | | |  | |       ║
║      \/     |______| |_| \_|  \___/  |_|  |_|       ║
║          Advanced OSINT Reconnaissance Framework     ║
╚══════════════════════════════════════════════════════╝

[*] Target: example.com
[*] Starting scan...

=== Phase 1 — Root Scan ===
  [+] WHOIS: Registered 2019-04-12 | Expires 2027-04-12
  [+] DNS: 4 A records, 2 MX, SPF present, DMARC MISSING ⚠
  [+] SSL: Valid until 2026-11-30 | 6 SANs found
  [+] Tech: Nginx 1.18 | Frameworks: React | CMS: WordPress

=== Phase 2 — Subdomain Spread ===
  [+] Total: 27 subdomains found

=== Phase 3 — Surface Crawl ===
  [+] 142 endpoints & pages mapped
  [+] 8 emails found
  [+] 3 files with metadata

=== Phase 4 — Threat Intel & Reputation ===
  [+] Wayback: First archived 2019-05-01 | 834 snapshots
  [!] VirusTotal: 2 vendors flagged this domain ⚠
  [!] CVE Matcher: 3 potential CVE vulnerabilities correlated 🔴
  [+] GitHub Dorking: Generated 6 secret hunting dorks

=== Phase 5 — Analysis & Reports ===
  [+] AI Analyst: Intelligence narrative and remediation roadmap synthesized
  [+] report.json → ./output/example.com_report/
  [+] report.html → ./output/example.com_report/
  [+] graph.html  → ./output/example.com_report/

[+] Scan complete. Risk Score: 62/100 (HIGH)
    • 7 risk flag(s) detected
```

---

## CLI Reference

```
usage: venom [-t TARGET] [options]
```

### Arguments

| Flag | Short | Description | Default |
|---|---|---|---|
| `--target` | `-t` | **Required.** Target domain (e.g., `example.com`) | — |
| `--full` | `-f` | Run all modules including optional ones | `false` |
| `--no-crawl` | | Skip Phase 3 crawling (faster, infra-only) | `false` |
| `--depth` | `-d` | Crawl depth limit | `3` |
| `--ignore-robots` | | Ignore `robots.txt` during crawling | `false` |
| `--max-subdomains` | | Maximum subdomains to enumerate | `100` |
| `--timeout` | | Request timeout in seconds | `10` |
| `--output` | `-o` | Output directory | `./output/` |
| `--format` | | Output format: `all`, `json`, `html` | `all` |
| `--config` | `-c` | Path to config file | `config.yaml` |
| `--verbose` | `-v` | Enable verbose/debug logging | `false` |
| `--quiet` | `-q` | Minimal terminal output | `false` |
| `--version` | | Show version and exit | — |

---

## Configuration

Venom uses a `config.yaml` file for API keys, scan defaults, and module toggles. **Never commit this file to version control** (it's in `.gitignore`).

```yaml
# API Keys — all optional, enable extra modules
api_keys:
  virustotal: ""         # Free: https://virustotal.com/gui/join-us
  google_safebrowsing: "" # Free: https://console.cloud.google.com
  abuseipdb: ""          # Free: https://abuseipdb.com
  shodan: ""             # Optional: https://shodan.io
  github: ""             # Optional: for GitHub dorking module

# Scan defaults
scan:
  timeout: 10
  max_subdomains: 100
  crawl_depth: 3
  rate_limit: 5          # Max requests per second
  threads: 10

# Module toggles
modules:
  whois: true
  dns: true
  ssl: true
  tech_fingerprint: true
  subdomain_enum: true
  crawler: true
  email_extractor: true
  metadata_extractor: true
  wayback: true
  reputation: true
  shodan: false          # Requires API key
  github_dorking: false  # Requires API key
  cve_matching: true
```

---

## Module Reference

### Phase 1 — Root Scan

| Module | Description | Library | API Required |
|---|---|---|---|
| **WHOIS Lookup** | Registration info, registrar, dates, name servers. Flags domains < 6 months old. | `python-whois` | None |
| **DNS Recon** | A, MX, TXT (SPF/DKIM/DMARC), NS, CNAME, PTR records. Flags missing SPF/DMARC. | `dnspython` | None |
| **SSL Certificate** | Issuer, expiry, Subject Alternative Names (SANs). SANs feed into subdomain enumeration. | `ssl`, `cryptography` | None |
| **Tech Fingerprint** | Web server, CMS, frameworks, CDN, analytics, security headers. Flags missing headers and outdated software. | `requests`, regex patterns | None |

### Phase 2 — Subdomain Spread

| Module | Description | Library | API Required |
|---|---|---|---|
| **Subdomain Enum** | Three-layer approach: (1) Certificate Transparency via crt.sh, (2) DNS brute-force against wordlist, (3) SANs from Phase 1. Each discovered subdomain is recursed through Phase 1. | `httpx`, `asyncio`, `dnspython` | None |

### Phase 3 — Surface Crawl

| Module | Description | Library | API Required |
|---|---|---|---|
| **Crawler** | Spiders all discovered domains, maps pages, extracts forms, external links, `robots.txt`, and `sitemap.xml`. Configurable depth and `robots.txt` respect. | `httpx`, `BeautifulSoup4`, `lxml` | None |
| **Email Extractor** | Extracts and deduplicates email addresses from crawled page content and `mailto:` links. | `re` | None |
| **Metadata Extractor** | Downloads public documents (PDF, DOCX, images) and extracts hidden metadata — author names, GPS coordinates, software versions, timestamps. | `exifread`, `PyPDF2`, `Pillow` | None |

### Phase 4 — Threat Intel & Reputation

| Module | Description | Library | API Required |
|---|---|---|---|
| **Wayback Machine** | Historical snapshots, first-archived date, deleted pages, content changes over time. | `requests` | None (free) |
| **Reputation** | Cross-references domain/IP against VirusTotal, Google Safe Browsing, and AbuseIPDB for threat flags and blacklist status. | `requests` | VT / GSB / AbuseIPDB (free tiers) |
| **CVE Lookup** | Correlates fingerprinted technologies against a curated CVE database and the CIRCL/NVD API. Reports CVE IDs, CVSS scores, severity, and remediation steps. | `requests` | None |
| **GitHub Dorking** | Generates targeted dork queries to find leaked API keys, credentials, config files, and internal endpoints on GitHub. Supports live GitHub Search API queries with a token. | `requests` | GitHub PAT (optional) |

### Phase 5 — AI Analysis & Report Generation

| Module | Description | Library | API Required |
|---|---|---|---|
| **AI Analyst** | Rule-based intelligence engine that produces executive summaries, per-phase technical narratives, and a prioritized remediation roadmap — runs 100% offline. | Built-in | None |
| **Report Generator** | Assembles final `report.json` + `report.html` (Jinja2-templated dashboard) from all findings. | `Jinja2` | None |
| **Graph Builder** | Creates an interactive, colour-coded network graph of the target's domain structure. | `NetworkX`, `PyVis` | None |

---

## Risk Scoring

Venom calculates a quantitative risk score (0–100) based on discovered findings:

| Finding | Score Impact |
|---|---|
| Domain age < 6 months | +20 |
| Missing DMARC record | +10 |
| Missing SPF record | +10 |
| SSL expiring < 30 days | +15 |
| SSL expired | +25 |
| Plain HTTP / No SSL | +15 |
| Missing CSP header | +5 |
| Missing HSTS header | +5 |
| Missing X-Frame-Options | +5 |
| Missing X-Content-Type-Options | +5 |
| VirusTotal positive flag | +20 |
| Google Safe Browsing flag | +30 |
| AbuseIPDB high abuse confidence | +20 |
| Outdated CMS version | +10 |
| Exposed `.git` or `.env` reference | +25 |
| Exposed sensitive path/directory | +20 |
| Known Critical/High CVE matched | +20 |
| Public GitHub secret/credential leak | +25 |
| Exposed metadata with author/GPS | +10 |

### Severity Bands

| Score | Level | Indicator |
|---|---|---|
| 0–30 | 🟢 **LOW** | Minimal risk |
| 31–60 | 🟡 **MEDIUM** | Moderate exposure |
| 61–80 | 🟠 **HIGH** | Significant risk |
| 81–100 | 🔴 **CRITICAL** | Severe exposure |

---

## Output & Reports

All reports are saved to `./output/<domain>_report/` (or a custom path via `--output`).

| File | Format | Description |
|---|---|---|
| `report.json` | JSON | Complete machine-readable scan data — all phases, risk flags, CVEs, AI analysis |
| `report.html` | HTML | Styled dashboard with sections for each phase, risk scoring, and remediation roadmap |
| `graph.html` | HTML | Interactive NetworkX/PyVis graph — zoom, click, hover on nodes. Colour-coded by risk |

### JSON Report Structure

```json
{
  "target": "example.com",
  "scan_date": "2026-08-28T10:30:00Z",
  "risk_score": 65,
  "risk_level": "HIGH",
  "risk_flags": [...],
  "whois_data": {...},
  "dns_data": {...},
  "ssl_data": {...},
  "technologies": {...},
  "subdomains": [...],
  "pages_crawled": [...],
  "emails_found": [...],
  "metadata_findings": [...],
  "wayback_data": {...},
  "reputation_data": {...},
  "cve_matches": [...],
  "github_dorks": [...],
  "github_leaks": [...],
  "ai_analysis": {
    "executive_summary": [...],
    "narrative_sections": [...],
    "remediation_roadmap": [...]
  }
}
```

---

## API Keys

All API keys are **optional**. The core framework runs fully without them. Adding keys unlocks additional data sources:

| API | Free Tier | Where to Get |
|---|---|---|
| VirusTotal | 4 requests/min | [virustotal.com/gui/join-us](https://virustotal.com/gui/join-us) |
| Google Safe Browsing | Free | [console.cloud.google.com](https://console.cloud.google.com) |
| AbuseIPDB | 1,000 requests/day | [abuseipdb.com](https://www.abuseipdb.com) |
| Shodan | Limited (1 credit) | [shodan.io](https://shodan.io) |
| GitHub | Standard rate limits | [github.com/settings/tokens](https://github.com/settings/tokens) |

Keys without APIs (completely free, no registration):
- crt.sh (Certificate Transparency)
- Wayback Machine
- WHOIS
- DNS resolution
- CIRCL CVE API

---

## Project Structure

```
venom/
├── venom.py                    # Main CLI entry point
├── config.yaml                 # API keys & scan settings (gitignored)
├── requirements.txt            # Python dependencies
├── LICENSE                     # MIT License
│
├── core/
│   ├── __init__.py
│   ├── orchestrator.py         # 5-phase pipeline controller
│   ├── target.py               # Central data model & risk scoring
│   └── logger.py               # Rich-powered terminal output
│
├── modules/
│   ├── whois_lookup.py         # Phase 1 — WHOIS registration data
│   ├── dns_recon.py            # Phase 1 — DNS record enumeration
│   ├── ssl_cert.py             # Phase 1 — SSL/TLS certificate analysis
│   ├── tech_fingerprint.py     # Phase 1 — Technology stack detection
│   ├── subdomain_enum.py       # Phase 2 — Subdomain enumeration
│   ├── crawler.py              # Phase 3 — Web crawler
│   ├── email_extractor.py      # Phase 3 — Email address harvesting
│   ├── metadata_extractor.py   # Phase 3 — Document/image metadata
│   ├── wayback.py              # Phase 4 — Wayback Machine history
│   ├── reputation.py           # Phase 4 — Threat reputation checks
│   ├── cve_lookup.py           # Phase 4 — CVE vulnerability correlation
│   ├── github_dork.py          # Phase 4 — GitHub secret hunting
│   └── ai_analyst.py           # Phase 5 — AI intelligence narrative
│
├── report/
│   ├── generator.py            # Report assembler (JSON + HTML)
│   ├── graph.py                # Interactive graph visualization
│   └── templates/
│       └── report.html         # Jinja2 HTML report template
│
├── wordlists/
│   └── subdomains.txt          # Common subdomain wordlist
│
└── output/                     # Generated reports (gitignored)
    └── example.com_report/
        ├── report.json
        ├── report.html
        └── graph.html
```

---

## Comparison

| Feature | Venom | theHarvester | SpiderFoot | Maltego |
|---|---|---|---|---|
| Recursive subdomain spread | ✅ | ❌ | Partial | ❌ |
| AI-generated analyst narrative | ✅ | ❌ | ❌ | ❌ |
| CVE correlation on detected tech | ✅ | ❌ | ❌ | ❌ |
| GitHub secret dorking | ✅ | ❌ | Partial | ❌ |
| Historical Wayback analysis | ✅ | ❌ | ❌ | ❌ |
| Interactive graph visualization | ✅ | ❌ | ❌ | ✅ (paid) |
| Quantitative risk scoring | ✅ | ❌ | Partial | ❌ |
| Metadata extraction (EXIF/PDF) | ✅ | ❌ | ❌ | ❌ |
| Single-command full pipeline | ✅ | ✅ | Partial | ❌ |
| Free & open source | ✅ | ✅ | ✅ | ❌ (paid) |

---

## Legal & Ethical Use

> [!CAUTION]
> **VENOM is designed for legal, passive OSINT reconnaissance only.**

Use exclusively against:
- ✅ Domains you **own**
- ✅ Domains you have **explicit written permission** to test
- ✅ Bug bounty targets **explicitly listed in scope**

This tool does **not** exploit, inject, brute-force credentials, or perform any active attack. All data gathered is publicly available through open sources.

Unauthorized use against third-party systems may violate the **IT Act 2000** (India) and equivalent laws in your jurisdiction. The authors accept **no liability** for misuse.

---

## Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate docstrings.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with 🐍 by <strong>Mayank</strong> — Venom OSINT Framework
</p>
