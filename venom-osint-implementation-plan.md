# VENOM — OSINT Recon Tool
## Full Implementation Plan

---

## 1. Project Overview

**Name:** Venom  
**Tagline:** *One domain in. Everything out.*  
**Type:** Automated OSINT Recon Framework  
**Language:** Python (backend) + HTML/CSS/JS (report output)  
**Audience:** Security researchers, students, bug bounty hunters, authorized pentesters  
**Legal scope:** Passive OSINT only — all data pulled from publicly available sources, no active exploitation  

**Core idea:**  
Feed it a single root domain. It spreads like Venom — recursively outward across subdomains, historical records, community reputation, and tech fingerprints — and pulls back a single, structured, visual intelligence report.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        VENOM CORE                           │
│                                                             │
│  Input: domain.com                                          │
│         │                                                   │
│         ▼                                                   │
│   ┌─────────────┐                                          │
│   │ Orchestrator │  ← manages phase order, concurrency      │
│   └──────┬──────┘                                          │
│          │                                                  │
│    ┌─────┴──────────────────────────────┐                  │
│    │                                    │                  │
│    ▼                                    ▼                  │
│ Phase 1                            Phase 2                 │
│ Root Scan                          Spread                  │
│ (WHOIS, DNS,                       (Subdomain enum,        │
│  SSL, Tech)                         recursive Phase 1)     │
│    │                                    │                  │
│    └─────────────┬──────────────────────┘                  │
│                  ▼                                          │
│             Phase 3                                        │
│             Surface Crawl                                  │
│             (Pages, Files, Emails, Metadata)               │
│                  │                                          │
│                  ▼                                          │
│             Phase 4                                        │
│             History & Reputation                           │
│             (Wayback, VirusTotal, Safe Browsing)           │
│                  │                                          │
│                  ▼                                          │
│             Phase 5                                        │
│             Report Generator                               │
│             (JSON + HTML + Graph Visualization)            │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Folder Structure

```
venom/
│
├── venom.py                  ← main CLI entry point
├── config.yaml               ← API keys, settings, rate limits
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── orchestrator.py       ← controls phase pipeline, concurrency
│   ├── target.py             ← Target object (stores all findings)
│   └── logger.py             ← coloured terminal output
│
├── modules/
│   ├── __init__.py
│   ├── whois_lookup.py       ← Phase 1
│   ├── dns_recon.py          ← Phase 1
│   ├── ssl_cert.py           ← Phase 1
│   ├── tech_fingerprint.py   ← Phase 1
│   ├── subdomain_enum.py     ← Phase 2
│   ├── crawler.py            ← Phase 3
│   ├── email_extractor.py    ← Phase 3
│   ├── metadata_extractor.py ← Phase 3
│   ├── wayback.py            ← Phase 4
│   ├── reputation.py         ← Phase 4
│   └── shodan_lookup.py      ← Phase 4 (optional, needs API key)
│
├── report/
│   ├── generator.py          ← assembles final JSON + HTML report
│   ├── templates/
│   │   └── report.html       ← Jinja2 template
│   └── graph.py              ← NetworkX + PyVis graph builder
│
├── wordlists/
│   └── subdomains.txt        ← common subdomain wordlist
│
└── output/                   ← generated reports saved here
    └── example.com_report/
        ├── report.html
        ├── report.json
        └── graph.html
```

---

## 4. Module-by-Module Breakdown

---

### Phase 1 — Root Scan

#### `modules/whois_lookup.py`
**What it does:** Pulls registration info on the root domain.  
**Data extracted:**
- Registrar name
- Registration date, expiry date (flag if expiring soon)
- Registrant country
- Name servers
- Last updated date

**Library:** `python-whois`  
**API needed:** None  
**Flag logic:** If domain is < 6 months old → risk indicator (likely a scam/temp site)

```python
# Key function signature
def run(domain: str) -> dict:
    # returns structured dict of WHOIS data
```

---

#### `modules/dns_recon.py`
**What it does:** Pulls all DNS record types for the domain.  
**Data extracted:**
- A records (IP addresses)
- MX records (mail servers — useful for phishing detection)
- TXT records (SPF, DKIM, DMARC — email security posture)
- NS records (nameservers)
- CNAME records
- PTR records

**Library:** `dnspython`  
**API needed:** None  
**Flag logic:** Missing SPF/DMARC = email spoofable → flag as risk

---

#### `modules/ssl_cert.py`
**What it does:** Inspects the SSL/TLS certificate.  
**Data extracted:**
- Certificate issuer (Let's Encrypt vs trusted CA)
- Expiry date (flag if < 30 days)
- Subject Alternative Names (SANs) — these often leak extra subdomains
- Certificate chain info

**Library:** `ssl`, `socket`, `cryptography`  
**API needed:** None  
**Flag logic:** SANs extracted here fed back into subdomain Phase 2

---

#### `modules/tech_fingerprint.py`
**What it does:** Identifies what technology stack the site runs on.  
**Data extracted:**
- Web server (Apache, Nginx, IIS)
- CMS (WordPress, Drupal — check for known CVEs)
- Frameworks (React, Laravel, Django via headers/scripts)
- CDN (Cloudflare, Fastly)
- Analytics tools, ad trackers
- Security headers (CSP, HSTS, X-Frame-Options — flag missing ones)

**Library:** `requests`, regex pattern matching against a local tech signature database  
**API needed:** None  
**Flag logic:** Missing security headers → flag; Outdated software version detected → flag

---

### Phase 2 — Spread (Subdomain Enumeration)

#### `modules/subdomain_enum.py`
**What it does:** Discovers every subdomain of the root domain.  
**Three-layer approach:**

**Layer 1 — Certificate Transparency (crt.sh):**
```
GET https://crt.sh/?q=%.domain.com&output=json
```
Returns all subdomains ever issued an SSL cert — extremely comprehensive, totally passive, no API key.

**Layer 2 — DNS Brute Force (wordlist):**
Tries common subdomains from `wordlists/subdomains.txt` (mail, api, dev, staging, admin, vpn, etc.) via DNS resolution.

**Layer 3 — SANs from SSL module:**
SANs collected in Phase 1 fed here as additional candidates.

**Recursive behaviour:**  
Each discovered subdomain → passed back to Phase 1 pipeline as a new root → findings merged into parent report.

**Concurrency:** `asyncio` + `httpx` for async DNS resolution (critical — hundreds of subdomains need to be checked fast)

**Library:** `httpx`, `asyncio`, `dnspython`  
**API needed:** None (Shodan/Censys optional for extra coverage)

---

### Phase 3 — Surface Crawl

#### `modules/crawler.py`
**What it does:** Spiders each discovered domain/subdomain, maps all pages.  
**Data extracted:**
- Full sitemap of URLs (page tree)
- All forms found (login, search, upload — note for report, not exploit)
- All external links
- robots.txt contents (disallowed paths often reveal interesting endpoints)
- sitemap.xml contents

**Depth limit:** Configurable (default depth 3 to avoid infinite crawl)  
**Respect:** robots.txt honoured unless user sets `--ignore-robots` flag (with warning)  
**Library:** `httpx`, `BeautifulSoup4`, `lxml`

---

#### `modules/email_extractor.py`
**What it does:** Extracts email addresses from crawled page content.  
**Sources:**
- Page HTML text
- Page source code (mailto: links)
- Contact pages
- Footer content

**Output:** Deduplicated list of emails with source URL  
**Library:** `re` (regex), fed from crawler output

---

#### `modules/metadata_extractor.py`
**What it does:** Downloads publicly linked documents and images, extracts hidden metadata.  
**File types handled:** PDF, DOCX, XLSX, PNG, JPEG  
**Data extracted:**
- Author names (from PDF/Office metadata)
- Software used to create the file
- GPS coordinates in photos (if present)
- Creation/modification timestamps

**Library:** `exiftool` (subprocess call), `PyPDF2`, `Pillow`  
**Flag logic:** Author names → potential employee enumeration; GPS data → physical location leak

---

### Phase 4 — History & Reputation

#### `modules/wayback.py`
**What it does:** Queries the Wayback Machine API for historical snapshots.  
**Data extracted:**
- First archived date (how old is this site really?)
- Total snapshot count
- List of notable historical URLs (pages that existed before but are now deleted)
- Archived pages with different content than current (potential data leaks in old versions)

**API endpoint:**
```
http://archive.org/wayback/available?url=domain.com
http://web.archive.org/cdx/search/cdx?url=*.domain.com&output=json
```
**Library:** `requests`  
**API needed:** None (Wayback Machine is free and open)

---

#### `modules/reputation.py`
**What it does:** Checks community reputation of the domain.  
**Sources:**
- **VirusTotal API** — has it been flagged by any AV/security vendor?
- **URLVoid** — blacklist check
- **Google Safe Browsing API** — current safety rating
- **AbuseIPDB** — if IP resolved from DNS, check for reported abuse

**Library:** `requests`  
**API needed:** VirusTotal (free tier), Google Safe Browsing (free), AbuseIPDB (free)  
**Flag logic:** Any positive flags → HIGH RISK indicator in report

---

### Phase 5 — Report Generation

#### `report/generator.py`
**What it does:** Takes all collected data from every module → assembles structured report.

**Output formats:**
1. `report.json` — full raw data, machine-readable
2. `report.html` — human-readable, styled, with visual graph
3. Terminal summary — colour-coded risk overview printed after scan

**Structure of JSON output:**
```json
{
  "target": "example.com",
  "scan_date": "2026-08-28T10:30:00Z",
  "risk_score": 65,
  "risk_flags": ["Missing DMARC", "SSL expiring in 12 days"],
  "whois": {...},
  "dns": {...},
  "ssl": {...},
  "technologies": [...],
  "subdomains": [...],
  "pages_crawled": [...],
  "emails_found": [...],
  "metadata_findings": [...],
  "wayback": {...},
  "reputation": {...}
}
```

---

#### `report/graph.py`
**What it does:** Builds interactive visual graph of the target's structure.

**Graph structure:**
- Root domain = central node
- Subdomains = first-level child nodes
- Pages under each subdomain = second-level nodes
- Edges labelled with relationship type
- Node colour = risk level (green/yellow/red)

**Library:** `NetworkX` (graph logic) + `PyVis` (interactive HTML output)  
**Output:** `graph.html` — opens in browser, fully interactive (zoom, click, hover)

---

## 5. CLI Interface Design

```bash
# Basic scan
python venom.py --target example.com

# Full scan with all modules
python venom.py --target example.com --full

# Skip crawling (faster, infra-only)
python venom.py --target example.com --no-crawl

# Set crawl depth
python venom.py --target example.com --depth 2

# Output directory
python venom.py --target example.com --output ./reports/

# JSON only (no HTML)
python venom.py --target example.com --format json

# Verbose logging
python venom.py --target example.com --verbose
```

**Terminal output during scan:**
```
[*] VENOM initializing...
[*] Target: example.com
[+] Phase 1 — Root Scan
    [+] WHOIS: Registered 2019-04-12 | Expires 2027-04-12
    [+] DNS: 4 A records, 2 MX, SPF present, DMARC MISSING ⚠
    [+] SSL: Valid until 2026-11-30 | 6 SANs found
    [+] Tech: Nginx 1.18 | WordPress 6.4 | Cloudflare CDN
[+] Phase 2 — Subdomain Spread
    [+] crt.sh: 23 subdomains found
    [+] DNS brute: 4 additional subdomains resolved
    [+] Total: 27 subdomains → recursing...
[+] Phase 3 — Surface Crawl
    [+] 142 pages mapped | 8 emails found | 3 PDFs with metadata
[+] Phase 4 — History & Reputation
    [+] Wayback: First archived 2019-05-01 | 834 snapshots
    [!] VirusTotal: 2 vendors flagged this domain ⚠
[+] Phase 5 — Report Generated
    [+] report.html → ./output/example.com_report/
    [+] report.json → ./output/example.com_report/
    [+] graph.html  → ./output/example.com_report/
[*] Scan complete. Risk Score: 62/100 (MEDIUM)
```

---

## 6. Risk Scoring System

Each finding contributes to a 0–100 risk score:

| Finding | Score Impact |
|---|---|
| Domain age < 6 months | +20 |
| Missing DMARC record | +10 |
| Missing SPF record | +10 |
| SSL expiring < 30 days | +15 |
| SSL expired | +25 |
| Missing security headers (CSP, HSTS) | +5 each |
| VirusTotal positive flag | +20 per vendor |
| Google Safe Browsing flag | +30 |
| Outdated CMS version detected | +10 |
| Exposed .git or .env reference | +25 |
| No HTTPS on subdomains | +10 |

**Score bands:**
- 0–30: LOW
- 31–60: MEDIUM
- 61–80: HIGH
- 81–100: CRITICAL

---

## 7. APIs Needed & How to Get Them

| API | Free Tier | Where to Get |
|---|---|---|
| VirusTotal | 4 requests/min | virustotal.com/gui/join-us |
| Google Safe Browsing | Free | console.cloud.google.com |
| AbuseIPDB | 1000 req/day | abuseipdb.com |
| Shodan | Limited (1 credit) | shodan.io (student discount available) |

All others (crt.sh, Wayback Machine, WHOIS, DNS) — **completely free, no key needed.**

Store keys in `config.yaml`, never hardcoded:
```yaml
api_keys:
  virustotal: "your-key-here"
  google_safebrowsing: "your-key-here"
  abuseipdb: "your-key-here"
  shodan: ""  # optional
```

---

## 8. Development Timeline (10 Weeks)

### Week 1 — Setup & Architecture
- Set up GitHub repo, folder structure
- Write `requirements.txt`
- Implement `core/logger.py` and `core/target.py`
- Write `config.yaml` schema
- Get all API keys registered

### Week 2 — Phase 1 (Root Scan)
- Implement `whois_lookup.py`
- Implement `dns_recon.py`
- Implement `ssl_cert.py`
- Test all 3 against 3–4 real domains
- Basic terminal output working

### Week 3 — Phase 1 cont. + Tech Fingerprinting
- Implement `tech_fingerprint.py`
- Build tech signature pattern library (regex patterns for 20+ common stacks)
- Implement `core/orchestrator.py` skeleton
- Connect Phase 1 modules through orchestrator

### Week 4 — Phase 2 (Subdomain Spread)
- Implement crt.sh querying in `subdomain_enum.py`
- Implement DNS brute force
- Implement SANs feeding from Phase 1
- Implement recursive Phase 1 per subdomain
- **This is the hardest week — get async/concurrency right here**

### Week 5 — Phase 3 (Surface Crawl)
- Implement `crawler.py` with configurable depth
- Implement robots.txt parsing
- Implement `email_extractor.py`
- Test crawl on your own test domain

### Week 6 — Phase 3 cont. + Phase 4
- Implement `metadata_extractor.py`
- Implement `wayback.py`
- Implement `reputation.py` (VirusTotal + Google Safe Browsing)
- Connect all modules to orchestrator

### Week 7 — Risk Scoring + JSON Report
- Implement risk scoring logic in `report/generator.py`
- Implement JSON report assembly
- Write risk flag detection per module
- Test end-to-end: input domain → JSON report

### Week 8 — HTML Report + Graph
- Build Jinja2 HTML template (`report.html`)
- Implement `report/graph.py` with NetworkX + PyVis
- Style the HTML report
- Test full pipeline → HTML + graph output

### Week 9 — CLI Polish + Error Handling
- Finalize all CLI flags in `venom.py`
- Add rate limit handling (sleep between requests)
- Add timeout handling per module
- Handle edge cases: domain not found, API key missing, etc.
- Add `--verbose` and `--quiet` modes

### Week 10 — Testing + Documentation + Demo Prep
- Test against 5+ real domains (your own or bug bounty targets in scope)
- Write `README.md` with architecture diagram
- Add ethical use disclaimer
- Prepare demo script for college presentation
- Record demo video as backup

---

## 9. Requirements File

```
requests==2.31.0
httpx==0.27.0
dnspython==2.6.1
python-whois==0.9.4
beautifulsoup4==4.12.3
lxml==5.2.1
cryptography==42.0.5
networkx==3.3
pyvis==0.3.2
Jinja2==3.1.4
PyYAML==6.0.1
asyncio==3.4.3
exifread==3.0.0
PyPDF2==3.0.1
Pillow==10.3.0
colorama==0.4.6
tqdm==4.66.4
```

---

## 10. What to Present at College

**Live demo flow (7 minutes):**
1. Show the CLI help menu — looks professional
2. Run a scan live on a domain you own or a CTF/practice domain
3. Show the terminal output building in real time (the Venom spread)
4. Open `report.html` in browser — show the structured report
5. Open `graph.html` — show the interactive visual graph, explain the node colours
6. Pull up 1–2 flagged risk indicators and explain what they mean

**Slides structure:**
1. Problem — existing tools do one thing, analysts stitch them manually
2. Solution — Venom: recursive spread, one input, full report
3. Architecture diagram
4. Phase walkthrough (one slide per phase)
5. Risk scoring model
6. Live demo
7. Ethical use + legal boundaries
8. Future scope
9. Tech stack

**Future scope slide (shows depth):**
- Scheduled recurring scans (cron job) + diff reports (what changed?)
- Slack/Discord webhook alerts for risk changes
- Web UI (Flask) so non-technical users can use it
- CVE matching on detected tech versions (pull from NVD API)
- Export to PDF

---

## 11. Ethical Use Policy (Put This in README)

```
VENOM is designed for legal, passive OSINT only.
Use only against:
  - Domains you own
  - Domains you have explicit written permission to test
  - Bug bounty targets explicitly listed in scope

This tool does not exploit, inject, brute-force credentials,
or perform any active attack. All data gathered is publicly
available through open sources.

Unauthorized use against third-party systems may violate
the IT Act 2000 (India) and equivalent laws in your jurisdiction.
The authors accept no liability for misuse.
```


Good instinct. The core is the engine — but right now it reads like a well-built script, not a product people would actually talk about. Here's where the "this is different" comes from:

The 5 Special Layers That Change Everything
1. AI Analyst Layer — The "So What" Engine

Every existing OSINT tool gives you data. None of them tell you what it means.

After all phases complete, pipe the full JSON findings into Claude/GPT API and generate:

A written analyst narrative per phase: "The dev.example.com subdomain runs an outdated Nginx version with no HSTS header and its SSL cert expires in 9 days — this is a neglected shadow IT surface, a common phishing infrastructure target"
An executive summary (non-technical, 5 bullets — what a CEO or client reads)
A technical summary (what a pentest report looks like)
Suggested remediation steps per finding

Why this is novel: No OSINT tool has an LLM interpretation layer. You go from raw data → actual intelligence. That's the literal definition of the field.

2. CVE Matching — Tech Fingerprints → Known Vulnerabilities

You detect that a site runs WordPress 6.2, Apache 2.4.49, OpenSSL 1.0.2.

Right now Venom just logs that. Add NVD (National Vulnerability Database) API lookup:

For every detected technology + version → query NVD API for known CVEs
Output: "WordPress 6.2 → CVE-2024-4439 (CVSS 8.8, Critical) — Unauthenticated stored XSS"
Risk score automatically bumps based on CVSS severity

NVD API is completely free. This turns your tech fingerprinter from "WordPress detected" into "WordPress detected — here are 3 CVEs you need to patch immediately." That's the difference between a recon tool and an attack surface analyzer.

3. GitHub Dorking — The Secret Leak Hunter

Search GitHub's public API for code referencing the target domain:

Leaked API keys, tokens, passwords in public repos
Internal endpoints accidentally committed
Infrastructure details in config files
Employee personal repos that reference company systems
github.com/search?q="example.com"+password&type=code
github.com/search?q="example.com"+api_key&type=code

Why it matters: This is how real attackers find credentials before touching a single server. No mainstream OSINT tool does this automatically as part of a domain scan. Finding a leaked AWS key in a dev's public repo during a scan demo is an unforgettable moment.

4. Delta Mode — Change Intelligence

Run Venom twice on the same domain. Get a diff report:

CHANGES DETECTED since last scan (7 days ago):
  + 3 new subdomains appeared (staging2, api-v2, internal)
  - SSL cert changed (reissued — possible certificate rotation or breach response)
  - payments.example.com no longer resolves (taken down?)
  + 2 new emails found in metadata
  ! VirusTotal flags increased from 0 → 2

Store scan results in a lightweight SQLite DB. On each scan, compare against the previous. This turns Venom from a one-time tool into a continuous monitoring system.

Why it's in demand: Bug bounty hunters, security teams, and researchers need to watch targets over time. This is a feature enterprise tools charge for.

5. Rich Terminal UI — The First Impression

The difference between a tool people share and one they forget is often just how it looks running.

Replace plain print() with the Rich Python library:

╔══════════════════════════════════════════╗
║         VENOM  v1.0  |  ACTIVE SCAN      ║
╠══════════════════════════════════════════╣
║  Target: example.com                     ║
║  Phase 2: Subdomain Spread ████████░░ 82%║
╠══════════════════════════════════════════╣
║  Found so far:                           ║
║  Subdomains    ▸ 23                      ║
║  Emails        ▸ 8                       ║
║  Risk Flags    ▸ 4  ⚠                   ║
║  CVEs Matched  ▸ 2  🔴                  ║
╚══════════════════════════════════════════╝

Live-updating progress panels, colour-coded findings, animated spinner per module. When you demo this at college, people stop and watch.

Library: rich — takes 2 days to implement, changes everything visually.

Updated Architecture With Special Layers
Phases 1–4 (core) 
        ↓
[NEW] GitHub Dorking module
[NEW] CVE Matcher (NVD API per detected tech)
        ↓
[NEW] AI Analyst (LLM call → narrative + exec summary)
        ↓
Report Generator
        ↓
[NEW] Delta Engine (compare vs previous scan → diff)
What You Now Have to Pitch

"Venom is the only OSINT tool that combines recursive domain spread with CVE matching, GitHub secret detection, AI-generated analyst narrative, and continuous change monitoring — in a single command."

Every other tool does one of those. You do all five together. That's the product.

Want me to update the full implementation plan document with these layers, or go straight to writing the AI analyst module and CVE matcher code?

---

## 12. What Makes Venom Different

| Feature | Venom | theHarvester | SpiderFoot | Maltego |
|---|---|---|---|---|
| Recursive subdomain spread | ✅ | ❌ | Partial | ❌ |
| Historical analysis | ✅ | ❌ | ❌ | ❌ |
| Visual graph output | ✅ | ❌ | ❌ | ✅ (paid) |
| Risk scoring | ✅ | ❌ | Partial | ❌ |
| Single pipeline, one command | ✅ | ✅ | Partial | ❌ |
| Free, no license | ✅ | ✅ | ✅ | ❌ (paid) |
| Metadata extraction | ✅ | ❌ | ❌ | ❌ |
| Reputation + Wayback combined | ✅ | ❌ | Partial | ❌ |

---

*Built by Mayank — Venom OSINT Framework*
