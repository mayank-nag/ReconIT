"""
CVE lookup and technology vulnerability correlation module.

Correlates fingerprinted technologies with known Common Vulnerabilities and Exposures (CVEs)
using a curated vulnerability database and the CIRCL / NVD open CVE search APIs.
"""

from typing import Dict, Any, List
import requests

# Curated database of prominent high/critical CVEs for common web technologies
KNOWN_CVE_DATABASE = [
    {
        "tech": "Express",
        "cve_id": "CVE-2024-29041",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Express Open Redirect and IP parsing mismatch in routing layer",
        "remediation": "Upgrade Express to version >= 4.19.2 or 5.0.0.",
    },
    {
        "tech": "Express",
        "cve_id": "CVE-2022-29078",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "ejs template engine Remote Code Execution via unflattened settings in Express apps",
        "remediation": "Upgrade ejs to >= 3.1.7 and validate template option inputs.",
    },
    {
        "tech": "Node.js",
        "cve_id": "CVE-2023-30533",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Node.js crypto.createPrivateKey / prototype pollution leading to privilege escalation",
        "remediation": "Upgrade Node.js to latest LTS releases (18.16.1+, 20.3.1+).",
    },
    {
        "tech": "Angular",
        "cve_id": "CVE-2024-21490",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Angular Universal Server-Side Rendering (SSR) Expression Injection vulnerability",
        "remediation": "Upgrade @angular/core to latest secure minor/patch release.",
    },
    {
        "tech": "Angular",
        "cve_id": "CVE-2022-25869",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "AngularJS and Angular sanitization bypass allowing DOM-based Cross-Site Scripting (XSS)",
        "remediation": "Migrate deprecated Angular versions and enforce strict DomSanitizer policies.",
    },
    {
        "tech": "Socket.io",
        "cve_id": "CVE-2024-38355",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Socket.io unhandled exception Denial of Service (DoS) via crafted packet payloads",
        "remediation": "Upgrade socket.io and engine.io to >= 4.7.5.",
    },
    {
        "tech": "SQLite",
        "cve_id": "CVE-2023-22578",
        "cvss": 8.8,
        "severity": "HIGH",
        "summary": "Sequelize ORM SQL injection vulnerability in SQLite / PostgreSQL dialect operators",
        "remediation": "Upgrade sequelize to >= 6.29.0 and parameterize raw queries.",
    },
    {
        "tech": "Apache",
        "cve_id": "CVE-2021-41773",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Path traversal and remote code execution in Apache HTTP Server 2.4.49",
        "remediation": "Update Apache to version 2.4.51 or higher, ensure require all denied on root directory.",
    },
    {
        "tech": "Apache",
        "cve_id": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Incomplete fix for CVE-2021-41773 leading to RCE in Apache 2.4.49 and 2.4.50",
        "remediation": "Update Apache to version 2.4.51 or later.",
    },
    {
        "tech": "Nginx",
        "cve_id": "CVE-2021-23017",
        "cvss": 8.1,
        "severity": "HIGH",
        "summary": "1-byte memory overwrite in Nginx resolver during DNS response processing",
        "remediation": "Update Nginx to version 1.20.1, 1.21.0 or newer.",
    },
    {
        "tech": "WordPress",
        "cve_id": "CVE-2024-4439",
        "cvss": 8.8,
        "severity": "HIGH",
        "summary": "Unauthenticated Stored Cross-Site Scripting (XSS) via Avatar Block in WordPress Core",
        "remediation": "Update WordPress Core to latest release (>= 6.5.2).",
    },
    {
        "tech": "Drupal",
        "cve_id": "CVE-2018-7600",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Drupalgeddon2: Remote Code Execution via Form API AJAX requests",
        "remediation": "Upgrade Drupal to 7.58, 8.4.6, 8.5.1 or newer.",
    },
    {
        "tech": "Laravel",
        "cve_id": "CVE-2021-3129",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Ignition package RCE vulnerability via deserialization when APP_DEBUG=true",
        "remediation": "Disable APP_DEBUG in production and upgrade facade/ignition to >= 2.5.2.",
    },
    {
        "tech": "Django",
        "cve_id": "CVE-2024-45230",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Denial of Service via urlize and urlizetrunc template filters",
        "remediation": "Upgrade Django to 5.0.9, 4.2.16 or latest patch.",
    },
    {
        "tech": "LiteSpeed",
        "cve_id": "CVE-2024-47374",
        "cvss": 8.8,
        "severity": "HIGH",
        "summary": "Unauthenticated RCE in LiteSpeed Cache WordPress Plugin",
        "remediation": "Update LiteSpeed Cache plugin to >= 6.5.0.1.",
    },
    {
        "tech": "IIS",
        "cve_id": "CVE-2022-21907",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "HTTP Protocol Stack Remote Code Execution Vulnerability (HTTP.sys)",
        "remediation": "Apply Microsoft monthly security rollups for Windows Server.",
    },
]


def _query_circl_cve(tech_name: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Query CIRCL CVE search API for open vulnerabilities."""
    cves = []
    try:
        url = f"https://cve.circl.lu/api/search/{tech_name.lower()}"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            items = data if isinstance(data, list) else data.get("data", [])
            for item in items[:3]:
                cve_id = item.get("id", "")
                cvss = float(item.get("cvss", 7.0) or 7.0)
                summary = item.get("summary", "")[:160] + "..."
                severity = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
                cves.append({
                    "tech": tech_name,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "severity": severity,
                    "summary": summary,
                    "remediation": f"Review and patch {tech_name} components to latest stable version.",
                })
    except Exception:
        pass
    return cves


def run(technologies_data: Dict[str, Any], timeout: int = 5) -> Dict[str, Any]:
    """Correlate detected technologies with known CVEs.

    Args:
        technologies_data: The technologies dictionary from tech_fingerprint module.
        timeout: Timeout for online CVE queries.

    Returns:
        Dict with 'cve_matches' list, 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {
        "data": {"cve_matches": []},
        "risk_flags": [],
        "errors": []
    }

    detected_techs = set()
    server = technologies_data.get("server")
    if server:
        detected_techs.add(server)
    cms = technologies_data.get("cms")
    if cms:
        detected_techs.add(cms)
    for fw in technologies_data.get("frameworks", []):
        detected_techs.add(fw)
    for item in technologies_data.get("detected_technologies", []):
        detected_techs.add(item)

    if not detected_techs:
        return result

    matched_cves = []
    seen_cve_ids = set()

    # 1. Match against curated database
    for tech in detected_techs:
        tech_lower = tech.lower()
        for entry in KNOWN_CVE_DATABASE:
            if entry["tech"].lower() in tech_lower or tech_lower in entry["tech"].lower():
                if entry["cve_id"] not in seen_cve_ids:
                    seen_cve_ids.add(entry["cve_id"])
                    matched_cves.append(entry)

    # 2. If online queries enabled and matches < 2, optionally check CIRCL
    if len(matched_cves) < 2:
        for tech in list(detected_techs)[:2]:
            api_cves = _query_circl_cve(tech, timeout=timeout)
            for c in api_cves:
                if c["cve_id"] not in seen_cve_ids:
                    seen_cve_ids.add(c["cve_id"])
                    matched_cves.append(c)

    result["data"]["cve_matches"] = matched_cves

    if any(c["cvss"] >= 7.0 for c in matched_cves):
        result["risk_flags"].append("Known Critical/High CVE matched")

    return result
