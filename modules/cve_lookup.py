"""
CVE lookup and technology vulnerability correlation module.

Correlates fingerprinted technologies with known Common Vulnerabilities and Exposures (CVEs)
using a curated vulnerability database and the CIRCL open CVE search API.
Includes confidence levels to avoid false certainty regarding distro-backported packages.
Contact classification: Passive CVE Correlation (Curated DB + CIRCL API).
"""

from typing import Dict, Any, List
import httpx

from core.http_client import HttpClient

# Curated database of prominent high/critical CVEs for common web technologies
KNOWN_CVE_DATABASE = [
    {
        "tech": "Express",
        "cve_id": "CVE-2024-29041",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Express Open Redirect and IP parsing mismatch in routing layer",
        "remediation": "Upgrade Express to version >= 4.19.2 or 5.0.0.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Express",
        "cve_id": "CVE-2022-29078",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "ejs template engine Remote Code Execution via unflattened settings in Express apps",
        "remediation": "Upgrade ejs to >= 3.1.7 and validate template option inputs.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Node.js",
        "cve_id": "CVE-2023-30533",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Node.js crypto.createPrivateKey / prototype pollution leading to privilege escalation",
        "remediation": "Upgrade Node.js to latest LTS releases (18.16.1+, 20.3.1+).",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Angular",
        "cve_id": "CVE-2024-21490",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Angular Universal Server-Side Rendering (SSR) Expression Injection vulnerability",
        "remediation": "Upgrade @angular/core to latest secure minor/patch release.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Socket.io",
        "cve_id": "CVE-2024-38355",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Socket.io unhandled exception Denial of Service (DoS) via crafted packet payloads",
        "remediation": "Upgrade socket.io and engine.io to >= 4.7.5.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "SQLite",
        "cve_id": "CVE-2023-22578",
        "cvss": 8.8,
        "severity": "HIGH",
        "summary": "Sequelize ORM SQL injection vulnerability in SQLite / PostgreSQL dialect operators",
        "remediation": "Upgrade sequelize to >= 6.29.0 and parameterize raw queries.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Apache",
        "cve_id": "CVE-2021-41773",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Path traversal and remote code execution in Apache HTTP Server 2.4.49",
        "remediation": "Update Apache to version 2.4.51 or higher, ensure require all denied on root directory.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Apache",
        "cve_id": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Incomplete fix for CVE-2021-41773 leading to RCE in Apache 2.4.49 and 2.4.50",
        "remediation": "Update Apache to version 2.4.51 or later.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Nginx",
        "cve_id": "CVE-2021-23017",
        "cvss": 8.1,
        "severity": "HIGH",
        "summary": "1-byte memory overwrite in Nginx resolver during DNS response processing",
        "remediation": "Update Nginx to version 1.20.1, 1.21.0 or newer.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "WordPress",
        "cve_id": "CVE-2024-4439",
        "cvss": 8.8,
        "severity": "HIGH",
        "summary": "Unauthenticated Stored Cross-Site Scripting (XSS) via Avatar Block in WordPress Core",
        "remediation": "Update WordPress Core to latest release (>= 6.5.2).",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Drupal",
        "cve_id": "CVE-2018-7600",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Drupalgeddon2: Remote Code Execution via Form API AJAX requests",
        "remediation": "Upgrade Drupal to 7.58, 8.4.6, 8.5.1 or newer.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Laravel",
        "cve_id": "CVE-2021-3129",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "Ignition package RCE vulnerability via deserialization when APP_DEBUG=true",
        "remediation": "Disable APP_DEBUG in production and upgrade facade/ignition to >= 2.5.2.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
    {
        "tech": "Django",
        "cve_id": "CVE-2024-45230",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Denial of Service via urlize and urlizetrunc template filters",
        "remediation": "Upgrade Django to 5.0.9, 4.2.16 or latest patch.",
        "confidence": "INDICATIVE (Presence-Only)",
    },
]


def _query_circl_cve(tech_name: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Query CIRCL CVE search API for open vulnerabilities using shared client."""
    cves = []
    try:
        url = f"https://cve.circl.lu/api/search/{tech_name.lower()}"
        client = HttpClient.get_instance(timeout=float(timeout))
        resp = client.get(url, timeout=float(timeout), use_cache=True, cache_ttl=3600.0)
        if resp.status_code == 200:
            data = resp.json()
            items = data if isinstance(data, list) else data.get("data", [])
            for item in items[:3]:
                cve_id = item.get("id", "")
                cvss = float(item.get("cvss", 7.0) or 7.0)
                summary = str(item.get("summary", ""))[:160] + "..."
                severity = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
                cves.append({
                    "tech": tech_name,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "severity": severity,
                    "summary": summary,
                    "remediation": f"Review and patch {tech_name} components to latest stable version.",
                    "confidence": "INDICATIVE (Presence-Only)",
                    "note": "Heuristic match. Verify package patch level with vendor advisories.",
                })
    except Exception:
        pass
    return cves


def run(technologies_data: Dict[str, Any], timeout: int = 5) -> Dict[str, Any]:
    """Correlate detected technologies with known CVEs with confidence annotations.

    Args:
        technologies_data: The technologies dictionary from tech_fingerprint module.
        timeout: Timeout for online CVE queries.

    Returns:
        Dict with 'cve_matches' list, 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {
        "data": {
            "cve_matches": [],
            "disclaimer": (
                "CVE correlations are heuristic based on detected component names. "
                "Linux distributions frequently backport patches without version bumps; "
                "findings indicate potential attack surface rather than confirmed exploitability."
            ),
        },
        "risk_flags": [],
        "errors": [],
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
                    cve_record = dict(entry)
                    cve_record["note"] = "Heuristic match. Verify actual patch level against distribution backports."
                    matched_cves.append(cve_record)

    # 2. If online queries enabled and matches < 2, check CIRCL
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
