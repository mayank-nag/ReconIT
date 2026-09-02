"""
AI Analyst Layer — Intelligence Interpretation Module.

Transforms raw OSINT data into actionable security intelligence,
providing executive summaries, technical narratives, threat vectors,
and prioritized remediation roadmaps.
"""

from typing import Dict, Any, List


def generate_local_analysis(target_data: Dict[str, Any]) -> Dict[str, Any]:
    """Rule-based expert cybersecurity analysis engine that runs 100% offline."""
    domain = target_data.get("target") or target_data.get("domain", "unknown")
    risk_score = target_data.get("risk_score", 0)
    risk_level = target_data.get("risk_level", "LOW")
    risk_flags = target_data.get("risk_flags", [])
    subdomains = target_data.get("subdomains", [])
    technologies = target_data.get("technologies", {})
    dns_data = target_data.get("dns_data", {})
    ssl_data = target_data.get("ssl_data", {})
    whois_data = target_data.get("whois_data", {})
    cve_matches = target_data.get("cve_matches", [])
    reputation_data = target_data.get("reputation_data", {})
    emails_found = target_data.get("emails_found", [])
    metadata_findings = target_data.get("metadata_findings", [])
    pages_crawled = target_data.get("pages_crawled", [])
    is_local = target_data.get("is_local", False)

    # 1. Executive Summary Bullets
    exec_bullets = []
    exec_bullets.append(
        f"Overall Security Posture for **{domain}** is assessed as **{risk_level}** (Risk Score: {risk_score}/100)."
    )

    if subdomains:
        exec_bullets.append(
            f"Discovered **{len(subdomains)}** exposed subdomains, representing an expanded perimeter and potential shadow IT surface."
        )
    else:
        exec_bullets.append(f"Perimeter scan identified a concentrated single-host surface with {len(pages_crawled)} mapped endpoints.")

    # Email spoofing check
    has_missing_spf = any("SPF" in str(f.get("flag", "")) for f in risk_flags)
    has_missing_dmarc = any("DMARC" in str(f.get("flag", "")) for f in risk_flags)
    if not is_local:
        if has_missing_spf or has_missing_dmarc:
            exec_bullets.append(
                "Email authentication controls are deficient (missing SPF/DMARC), exposing the organization to brand impersonation and spoofing."
            )
        else:
            exec_bullets.append("Email security records (SPF/DMARC) are configured, helping mitigate basic direct-domain spoofing.")

    # CVE / Tech
    if cve_matches:
        exec_bullets.append(
            f"Correlated **{len(cve_matches)}** known CVE vulnerability disclosures against detected application technologies ({', '.join(set(c['tech'] for c in cve_matches))})."
        )

    # Sensitive endpoints
    sensitive_pages = [p for p in pages_crawled if any(k in p.get("url", "").lower() for k in ["/.env", "/.git", "/ftp", "/package.json", "/api-docs"])]
    if sensitive_pages:
        exec_bullets.append(
            f"⚠️ Exposed sensitive endpoints or directories detected ({len(sensitive_pages)} locations including {', '.join(p.get('url', '').split('/')[-1] or p.get('url', '') for p in sensitive_pages[:3])})."
        )

    # Reputation
    vt_pos = reputation_data.get("virustotal_positives", 0)
    if vt_pos > 0:
        exec_bullets.append(f"Domain flagged by {vt_pos} security vendor(s) on VirusTotal, indicating potential historical or active reputation blacklisting.")

    # 2. Detailed Technical Narrative
    narrative_sections = []

    # Section A: Perimeter & Infrastructure
    infra_text = []
    registrar = whois_data.get("registrar", "Unknown Registrar")
    reg_date = whois_data.get("registration_date", "Unknown")
    infra_text.append(f"The domain **{domain}** is associated with **{registrar}** (Registration Date: {reg_date}).")
    if any("young_domain" in str(f.get("flag", "")) or "age < 6" in str(f.get("flag", "")) for f in risk_flags):
        infra_text.append("⚠️ The domain was registered within the last 6 months, a risk trait frequently associated with newly spun-up phishing or disposable campaigns.")

    a_records = dns_data.get("A", [])
    if a_records:
        infra_text.append(f"DNS resolution points to IP addresses: {', '.join(a_records)}.")
    
    ssl_expiry = ssl_data.get("not_after", "N/A")
    if "Plain HTTP" in ssl_expiry or "No SSL" in ssl_expiry:
        infra_text.append("The target operates over unencrypted HTTP without valid SSL/TLS, leaving communications vulnerable to interception and MITM tampering.")
    else:
        infra_text.append(f"SSL/TLS certificate is active (Valid until {ssl_expiry}) with {len(ssl_data.get('sans', []))} Subject Alternative Names.")

    narrative_sections.append({"title": "Perimeter & Infrastructure Analysis", "content": " ".join(infra_text)})

    # Section B: Attack Surface & Shadow IT
    surface_text = []
    if subdomains:
        surface_text.append(f"A total of {len(subdomains)} subdomains were mapped via certificate transparency logs and DNS enumeration.")
        interesting_subs = [s for s in subdomains if any(k in s for k in ["api", "dev", "staging", "admin", "vpn", "test", "internal", "portal"])]
        if interesting_subs:
            surface_text.append(f"High-value targets identified: {', '.join(interesting_subs)}. Staging and development environments often lack production-grade security headers.")
    else:
        surface_text.append(f"Perimeter reconnaissance mapped {len(pages_crawled)} endpoints and routes across the target.")
    narrative_sections.append({"title": "Attack Surface & Exposure", "content": " ".join(surface_text)})

    # Section C: Application & Technology Stack
    tech_text = []
    server = technologies.get("server", "Unknown")
    cms = technologies.get("cms", "None detected")
    frameworks = technologies.get("frameworks", [])
    framework_str = ", ".join(frameworks) if frameworks else "None explicitly detected"
    tech_text.append(f"The target runs on **{server}** with frameworks: **{framework_str}**, and CMS: **{cms}**.")
    
    sec_headers = technologies.get("security_headers", {})
    missing_headers = [h for h, s in sec_headers.items() if s == "missing"]
    if missing_headers:
        tech_text.append(f"Critical security headers missing: {', '.join(missing_headers)}. Lack of CSP (Content Security Policy) leaves users susceptible to Cross-Site Scripting (XSS), while missing HSTS permits SSL stripping downgrade attacks.")
    narrative_sections.append({"title": "Application & Defense Controls", "content": " ".join(tech_text)})

    # 3. Top Prioritized Remediation Roadmap
    remediations = []
    if any("Exposed" in str(f.get("flag", "")) for f in risk_flags) or sensitive_pages:
        remediations.append({
            "priority": "P1 (Critical)",
            "action": "Restrict Public Access to Sensitive Endpoints",
            "details": "Disable public directory listings, block access to administrative routes, /ftp, /.git, and configuration artifacts."
        })
    if cve_matches:
        remediations.append({
            "priority": "P1 (High)",
            "action": "Patch Known Framework CVEs",
            "details": f"Upgrade and patch identified components ({', '.join(set(c['tech'] for c in cve_matches))}) to recent vendor releases."
        })
    if "CSP" in missing_headers or "HSTS" in missing_headers:
        remediations.append({
            "priority": "P2 (Medium)",
            "action": "Harden HTTP Security Headers",
            "details": "Deploy Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Content-Type-Options: nosniff, and X-Frame-Options: DENY."
        })
    if has_missing_dmarc and not is_local:
        remediations.append({
            "priority": "P2 (Medium)",
            "action": "Implement DMARC Policy",
            "details": "Publish a _dmarc TXT record with at least p=quarantine or p=reject to prevent email spoofing."
        })
    if has_missing_spf and not is_local:
        remediations.append({
            "priority": "P2 (Medium)",
            "action": "Configure SPF TXT Record",
            "details": "Authorize legitimate outbound mail servers in the domain DNS TXT records (v=spf1)."
        })
    if emails_found or metadata_findings:
        remediations.append({
            "priority": "P3 (Low)",
            "action": "Scrub Public Document Metadata",
            "details": "Sanitize author names, creator tools, and GPS EXIF data from public PDFs and imagery before web deployment."
        })

    if not remediations:
        remediations.append({
            "priority": "P3 (Maintenance)",
            "action": "Maintain Routine Security Hygiene",
            "details": "Perform periodic certificate rotation checks and continuous OSINT attack surface monitoring."
        })

    return {
        "executive_summary": exec_bullets,
        "narrative_sections": narrative_sections,
        "remediation_roadmap": remediations,
    }


def run(target_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate AI Analyst intelligence narrative and report summary.

    Args:
        target_data: Dict representation of Target findings.

    Returns:
        Dict with 'ai_analysis' structured data, 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {
        "data": {},
        "risk_flags": [],
        "errors": [],
    }

    try:
        analysis = generate_local_analysis(target_data)
        result["data"] = analysis
    except Exception as e:
        result["errors"].append(f"AI Analyst generation failed: {e}")

    return result
