"""
Subdomain enumeration module.

Discovers subdomains using three layers:
1. Certificate Transparency (crt.sh)
2. DNS brute force from wordlist
3. SANs from SSL certificate inspection

All sources are passive OSINT — no active scanning.
"""

import dns.resolver
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional


def _query_crtsh(domain: str, timeout: int = 20) -> List[str]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()

        for entry in resp.json():
            name = entry.get("name_value", "")
            # crt.sh returns newline-separated names in some entries
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                # Remove wildcard prefix
                if sub.startswith("*."):
                    sub = sub[2:]
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
    except Exception:
        pass

    return list(subdomains)


def _dns_bruteforce(domain: str, max_checks: int = 200, timeout: int = 3) -> List[str]:
    """Brute force subdomains from wordlist via DNS resolution."""
    subdomains = set()

    # Locate wordlist relative to project root
    wordlist_paths = [
        Path(__file__).parent.parent / "wordlists" / "subdomains.txt",
        Path("wordlists/subdomains.txt"),
    ]

    wordlist = None
    for p in wordlist_paths:
        if p.is_file():
            wordlist = p
            break

    if not wordlist:
        return []

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    words = wordlist.read_text().strip().splitlines()
    for word in words[:max_checks]:
        word = word.strip().lower()
        if not word or word.startswith("#"):
            continue

        candidate = f"{word}.{domain}"
        try:
            resolver.resolve(candidate, "A")
            subdomains.add(candidate)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue

    return list(subdomains)


def _filter_sans(domain: str, sans: List[str]) -> List[str]:
    """Filter SANs to only include subdomains of the target domain."""
    filtered = set()
    for san in sans:
        san = san.strip().lower()
        if san.startswith("*."):
            san = san[2:]
        if san.endswith(f".{domain}") and san != domain:
            filtered.add(san)
    return list(filtered)


def _is_local_host(domain: str) -> bool:
    d = domain.lower().split(":")[0]
    return (
        d in ("localhost", "127.0.0.1", "0.0.0.0", "::1")
        or d.endswith(".local")
        or d.startswith("192.168.")
        or d.startswith("10.")
        or (d.startswith("172.") and 16 <= int(d.split(".")[1]) <= 31 if len(d.split(".")) > 1 and d.split(".")[1].isdigit() else False)
        or all(part.isdigit() for part in d.split("."))
    )


def run(
    domain: str,
    sans: Optional[List[str]] = None,
    max_subdomains: int = 100,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Enumerate subdomains using Certificate Transparency, DNS brute force, and SSL SANs.

    Args:
        domain: Root domain to enumerate subdomains for.
        sans: Optional list of Subject Alternative Names from SSL cert.
        max_subdomains: Maximum number of subdomains to return.
        timeout: Timeout for network requests in seconds.

    Returns:
        Dict with 'data' containing discovered subdomains and sources,
        'risk_flags' list, and 'errors' list.
    """
    result: Dict[str, Any] = {"data": {"subdomains": [], "sources": {}}, "risk_flags": [], "errors": []}

    clean_domain = domain.split(":")[0].lower()
    if _is_local_host(clean_domain):
        result["data"]["subdomains"] = []
        result["data"]["total"] = 0
        result["data"]["sources"] = {"local_target": "Subdomain enum skipped for local/IP target"}
        return result

    all_subdomains: Dict[str, str] = {}  # subdomain -> source

    # Layer 1: Certificate Transparency
    try:
        crtsh_results = _query_crtsh(clean_domain, timeout=timeout)
        for sub in crtsh_results:
            if sub != domain and sub not in all_subdomains:
                all_subdomains[sub] = "crt.sh"
        result["data"]["sources"]["crt.sh"] = len(crtsh_results)
    except Exception as e:
        result["errors"].append(f"crt.sh query failed: {str(e)}")
        result["data"]["sources"]["crt.sh"] = 0

    # Layer 2: DNS Brute Force
    try:
        brute_results = _dns_bruteforce(domain, max_checks=max_subdomains * 2, timeout=timeout)
        new_from_brute = 0
        for sub in brute_results:
            if sub != domain and sub not in all_subdomains:
                all_subdomains[sub] = "dns_brute"
                new_from_brute += 1
        result["data"]["sources"]["dns_brute"] = new_from_brute
    except Exception as e:
        result["errors"].append(f"DNS brute force failed: {str(e)}")
        result["data"]["sources"]["dns_brute"] = 0

    # Layer 3: SANs from SSL
    if sans:
        try:
            san_results = _filter_sans(domain, sans)
            new_from_sans = 0
            for sub in san_results:
                if sub not in all_subdomains:
                    all_subdomains[sub] = "ssl_sans"
                    new_from_sans += 1
            result["data"]["sources"]["ssl_sans"] = new_from_sans
        except Exception as e:
            result["errors"].append(f"SAN filtering failed: {str(e)}")
            result["data"]["sources"]["ssl_sans"] = 0

    # Deduplicate, sort, cap
    unique_subs = sorted(all_subdomains.keys())[:max_subdomains]

    result["data"]["subdomains"] = unique_subs
    result["data"]["total"] = len(unique_subs)

    return result
