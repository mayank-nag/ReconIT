"""
Subdomain enumeration module.

Discovers subdomains using three layers:
1. Certificate Transparency (crt.sh) - Passive OSINT
2. DNS brute force from wordlist - Direct Low-Impact Query
3. SANs from SSL certificate inspection - Passive Inspection

Features built-in Wildcard DNS detection and ScopeGuard enforcement to
eliminate false positives and out-of-scope third-party domains.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import dns.resolver

from core.http_client import HttpClient
from core.scope import ScopeGuard, WildcardDnsDetector


def _query_crtsh(domain: str, timeout: int = 20) -> List[str]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        client = HttpClient.get_instance(timeout=float(timeout))
        resp = client.get(url, use_cache=True, cache_ttl=600.0)
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass

    return list(subdomains)


def _dns_bruteforce(
    domain: str,
    max_checks: int = 200,
    timeout: int = 3,
    wildcard_detector: Optional[WildcardDnsDetector] = None,
) -> List[str]:
    """Brute force subdomains from wordlist via DNS resolution, filtering wildcard false positives."""
    subdomains = set()

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
            answers = resolver.resolve(candidate, "A")
            resolved_ips = [str(rdata) for rdata in answers]

            # Filter out wildcard false positives
            if wildcard_detector and wildcard_detector.is_false_positive(resolved_ips):
                continue

            subdomains.add(candidate)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
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
        or (
            d.startswith("172.")
            and 16 <= int(d.split(".")[1]) <= 31
            if len(d.split(".")) > 1 and d.split(".")[1].isdigit()
            else False
        )
        or all(part.isdigit() for part in d.split("."))
    )


def run(
    domain: str,
    sans: Optional[List[str]] = None,
    max_subdomains: int = 100,
    timeout: int = 10,
    scope_guard: Optional[ScopeGuard] = None,
) -> Dict[str, Any]:
    """Enumerate subdomains with wildcard filtering and scope boundaries.

    Args:
        domain: Root domain to enumerate subdomains for.
        sans: Optional list of Subject Alternative Names from SSL cert.
        max_subdomains: Maximum number of subdomains to return.
        timeout: Timeout for network requests in seconds.
        scope_guard: Optional ScopeGuard instance to ensure subdomains remain in-scope.

    Returns:
        Dict with discovered subdomains, sources, wildcard status, and errors.
    """
    result: Dict[str, Any] = {
        "data": {
            "subdomains": [],
            "sources": {},
            "wildcard_dns": False,
            "wildcard_ips": [],
        },
        "risk_flags": [],
        "errors": [],
    }

    clean_domain = domain.split(":")[0].lower()
    if _is_local_host(clean_domain):
        result["data"]["subdomains"] = []
        result["data"]["total"] = 0
        result["data"]["sources"] = {"local_target": "Subdomain enum skipped for local/IP target"}
        return result

    guard = scope_guard or ScopeGuard(clean_domain)

    # Step 0: Check for Wildcard DNS
    wildcard_detector = WildcardDnsDetector(clean_domain, timeout=min(3.0, float(timeout)))
    is_wildcard, wildcard_ips = wildcard_detector.check()
    result["data"]["wildcard_dns"] = is_wildcard
    result["data"]["wildcard_ips"] = list(wildcard_ips)

    all_subdomains: Dict[str, str] = {}  # subdomain -> source

    # Layer 1: Certificate Transparency (Passive)
    try:
        crtsh_results = _query_crtsh(clean_domain, timeout=timeout)
        for sub in crtsh_results:
            if sub != clean_domain and guard.is_in_scope(sub):
                if sub not in all_subdomains:
                    all_subdomains[sub] = "crt.sh (Passive CT Log)"
        result["data"]["sources"]["crt.sh"] = len(crtsh_results)
    except Exception as e:
        result["errors"].append(f"crt.sh query failed: {str(e)}")
        result["data"]["sources"]["crt.sh"] = 0

    # Layer 2: DNS Brute Force (Active contact, filtered if wildcard)
    try:
        brute_results = _dns_bruteforce(
            clean_domain,
            max_checks=max_subdomains * 2,
            timeout=timeout,
            wildcard_detector=wildcard_detector,
        )
        new_from_brute = 0
        for sub in brute_results:
            if sub != clean_domain and guard.is_in_scope(sub):
                if sub not in all_subdomains:
                    all_subdomains[sub] = "dns_brute (Active Resolution)"
                    new_from_brute += 1
        result["data"]["sources"]["dns_brute"] = new_from_brute
    except Exception as e:
        result["errors"].append(f"DNS brute force failed: {str(e)}")
        result["data"]["sources"]["dns_brute"] = 0

    # Layer 3: SANs from SSL (Passive)
    if sans:
        try:
            san_results = _filter_sans(clean_domain, sans)
            new_from_sans = 0
            for sub in san_results:
                if guard.is_in_scope(sub) and sub not in all_subdomains:
                    all_subdomains[sub] = "ssl_sans (Passive Cert Data)"
                    new_from_sans += 1
            result["data"]["sources"]["ssl_sans"] = new_from_sans
        except Exception as e:
            result["errors"].append(f"SAN filtering failed: {str(e)}")
            result["data"]["sources"]["ssl_sans"] = 0

    # Final filter through ScopeGuard and cap
    in_scope_subs = [s for s in sorted(all_subdomains.keys()) if guard.is_in_scope(s)]
    unique_subs = in_scope_subs[:max_subdomains]

    result["data"]["subdomains"] = unique_subs
    result["data"]["total"] = len(unique_subs)

    return result
