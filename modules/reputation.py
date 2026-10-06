"""
Reputation and Threat Intelligence Module.

Checks domain/IP reputation across VirusTotal, Google Safe Browsing, and AbuseIPDB
with caching, exponential backoff retries, and graceful degradation for free tier limits.
Contact classification: Passive Third-Party Threat Intel Query.
"""

import socket
from typing import Dict, Any, Optional
import httpx

from core.http_client import HttpClient


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


def run(domain: str, api_keys: Optional[Dict[str, str]] = None, timeout: int = 15) -> Dict[str, Any]:
    """Check community and threat reputation of the target domain/IP."""
    result: Dict[str, Any] = {
        "data": {
            "checks_performed": [],
            "virustotal_positives": 0,
            "virustotal_total": 0,
            "safebrowsing_status": "clean",
            "contact_type": "Passive Third-Party Threat Intel",
        },
        "risk_flags": [],
        "errors": [],
    }
    api_keys = api_keys or {}
    clean_domain = domain.split(":")[0].lower()

    if _is_local_host(clean_domain):
        result["data"]["checks_performed"] = ["local_environment"]
        result["data"]["environment"] = "Private / Local Test Target"
        result["data"]["safebrowsing_status"] = "local"
        return result

    client = HttpClient.get_instance(timeout=float(timeout))

    # 1. VirusTotal Check (4 requests/min free tier, with cache and backoff)
    vt_key = api_keys.get("virustotal")
    if vt_key:
        try:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"
            headers = {"x-apikey": vt_key}
            vt_resp = client.get(
                vt_url,
                headers=headers,
                timeout=float(timeout),
                use_cache=True,
                cache_ttl=900.0,
                max_retries=2,
            )
            if vt_resp.status_code == 200:
                vt_data = vt_resp.json()
                stats = (
                    vt_data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())

                result["data"]["virustotal_positives"] = positives
                result["data"]["virustotal_total"] = total
                result["data"]["checks_performed"].append("virustotal")

                if positives > 0:
                    result["risk_flags"].append("virustotal_flagged")
            elif vt_resp.status_code == 429:
                result["errors"].append("VirusTotal free rate limit (4 req/min) exceeded; degraded gracefully.")
            else:
                result["errors"].append(f"VirusTotal API returned HTTP status {vt_resp.status_code}")
        except Exception as e:
            result["errors"].append(f"VirusTotal check failed: {str(e)}")

    # 2. AbuseIPDB Check (requires resolving domain to IP)
    abuse_key = api_keys.get("abuseipdb")
    if abuse_key:
        try:
            ip = socket.gethostbyname(clean_domain)
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": abuse_key}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            abuse_resp = client.get(
                abuse_url,
                headers=headers,
                params=params,
                timeout=float(timeout),
                use_cache=True,
                cache_ttl=900.0,
            )
            if abuse_resp.status_code == 200:
                abuse_data = abuse_resp.json()
                score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)

                result["data"]["abuseipdb_score"] = score
                result["data"]["checks_performed"].append("abuseipdb")

                if score > 50:
                    result["risk_flags"].append("abuseipdb_flagged")
            elif abuse_resp.status_code == 429:
                result["errors"].append("AbuseIPDB rate limit exceeded; degraded gracefully.")
            else:
                result["errors"].append(f"AbuseIPDB API returned HTTP status {abuse_resp.status_code}")
        except socket.gaierror:
            result["errors"].append("Failed to resolve domain to IP for AbuseIPDB check.")
        except Exception as e:
            result["errors"].append(f"AbuseIPDB check failed: {str(e)}")

    # 3. Google Safe Browsing Check
    gsb_key = api_keys.get("safebrowsing") or api_keys.get("google_safebrowsing")
    if gsb_key:
        try:
            gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}"
            payload = {
                "client": {"clientId": "venom-osint", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{clean_domain}/"}, {"url": f"https://{clean_domain}/"}],
                },
            }
            gsb_resp = client.post(gsb_url, json=payload, timeout=float(timeout))
            if gsb_resp.status_code == 200:
                gsb_data = gsb_resp.json()
                matches = gsb_data.get("matches", [])
                result["data"]["checks_performed"].append("safebrowsing")
                if matches:
                    result["data"]["safebrowsing_status"] = "flagged"
                    result["risk_flags"].append("Google Safe Browsing flag")
                else:
                    result["data"]["safebrowsing_status"] = "clean"
            else:
                result["errors"].append(f"Google Safe Browsing API returned HTTP status {gsb_resp.status_code}")
        except Exception as e:
            result["errors"].append(f"Google Safe Browsing check failed: {str(e)}")

    return result
