"""
Wayback Machine historical snapshot module.

Queries the Internet Archive's Wayback Machine APIs for historical
snapshots of the target domain, including deleted pages.
Contact classification: Passive Third-Party (Archive.org).
"""

from typing import Dict, Any
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


def run(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """Query the Wayback Machine for historical snapshots of the given domain.

    Args:
        domain: Target domain to look up.
        timeout: Request timeout in seconds.

    Returns:
        Dict with 'data' containing snapshot info, 'risk_flags', and 'errors'.
    """
    result: Dict[str, Any] = {
        "data": {
            "first_archived": "N/A",
            "snapshot_count": 0,
            "urls": [],
            "deleted_urls": [],
            "contact_type": "Passive Third-Party (Archive.org)",
        },
        "risk_flags": [],
        "errors": [],
    }

    clean_domain = domain.split(":")[0].lower()
    if _is_local_host(clean_domain):
        result["data"]["first_archived"] = "N/A (Local / Internal Target)"
        return result

    client = HttpClient.get_instance(timeout=float(timeout))

    try:
        # Check available snapshot (closest)
        avail_url = f"https://archive.org/wayback/available?url={clean_domain}"
        avail_resp = client.get(avail_url, timeout=float(timeout), use_cache=True)

        if avail_resp.status_code == 200:
            avail_data = avail_resp.json()
            if "archived_snapshots" in avail_data and "closest" in avail_data["archived_snapshots"]:
                closest = avail_data["archived_snapshots"]["closest"]
                ts = closest.get("timestamp", "")
                if ts and len(ts) >= 8:
                    result["data"]["first_archived"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                else:
                    result["data"]["first_archived"] = ts or "N/A"

        # Query CDX API for snapshots
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?"
            f"url=*.{domain}&output=json&limit=500"
            f"&fl=timestamp,original,statuscode,mimetype"
        )
        cdx_resp = client.get(cdx_url, timeout=float(timeout), use_cache=True)

        if cdx_resp.status_code == 200:
            try:
                cdx_data = cdx_resp.json()
                if len(cdx_data) > 1:
                    headers = cdx_data[0]
                    rows = cdx_data[1:]
                    result["data"]["snapshot_count"] = len(rows)

                    unique_urls: set = set()
                    deleted_urls: set = set()

                    for row in rows:
                        if len(row) == len(headers):
                            row_dict = dict(zip(headers, row))
                            url = row_dict.get("original")
                            status = row_dict.get("statuscode")

                            if url:
                                unique_urls.add(url)
                                if status == "404":
                                    deleted_urls.add(url)

                    result["data"]["urls"] = sorted(unique_urls)[:50]
                    result["data"]["deleted_urls"] = sorted(deleted_urls)
            except ValueError:
                result["errors"].append("Failed to parse CDX API JSON response.")

    except httpx.TimeoutException:
        result["errors"].append("Wayback Machine API request timed out.")
    except Exception as e:
        result["errors"].append(f"Wayback Machine query failed: {str(e)}")

    return result
