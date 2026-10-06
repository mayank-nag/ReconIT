"""
GitHub Dorking & Public Secret Recon Module.

Constructs targeted GitHub dorks to discover leaked credentials, API keys,
configuration files, and internal endpoints associated with the target domain.
Supports live GitHub Search API querying when a token is configured.
Ensures discovered secrets are masked (only first 4 characters revealed).
Contact classification: Passive Search (GitHub API / Search Engine).
"""

import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from core.http_client import HttpClient
from core.target import mask_secret

DORK_TEMPLATES = [
    {
        "title": "API Keys & Secrets",
        "pattern": '"{domain}" api_key OR apikey OR secret_key',
        "category": "Credentials",
        "severity": "HIGH",
    },
    {
        "title": "Environment & Configuration Files",
        "pattern": '"{domain}" filename:.env OR filename:config.json OR filename:wp-config.php',
        "category": "Configuration Leak",
        "severity": "CRITICAL",
    },
    {
        "title": "Database Connection Strings",
        "pattern": '"{domain}" mongodb:// OR postgresql:// OR mysql:// OR jdbc:',
        "category": "Database Exposure",
        "severity": "CRITICAL",
    },
    {
        "title": "Authorization Headers & Bearer Tokens",
        "pattern": '"{domain}" "Bearer " OR "Authorization: Basic"',
        "category": "Tokens",
        "severity": "HIGH",
    },
    {
        "title": "Cloud Provider Credentials (AWS/GCP/Azure)",
        "pattern": '"{domain}" AWS_SECRET_ACCESS_KEY OR "AIzaSy"',
        "category": "Cloud Keys",
        "severity": "CRITICAL",
    },
    {
        "title": "Internal Endpoints & Staging Systems",
        "pattern": '"{domain}" dev. OR staging. OR internal. OR vpn.',
        "category": "Infrastructure",
        "severity": "MEDIUM",
    },
]


def run(domain: str, api_keys: Optional[Dict[str, str]] = None, timeout: int = 10) -> Dict[str, Any]:
    """Run GitHub dorking queries for the target domain, masking any discovered secrets."""
    result: Dict[str, Any] = {
        "data": {
            "dorks": [],
            "findings": [],
            "total_dorks": len(DORK_TEMPLATES),
            "contact_type": "Passive Third-Party (GitHub API / Code Search)",
        },
        "risk_flags": [],
        "errors": [],
    }

    api_keys = api_keys or {}
    github_token = api_keys.get("github", "").strip()
    client = HttpClient.get_instance(timeout=float(timeout))

    # Generate dork URLs
    dorks_list = []
    for tmpl in DORK_TEMPLATES:
        query_str = tmpl["pattern"].format(domain=domain)
        encoded_query = urllib.parse.quote_plus(query_str)
        github_url = f"https://github.com/search?q={encoded_query}&type=code"
        google_dork = f"https://www.google.com/search?q=site:github.com+{encoded_query}"

        dorks_list.append({
            "title": tmpl["title"],
            "category": tmpl["category"],
            "severity": tmpl["severity"],
            "query": query_str,
            "search_url": github_url,
            "google_dork_url": google_dork,
        })

    result["data"]["dorks"] = dorks_list

    # If GitHub token is provided, query GitHub Search API with rate limits
    if github_token:
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        for dork in dorks_list[:3]:
            try:
                api_url = f"https://api.github.com/search/code?q={urllib.parse.quote_plus(dork['query'])}"
                resp = client.get(api_url, headers=headers, timeout=float(timeout))
                if resp.status_code == 200:
                    data = resp.json()
                    total_count = data.get("total_count", 0)
                    if total_count > 0:
                        for item in data.get("items", [])[:5]:
                            repo_name = item.get("repository", {}).get("full_name", "Unknown")
                            file_path = item.get("path", "")
                            html_url = item.get("html_url", "")

                            # Extract and mask any text matches
                            snippet = ""
                            if "text_matches" in item and item["text_matches"]:
                                raw_snippet = item["text_matches"][0].get("fragment", "")
                                snippet = mask_secret(raw_snippet)

                            result["data"]["findings"].append({
                                "dork_title": dork["title"],
                                "repo": repo_name,
                                "path": file_path,
                                "url": html_url,
                                "snippet": snippet,
                            })
                        result["risk_flags"].append("Public GitHub secret / credential leak")
                elif resp.status_code == 403:
                    result["errors"].append("GitHub API rate limit exceeded or invalid token.")
                    break
            except Exception as e:
                result["errors"].append(f"GitHub search query failed: {e}")

    return result
