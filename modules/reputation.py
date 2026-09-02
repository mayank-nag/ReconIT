import requests
import socket
from typing import Dict, Any, Optional

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

def run(domain: str, api_keys: Optional[Dict[str, str]] = None, timeout: int = 15) -> Dict[str, Any]:
    """
    Checks community reputation of the domain using various sources.
    """
    result = {'data': {}, 'risk_flags': [], 'errors': []}
    api_keys = api_keys or {}
    clean_domain = domain.split(":")[0].lower()
    
    if _is_local_host(clean_domain):
        result['data'] = {
            'checks_performed': ['local_environment'],
            'environment': 'Private / Local Test Target',
            'virustotal_positives': 0,
            'virustotal_total': 0,
            'safebrowsing_status': 'local',
        }
        return result

    checks_performed = []
    
    # VirusTotal Check
    vt_key = api_keys.get('virustotal')
    if vt_key:
        try:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"
            headers = {"x-apikey": vt_key}
            vt_resp = requests.get(vt_url, headers=headers, timeout=timeout)
            if vt_resp.status_code == 200:
                vt_data = vt_resp.json()
                stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
                total = sum(stats.values())
                
                result['data']['virustotal_positives'] = positives
                result['data']['virustotal_total'] = total
                checks_performed.append('virustotal')
                
                if positives > 0:
                    result['risk_flags'].append('virustotal_flagged')
            else:
                result['errors'].append(f"VirusTotal API returned status code {vt_resp.status_code}")
        except Exception as e:
            result['errors'].append(f"VirusTotal check failed: {str(e)}")
            
    # AbuseIPDB Check (requires resolving domain to IP)
    abuse_key = api_keys.get('abuseipdb')
    if abuse_key:
        try:
            ip = socket.gethostbyname(clean_domain)
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Key": abuse_key
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            abuse_resp = requests.get(abuse_url, headers=headers, params=params, timeout=timeout)
            if abuse_resp.status_code == 200:
                abuse_data = abuse_resp.json()
                score = abuse_data.get('data', {}).get('abuseConfidenceScore', 0)
                
                result['data']['abuseipdb_score'] = score
                checks_performed.append('abuseipdb')
                
                if score > 50:
                    result['risk_flags'].append('abuseipdb_flagged')
            else:
                result['errors'].append(f"AbuseIPDB API returned status code {abuse_resp.status_code}")
        except socket.gaierror:
            result['errors'].append("Failed to resolve domain to IP for AbuseIPDB check.")
        except Exception as e:
            result['errors'].append(f"AbuseIPDB check failed: {str(e)}")
            
    # Google Safe Browsing Check
    gsb_key = api_keys.get('safebrowsing')
    if gsb_key:
        try:
            gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}"
            payload = {
                "client": {
                    "clientId": "venom-osint",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{clean_domain}"}, {"url": f"https://{clean_domain}"}]
                }
            }
            gsb_resp = requests.post(gsb_url, json=payload, timeout=timeout)
            if gsb_resp.status_code == 200:
                gsb_data = gsb_resp.json()
                matches = gsb_data.get('matches', [])
                checks_performed.append('safebrowsing')
                
                if matches:
                    result['data']['safebrowsing_status'] = "flagged"
                    result['risk_flags'].append('safebrowsing_flagged')
                else:
                    result['data']['safebrowsing_status'] = "clean"
            else:
                result['errors'].append(f"Google Safe Browsing API returned status code {gsb_resp.status_code}")
        except Exception as e:
            result['errors'].append(f"Google Safe Browsing check failed: {str(e)}")

    # Basic checks if no API keys are provided
    if not api_keys:
        try:
            basic_resp = requests.get(f"http://{clean_domain}", timeout=timeout, allow_redirects=True)
            result['data']['basic_http_status'] = basic_resp.status_code
            result['data']['redirect_chain'] = [resp.url for resp in basic_resp.history] + [basic_resp.url]
            checks_performed.append('basic_http')
        except requests.Timeout:
            result['errors'].append("Basic HTTP check timed out.")
        except requests.RequestException as e:
            result['errors'].append(f"Basic HTTP check failed: {str(e)}")

    result['data']['checks_performed'] = checks_performed
    return result
