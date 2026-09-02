"""
DNS record enumeration module.
Queries various DNS record types for a given domain and checks for basic email security records (SPF, DMARC).
"""

import dns.resolver
from typing import Dict, Any

def _is_local_host(domain: str) -> bool:
    d = domain.lower().split(":")[0]
    return (
        d in ("localhost", "127.0.0.1", "0.0.0.0", "::1")
        or d.endswith(".local")
        or d.startswith("192.168.")
        or d.startswith("10.")
        or (d.startswith("172.") and 16 <= int(d.split(".")[1]) <= 31 if len(d.split(".")) > 1 and d.split(".")[1].isdigit() else False)
    )

def run(domain: str) -> Dict[str, Any]:
    result = {'data': {}, 'risk_flags': [], 'errors': []}
    clean_domain = domain.split(":")[0].lower()
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR']
    
    for rtype in record_types:
        result['data'][rtype] = []

    if _is_local_host(clean_domain):
        ip = "127.0.0.1" if clean_domain == "localhost" else clean_domain
        result['data']['A'] = [ip]
        result['data']['TXT'] = ["local-target (internal test network)"]
        return result
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(clean_domain, rtype)
            for rdata in answers:
                result['data'][rtype].append(rdata.to_text())
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            result['errors'].append(f"Error querying {rtype}: {str(e)}")
            
    # Check SPF and DMARC in TXT records
    has_spf = False
    has_dmarc = False
    
    for txt in result['data'].get('TXT', []):
        if 'v=spf1' in txt.lower():
            has_spf = True

    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{clean_domain}", 'TXT')
        for rdata in dmarc_answers:
            txt = rdata.to_text()
            if 'v=DMARC1' in txt:
                has_dmarc = True
                result['data']['TXT'].append(f"_dmarc.{clean_domain}: {txt}")
    except Exception:
        pass
        
    if not has_spf:
        result['risk_flags'].append('missing_spf (+10)')
    if not has_dmarc:
        result['risk_flags'].append('missing_dmarc (+10)')
        
    return result
