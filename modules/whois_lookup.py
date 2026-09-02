"""
WHOIS domain lookup module.
Retrieves and parses WHOIS information for a given domain, extracting key details and assessing domain age risk.
"""

import whois
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from typing import Dict, Any, List

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
    
    if _is_local_host(clean_domain):
        result['data'] = {
            'registrar': 'Loopback / Private Network',
            'registration_date': 'N/A (Local Target)',
            'expiry_date': 'N/A (Local Target)',
            'registrant_country': 'Localhost',
            'name_servers': ['127.0.0.1'],
            'updated_date': 'N/A'
        }
        return result

    try:
        w = whois.whois(clean_domain)
        
        # Helper to get first item if list or just the item, and normalize dates
        def normalize_date(d):
            if isinstance(d, list):
                if not d: return None
                d = d[0]
            if isinstance(d, datetime):
                return d.isoformat()
            return str(d) if d else None
        
        def get_str(val):
            if isinstance(val, list):
                if not val: return None
                return str(val[0])
            return str(val) if val else None
        
        creation_date = w.creation_date
        c_date_obj = None
        if isinstance(creation_date, list) and creation_date:
            c_date_obj = creation_date[0]
        elif isinstance(creation_date, datetime):
            c_date_obj = creation_date
            
        data = {
            'registrar': get_str(w.registrar),
            'registration_date': normalize_date(w.creation_date),
            'expiry_date': normalize_date(w.expiration_date),
            'registrant_country': get_str(w.country),
            'name_servers': [str(ns) for ns in w.name_servers] if isinstance(w.name_servers, list) else [str(w.name_servers)] if w.name_servers else [],
            'updated_date': normalize_date(w.updated_date)
        }
        
        result['data'] = data
        
        # Risk flag for domain age < 6 months
        if c_date_obj:
            six_months_ago = datetime.now() - relativedelta(months=6)
            # Ensure timezone awareness matches
            if c_date_obj.tzinfo is not None:
                six_months_ago = datetime.now(timezone.utc) - relativedelta(months=6)
            
            try:
                if c_date_obj > six_months_ago:
                    result['risk_flags'].append('young_domain')
            except TypeError:
                pass
                
    except Exception as e:
        result['errors'].append(f"WHOIS lookup failed: {str(e)}")
        
    return result
