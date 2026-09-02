"""
SSL/TLS certificate inspection module.
Extracts certificate details, validity periods, and Subject Alternative Names (SANs), identifying risks like expired certs.
"""

import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any

def run(domain: str, port: int = 443) -> Dict[str, Any]:
    result = {'data': {}, 'risk_flags': [], 'errors': []}
    
    # Extract host and port if domain has :port
    host = domain
    if ":" in domain:
        parts = domain.split(":", 1)
        host = parts[0]
        if parts[1].isdigit():
            port = int(parts[1])

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                
        if not der_cert:
            raise ValueError("No certificate returned")
            
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value
            
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value
            
        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        result['data'] = {
            'issuer': issuer,
            'subject': subject,
            'serial_number': str(cert.serial_number),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'sans': sans,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'version': cert.version.name
        }
        
        now = datetime.now(timezone.utc)
        if now > not_after:
            result['risk_flags'].append('cert_expired (+25)')
        elif (not_after - now).days < 30:
            result['risk_flags'].append('cert_expiring_soon (+15)')
            
    except Exception as e:
        # If port is 80 or connection is plain HTTP, record plain HTTP state
        result['data'] = {
            'issuer': 'None (Unencrypted / Plain HTTP)',
            'subject': 'None',
            'serial_number': 'N/A',
            'not_before': 'N/A',
            'not_after': 'N/A (No SSL)',
            'sans': [],
            'signature_algorithm': 'None',
            'version': 'None',
        }
        result['risk_flags'].append('Plain HTTP / Missing SSL Encryption')
        result['errors'].append(f"SSL handshake not established on {host}:{port} ({str(e)})")
        
    return result
