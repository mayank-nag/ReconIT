"""
Technology stack fingerprinting module.
Analyzes HTTP headers and page content to identify web servers, CMS, frameworks, CDNs, and security headers.
"""

import requests
from typing import Dict, Any

def run(domain: str, base_url: str = "") -> Dict[str, Any]:
    result = {'data': {}, 'risk_flags': [], 'errors': []}
    
    # Determine target URL
    candidate_urls = []
    if base_url:
        candidate_urls.append(base_url)
    elif domain.startswith('http://') or domain.startswith('https://'):
        candidate_urls.append(domain)
    else:
        # Check if local or port specified
        clean_host = domain.split(":")[0].lower()
        if clean_host in ("localhost", "127.0.0.1", "0.0.0.0") or ":3000" in domain or ":8080" in domain or ":8000" in domain:
            candidate_urls.append(f"http://{domain}")
            candidate_urls.append(f"https://{domain}")
        else:
            candidate_urls.append(f"https://{domain}")
            candidate_urls.append(f"http://{domain}")
        
    response = None
    successful_url = ""
    for url in candidate_urls:
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            successful_url = response.url or url
            break
        except Exception:
            continue

    if response is None:
        result['errors'].append(f"Failed to connect to target {domain} over HTTP/HTTPS")
        return result

    try:
        headers = {k.lower(): v for k, v in response.headers.items()}
        content = response.text.lower()
        raw_text = response.text
        
        tech = {
            'server': None,
            'cms': None,
            'frameworks': [],
            'cdn': None,
            'analytics': [],
            'js_libraries': [],
            'database_orm': [],
            'api_specs': []
        }
        
        # Web Servers & Backend runtimes
        server_header = headers.get('server', '').lower()
        x_powered_by = headers.get('x-powered-by', '').lower()
        
        if 'apache' in server_header or 'apache' in x_powered_by: tech['server'] = 'Apache'
        elif 'nginx' in server_header: tech['server'] = 'Nginx'
        elif 'iis' in server_header or 'asp.net' in x_powered_by: tech['server'] = 'IIS / ASP.NET'
        elif 'litespeed' in server_header: tech['server'] = 'LiteSpeed'
        elif 'caddy' in server_header: tech['server'] = 'Caddy'
        elif 'express' in x_powered_by or 'express' in server_header:
            tech['server'] = 'Express (Node.js)'
            tech['frameworks'].append('Express')
            tech['frameworks'].append('Node.js')
        elif 'uvicorn' in server_header or 'gunicorn' in server_header:
            tech['server'] = 'Python ASGI/WSGI (Uvicorn/Gunicorn)'
        
        # Check Node.js cues
        if 'node' in server_header or 'connect.sid' in headers.get('set-cookie', '') or 'express' in x_powered_by:
            if 'Node.js' not in tech['frameworks']: tech['frameworks'].append('Node.js')
            if 'Express' not in tech['frameworks'] and 'express' in x_powered_by: tech['frameworks'].append('Express')
        
        # CMS
        if 'wp-content/' in content or 'wordpress' in content: tech['cms'] = 'WordPress'
        elif 'drupal.js' in content or 'drupal' in content: tech['cms'] = 'Drupal'
        elif 'joomla' in content: tech['cms'] = 'Joomla'
        elif 'ghost' in content: tech['cms'] = 'Ghost'
        elif 'shopify' in content: tech['cms'] = 'Shopify'
        
        # Frontend Frameworks & Single Page Applications (SPAs)
        if 'ng-version' in content or '<app-root' in content or 'polyfills.js' in content or 'main.js' in content and 'vendor.js' in content:
            tech['frameworks'].append('Angular')
        elif 'angular' in content or 'ng-' in content or 'ng-app' in content:
            tech['frameworks'].append('Angular')
            
        if 'react' in content or 'data-reactroot' in content or '__next' in content:
            tech['frameworks'].append('React')
        if '__next' in content or '_next/static' in content:
            tech['frameworks'].append('Next.js')
        if 'data-v-' in content or 'vue' in content or '__nuxt' in content:
            tech['frameworks'].append('Vue.js')
        if '__nuxt' in content:
            tech['frameworks'].append('Nuxt.js')
        if 'svelte' in content or '__svelte' in content:
            tech['frameworks'].append('Svelte')
        if 'csrfmiddlewaretoken' in content:
            tech['frameworks'].append('Django')
        if 'laravel' in content or 'laravel_session' in headers.get('set-cookie', ''):
            tech['frameworks'].append('Laravel')
        if 'rails' in content or '_rails' in headers.get('set-cookie', ''):
            tech['frameworks'].append('Ruby on Rails')
        if 'spring' in content or 'jsessionid' in headers.get('set-cookie', ''):
            tech['frameworks'].append('Spring Boot')
        if 'socket.io' in content or '/socket.io/' in content:
            tech['frameworks'].append('Socket.io')

        # API & Documentation
        if 'swagger' in content or '/api-docs' in content or 'openapi' in content:
            tech['api_specs'].append('Swagger / OpenAPI')
        if '/rest/' in content or '/api/' in content:
            tech['api_specs'].append('REST API')

        # Database / ORM cues
        if 'sqlite' in content or 'sequelize' in content:
            tech['database_orm'].append('SQLite / Sequelize')
        elif 'mongodb' in content or 'mongoose' in content:
            tech['database_orm'].append('MongoDB / Mongoose')

        # CDN
        if 'cf-ray' in headers: tech['cdn'] = 'Cloudflare'
        elif 'x-fastly-request-id' in headers: tech['cdn'] = 'Fastly'
        elif 'akamai' in headers.get('server', '').lower(): tech['cdn'] = 'Akamai'
        elif 'cloudfront' in headers.get('server', '').lower() or 'x-amz-cf-id' in headers: tech['cdn'] = 'AWS CloudFront'
        
        # JS Libs & UI CSS
        if 'jquery' in content: tech['js_libraries'].append('jQuery')
        if 'bootstrap' in content or 'bootstrap.min.css' in content: tech['js_libraries'].append('Bootstrap')
        if 'tailwind' in content: tech['js_libraries'].append('Tailwind CSS')
        if 'font-awesome' in content or 'fontawesome' in content or 'fa-' in content: tech['js_libraries'].append('Font Awesome')
        if 'material' in content or 'mat-' in content or 'mat-icon' in content: tech['js_libraries'].append('Angular Material')
        
        # Analytics
        if 'gtag' in content or 'analytics.js' in content: tech['analytics'].append('Google Analytics')
        if 'fbq(' in content: tech['analytics'].append('Facebook Pixel')
        if 'hotjar' in content: tech['analytics'].append('Hotjar')
        
        sec_headers = {
            'content-security-policy': 'CSP',
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy'
        }
        
        security_headers_status = {}
        for header, name in sec_headers.items():
            if header in headers:
                security_headers_status[name] = 'present'
            else:
                security_headers_status[name] = 'missing'
                
        if security_headers_status['CSP'] == 'missing':
            result['risk_flags'].append('missing_csp (+5)')
        if security_headers_status['HSTS'] == 'missing':
            result['risk_flags'].append('missing_hsts (+5)')
        if security_headers_status['X-Frame-Options'] == 'missing':
            result['risk_flags'].append('missing_xfo (+5)')
        if security_headers_status['X-Content-Type-Options'] == 'missing':
            result['risk_flags'].append('missing_xcto (+5)')
            
        detected = []
        if tech['server']: detected.append(tech['server'])
        if tech['cms']: detected.append(tech['cms'])
        if tech['cdn']: detected.append(tech['cdn'])
        detected.extend(tech['frameworks'])
        detected.extend(tech['js_libraries'])
        detected.extend(tech['analytics'])
        detected.extend(tech['database_orm'])
        detected.extend(tech['api_specs'])
        
        # Deduplicate
        tech['frameworks'] = sorted(list(set(tech['frameworks'])))
        tech['js_libraries'] = sorted(list(set(tech['js_libraries'])))
        tech['analytics'] = sorted(list(set(tech['analytics'])))
        
        result['data'] = {
            'server': tech['server'] or 'Not explicitly identified',
            'cms': tech['cms'] or 'None detected',
            'frameworks': tech['frameworks'],
            'cdn': tech['cdn'] or 'None detected',
            'js_libraries': tech['js_libraries'],
            'analytics': tech['analytics'],
            'database_orm': tech['database_orm'],
            'api_specs': tech['api_specs'],
            'security_headers': security_headers_status,
            'detected_technologies': sorted(list(set(detected))),
            'resolved_url': successful_url,
        }
        
    except requests.exceptions.RequestException as e:
        result['errors'].append(f"Request failed: {str(e)}")
    except Exception as e:
        result['errors'].append(f"Fingerprinting failed: {str(e)}")
        
    return result
