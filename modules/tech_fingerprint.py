"""
Technology stack fingerprinting module.

Analyzes HTTP response headers, meta tags, and page content to identify web servers,
CMS, frameworks, CDNs, and security headers with explicit confidence ratings.
Direct contact classification: Non-intrusive Direct Web Probe.
"""

from typing import Dict, Any, List
import httpx
from core.http_client import HttpClient


def run(domain: str, base_url: str = "", timeout: int = 10) -> Dict[str, Any]:
    """Fingerprint technologies and headers using standard HTTP client."""
    result: Dict[str, Any] = {"data": {}, "risk_flags": [], "errors": []}

    candidate_urls = []
    if base_url:
        candidate_urls.append(base_url)
    elif domain.startswith("http://") or domain.startswith("https://"):
        candidate_urls.append(domain)
    else:
        clean_host = domain.split(":")[0].lower()
        if clean_host in ("localhost", "127.0.0.1", "0.0.0.0") or any(
            p in domain for p in (":3000", ":8080", ":8000")
        ):
            candidate_urls.append(f"http://{domain}")
            candidate_urls.append(f"https://{domain}")
        else:
            candidate_urls.append(f"https://{domain}")
            candidate_urls.append(f"http://{domain}")

    http_client = HttpClient.get_instance(timeout=float(timeout))
    response = None
    successful_url = ""

    for url in candidate_urls:
        try:
            response = http_client.get(url, timeout=float(timeout))
            successful_url = str(response.url) if response.url else url
            break
        except Exception:
            continue

    if response is None:
        result["errors"].append(f"Failed to connect to target {domain} over HTTP/HTTPS")
        return result

    try:
        headers = {k.lower(): v for k, v in response.headers.items()}
        content = response.text.lower()
        raw_text = response.text

        tech: Dict[str, Any] = {
            "server": None,
            "cms": None,
            "frameworks": [],
            "cdn": None,
            "analytics": [],
            "js_libraries": [],
            "database_orm": [],
            "api_specs": [],
        }

        confidence_map: Dict[str, str] = {}  # tech_name -> HIGH / MEDIUM / LOW

        # Web Servers & Backend runtimes
        server_header = headers.get("server", "").lower()
        x_powered_by = headers.get("x-powered-by", "").lower()

        if "apache" in server_header or "apache" in x_powered_by:
            tech["server"] = "Apache"
            confidence_map["Apache"] = "HIGH"
        elif "nginx" in server_header:
            tech["server"] = "Nginx"
            confidence_map["Nginx"] = "HIGH"
        elif "iis" in server_header or "asp.net" in x_powered_by:
            tech["server"] = "IIS / ASP.NET"
            confidence_map["IIS / ASP.NET"] = "HIGH"
        elif "litespeed" in server_header:
            tech["server"] = "LiteSpeed"
            confidence_map["LiteSpeed"] = "HIGH"
        elif "caddy" in server_header:
            tech["server"] = "Caddy"
            confidence_map["Caddy"] = "HIGH"
        elif "express" in x_powered_by or "express" in server_header:
            tech["server"] = "Express (Node.js)"
            tech["frameworks"].extend(["Express", "Node.js"])
            confidence_map["Express"] = "HIGH"
            confidence_map["Node.js"] = "HIGH"
        elif "uvicorn" in server_header or "gunicorn" in server_header:
            tech["server"] = "Python ASGI/WSGI (Uvicorn/Gunicorn)"
            confidence_map["Python ASGI/WSGI"] = "HIGH"

        if "node" in server_header or "connect.sid" in headers.get("set-cookie", ""):
            if "Node.js" not in tech["frameworks"]:
                tech["frameworks"].append("Node.js")
                confidence_map["Node.js"] = "HIGH"

        # CMS detection
        if "wp-content/" in content or "wordpress" in content:
            tech["cms"] = "WordPress"
            confidence_map["WordPress"] = "HIGH" if "wp-content/" in content else "MEDIUM"
        elif "drupal.js" in content or "drupal" in content:
            tech["cms"] = "Drupal"
            confidence_map["Drupal"] = "HIGH" if "drupal.js" in content else "MEDIUM"
        elif "joomla" in content:
            tech["cms"] = "Joomla"
            confidence_map["Joomla"] = "MEDIUM"
        elif "ghost" in content:
            tech["cms"] = "Ghost"
            confidence_map["Ghost"] = "MEDIUM"
        elif "shopify" in content:
            tech["cms"] = "Shopify"
            confidence_map["Shopify"] = "HIGH"

        # Frontend Frameworks & Single Page Applications (SPAs)
        if "ng-version" in content or "<app-root" in content:
            tech["frameworks"].append("Angular")
            confidence_map["Angular"] = "HIGH"
        elif "angular" in content or "ng-" in content or "ng-app" in content:
            tech["frameworks"].append("Angular")
            confidence_map["Angular"] = "MEDIUM"

        if "react" in content or "data-reactroot" in content or "__next" in content:
            tech["frameworks"].append("React")
            confidence_map["React"] = "HIGH" if ("data-reactroot" in content or "__next" in content) else "MEDIUM"

        if "__next" in content or "_next/static" in content:
            tech["frameworks"].append("Next.js")
            confidence_map["Next.js"] = "HIGH"

        if "data-v-" in content or "vue" in content or "__nuxt" in content:
            tech["frameworks"].append("Vue.js")
            confidence_map["Vue.js"] = "HIGH" if ("data-v-" in content or "__nuxt" in content) else "MEDIUM"

        if "__nuxt" in content:
            tech["frameworks"].append("Nuxt.js")
            confidence_map["Nuxt.js"] = "HIGH"

        if "svelte" in content or "__svelte" in content:
            tech["frameworks"].append("Svelte")
            confidence_map["Svelte"] = "MEDIUM"

        if "csrfmiddlewaretoken" in content:
            tech["frameworks"].append("Django")
            confidence_map["Django"] = "HIGH"

        if "laravel" in content or "laravel_session" in headers.get("set-cookie", ""):
            tech["frameworks"].append("Laravel")
            confidence_map["Laravel"] = "HIGH" if "laravel_session" in headers.get("set-cookie", "") else "MEDIUM"

        if "rails" in content or "_rails" in headers.get("set-cookie", ""):
            tech["frameworks"].append("Ruby on Rails")
            confidence_map["Ruby on Rails"] = "HIGH"

        if "spring" in content or "jsessionid" in headers.get("set-cookie", ""):
            tech["frameworks"].append("Spring Boot")
            confidence_map["Spring Boot"] = "MEDIUM"

        if "socket.io" in content or "/socket.io/" in content:
            tech["frameworks"].append("Socket.io")
            confidence_map["Socket.io"] = "HIGH"

        # API & Documentation
        if "swagger" in content or "/api-docs" in content or "openapi" in content:
            tech["api_specs"].append("Swagger / OpenAPI")
            confidence_map["Swagger / OpenAPI"] = "HIGH"
        if "/rest/" in content or "/api/" in content:
            tech["api_specs"].append("REST API")
            confidence_map["REST API"] = "MEDIUM"

        # Database / ORM cues
        if "sqlite" in content or "sequelize" in content:
            tech["database_orm"].append("SQLite / Sequelize")
            confidence_map["SQLite / Sequelize"] = "MEDIUM"
        elif "mongodb" in content or "mongoose" in content:
            tech["database_orm"].append("MongoDB / Mongoose")
            confidence_map["MongoDB / Mongoose"] = "MEDIUM"

        # CDN
        if "cf-ray" in headers:
            tech["cdn"] = "Cloudflare"
            confidence_map["Cloudflare"] = "HIGH"
        elif "x-fastly-request-id" in headers:
            tech["cdn"] = "Fastly"
            confidence_map["Fastly"] = "HIGH"
        elif "akamai" in headers.get("server", "").lower():
            tech["cdn"] = "Akamai"
            confidence_map["Akamai"] = "HIGH"
        elif "cloudfront" in headers.get("server", "").lower() or "x-amz-cf-id" in headers:
            tech["cdn"] = "AWS CloudFront"
            confidence_map["AWS CloudFront"] = "HIGH"

        # JS Libs & UI CSS
        if "jquery" in content:
            tech["js_libraries"].append("jQuery")
            confidence_map["jQuery"] = "MEDIUM"
        if "bootstrap" in content or "bootstrap.min.css" in content:
            tech["js_libraries"].append("Bootstrap")
            confidence_map["Bootstrap"] = "MEDIUM"
        if "tailwind" in content:
            tech["js_libraries"].append("Tailwind CSS")
            confidence_map["Tailwind CSS"] = "MEDIUM"
        if "font-awesome" in content or "fontawesome" in content or "fa-" in content:
            tech["js_libraries"].append("Font Awesome")
            confidence_map["Font Awesome"] = "MEDIUM"
        if "material" in content or "mat-" in content or "mat-icon" in content:
            tech["js_libraries"].append("Angular Material")
            confidence_map["Angular Material"] = "MEDIUM"

        # Analytics
        if "gtag" in content or "analytics.js" in content:
            tech["analytics"].append("Google Analytics")
            confidence_map["Google Analytics"] = "HIGH"
        if "fbq(" in content:
            tech["analytics"].append("Facebook Pixel")
            confidence_map["Facebook Pixel"] = "HIGH"
        if "hotjar" in content:
            tech["analytics"].append("Hotjar")
            confidence_map["Hotjar"] = "HIGH"

        sec_headers = {
            "content-security-policy": "CSP",
            "strict-transport-security": "HSTS",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }

        security_headers_status = {}
        for header, name in sec_headers.items():
            if header in headers:
                security_headers_status[name] = "present"
            else:
                security_headers_status[name] = "missing"

        if security_headers_status["CSP"] == "missing":
            result["risk_flags"].append("missing_csp (+5)")
        if security_headers_status["HSTS"] == "missing":
            result["risk_flags"].append("missing_hsts (+5)")
        if security_headers_status["X-Frame-Options"] == "missing":
            result["risk_flags"].append("missing_xfo (+5)")
        if security_headers_status["X-Content-Type-Options"] == "missing":
            result["risk_flags"].append("missing_xcto (+5)")

        detected = []
        if tech["server"]:
            detected.append(tech["server"])
        if tech["cms"]:
            detected.append(tech["cms"])
        if tech["cdn"]:
            detected.append(tech["cdn"])
        detected.extend(tech["frameworks"])
        detected.extend(tech["js_libraries"])
        detected.extend(tech["analytics"])
        detected.extend(tech["database_orm"])
        detected.extend(tech["api_specs"])

        # Deduplicate
        tech["frameworks"] = sorted(list(set(tech["frameworks"])))
        tech["js_libraries"] = sorted(list(set(tech["js_libraries"])))
        tech["analytics"] = sorted(list(set(tech["analytics"])))

        result["data"] = {
            "server": tech["server"] or "Not explicitly identified",
            "cms": tech["cms"] or "None detected",
            "frameworks": tech["frameworks"],
            "cdn": tech["cdn"] or "None detected",
            "js_libraries": tech["js_libraries"],
            "analytics": tech["analytics"],
            "database_orm": tech["database_orm"],
            "api_specs": tech["api_specs"],
            "security_headers": security_headers_status,
            "detected_technologies": sorted(list(set(detected))),
            "confidence_map": confidence_map,
            "resolved_url": successful_url,
            "contact_type": "Direct Probe (Low-Impact GET)",
        }

    except httpx.RequestError as e:
        result["errors"].append(f"Request failed: {str(e)}")
    except Exception as e:
        result["errors"].append(f"Fingerprinting failed: {str(e)}")

    return result
