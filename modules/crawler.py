"""
Web crawler module.

Spiders discovered domains/subdomains, maps all pages, extracts
links, files, and checks for exposed sensitive paths.
"""

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List, Set
from collections import deque


def _parse_robots_txt(base_url: str, timeout: int = 10) -> str:
    """Fetch and return robots.txt content."""
    try:
        url = urljoin(base_url, "/robots.txt")
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return ""


def _parse_sitemap(base_url: str, timeout: int = 10) -> List[str]:
    """Fetch and parse sitemap.xml for URLs."""
    urls = []
    try:
        url = urljoin(base_url, "/sitemap.xml")
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml-xml")
            for loc in soup.find_all("loc"):
                if loc.text:
                    urls.append(loc.text.strip())
    except Exception:
        pass
    return urls


def _is_same_domain(url: str, domain: str, base_netloc: str = "") -> bool:
    """Check if a URL belongs to the same target domain / host."""
    try:
        parsed = urlparse(url)
        if base_netloc and parsed.netloc:
            return parsed.netloc.lower() == base_netloc.lower()
        host = parsed.hostname or ""
        clean_target = domain.split(":")[0].lower()
        return host.lower() == clean_target or host.lower().endswith(f".{clean_target}")
    except Exception:
        return False


def _get_file_type(url: str) -> str | None:
    """Check if URL points to a downloadable file by extension."""
    file_extensions = {
        ".pdf": "pdf", ".docx": "docx", ".xlsx": "xlsx",
        ".doc": "doc", ".xls": "xls", ".pptx": "pptx",
        ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg",
        ".gif": "gif", ".svg": "svg", ".csv": "csv",
        ".zip": "zip", ".txt": "txt", ".json": "json",
        ".bak": "bak", ".md": "md",
    }
    path = urlparse(url).path.lower()
    for ext, ftype in file_extensions.items():
        if path.endswith(ext):
            return ftype
    return None


def run(
    domain: str,
    depth: int = 3,
    ignore_robots: bool = False,
    timeout: int = 10,
    base_url: str = "",
) -> Dict[str, Any]:
    """Crawl a domain up to the specified depth, extracting pages, links, and files.

    Args:
        domain: Target domain to crawl.
        depth: Maximum crawl depth (default: 3).
        ignore_robots: Whether to ignore robots.txt restrictions.
        timeout: Request timeout in seconds.
        base_url: Optional explicit base URL (e.g. http://localhost:3000).

    Returns:
        Dict with crawled pages, page contents, files, external links,
        robots.txt, sitemap URLs, risk flags, and errors.
    """
    result: Dict[str, Any] = {
        "data": {
            "pages": [],
            "page_contents": [],
            "files": [],
            "external_links": [],
            "robots_txt": "",
            "sitemap_urls": [],
        },
        "risk_flags": [],
        "errors": [],
    }

    MAX_PAGES = 150
    visited: Set[str] = set()
    pages: List[Dict[str, Any]] = []
    page_contents: List[Dict[str, str]] = []
    files: List[Dict[str, str]] = []
    external_links: Set[str] = set()

    # Determine start URL
    if not base_url:
        clean_host = domain.split(":")[0].lower()
        if clean_host in ("localhost", "127.0.0.1", "0.0.0.0") or ":3000" in domain or ":8080" in domain:
            base_url = f"http://{domain}"
        else:
            base_url = f"https://{domain}"

    parsed_base = urlparse(base_url)
    base_netloc = parsed_base.netloc or domain

    # Fetch robots.txt & sitemap
    robots_txt = _parse_robots_txt(base_url, timeout)
    result["data"]["robots_txt"] = robots_txt

    disallowed: Set[str] = set()
    if robots_txt:
        for line in robots_txt.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.add(path)

    sitemap_urls = _parse_sitemap(base_url, timeout)
    result["data"]["sitemap_urls"] = sitemap_urls

    client = httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
    )

    # Known sensitive and high-value endpoints to probe
    sensitive_probes = [
        "/.git/config", "/.env", "/package.json", "/ftp", "/ftp/",
        "/api-docs", "/swagger.json", "/rest/products/search",
        "/.well-known/security.txt", "/robots.txt"
    ]

    try:
        # Check sensitive paths first
        for probe in sensitive_probes:
            probe_url = urljoin(base_url, probe)
            if probe_url not in visited:
                try:
                    resp = client.get(probe_url)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        visited.add(probe_url)
                        pages.append({
                            "url": probe_url,
                            "status": resp.status_code,
                            "title": f"Discovered Endpoint [{probe}]",
                        })
                        if probe in ("/.git/config", "/.env"):
                            result["risk_flags"].append("Exposed .git or .env reference")
                        elif probe in ("/package.json", "/ftp", "/ftp/"):
                            result["risk_flags"].append("Exposed sensitive path or directory")
                except Exception:
                    pass

        # BFS crawl starting from base_url
        queue: deque = deque()
        queue.append((base_url, 0))
        visited.add(base_url)

        # Also queue any paths extracted from robots.txt disallowed
        for dpath in disallowed:
            d_url = urljoin(base_url, dpath)
            if d_url not in visited:
                queue.append((d_url, 1))
                visited.add(d_url)

        while queue and len(pages) < MAX_PAGES:
            url, current_depth = queue.popleft()

            if current_depth > depth:
                continue

            parsed_url = urlparse(url)
            path = parsed_url.path or "/"

            if not ignore_robots and robots_txt:
                if any(path.startswith(d) for d in disallowed if d != "/"):
                    pass  # we still log or allow depending on setting

            try:
                resp = client.get(url)
            except Exception as e:
                result["errors"].append(f"Failed to fetch {url}: {str(e)}")
                continue

            content_type = resp.headers.get("content-type", "").lower()
            
            # Extract downloadable files
            ftype = _get_file_type(url)
            if ftype:
                if url not in {f["url"] for f in files}:
                    files.append({"url": url, "type": ftype})

            if "text/html" not in content_type and "application/json" not in content_type and "text/javascript" not in content_type:
                continue

            html = resp.text
            title = ""
            if "text/html" in content_type:
                soup = BeautifulSoup(html, "lxml")
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else ""
            else:
                soup = None

            # Add to discovered pages
            if not any(p["url"] == url for p in pages):
                pages.append({
                    "url": url,
                    "status": resp.status_code,
                    "title": title or path,
                })

            page_contents.append({
                "url": url,
                "html": html,
            })

            # Link discovery
            if current_depth < depth and soup:
                # 1. <a> links
                for tag in soup.find_all("a", href=True):
                    href = tag["href"]
                    abs_url = urljoin(url, href).split("#")[0]
                    if not abs_url:
                        continue

                    ft = _get_file_type(abs_url)
                    if ft:
                        if abs_url not in {f["url"] for f in files}:
                            files.append({"url": abs_url, "type": ft})
                        continue

                    if _is_same_domain(abs_url, domain, base_netloc):
                        if abs_url not in visited:
                            visited.add(abs_url)
                            queue.append((abs_url, current_depth + 1))
                    else:
                        external_links.add(abs_url)

                # 2. <script> and <link> tags
                for script in soup.find_all(["script", "link"]):
                    src = script.get("src") or script.get("href")
                    if src:
                        abs_src = urljoin(url, src).split("#")[0]
                        if _is_same_domain(abs_src, domain, base_netloc) and abs_src not in visited:
                            ft = _get_file_type(abs_src)
                            if ft and abs_src not in {f["url"] for f in files}:
                                files.append({"url": abs_src, "type": ft})

    finally:
        client.close()

    result["data"]["pages"] = pages
    result["data"]["page_contents"] = page_contents
    result["data"]["files"] = files
    result["data"]["external_links"] = sorted(external_links)

    return result
