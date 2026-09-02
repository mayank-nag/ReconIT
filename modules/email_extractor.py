"""
Email extractor module.

Extracts email addresses from crawled page HTML content,
including mailto: links and inline text patterns.
"""

import re
from typing import Any, Dict, List


# Common false-positive email patterns to filter out
_FALSE_POSITIVE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "domain.com", "domain.tld", "email.com",
    "yoursite.com", "yourdomain.com", "company.com",
    "test.com", "sentry.io", "wixpress.com",
}

# Email regex pattern
_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

# mailto: link pattern
_MAILTO_PATTERN = re.compile(
    r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
    re.IGNORECASE,
)


def _is_valid_email(email: str) -> bool:
    """Filter out common false positives and invalid patterns."""
    email = email.lower().strip()

    # Filter by domain
    domain = email.split("@")[1] if "@" in email else ""
    if domain in _FALSE_POSITIVE_DOMAINS:
        return False

    # Filter obviously invalid
    if ".." in email or email.startswith(".") or email.endswith("."):
        return False

    # Filter image/file extensions used as emails
    if domain.endswith((".png", ".jpg", ".gif", ".css", ".js", ".svg")):
        return False

    return True


def run(page_contents: List[Dict[str, str]]) -> Dict[str, Any]:
    """Extract email addresses from crawled page HTML content.

    Args:
        page_contents: List of dicts with 'url' and 'html' keys.

    Returns:
        Dict with deduplicated emails and their source URLs.
    """
    result: Dict[str, Any] = {
        "data": {"emails": []},
        "risk_flags": [],
        "errors": [],
    }

    seen_emails: Dict[str, str] = {}  # email -> first source URL

    for page in page_contents:
        url = page.get("url", "")
        html = page.get("html", "")

        if not html:
            continue

        try:
            # Extract from mailto: links
            for match in _MAILTO_PATTERN.finditer(html):
                email = match.group(1).lower().strip()
                if _is_valid_email(email) and email not in seen_emails:
                    seen_emails[email] = url

            # Extract from general text
            for match in _EMAIL_PATTERN.finditer(html):
                email = match.group(0).lower().strip()
                if _is_valid_email(email) and email not in seen_emails:
                    seen_emails[email] = url

        except Exception as e:
            result["errors"].append(f"Error extracting emails from {url}: {str(e)}")

    result["data"]["emails"] = [
        {"email": email, "source_url": source}
        for email, source in sorted(seen_emails.items())
    ]

    return result
