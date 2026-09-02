"""
Target Dataclass for Venom OSINT.

Stores all scan findings for a domain and calculates risk scores
based on discovered vulnerabilities and misconfigurations.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
import json
from datetime import datetime, timezone


@dataclass
class Target:
    """Central data object that accumulates all findings across scan phases."""

    domain: str
    target_url: str = ""
    host: str = ""
    port: int = 80
    protocol: str = "http"
    is_local: bool = False
    scan_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    whois_data: Dict[str, Any] = field(default_factory=dict)
    dns_data: Dict[str, Any] = field(default_factory=dict)
    ssl_data: Dict[str, Any] = field(default_factory=dict)
    technologies: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    pages_crawled: List[Dict[str, Any]] = field(default_factory=list)
    emails_found: List[Any] = field(default_factory=list)
    metadata_findings: List[Dict[str, Any]] = field(default_factory=list)
    wayback_data: Dict[str, Any] = field(default_factory=dict)
    reputation_data: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    risk_flags: List[Dict[str, Any]] = field(default_factory=list)
    github_dorks: List[Dict[str, Any]] = field(default_factory=list)
    github_leaks: List[Dict[str, Any]] = field(default_factory=list)
    cve_matches: List[Dict[str, Any]] = field(default_factory=list)
    ai_analysis: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # Risk scoring table from the implementation plan
    RISK_SCORES: Dict[str, int] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.host:
            self.host = self.domain
        if not self.target_url:
            self.target_url = f"{self.protocol}://{self.host}" if self.port in (80, 443) else f"{self.protocol}://{self.host}:{self.port}"

        self.RISK_SCORES = {
            "Domain age < 6 months": 20,
            "Missing DMARC": 10,
            "Missing SPF": 10,
            "SSL expiring < 30 days": 15,
            "SSL expired": 25,
            "Plain HTTP / Missing SSL Encryption": 15,
            "Missing CSP header": 5,
            "Missing HSTS header": 5,
            "Missing X-Frame-Options": 5,
            "Missing X-Content-Type-Options": 5,
            "Missing Referrer-Policy": 5,
            "Missing Permissions-Policy": 5,
            "VirusTotal positive flag": 20,
            "Google Safe Browsing flag": 30,
            "AbuseIPDB high abuse confidence": 20,
            "Outdated CMS version detected": 10,
            "Exposed .git or .env reference": 25,
            "Exposed sensitive path or directory": 20,
            "No HTTPS on subdomains": 10,
            "Known Critical/High CVE matched": 20,
            "Public GitHub secret / credential leak": 25,
            "Exposed metadata with author/GPS info": 10,
        }

    def add_risk_flag(self, flag: str, details: str = "", score: Optional[int] = None) -> None:
        """Adds a risk flag if it's not already present.

        Args:
            flag: Short identifier for the risk (e.g., "Missing DMARC")
            details: Optional longer description
            score: Override score; if None, looks up from RISK_SCORES table
        """
        # Deduplicate by flag name
        existing = {f["flag"] for f in self.risk_flags}
        if flag in existing:
            return

        if score is None:
            score = self.RISK_SCORES.get(flag, 5)

        self.risk_flags.append({
            "flag": flag,
            "details": details,
            "score": score,
        })

    def calculate_risk_score(self) -> int:
        """Calculates the overall risk score (0-100) based on accumulated risk flags.

        Score bands:
            0-30:  LOW
            31-60: MEDIUM
            61-80: HIGH
            81-100: CRITICAL
        """
        score = sum(f["score"] for f in self.risk_flags)
        self.risk_score = min(score, 100)
        return self.risk_score

    def get_risk_level(self) -> str:
        """Returns the risk level string based on the current score."""
        if self.risk_score <= 30:
            return "LOW"
        elif self.risk_score <= 60:
            return "MEDIUM"
        elif self.risk_score <= 80:
            return "HIGH"
        else:
            return "CRITICAL"

    def to_dict(self) -> Dict[str, Any]:
        """Converts the Target instance to a dictionary."""
        data = asdict(self)
        data.pop("RISK_SCORES", None)
        data["target"] = self.domain
        data["risk_level"] = self.get_risk_level()
        return data

    def to_json(self) -> str:
        """Converts the Target instance to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)
