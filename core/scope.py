"""
Scope Guard and Wildcard DNS Detection for Venom OSINT Framework.

Ensures that scanning operations never wander to out-of-scope third-party
domains (e.g., third-party SANs like cloudfront.net) and protects against
wildcard DNS false positives.
"""

import uuid
from typing import List, Set, Optional, Union, Tuple
from pathlib import Path
import dns.resolver


class ScopeGuard:
    """Validates and enforces domain and target scope boundaries."""

    def __init__(
        self,
        root_domain: str,
        allowed_scope: Optional[Union[List[str], Set[str], Path, str]] = None,
    ):
        self.root_domain = root_domain.strip().lower()
        self.allowed_domains: Set[str] = {self.root_domain}

        if allowed_scope:
            if isinstance(allowed_scope, (str, Path)) and Path(allowed_scope).is_file():
                self._load_from_file(Path(allowed_scope))
            elif isinstance(allowed_scope, (list, set, tuple)):
                for item in allowed_scope:
                    clean = str(item).strip().lower()
                    if clean:
                        self.allowed_domains.add(clean)
            elif isinstance(allowed_scope, str):
                for part in allowed_scope.split(","):
                    clean = part.strip().lower()
                    if clean:
                        self.allowed_domains.add(clean)

    def _load_from_file(self, path: Path) -> None:
        """Load allowed domains from file (one per line, # comments ignored)."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        self.allowed_domains.add(line)
        except Exception:
            pass

    def is_in_scope(self, candidate: str) -> bool:
        """Check if candidate domain or host is within authorized scope."""
        if not candidate:
            return False

        clean = candidate.strip().lower()
        if "://" in clean:
            clean = clean.split("://", 1)[1]
        clean = clean.split("/", 1)[0].split(":", 1)[0]

        # Exact match with any allowed domain
        if clean in self.allowed_domains:
            return True

        # Subdomain match with any allowed domain or root domain
        for allowed in self.allowed_domains:
            if clean.endswith(f".{allowed}"):
                return True

        return False

    def filter_in_scope(self, candidates: List[str]) -> List[str]:
        """Filter a list of candidates to keep only in-scope items."""
        return [c for c in candidates if self.is_in_scope(c)]


class WildcardDnsDetector:
    """Detects wildcard DNS records to avoid thousands of brute-force false positives."""

    def __init__(self, domain: str, timeout: float = 3.0):
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.is_wildcard: bool = False
        self.wildcard_ips: Set[str] = set()

    def check(self) -> Tuple[bool, Set[str]]:
        """Query non-existent randomized subdomains to verify wildcard behavior."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # Test two independent pseudo-random subdomains
        test_sub1 = f"venom-wildcard-{uuid.uuid4().hex[:12]}.{self.domain}"
        test_sub2 = f"venom-wildcard-{uuid.uuid4().hex[:12]}.{self.domain}"

        ips1 = self._resolve(resolver, test_sub1)
        ips2 = self._resolve(resolver, test_sub2)

        if ips1 and ips2 and (ips1 & ips2):
            self.is_wildcard = True
            self.wildcard_ips = ips1 | ips2
            return True, self.wildcard_ips

        self.is_wildcard = False
        return False, set()

    def _resolve(self, resolver: dns.resolver.Resolver, host: str) -> Set[str]:
        ips = set()
        try:
            answers = resolver.resolve(host, "A")
            for rdata in answers:
                ips.add(str(rdata))
        except Exception:
            pass
        return ips

    def is_false_positive(self, resolved_ips: List[str]) -> bool:
        """Check if resolved IPs match the wildcard signature."""
        if not self.is_wildcard or not resolved_ips:
            return False
        return any(ip in self.wildcard_ips for ip in resolved_ips)
