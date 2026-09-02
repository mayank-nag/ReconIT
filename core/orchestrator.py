"""
Orchestrator for Venom OSINT.

Controls the phase pipeline, manages concurrency, and coordinates
all scanning modules into a unified workflow.
"""

import asyncio
from typing import Any, Dict, Optional
from pathlib import Path

from .target import Target
from .logger import VenomLogger


class Orchestrator:
    """Manages the 5-phase OSINT scanning pipeline.

    Phase 1: Root Scan (WHOIS, DNS, SSL, Tech Fingerprinting)
    Phase 2: Spread (Subdomain Enumeration + recursive Phase 1)
    Phase 3: Surface Crawl (Pages, Files, Emails, Metadata)
    Phase 4: History & Reputation (Wayback, VirusTotal, Safe Browsing)
    Phase 5: Report Generation (JSON + HTML + Graph)
    """

    def __init__(
        self,
        domain: str,
        config: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None,
        target_url: str = "",
        host: str = "",
        port: int = 80,
        protocol: str = "http",
        is_local: bool = False,
    ):
        self.domain = domain
        self.config = config
        self.options = options or {}
        self.target = Target(
            domain=domain,
            target_url=target_url or f"{protocol}://{host}" if port in (80, 443) else f"{protocol}://{host}:{port}",
            host=host or domain.split(":")[0],
            port=port,
            protocol=protocol,
            is_local=is_local,
        )
        self.logger = VenomLogger()

    async def _run_module(self, module_name: str, func, *args, **kwargs) -> Optional[Dict[str, Any]]:
        """Safely run a single module, catching any exceptions.

        Returns the module result dict or None on failure.
        """
        try:
            # Run sync functions in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: func(*args, **kwargs))

            # Log any module-level errors
            if result.get("errors"):
                for err in result["errors"]:
                    self.logger.warning(f"  {module_name}: {err}")

            return result
        except Exception as e:
            self.logger.error(f"  {module_name} crashed: {e}")
            self.target.errors.append(f"{module_name}: {str(e)}")
            return None

    def _process_risk_flags(self, module_name: str, result: Optional[Dict[str, Any]]) -> None:
        """Extract risk flags from a module result and add them to the target."""
        if not result:
            return

        flag_mapping = {
            "young_domain": ("Domain age < 6 months", None),
            "missing_spf (+10)": ("Missing SPF", None),
            "missing_dmarc (+10)": ("Missing DMARC", None),
            "cert_expired (+25)": ("SSL expired", None),
            "cert_expiring_soon (+15)": ("SSL expiring < 30 days", None),
            "missing_csp (+5)": ("Missing CSP header", None),
            "missing_hsts (+5)": ("Missing HSTS header", None),
            "missing_xfo (+5)": ("Missing X-Frame-Options", None),
            "missing_xcto (+5)": ("Missing X-Content-Type-Options", None),
        }

        for flag_str in result.get("risk_flags", []):
            if flag_str in flag_mapping:
                name, score = flag_mapping[flag_str]
                self.target.add_risk_flag(name, details=f"Detected by {module_name}")
            else:
                self.target.add_risk_flag(flag_str, details=f"Detected by {module_name}")

    async def run_phase_1(self) -> None:
        """Phase 1: Root Scan — WHOIS, DNS, SSL, Tech Fingerprinting."""
        self.logger.phase_start("Phase 1 — Root Scan", "WHOIS, DNS, SSL, Tech Fingerprinting...")

        from modules import whois_lookup, dns_recon, ssl_cert, tech_fingerprint

        # Run all Phase 1 modules concurrently
        whois_task = self._run_module("WHOIS", whois_lookup.run, self.target.host)
        dns_task = self._run_module("DNS", dns_recon.run, self.target.host)
        ssl_task = self._run_module("SSL", ssl_cert.run, self.target.host, port=self.target.port)
        tech_task = self._run_module("Tech", tech_fingerprint.run, self.target.domain, base_url=self.target.target_url)

        whois_result, dns_result, ssl_result, tech_result = await asyncio.gather(
            whois_task, dns_task, ssl_task, tech_task
        )

        # Store results in target
        if whois_result:
            self.target.whois_data = whois_result.get("data", {})
            self._process_risk_flags("WHOIS", whois_result)
            reg_date = self.target.whois_data.get("registration_date", "N/A")
            exp_date = self.target.whois_data.get("expiry_date", "N/A")
            self.logger.success(f"  WHOIS: Registered {reg_date} | Expires {exp_date}")

        if dns_result:
            self.target.dns_data = dns_result.get("data", {})
            self._process_risk_flags("DNS", dns_result)
            a_count = len(self.target.dns_data.get("A", []))
            mx_count = len(self.target.dns_data.get("MX", []))
            spf = "present" if not any("Missing SPF" in f["flag"] for f in self.target.risk_flags) else "MISSING ⚠"
            dmarc = "present" if not any("Missing DMARC" in f["flag"] for f in self.target.risk_flags) else "MISSING ⚠"
            self.logger.success(f"  DNS: {a_count} A records, {mx_count} MX, SPF {spf}, DMARC {dmarc}")

        if ssl_result:
            self.target.ssl_data = ssl_result.get("data", {})
            self._process_risk_flags("SSL", ssl_result)
            expiry = self.target.ssl_data.get("not_after", "N/A")
            san_count = len(self.target.ssl_data.get("sans", []))
            self.logger.success(f"  SSL: Valid until {expiry} | {san_count} SANs found")

        if tech_result:
            self.target.technologies = tech_result.get("data", {})
            self._process_risk_flags("Tech", tech_result)
            server = self.target.technologies.get("server", "Unknown")
            cms = self.target.technologies.get("cms", "None")
            fws = ", ".join(self.target.technologies.get("frameworks", [])) or "None"
            self.logger.success(f"  Tech: {server} | Frameworks: {fws} | CMS: {cms}")

        self.logger.phase_end("Phase 1")

    async def run_phase_2(self) -> None:
        """Phase 2: Spread — Subdomain Enumeration."""
        self.logger.phase_start("Phase 2 — Subdomain Spread", "Discovering subdomains...")

        try:
            from modules import subdomain_enum

            sans = self.target.ssl_data.get("sans", [])

            result = await self._run_module(
                "Subdomain Enum",
                subdomain_enum.run,
                self.target.domain,
                sans=sans,
                max_subdomains=self.options.get("max_subdomains", 100),
                timeout=self.options.get("timeout", 10),
            )

            if result:
                self.target.subdomains = result.get("data", {}).get("subdomains", [])
                self._process_risk_flags("Subdomain Enum", result)
                self.logger.success(f"  Total: {len(self.target.subdomains)} subdomains found")

        except ImportError:
            self.logger.warning("  Subdomain enumeration module not yet implemented")

        self.logger.phase_end("Phase 2")

    async def run_phase_3(self) -> None:
        """Phase 3: Surface Crawl — Pages, Emails, Metadata."""
        no_crawl = self.options.get("skip_crawl", False)

        self.logger.phase_start("Phase 3 — Surface Crawl", "Crawling, extracting endpoints, emails & metadata...")

        if no_crawl:
            self.logger.warning("  Crawling disabled by --no-crawl flag. Skipping.")
            self.logger.phase_end("Phase 3")
            return

        try:
            from modules import crawler, email_extractor, metadata_extractor

            depth = self.options.get("crawl_depth", 3)
            ignore_robots = self.options.get("ignore_robots", False)

            crawl_result = await self._run_module(
                "Crawler", crawler.run, self.target.domain,
                depth=depth, ignore_robots=ignore_robots,
                timeout=self.options.get("timeout", 10),
                base_url=self.target.target_url,
            )

            if crawl_result:
                pages = crawl_result.get("data", {}).get("pages", [])
                self.target.pages_crawled = pages
                self._process_risk_flags("Crawler", crawl_result)
                self.logger.success(f"  {len(pages)} endpoints & pages mapped")

                # Extract emails from crawled content
                page_contents = crawl_result.get("data", {}).get("page_contents", [])
                email_result = await self._run_module(
                    "Email Extractor", email_extractor.run, page_contents
                )
                if email_result:
                    self.target.emails_found = email_result.get("data", {}).get("emails", [])
                    self.logger.success(f"  {len(self.target.emails_found)} emails found")

                # Extract metadata from linked files
                files = crawl_result.get("data", {}).get("files", [])
                if files:
                    meta_result = await self._run_module(
                        "Metadata Extractor", metadata_extractor.run, files
                    )
                    if meta_result:
                        self.target.metadata_findings = meta_result.get("data", {}).get("findings", [])
                        self._process_risk_flags("Metadata", meta_result)
                        self.logger.success(f"  {len(self.target.metadata_findings)} files with metadata")

        except ImportError:
            self.logger.warning("  Crawl modules not yet implemented")

        self.logger.phase_end("Phase 3")

    async def run_phase_4(self) -> None:
        """Phase 4: History, Reputation & Threat Intel — Wayback, VirusTotal, CVE Correlation, GitHub Dorking."""
        self.logger.phase_start("Phase 4 — Threat Intel & Reputation", "Wayback Machine, CVE matching, GitHub dorks, reputation...")

        api_keys = self.config.get("api_keys", {})

        # 1. Wayback
        try:
            from modules import wayback
            wb_result = await self._run_module("Wayback", wayback.run, self.target.host)
            if wb_result:
                self.target.wayback_data = wb_result.get("data", {})
                snapshots = self.target.wayback_data.get("snapshot_count", 0)
                first = self.target.wayback_data.get("first_archived", "N/A")
                self.logger.success(f"  Wayback: First archived {first} | {snapshots} snapshots")
        except ImportError:
            self.logger.warning("  Wayback module not available")

        # 2. Reputation (VirusTotal / Safe Browsing / AbuseIPDB)
        try:
            from modules import reputation
            rep_result = await self._run_module("Reputation", reputation.run, self.target.host, api_keys=api_keys)
            if rep_result:
                self.target.reputation_data = rep_result.get("data", {})
                self._process_risk_flags("Reputation", rep_result)
                vt_flags = self.target.reputation_data.get("virustotal_positives", 0)
                if vt_flags:
                    self.logger.warning(f"  VirusTotal: {vt_flags} vendors flagged this domain ⚠")
                else:
                    self.logger.success("  Reputation: Clean / Verified")
        except ImportError:
            self.logger.warning("  Reputation module not available")

        # 3. CVE Correlation
        try:
            from modules import cve_lookup
            cve_result = await self._run_module("CVE Matcher", cve_lookup.run, self.target.technologies)
            if cve_result:
                self.target.cve_matches = cve_result.get("data", {}).get("cve_matches", [])
                self._process_risk_flags("CVE Matcher", cve_result)
                if self.target.cve_matches:
                    self.logger.warning(f"  CVE Matcher: {len(self.target.cve_matches)} potential CVE vulnerabilities correlated 🔴")
                else:
                    self.logger.success("  CVE Matcher: No critical CVE correlations identified")
        except ImportError:
            self.logger.warning("  CVE lookup module not available")

        # 4. GitHub Dorking
        try:
            from modules import github_dork
            gh_result = await self._run_module("GitHub Dorking", github_dork.run, self.target.host, api_keys=api_keys)
            if gh_result:
                self.target.github_dorks = gh_result.get("data", {}).get("dorks", [])
                self.target.github_leaks = gh_result.get("data", {}).get("findings", [])
                self._process_risk_flags("GitHub Dorking", gh_result)
                self.logger.success(f"  GitHub Dorking: Generated {len(self.target.github_dorks)} secret hunting dorks")
        except ImportError:
            self.logger.warning("  GitHub dorking module not available")

        self.logger.phase_end("Phase 4")

    async def run_phase_5(self) -> None:
        """Phase 5: AI Analysis & Report Generation — JSON + HTML Dashboard + Interactive Graph."""
        self.logger.phase_start("Phase 5 — Analysis & Reports", "Running AI Analyst & generating reports...")

        # 1. AI Analyst Layer
        try:
            from modules import ai_analyst
            ai_result = await self._run_module("AI Analyst", ai_analyst.run, self.target.to_dict())
            if ai_result:
                self.target.ai_analysis = ai_result.get("data", {})
                self.logger.success("  AI Analyst: Intelligence narrative and remediation roadmap synthesized")
        except Exception as e:
            self.logger.warning(f"  AI Analyst warning: {e}")

        # 2. Calculate final risk score
        self.target.calculate_risk_score()
        risk_level = self.target.get_risk_level()

        output_dir = Path(self.options.get("output_dir", "./output")) / f"{self.domain.replace(':', '_')}_report"
        output_dir.mkdir(parents=True, exist_ok=True)

        output_format = self.options.get("output_format", "all")

        # 3. Assemble Report
        try:
            from report import generator

            result = await self._run_module(
                "Report Generator",
                generator.run,
                self.target,
                output_dir=str(output_dir),
                output_format=output_format,
            )

            if result:
                for f in result.get("data", {}).get("files_created", []):
                    self.logger.success(f"  {f}")
        except Exception as e:
            # Fallback: write JSON
            json_path = output_dir / "report.json"
            json_path.write_text(self.target.to_json())
            self.logger.success(f"  report.json → {json_path}")

        self.logger.phase_end("Phase 5")

    async def run(self) -> Target:
        """Runs the complete OSINT pipeline and returns the populated Target."""
        self.logger.banner()
        self.logger.info(f"Target: {self.target.target_url} ({self.domain})")
        self.logger.info(f"Environment: {'Local / Internal' if self.target.is_local else 'Public Internet'}")
        self.logger.info("Starting scan...\n")

        await self.run_phase_1()
        await self.run_phase_2()
        await self.run_phase_3()
        await self.run_phase_4()
        await self.run_phase_5()

        # Final summary
        risk_level = self.target.get_risk_level()
        score = self.target.risk_score
        flag_count = len(self.target.risk_flags)

        self.logger.info("")
        self.logger.success(f"Scan complete. Risk Score: {score}/100 ({risk_level})")
        if flag_count:
            self.logger.warning(f"  {flag_count} risk flag(s) detected")
            for f in self.target.risk_flags:
                self.logger.warning(f"    • {f['flag']}: {f.get('details', '')}")

        return self.target
