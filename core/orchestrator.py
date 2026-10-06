"""
Orchestrator for ReconIT / Venom OSINT Framework.

Controls the 5-phase pipeline, manages concurrency, coordinates
shared rate-limiting, enforces scope boundaries, and supports recursion
safeguards, dry-run previews, and scan diffing.
"""

import os
import json
import asyncio
from typing import Any, Dict, Optional, Set, List
from pathlib import Path

from .target import Target
from .logger import VenomLogger
from .http_client import HttpClient
from .scope import ScopeGuard, WildcardDnsDetector


class Orchestrator:
    """Manages the 5-phase OSINT scanning pipeline with scope, recursion, and rate limiting controls."""

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

        # Initialize Target model
        self.target = Target(
            domain=domain,
            target_url=target_url or (f"{protocol}://{host}" if port in (80, 443) else f"{protocol}://{host}:{port}"),
            host=host or domain.split(":")[0],
            port=port,
            protocol=protocol,
            is_local=is_local,
        )

        # Initialize Logger
        log_file = self.options.get("log_file")
        self.logger = VenomLogger(verbose=self.options.get("verbose", False), log_file=log_file)

        # Initialize Scope Guard
        scope_source = self.options.get("scope_file") or self.config.get("scan", {}).get("scope")
        self.scope_guard = ScopeGuard(self.domain, allowed_scope=scope_source)

        # Initialize shared HTTP Client
        scan_cfg = self.config.get("scan", {})
        rate_limit = float(self.options.get("rate_limit") or scan_cfg.get("rate_limit", 5.0))
        timeout = float(self.options.get("timeout") or scan_cfg.get("timeout", 10.0))
        user_agent = scan_cfg.get("user_agent")
        self.http_client = HttpClient.get_instance(
            rate_limit=rate_limit,
            timeout=timeout,
            user_agent=user_agent,
        )

        # Recursion and visited tracking
        self.visited_hosts: Set[str] = {self.domain}
        self.max_hosts = int(self.options.get("max_hosts") or scan_cfg.get("max_hosts", 25))

    async def _run_module(self, module_name: str, func, *args, **kwargs) -> Optional[Dict[str, Any]]:
        """Safely run a module in an executor, catching and logging any exceptions."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: func(*args, **kwargs))

            if result and result.get("errors"):
                for err in result["errors"]:
                    self.logger.warning(f"  {module_name}: {err}")

            return result
        except Exception as e:
            self.logger.error(f"  {module_name} crashed: {e}")
            self.logger.exception(f"Exception details for {module_name}", e)
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
            "virustotal_flagged": ("VirusTotal positive flag", None),
            "abuseipdb_flagged": ("AbuseIPDB high abuse confidence", None),
        }

        for flag_str in result.get("risk_flags", []):
            if flag_str in flag_mapping:
                name, score = flag_mapping[flag_str]
                self.target.add_risk_flag(name, details=f"Detected by {module_name}")
            else:
                self.target.add_risk_flag(flag_str, details=f"Detected by {module_name}")

    def execute_dry_run(self) -> None:
        """Display an operational execution preview without performing network actions."""
        self.logger.banner()
        self.logger.info("=== DRY-RUN PREVIEW MODE ACTIVATED ===")
        self.logger.info(f"Target: {self.target.target_url} ({self.domain})")
        self.logger.info(f"Scope Root: {self.scope_guard.root_domain} (Allowed: {len(self.scope_guard.allowed_domains)} domains)")
        self.logger.info(f"Rate Limiting: {self.http_client.rate_limiter.rate} requests/sec")
        self.logger.info(f"Network Timeout: {self.http_client.timeout}s")
        self.logger.info("")
        self.logger.info("Configured Modules Pipeline:")
        modules_plan = [
            ("Phase 1: WHOIS Lookup", "Passive third-party WHOIS registration query"),
            ("Phase 1: DNS Recon", "Low-impact direct DNS record resolution (A, MX, TXT, SPF, DMARC)"),
            ("Phase 1: SSL Inspection", "Direct TLS handshake & certificate SAN inspection"),
            ("Phase 1: Tech Fingerprint", "Low-impact direct HTTP probe & security header inspection"),
            ("Phase 2: Subdomain Enumeration", "Passive crt.sh CT logs + Wildcard-guarded DNS brute force"),
            ("Phase 3: Web Crawler", "Rate-limited internal spidering (BFS capped depth)"),
            ("Phase 3: Email & Metadata Extraction", "Passive parsing of crawled content & defensive asset inspection"),
            ("Phase 4: Threat Intel & Reputation", "Passive queries to Wayback, VirusTotal, AbuseIPDB, CIRCL CVEs"),
            ("Phase 4: GitHub Dorking", "Passive search queries for leaked credentials and public tokens"),
            ("Phase 5: Analyst Engine", "Rule-based heuristic evaluation + multi-format report export"),
        ]
        for name, desc in modules_plan:
            self.logger.info(f"  • {name:<32} -> {desc}")
        self.logger.info("")
        self.logger.success("Dry run preview completed. No network requests were dispatched.")

    async def run_phase_1(self) -> None:
        """Phase 1: Root Scan — WHOIS, DNS, SSL, Tech Fingerprinting."""
        self.logger.phase_start(
            "Phase 1 — Root Scan",
            "WHOIS (Passive), DNS (Direct Query), SSL (Direct TLS), Tech Fingerprint (Direct HTTP)...",
        )

        from modules import whois_lookup, dns_recon, ssl_cert, tech_fingerprint

        timeout = self.options.get("timeout", 10)

        # Run Phase 1 modules concurrently
        whois_task = self._run_module("WHOIS", whois_lookup.run, self.target.host)
        dns_task = self._run_module("DNS", dns_recon.run, self.target.host)
        ssl_task = self._run_module("SSL", ssl_cert.run, self.target.host, port=self.target.port)
        tech_task = self._run_module(
            "Tech",
            tech_fingerprint.run,
            self.target.domain,
            base_url=self.target.target_url,
            timeout=timeout,
        )

        whois_result, dns_result, ssl_result, tech_result = await asyncio.gather(
            whois_task, dns_task, ssl_task, tech_task
        )

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
        """Phase 2: Spread — Subdomain Enumeration with Wildcard Detection and Scope Guard."""
        self.logger.phase_start(
            "Phase 2 — Subdomain Spread",
            "Enumerating subdomains via crt.sh CT logs, SSL SANs, and guarded DNS brute-forcing...",
        )

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
                scope_guard=self.scope_guard,
            )

            if result:
                self.target.subdomains = result.get("data", {}).get("subdomains", [])
                self._process_risk_flags("Subdomain Enum", result)
                if result.get("data", {}).get("wildcard_dns"):
                    self.logger.warning("  Wildcard DNS detected (*.domain resolves). Brute force was safely filtered.")
                self.logger.success(f"  Total: {len(self.target.subdomains)} in-scope subdomains verified")

                # Handle safe recursion if requested
                if self.options.get("recursive") and self.target.subdomains:
                    await self._handle_recursion()

        except ImportError:
            self.logger.warning("  Subdomain enumeration module not available")

        self.logger.phase_end("Phase 2")

    async def _handle_recursion(self) -> None:
        """Recurse on discovered in-scope subdomains with strict depth and host caps."""
        candidates = [s for s in self.target.subdomains if s not in self.visited_hosts]
        capped_candidates = candidates[: min(len(candidates), self.max_hosts - len(self.visited_hosts))]

        if not capped_candidates:
            return

        self.logger.info(f"  Recursive expansion: scanning {len(capped_candidates)} subdomains (capped at {self.max_hosts} total hosts)...")

        from modules import tech_fingerprint, ssl_cert

        timeout = self.options.get("timeout", 10)
        for sub in capped_candidates:
            if not self.scope_guard.is_in_scope(sub):
                continue

            self.visited_hosts.add(sub)
            self.logger.debug(f"  [Recurse] Probing subdomain: {sub}")

            # Lightweight probe on recursed subdomains
            sub_ssl = await self._run_module("SSL (Recurse)", ssl_cert.run, sub)
            if sub_ssl and sub_ssl.get("risk_flags"):
                self._process_risk_flags(f"SSL ({sub})", sub_ssl)

            sub_tech = await self._run_module("Tech (Recurse)", tech_fingerprint.run, sub, timeout=timeout)
            if sub_tech and sub_tech.get("risk_flags"):
                self._process_risk_flags(f"Tech ({sub})", sub_tech)

    async def run_phase_3(self) -> None:
        """Phase 3: Surface Crawl — Pages, Emails, Metadata."""
        no_crawl = self.options.get("skip_crawl", False)

        self.logger.phase_start(
            "Phase 3 — Surface Crawl",
            "Rate-limited spidering, endpoint discovery, emails, and defensive document metadata extraction...",
        )

        if no_crawl:
            self.logger.warning("  Crawling disabled by --no-crawl flag. Skipping.")
            self.logger.phase_end("Phase 3")
            return

        try:
            from modules import crawler, email_extractor, metadata_extractor

            depth = self.options.get("crawl_depth", 3)
            ignore_robots = self.options.get("ignore_robots", False)
            timeout = self.options.get("timeout", 10)

            crawl_result = await self._run_module(
                "Crawler",
                crawler.run,
                self.target.domain,
                depth=depth,
                ignore_robots=ignore_robots,
                timeout=timeout,
                base_url=self.target.target_url,
            )

            if crawl_result:
                pages = crawl_result.get("data", {}).get("pages", [])
                self.target.pages_crawled = pages
                self._process_risk_flags("Crawler", crawl_result)
                self.logger.success(f"  {len(pages)} endpoints mapped")

                page_contents = crawl_result.get("data", {}).get("page_contents", [])
                email_result = await self._run_module(
                    "Email Extractor", email_extractor.run, page_contents
                )
                if email_result:
                    self.target.emails_found = email_result.get("data", {}).get("emails", [])
                    self.logger.success(f"  {len(self.target.emails_found)} emails found")

                files = crawl_result.get("data", {}).get("files", [])
                if files:
                    meta_result = await self._run_module(
                        "Metadata Extractor",
                        metadata_extractor.run,
                        files,
                        timeout=timeout,
                    )
                    if meta_result:
                        self.target.metadata_findings = meta_result.get("data", {}).get("findings", [])
                        self._process_risk_flags("Metadata", meta_result)
                        self.logger.success(f"  {len(self.target.metadata_findings)} files with metadata analyzed")

        except ImportError:
            self.logger.warning("  Crawl modules not available")

        self.logger.phase_end("Phase 3")

    async def run_phase_4(self) -> None:
        """Phase 4: History, Reputation & Threat Intel — Wayback, VirusTotal, Safe Browsing, CVEs, GitHub Dorking."""
        self.logger.phase_start(
            "Phase 4 — Threat Intel & Reputation",
            "Wayback Machine, VirusTotal/SafeBrowsing, CVE correlation, and GitHub secret dorks...",
        )

        api_keys = self.config.get("api_keys", {})
        timeout = self.options.get("timeout", 10)

        # 1. Wayback
        try:
            from modules import wayback

            wb_result = await self._run_module("Wayback", wayback.run, self.target.host, timeout=timeout)
            if wb_result:
                self.target.wayback_data = wb_result.get("data", {})
                snapshots = self.target.wayback_data.get("snapshot_count", 0)
                first = self.target.wayback_data.get("first_archived", "N/A")
                self.logger.success(f"  Wayback: First archived {first} | {snapshots} snapshots")
        except ImportError:
            self.logger.warning("  Wayback module not available")

        # 2. Reputation
        try:
            from modules import reputation

            rep_result = await self._run_module("Reputation", reputation.run, self.target.host, api_keys=api_keys, timeout=timeout)
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

            cve_result = await self._run_module("CVE Matcher", cve_lookup.run, self.target.technologies, timeout=timeout)
            if cve_result:
                self.target.cve_matches = cve_result.get("data", {}).get("cve_matches", [])
                self._process_risk_flags("CVE Matcher", cve_result)
                if self.target.cve_matches:
                    self.logger.warning(f"  CVE Matcher: {len(self.target.cve_matches)} potential CVE correlations identified 🔴")
                else:
                    self.logger.success("  CVE Matcher: No critical CVE correlations identified")
        except ImportError:
            self.logger.warning("  CVE lookup module not available")

        # 4. GitHub Dorking
        try:
            from modules import github_dork

            gh_result = await self._run_module("GitHub Dorking", github_dork.run, self.target.host, api_keys=api_keys, timeout=timeout)
            if gh_result:
                self.target.github_dorks = gh_result.get("data", {}).get("dorks", [])
                self.target.github_leaks = gh_result.get("data", {}).get("findings", [])
                self._process_risk_flags("GitHub Dorking", gh_result)
                self.logger.success(f"  GitHub Dorking: Generated {len(self.target.github_dorks)} secret hunting dorks")
        except ImportError:
            self.logger.warning("  GitHub dorking module not available")

        self.logger.phase_end("Phase 4")

    async def run_phase_5(self) -> None:
        """Phase 5: Analyst Engine & Report Generation — JSON, HTML Dashboard, CSV, Graph."""
        self.logger.phase_start(
            "Phase 5 — Analysis & Reports",
            "Running Analyst Engine (Rule-based heuristic / Optional LLM) and generating secure reports...",
        )

        api_keys = self.config.get("api_keys", {})

        # 1. Analyst Engine Layer
        try:
            from modules import ai_analyst

            ai_result = await self._run_module("Analyst Engine", ai_analyst.run, self.target.to_dict(), api_keys=api_keys)
            if ai_result:
                self.target.ai_analysis = ai_result.get("data", {})
                mode_label = self.target.ai_analysis.get("mode", "Analyst Engine")
                self.logger.success(f"  Analyst Engine [{mode_label}]: Narrative and roadmap synthesized")
        except Exception as e:
            self.logger.warning(f"  Analyst Engine warning: {e}")

        # 2. Diffing with previous scan if requested
        diff_file = self.options.get("diff_file")
        if diff_file and Path(diff_file).is_file():
            self._compute_scan_diff(Path(diff_file))

        # 3. Calculate final heuristic risk score (capped at 100)
        self.target.calculate_risk_score()

        output_dir = Path(self.options.get("output_dir", "./output")) / f"{self.domain.replace(':', '_')}_report"
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(output_dir, 0o700)
        except Exception:
            pass

        output_format = self.options.get("output_format", "all")

        # 4. Assemble Reports
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
            json_path = output_dir / "report.json"
            json_path.write_text(self.target.to_json())
            try:
                os.chmod(json_path, 0o600)
            except Exception:
                pass
            self.logger.success(f"  report.json → {json_path}")

        self.logger.phase_end("Phase 5")

    def _compute_scan_diff(self, old_report_path: Path) -> None:
        """Compute delta between current scan and a previous report JSON."""
        try:
            with open(old_report_path, "r", encoding="utf-8") as f:
                old_data = json.load(f)

            old_subs = set(old_data.get("subdomains", []))
            new_subs = set(self.target.subdomains)

            added_subs = sorted(list(new_subs - old_subs))
            removed_subs = sorted(list(old_subs - new_subs))

            old_score = old_data.get("risk_score", 0)
            score_delta = self.target.risk_score - old_score

            diff_summary = {
                "previous_scan_date": old_data.get("scan_date", "Unknown"),
                "previous_risk_score": old_score,
                "current_risk_score": self.target.risk_score,
                "score_delta": score_delta,
                "new_subdomains": added_subs,
                "removed_subdomains": removed_subs,
            }

            if not hasattr(self.target, "ai_analysis") or not isinstance(self.target.ai_analysis, dict):
                self.target.ai_analysis = {}
            self.target.ai_analysis["scan_diff"] = diff_summary

            self.logger.info("  === Scan Diff Summary ===")
            self.logger.info(f"    Risk Score Change: {old_score} -> {self.target.risk_score} ({'+' if score_delta >= 0 else ''}{score_delta})")
            if added_subs:
                self.logger.warning(f"    New Subdomains Discovered ({len(added_subs)}): {', '.join(added_subs[:5])}")
            if removed_subs:
                self.logger.info(f"    Removed Subdomains ({len(removed_subs)}): {', '.join(removed_subs[:5])}")

        except Exception as e:
            self.logger.warning(f"Could not compute scan diff: {e}")

    async def run(self) -> Target:
        """Runs the complete OSINT pipeline and returns the populated Target."""
        if self.options.get("dry_run"):
            self.execute_dry_run()
            return self.target

        self.logger.banner()
        self.logger.info(f"Target: {self.target.target_url} ({self.domain})")
        self.logger.info(f"Environment: {'Local / Internal' if self.target.is_local else 'Public Internet'}")
        self.logger.info(f"Scope Guard: Root domain {self.scope_guard.root_domain} (enforcing in-scope boundaries)")
        self.logger.info("Starting scan...\n")

        try:
            await self.run_phase_1()
            await self.run_phase_2()
            await self.run_phase_3()
            await self.run_phase_4()
            await self.run_phase_5()
        finally:
            self.http_client.close()

        # Final summary
        risk_level = self.target.get_risk_level()
        score = self.target.risk_score
        flag_count = len(self.target.risk_flags)

        self.logger.info("")
        self.logger.success(f"Scan complete. Heuristic Risk Score: {score}/100 ({risk_level})")
        if flag_count:
            self.logger.warning(f"  {flag_count} risk flag(s) detected")
            for f in self.target.risk_flags:
                self.logger.warning(f"    • {f['flag']}: {f.get('details', '')}")

        return self.target
