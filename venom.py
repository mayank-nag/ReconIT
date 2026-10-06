#!/usr/bin/env python3
"""
ReconIT / VENOM — OSINT Recon Tool
One domain in. Everything out.

Main CLI entry point with configuration precedence, safe defaults,
and scope management.
"""

import argparse
import asyncio
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from core.orchestrator import Orchestrator
from core.logger import VenomLogger

__version__ = "1.0.0"


def normalize_target(target: str) -> str:
    """Extract and normalize domain from target string or URL."""
    if not target:
        return ""
    target = target.strip()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0]
    target = target.split(":", 1)[0]
    return target.lower()


def validate_domain(domain: str) -> bool:
    """Validate target domain or host format.

    Accepts standard domain names, subdomains, and local test hosts.
    """
    if not domain:
        return False

    # Check for localhost / local IP
    clean = domain.lower()
    if clean in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or clean.endswith(".local"):
        return True

    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def load_config(config_path: str, is_default_path: bool = True) -> Dict[str, Any]:
    """Load configuration from a YAML file.

    Distinguishes between a missing default config and a malformed YAML file.
    Fails loudly on malformed configuration.
    """
    path = Path(config_path)
    if not path.is_file():
        if is_default_path:
            return {}
        raise FileNotFoundError(f"Specified configuration file not found: '{config_path}'")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except yaml.YAMLError as e:
        raise ValueError(f"Malformed YAML in configuration file '{config_path}': {e}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to read configuration file '{config_path}': {e}") from e


def merge_options(cli_args: argparse.Namespace, config: Dict[str, Any]) -> Dict[str, Any]:
    """Merge CLI flags, config values, and built-in defaults with strict precedence.

    Order of Precedence: CLI argument > config.yaml > built-in default.
    """
    scan_cfg = config.get("scan", {})
    output_cfg = config.get("output", {})

    def resolve(cli_val: Any, cfg_val: Any, default_val: Any) -> Any:
        if cli_val is not None:
            return cli_val
        if cfg_val is not None:
            return cfg_val
        return default_val

    return {
        "full_run": cli_args.full,
        "skip_crawl": cli_args.no_crawl,
        "crawl_depth": int(resolve(cli_args.depth, scan_cfg.get("crawl_depth"), 3)),
        "max_subdomains": int(resolve(cli_args.max_subdomains, scan_cfg.get("max_subdomains"), 100)),
        "timeout": int(resolve(cli_args.timeout, scan_cfg.get("timeout"), 10)),
        "rate_limit": float(resolve(cli_args.rate_limit, scan_cfg.get("rate_limit"), 5.0)),
        "output_dir": str(resolve(cli_args.output, output_cfg.get("directory"), "./output/")),
        "output_format": str(resolve(cli_args.format, output_cfg.get("format"), "all")),
        "ignore_robots": cli_args.ignore_robots,
        "verbose": cli_args.verbose,
        "quiet": cli_args.quiet,
        "log_file": cli_args.log_file,
        "scope_file": cli_args.scope,
        "dry_run": cli_args.dry_run,
        "diff_file": cli_args.diff,
        "recursive": cli_args.recursive or scan_cfg.get("recursive", False),
    }


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments with default=None for config merging."""
    parser = argparse.ArgumentParser(
        prog="venom",
        description="ReconIT / VENOM — Low-Impact OSINT Reconnaissance Framework. One domain in. Everything out.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python venom.py --target example.com
  python venom.py --target example.com --dry-run
  python venom.py --target example.com --scope inscope.txt --full
  python venom.py --target example.com --format json,csv --log-file scan.log
  python venom.py --target example.com --diff ./output/example.com_report/report.json
        """,
    )

    # Required target
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")

    # Scan control options (default=None to allow config.yaml values to apply)
    parser.add_argument("-f", "--full", action="store_true", help="Run all modules including optional threat feeds")
    parser.add_argument("--no-crawl", action="store_true", help="Skip Phase 3 web crawling (faster, infra-only)")
    parser.add_argument("-d", "--depth", type=int, default=None, help="Crawl depth limit (default: 3 or config)")
    parser.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt during crawling")
    parser.add_argument("--max-subdomains", type=int, default=None, help="Max subdomains to enumerate (default: 100 or config)")
    parser.add_argument("--timeout", type=int, default=None, help="Request timeout in seconds (default: 10 or config)")
    parser.add_argument("--rate-limit", type=float, default=None, help="Requests per second rate limit (default: 5.0 or config)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan discovered in-scope subdomains")

    # Scope and dry-run
    parser.add_argument("--scope", default=None, help="Path to scope file or comma-separated allowed domains")
    parser.add_argument("--dry-run", action="store_true", help="Display execution blueprint without sending network requests")

    # Output & Diffing
    parser.add_argument("-o", "--output", default=None, help="Output directory (default: ./output/ or config)")
    parser.add_argument("--format", choices=["all", "json", "html", "csv"], default=None, help="Output format: all, json, html, csv (default: all)")
    parser.add_argument("--diff", default=None, help="Path to previous scan report.json for change diffing")

    # Config & Logging
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config file (default: config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal console output")
    parser.add_argument("--log-file", default=None, help="Write detailed execution logs to specified file")

    # Version
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    return parser.parse_args()


def main() -> None:
    """Main CLI entry point."""
    args = parse_arguments()
    logger = VenomLogger(verbose=args.verbose, log_file=args.log_file)

    # Normalize and validate domain
    target_domain = normalize_target(args.target)
    if not validate_domain(target_domain):
        logger.error(f"Invalid domain format: '{args.target}'")
        logger.info("Please provide a valid domain name (e.g., example.com)")
        sys.exit(1)
    args.target = target_domain

    # Load configuration with error handling
    is_default_cfg = args.config == "config.yaml"
    try:
        config = load_config(args.config, is_default_path=is_default_cfg)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    if not config and is_default_cfg:
        logger.info(f"Default config '{args.config}' not found. Using framework defaults (see config.yaml.example).")

    if args.ignore_robots:
        logger.warning("robots.txt will be ignored during crawling. Ensure you have explicit authorization!")

    # Merge options with proper precedence
    options = merge_options(args, config)

    # Initialize orchestrator
    orchestrator = Orchestrator(domain=args.target, config=config, options=options)

    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user. Exiting cleanly...")
        sys.exit(130)
    except Exception as e:
        logger.exception("Scan failed with unexpected error", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
