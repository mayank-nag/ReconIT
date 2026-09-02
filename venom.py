#!/usr/bin/env python3
"""
VENOM — OSINT Recon Tool
One domain in. Everything out.

Main CLI entry point.
"""

import argparse
import asyncio
import re
import sys
from pathlib import Path

import yaml

from core.orchestrator import Orchestrator
from core.logger import VenomLogger

__version__ = "1.0.0"


def normalize_target(target: str) -> str:
    """Extract and normalize domain from target string or URL."""
    target = target.strip()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0]
    target = target.split(":", 1)[0]
    return target.lower()


def validate_domain(domain: str) -> bool:
    """Validate the target domain format.

    Accepts standard domain names like example.com, sub.example.co.uk, etc.
    """
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def load_config(config_path: str) -> dict:
    """Load configuration from a YAML file.

    Returns an empty dict if the file doesn't exist or can't be parsed.
    """
    path = Path(config_path)
    if not path.is_file():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def main() -> None:
    """Main entry point for Venom CLI."""
    parser = argparse.ArgumentParser(
        prog="venom",
        description="VENOM — Automated OSINT Recon Framework. One domain in. Everything out.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python venom.py --target example.com
  python venom.py --target example.com --full
  python venom.py --target example.com --no-crawl
  python venom.py --target example.com --depth 2 --output ./reports/
  python venom.py --target example.com --format json --verbose
        """,
    )

    # Required
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")

    # Scan options
    parser.add_argument("-f", "--full", action="store_true", help="Run all modules including optional ones")
    parser.add_argument("--no-crawl", action="store_true", help="Skip Phase 3 crawling (faster, infra-only)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt during crawling")
    parser.add_argument("--max-subdomains", type=int, default=100, help="Max subdomains to enumerate (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")

    # Output
    parser.add_argument("-o", "--output", default="./output/", help="Output directory (default: ./output/)")
    parser.add_argument("--format", choices=["all", "json", "html"], default="all", help="Output format (default: all)")

    # Config
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config file (default: config.yaml)")

    # Logging
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")

    # Version
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    logger = VenomLogger()

    # Normalize and validate domain
    target_domain = normalize_target(args.target)
    if not validate_domain(target_domain):
        logger.error(f"Invalid domain format: '{args.target}'")
        logger.info("Please provide a valid domain (e.g., example.com)")
        sys.exit(1)
    args.target = target_domain

    # Load config
    config = load_config(args.config)
    if not config:
        logger.warning(f"Config file '{args.config}' not found or empty. Using defaults.")

    if args.ignore_robots:
        logger.warning("robots.txt will be ignored during crawling. Ensure you have authorization!")

    # Build options dict from CLI args
    options = {
        "full_run": args.full,
        "skip_crawl": args.no_crawl,
        "crawl_depth": args.depth,
        "output_dir": args.output,
        "output_format": args.format,
        "ignore_robots": args.ignore_robots,
        "max_subdomains": args.max_subdomains,
        "timeout": args.timeout,
        "verbose": args.verbose,
        "quiet": args.quiet,
    }

    # Create orchestrator and run
    orchestrator = Orchestrator(domain=args.target, config=config, options=options)

    try:
        target = asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user. Exiting gracefully...")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
