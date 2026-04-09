#!/usr/bin/env python3
"""
main.py — CLI entry-point for the standalone Confluence secret scanner.

Usage:
    python -m confluence_scanner.main [OPTIONS]

    # or if installed:
    confluence-scan [OPTIONS]

Examples:
    # Scan all spaces (interactive approval prompt):
    python -m confluence_scanner.main

    # Scoped CQL scan, auto-approve, 4 workers:
    python -m confluence_scanner.main --scope "cql:space=SEC AND type=page" --yes --workers 4

    # Skip comment scanning:
    python -m confluence_scanner.main --skip-comments
"""

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

from .scanner import ConfluenceSecretScanner
from .confluence_controller import CQLValidationError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="confluence-scan",
        description="Confluence secret scanner — find leaked credentials in Confluence pages.",
    )

    # Connection
    p.add_argument("--server",  default="", help="Confluence base URL  (or env CONFLUENCE_SERVER)")
    p.add_argument("--email",   default="", help="Confluence user email (or env CONFLUENCE_EMAIL)")
    p.add_argument("--api-key", dest="api_key", default="", help="Confluence API token  (or env CONFLUENCE_TOKEN)")

    # Scope
    p.add_argument("--scope", default=None,
                   help='CQL scope query, e.g. "cql:space=SEC AND type=page"')

    # Regex
    p.add_argument("--regex-file", dest="regex_file", default="",
                   help="Path to a YAML file with regex rules (default: bundled regex_patterns.yaml)")

    # Output
    p.add_argument("--report-file", dest="report_file", default="confluence_report.json",
                   help="Output JSON report path (default: confluence_report.json)")

    # Behaviour
    p.add_argument("-y", "--yes", dest="auto_approve", action="store_true",
                   help="Auto-approve scan scope summary (skip interactive prompt)")
    p.add_argument("--workers", default="1",
                   help="Parallel worker processes for regex phase. 'auto' = min(cpu_count, 8). Default: 1")
    p.add_argument("--skip-comments", dest="skip_comments", action="store_true",
                   help="Do not scan page comments")
    p.add_argument("--show-secrets", dest="show_secrets", action="store_true",
                   help="Show raw matched secrets in logs (CAUTION: may leak sensitive data)")
    p.add_argument("--timeout", type=int, default=None, help="HTTP request timeout in seconds")
    p.add_argument("--limit",   type=int, default=None, help="Max total pages to scan (default: unlimited)")
    p.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    p.add_argument("--debug",    action="store_true", help="Enable debug logging")

    return p


def main():
    load_dotenv()

    parser = build_parser()
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    # Resolve credentials (CLI > env)
    server = args.server or os.getenv("CONFLUENCE_SERVER", "")
    email  = args.email  or os.getenv("CONFLUENCE_EMAIL", "")
    token  = args.api_key or os.getenv("CONFLUENCE_TOKEN", "")

    missing = []
    if not server: missing.append("CONFLUENCE_SERVER (--server)")
    if not token:  missing.append("CONFLUENCE_TOKEN  (--api-key)")
    if missing:
        logging.error("Missing required configuration:\n  %s", "\n  ".join(missing))
        logging.error("Set them via CLI flags, environment variables, or a .env file.")
        sys.exit(1)

    # Workers
    workers_str = args.workers
    if workers_str.lower() == "auto":
        import multiprocessing
        num_workers = min(multiprocessing.cpu_count(), 8)
    else:
        num_workers = max(1, int(workers_str))

    # Build scanner
    scanner = ConfluenceSecretScanner(
        server=server,
        email=email,
        token=token,
        regex_file=args.regex_file,
        report_file=args.report_file,
        scope=args.scope,
        skip_comments=args.skip_comments,
        show_secrets=args.show_secrets,
        timeout=args.timeout,
        limit=args.limit,
        insecure=args.insecure,
        debug=args.debug,
    )

    try:
        scanner.run(auto_approve=args.auto_approve, num_workers=num_workers)
    except CQLValidationError as e:
        logging.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logging.warning("Interrupted — saving partial report...")
        sys.exit(130)
    except Exception as e:
        logging.error("Unexpected error: %s", e)
        sys.exit(1)
    finally:
        scanner.save_report()
        logging.info("Done!")


if __name__ == "__main__":
    main()
