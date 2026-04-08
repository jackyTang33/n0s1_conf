"""
scanner.py — Regex secret scanning engine for the standalone Confluence scanner.

Responsibilities:
  • Load regex rules from YAML
  • Scan text blocks for secret matches
  • Orchestrate the two-pass flow (prefetch → approve → scan)
  • Parallel scanning via ProcessPoolExecutor
  • Report generation (JSON and SARIF-lite)
"""

import concurrent.futures
import hashlib
import json
import logging
import os
import re
import sys

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex matching (module-level so workers can pickle them)
# ---------------------------------------------------------------------------

def _safe_re_search(regex_str: str, text: str):
    """Attempt a regex search, falling back to case-insensitive on error."""
    try:
        return re.search(regex_str, text)
    except Exception:
        try:
            return re.search(regex_str.replace("(?i)", ""), text, re.IGNORECASE)
        except Exception:
            return None


def match_regex(regex_config: dict, text: str):
    """Try every rule in *regex_config* against *text*.

    Returns (matched_rule, raw_match, sanitized, snippet, line_number) or
    all-Nones if nothing matched.
    """
    for rule in regex_config.get("rules", []):
        regex_str = rule["regex"]
        # Move inline modifiers to the front (some patterns put them mid-string)
        for mod in ("(?i)", "(?m)", "(?s)", "(?x)", "(?g)", "(?u)", "(?A)", "(?L)", "(?U)"):
            if regex_str.find(mod) > 0:
                regex_str = mod + regex_str.replace(mod, "")
        m = _safe_re_search(regex_str, text)
        if m:
            begin, end = m.span()
            matched_text = text[begin:end]
            sanitized, snippet = _sanitize(text, begin, end)
            line_number = text[:begin].count("\n") + 1
            return rule, matched_text, sanitized, snippet, line_number
    return None, None, None, None, None


def scan_text(regex_config: dict, text: str):
    """Return (found: bool, result_dict) for a single text block."""
    try:
        rule, secret, sanitized, snippet, lineno = match_regex(regex_config, str(text))
        result = {
            "matched_regex_config": rule,
            "secret": secret,
            "sanitized_secret": sanitized,
            "snippet_text": snippet,
            "line_number": lineno,
        }
        return (rule is not None), result
    except Exception:
        return False, {}


def _sanitize(text, begin, end):
    s_begin = max(begin - 20, 0)
    s_end = min(end + 20, len(text))
    sanitized = f"{text[s_begin:begin]}<REDACTED>{text[end:s_end]}"
    snippet = text[s_begin:s_end]
    return sanitized, snippet


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Top-level worker function (must be at module scope for pickling)
# ---------------------------------------------------------------------------

def _worker_scan_chunk(pages: list, regex_config: dict, label: str) -> list:
    """Scan a chunk of pages — called by ProcessPoolExecutor workers."""
    results = []
    for ticket in pages:
        for key, item in ticket.get("ticket", {}).items():
            name = item.get("name", "")
            data = item.get("data")
            dtype = item.get("data_type")

            texts = []
            if dtype == "str" and data and label.lower() not in data.lower():
                texts.append(data)
            elif dtype == "list" and data:
                texts.extend(t for t in data if t and label.lower() not in t.lower())

            for text in texts:
                found, result = scan_text(regex_config, text)
                if found:
                    result["ticket_data"] = {**ticket, "field": name, "platform": "Confluence"}
                    result["secret_found"] = True
                    results.append(result)
    return results


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class ConfluenceSecretScanner:
    """Orchestrates the full scan lifecycle:

    1. Connect to Confluence
    2. (Optional) Validate CQL scope
    3. Prefetch page data — compute stats
    4. Display summary — prompt user
    5. Regex scan (sequential or parallel)
    6. Save report
    """

    def __init__(
        self,
        server: str = "",
        email: str = "",
        token: str = "",
        regex_file: str = "",
        report_file: str = "confluence_report.json",
        scope: str | None = None,
        skip_comments: bool = False,
        show_secrets: bool = False,
        post_comment: bool = False,
        timeout: int | None = None,
        limit: int | None = None,
        insecure: bool = False,
        debug: bool = False,
        label: str = "",
        secret_manager: str = "a secret manager tool",
        contact_help: str = "",
    ):
        from .confluence_controller import ConfluenceController

        self.server = server
        self.email = email
        self.token = token
        self.regex_file = regex_file or os.path.join(os.path.dirname(__file__), "regex_patterns.yaml")
        self.report_file = report_file
        self.scope = scope
        self.skip_comments = skip_comments
        self.show_secrets = show_secrets
        self.post_comment = post_comment
        self.timeout = timeout
        self.limit = limit
        self.insecure = insecure
        self.debug = debug
        self.label = label
        self.secret_manager = secret_manager
        self.contact_help = contact_help

        self.regex_config: dict | None = None
        self.scope_config: dict | None = None
        self.report: dict = {"tool": "confluence_scanner", "findings": {}}
        self.controller = ConfluenceController()

        self._load_regex_config()
        self._parse_scope()

    # ---- setup helpers -----------------------------------------------------

    def _load_regex_config(self):
        if not os.path.exists(self.regex_file):
            logger.warning("Regex file [%s] not found!", self.regex_file)
            return
        with open(self.regex_file) as f:
            self.regex_config = yaml.safe_load(f)
        self.report["regex_config"] = self.regex_file

    def _parse_scope(self):
        """Convert a --scope CLI string into a scope_config dict."""
        if not self.scope:
            return
        for prefix in ("cql:", "query:", "search:"):
            if self.scope.lower().replace(" ", "").startswith(prefix):
                key = prefix.rstrip(":")
                self.scope_config = {key: self.scope[len(prefix):]}
                return
        # Bare string treated as CQL
        self.scope_config = {"cql": self.scope}

    def connect(self) -> bool:
        """Build controller config and connect to Confluence."""
        cfg = {
            "server": self.server,
            "email": self.email,
            "token": self.token,
            "timeout": self.timeout or -1,
            "insecure": self.insecure,
            "scan_scope": self.scope_config,
        }
        return self.controller.set_config(cfg)

    # ---- two-pass scan lifecycle -------------------------------------------

    def run(self, auto_approve: bool = False, num_workers: int = 1):
        """Full scan lifecycle.  Returns the report dict."""

        # Step 1 — connect
        if not self.connect():
            logger.error("Failed to connect to Confluence. Aborting.")
            sys.exit(1)

        if not self.regex_config:
            logger.error("No regex configuration loaded. Aborting.")
            sys.exit(1)

        # Step 2 — CQL validation (fail fast)
        cql_query = self.controller._get_cql_from_scope()
        if cql_query:
            logger.info("Validating CQL query: %s", cql_query)
            self.controller.validate_cql(cql_query)

        # Step 3 — prefetch
        logger.info("Prefetching page data...")
        include_comments = not self.skip_comments
        pages, stats = self._prefetch(include_comments)

        if stats["num_pages"] == 0:
            logger.info("No pages found to scan.")
            return self.report

        # Step 4 — summary & approval
        self._display_summary(stats, cql_query)
        if not self._prompt_approval(auto_approve):
            return self.report

        # Step 5 — regex scan
        logger.info("Starting regex scan...")
        if num_workers > 1:
            self._scan_parallel(pages, num_workers)
        else:
            self._scan_sequential(pages)

        # Step 6 — summary
        n = len(self.report["findings"])
        logger.info("Scan complete. %d finding(s) reported.", n)
        return self.report

    # ---- pass 1: prefetch --------------------------------------------------

    def _prefetch(self, include_comments):
        pages = []
        spaces_seen: set[str] = set()
        total_chars = 0
        total_comments = 0

        for ticket in self.controller.get_data(include_comments, self.limit):
            pages.append(ticket)
            url = ticket.get("url", "")
            for marker in ("/spaces/", "/display/"):
                if marker in url:
                    space_key = url.split(marker)[1].split("/")[0]
                    spaces_seen.add(space_key)
                    break

            td = ticket.get("ticket", {})
            total_chars += len(td.get("title", {}).get("data", "") or "")
            total_chars += len(td.get("description", {}).get("data", "") or "")
            for c in (td.get("comments", {}).get("data") or []):
                total_chars += len(c) if c else 0
                total_comments += 1

        stats = {
            "spaces": sorted(spaces_seen),
            "num_spaces": len(spaces_seen),
            "num_pages": len(pages),
            "num_comments": total_comments,
            "total_chars": total_chars,
            "total_mb": round(total_chars / (1024 * 1024), 2),
        }
        return pages, stats

    # ---- summary & approval ------------------------------------------------

    def _display_summary(self, stats, cql_query=None):
        num_rules = len(self.regex_config.get("rules", []))
        throughput = 5.0  # MB/s heuristic
        mb = stats["total_mb"]
        lo = (mb * num_rules) / (throughput * 2) if num_rules and mb else 0
        hi = (mb * num_rules) / throughput if num_rules and mb else 0

        def fmt(s):
            if s < 60: return f"~{int(s)} seconds"
            if s < 3600: return f"~{int(s/60)} minutes"
            return f"~{s/3600:.1f} hours"

        lines = ["", "============ Scan Scope Summary ============"]
        if cql_query:
            lines.append(f"CQL Query:            {cql_query}")
        if stats["num_spaces"]:
            lines.append(f"Spaces matched:       {stats['num_spaces']} ({', '.join(stats['spaces'])})")
        lines.append(f"Pages to scan:        {stats['num_pages']:,}")
        lines.append(f"Comments to scan:     {stats['num_comments']:,}")
        lines.append(f"Total scannable text: ~{mb} MB ({stats['total_chars']:,} chars)")
        lines.append(f"Regex rules loaded:   {num_rules}")
        if hi:
            lines.append(f"Est. scan duration:   {fmt(lo)} – {fmt(hi)}")
        lines.append("============================================")
        lines.append("")
        logger.info("\n".join(lines))

    @staticmethod
    def _prompt_approval(auto_approve: bool) -> bool:
        if auto_approve:
            logger.info("Auto-approve enabled (--yes). Proceeding with scan.")
            return True
        if not sys.stdin.isatty():
            logger.info("Non-interactive mode detected, proceeding automatically.")
            return True
        try:
            ans = input("Proceed with scan? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            logger.info("Scan aborted by user.")
            return False
        if ans in ("", "y", "yes"):
            return True
        logger.info("Scan aborted by user.")
        return False

    # ---- pass 2: regex scanning --------------------------------------------

    def _scan_sequential(self, pages):
        for ticket in pages:
            if self.debug:
                logger.debug("Scanning [%s]: %s", ticket.get("issue_id"), ticket.get("url"))
            self._scan_ticket(ticket)

    def _scan_parallel(self, pages, num_workers):
        chunk_size = max(1, len(pages) // num_workers)
        chunks = [pages[i:i+chunk_size] for i in range(0, len(pages), chunk_size)]
        actual = min(num_workers, len(chunks))
        logger.info("Scanning with %d worker process(es) across %d chunk(s)...", actual, len(chunks))

        with concurrent.futures.ProcessPoolExecutor(max_workers=actual) as pool:
            futures = {pool.submit(_worker_scan_chunk, ch, self.regex_config, self.label): i
                       for i, ch in enumerate(chunks)}
            for fut in concurrent.futures.as_completed(futures):
                idx = futures[fut]
                try:
                    for result in fut.result():
                        if result.get("secret_found"):
                            self._record_finding(result)
                except Exception as e:
                    logger.error("Worker %d failed: %s", idx, e)

    def _scan_ticket(self, ticket):
        for item in ticket.get("ticket", {}).values():
            name = item.get("name", "")
            data = item.get("data")
            dtype = item.get("data_type")

            texts = []
            if dtype == "str" and data and self.label.lower() not in data.lower():
                texts.append(data)
            elif dtype == "list" and data:
                texts.extend(t for t in data if t and self.label.lower() not in t.lower())

            for text in texts:
                found, result = scan_text(self.regex_config, text)
                if found:
                    result["ticket_data"] = {**ticket, "field": name, "platform": "Confluence"}
                    self._record_finding(result)

    def _record_finding(self, result):
        sanitized = result.get("sanitized_secret", "")
        url = result.get("ticket_data", {}).get("url", "")
        rule = result.get("matched_regex_config", {})

        logger.warning(
            "Potential secret leak! Rule: [%s] %s\n  Sanitized: %s\n  Source: %s",
            rule.get("id", ""), rule.get("description", ""), sanitized, url,
        )
        if self.show_secrets:
            logger.warning("  Raw snippet: %s", result.get("snippet_text", ""))

        fid = _sha256(f"{url}_{sanitized}")
        self.report["findings"][fid] = {
            "id": fid,
            "url": url,
            "secret": sanitized,
            "details": {
                "matched_regex_config": rule,
                "platform": "Confluence",
                "ticket_field": result.get("ticket_data", {}).get("field", ""),
            },
        }

    # ---- report persistence ------------------------------------------------

    def save_report(self):
        try:
            with open(self.report_file, "w") as f:
                json.dump(self.report, f, indent=2)
            logger.info("Report saved to %s", self.report_file)
        except Exception as e:
            logger.error("Failed to save report: %s", e)
