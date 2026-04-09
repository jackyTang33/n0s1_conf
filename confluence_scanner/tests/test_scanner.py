"""Unit tests for the standalone Confluence scanner."""
import logging
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from confluence_scanner.confluence_controller import (
    ConfluenceController,
    CQLValidationError,
    CQLSyntaxError,
    CQLPermissionError,
    CQLEmptyResultError,
)
from confluence_scanner.scanner import (
    scan_text,
    match_regex,
    _worker_scan_chunk,
    ConfluenceSecretScanner,
)


# ===== CQL exception hierarchy =====

class TestCQLExceptions(unittest.TestCase):
    def test_hierarchy(self):
        self.assertTrue(issubclass(CQLSyntaxError, CQLValidationError))
        self.assertTrue(issubclass(CQLPermissionError, CQLValidationError))
        self.assertTrue(issubclass(CQLEmptyResultError, CQLValidationError))
        self.assertTrue(issubclass(CQLValidationError, Exception))


# ===== validate_cql() =====

class TestValidateCQL(unittest.TestCase):
    def _ctrl(self):
        c = ConfluenceController()
        c._client = MagicMock()
        c._url = "https://example.atlassian.net"
        return c

    def test_success(self):
        c = self._ctrl()
        c._client.cql.return_value = {"results": [{"content": {"type": "page", "id": "1"}}]}
        self.assertTrue(c.validate_cql("space=SEC AND type=page"))

    def test_empty_results(self):
        c = self._ctrl()
        c._client.cql.return_value = {"results": []}
        with self.assertRaises(CQLEmptyResultError):
            c.validate_cql("space=NOPE AND type=page")

    def test_non_page_only(self):
        c = self._ctrl()
        c._client.cql.return_value = {"results": [{"content": {"type": "blogpost", "id": "2"}}]}
        with self.assertRaises(CQLEmptyResultError):
            c.validate_cql("type=blogpost")

    def test_http_400(self):
        import requests
        c = self._ctrl()
        resp = MagicMock(status_code=400)
        resp.json.return_value = {"message": "bad cql"}
        resp.text = "bad cql"
        c._client.cql.side_effect = requests.exceptions.HTTPError(response=resp)
        with self.assertRaises(CQLSyntaxError):
            c.validate_cql("BAD!!!")

    def test_http_403(self):
        import requests
        c = self._ctrl()
        resp = MagicMock(status_code=403)
        resp.json.return_value = {"message": "Forbidden"}
        resp.text = "Forbidden"
        c._client.cql.side_effect = requests.exceptions.HTTPError(response=resp)
        with self.assertRaises(CQLPermissionError):
            c.validate_cql("space=SECRET")

    def test_connection_error(self):
        import requests
        c = self._ctrl()
        c._client.cql.side_effect = requests.exceptions.ConnectionError("refused")
        with self.assertRaises(CQLValidationError):
            c.validate_cql("space=SEC")


# ===== get_data() — no silent fallback =====

class TestGetDataNoFallback(unittest.TestCase):
    def _ctrl(self):
        c = ConfluenceController()
        c._client = MagicMock()
        c._url = "https://example.atlassian.net"
        c._scan_scope = {"cql": "space=NOPE AND type=page"}
        return c

    def test_raises_on_empty(self):
        c = self._ctrl()
        c._client.cql.return_value = {"results": []}
        with self.assertRaises(CQLEmptyResultError):
            list(c.get_data(include_comments=False, limit=50))

    def test_raises_on_error(self):
        c = self._ctrl()
        c._client.cql.side_effect = RuntimeError("boom")
        with self.assertRaises(CQLValidationError):
            list(c.get_data(include_comments=False, limit=50))


# ===== Regex scanning =====

class TestRegexScanning(unittest.TestCase):
    RULES = {"rules": [{"id": "ghp", "description": "GitHub PAT", "regex": r"ghp_[A-Za-z0-9]{36}"}]}

    def test_match(self):
        found, result = scan_text(self.RULES, "token: ghp_ABCDEFghijklmnop1234567890abcdef1234")
        self.assertTrue(found)
        self.assertIn("REDACTED", result["sanitized_secret"])

    def test_no_match(self):
        found, result = scan_text(self.RULES, "nothing here")
        self.assertFalse(found)


# ===== Worker chunk scanner =====

class TestWorkerChunk(unittest.TestCase):
    RULES = {"rules": [{"id": "ghp", "description": "GitHub PAT", "regex": r"ghp_[A-Za-z0-9]{36}"}]}
    PAGES = [
        {
            "issue_id": "1", "url": "https://example.atlassian.net/wiki/spaces/DEV/pages/1",
            "ticket": {
                "title":       {"name": "title",       "data": "Normal",                                     "data_type": "str"},
                "description": {"name": "description", "data": "ghp_ABCDEFghijklmnop1234567890abcdef1234", "data_type": "str"},
                "comments":    {"name": "comments",    "data": [],                                           "data_type": "list"},
            },
        }
    ]

    def test_finds_secrets(self):
        results = _worker_scan_chunk(self.PAGES, self.RULES)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["secret_found"])

    def test_no_secrets(self):
        clean = [{**self.PAGES[0], "ticket": {
            "title":       {"name": "title",       "data": "Safe",      "data_type": "str"},
            "description": {"name": "description", "data": "No leaks",  "data_type": "str"},
            "comments":    {"name": "comments",    "data": [],          "data_type": "list"},
        }}]
        results = _worker_scan_chunk(clean, self.RULES)
        self.assertEqual(len(results), 0)


# ===== Prefetch stats =====

class TestPrefetch(unittest.TestCase):
    def test_collects_stats(self):
        tickets = [
            {
                "issue_id": "1",
                "url": "https://example.atlassian.net/wiki/spaces/DEV/pages/1",
                "ticket": {
                    "title":       {"name": "title",       "data": "Hello World",                "data_type": "str"},
                    "description": {"name": "description", "data": "Some description text here", "data_type": "str"},
                    "comments":    {"name": "comments",    "data": ["comment 1", "comment 2"],   "data_type": "list"},
                },
            },
            {
                "issue_id": "2",
                "url": "https://example.atlassian.net/wiki/spaces/SEC/pages/2",
                "ticket": {
                    "title":       {"name": "title",       "data": "Another Page", "data_type": "str"},
                    "description": {"name": "description", "data": "More content", "data_type": "str"},
                    "comments":    {"name": "comments",    "data": [],             "data_type": "list"},
                },
            },
        ]

        scanner = ConfluenceSecretScanner.__new__(ConfluenceSecretScanner)
        scanner.controller = MagicMock()
        scanner.controller.get_data.return_value = iter(tickets)
        scanner.skip_comments = False
        scanner.limit = None

        pages, stats = scanner._prefetch(include_comments=True)
        self.assertEqual(stats["num_pages"], 2)
        self.assertEqual(stats["num_spaces"], 2)
        self.assertIn("DEV", stats["spaces"])
        self.assertIn("SEC", stats["spaces"])
        self.assertEqual(stats["num_comments"], 2)
        expected = 11 + 26 + 9 + 9 + 12 + 12  # title+desc+comments chars
        self.assertEqual(stats["total_chars"], expected)


# ===== HTML stripping =====

class TestStripHtml(unittest.TestCase):
    def test_strips_tags_keeps_text(self):
        c = ConfluenceController()
        html = '<p local-id="c166c5a236d4">Log in: myusername</p><p local-id="22b58b398035">p: testingmaaa</p>'
        result = c._strip_html(html)
        self.assertIn("Log in: myusername", result)
        self.assertIn("p: testingmaaa", result)
        self.assertNotIn("local-id", result)
        self.assertNotIn("<p", result)

    def test_strips_confluence_macros(self):
        c = ConfluenceController()
        html = '<ac:adf-attribute key="panel-type">note</ac:adf-attribute>'
        result = c._strip_html(html)
        self.assertIn("note", result)
        self.assertNotIn("key=", result)
        self.assertNotIn("panel-type", result)

    def test_empty_paragraphs_produce_no_noise(self):
        c = ConfluenceController()
        html = '<p local-id="abc123" /><p local-id="def456" />'
        result = c._strip_html(html)
        self.assertNotIn("abc123", result)
        self.assertNotIn("def456", result)

    def test_preserves_entities(self):
        c = ConfluenceController()
        html = "<p>5 &gt; 3 &amp; 2 &lt; 4</p>"
        result = c._strip_html(html)
        self.assertIn(">", result)
        self.assertIn("&", result)
        self.assertIn("<", result)

    def test_empty_input(self):
        c = ConfluenceController()
        self.assertEqual(c._strip_html(""), "")
        self.assertEqual(c._strip_html(None), None)

    def test_plain_text_passes_through(self):
        c = ConfluenceController()
        self.assertEqual(c._strip_html("just plain text"), "just plain text")

    def test_no_false_positive_on_generic_api_key(self):
        """The generic-api-key pattern should NOT match stripped Confluence HTML."""
        import re
        generic_api_key_regex = r'(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|\'|\"|\=]){0,3}(?:[\'|\"|\s|\=]){0,3}([0-9a-z\-_.=]{10,150})'
        c = ConfluenceController()
        html = '<ac:adf-attribute key="panel-type">note</ac:adf-attribute>'
        raw_match = re.search(generic_api_key_regex, html)
        stripped_match = re.search(generic_api_key_regex, c._strip_html(html))
        self.assertIsNotNone(raw_match, "Sanity: raw HTML should trigger the pattern")
        self.assertIsNone(stripped_match, "Stripped text should NOT trigger the pattern")


# ===== Approval prompt =====

class TestApproval(unittest.TestCase):
    def test_auto_approve(self):
        self.assertTrue(ConfluenceSecretScanner._prompt_approval(auto_approve=True))

    @patch("sys.stdin")
    def test_non_tty(self, mock_stdin):
        mock_stdin.isatty.return_value = False
        self.assertTrue(ConfluenceSecretScanner._prompt_approval(auto_approve=False))

    @patch("builtins.input", return_value="n")
    @patch("sys.stdin")
    def test_user_rejects(self, mock_stdin, _):
        mock_stdin.isatty.return_value = True
        self.assertFalse(ConfluenceSecretScanner._prompt_approval(auto_approve=False))

    @patch("builtins.input", return_value="y")
    @patch("sys.stdin")
    def test_user_accepts(self, mock_stdin, _):
        mock_stdin.isatty.return_value = True
        self.assertTrue(ConfluenceSecretScanner._prompt_approval(auto_approve=False))

    @patch("builtins.input", return_value="")
    @patch("sys.stdin")
    def test_enter_accepts(self, mock_stdin, _):
        mock_stdin.isatty.return_value = True
        self.assertTrue(ConfluenceSecretScanner._prompt_approval(auto_approve=False))


# ===== Regex config checker =====

class TestRegexConfigChecker(unittest.TestCase):
    """Validate _load_regex_config() structure checks, pre-compilation, and stats."""

    def _make_scanner(self, yaml_content: str) -> ConfluenceSecretScanner:
        """Create a scanner with a temp YAML file containing *yaml_content*."""
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        tmp.write(yaml_content)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)

        scanner = ConfluenceSecretScanner.__new__(ConfluenceSecretScanner)
        scanner.regex_file = tmp.name
        scanner.regex_config = None
        scanner.regex_stats = {"total": 0, "valid": 0, "skipped": 0, "skip_reasons": [], "tags": {}}
        scanner.report = {"tool": "confluence_scanner", "findings": {}}
        scanner._load_regex_config()
        return scanner

    def test_valid_rules_all_loaded(self):
        yaml_text = """
rules:
  - id: ghp
    description: GitHub PAT
    regex: 'ghp_[A-Za-z0-9]{36}'
    tags: [github]
  - id: aws
    description: AWS key
    regex: 'AKIA[A-Z0-9]{16}'
    tags: [aws]
"""
        s = self._make_scanner(yaml_text)
        self.assertIsNotNone(s.regex_config)
        self.assertEqual(len(s.regex_config["rules"]), 2)
        self.assertEqual(s.regex_stats["total"], 2)
        self.assertEqual(s.regex_stats["valid"], 2)
        self.assertEqual(s.regex_stats["skipped"], 0)
        self.assertEqual(s.regex_stats["tags"], {"github": 1, "aws": 1})

    def test_missing_regex_key_skipped(self):
        yaml_text = """
rules:
  - id: good
    regex: 'ghp_[A-Za-z0-9]{36}'
  - id: bad_no_regex
    description: oops
"""
        s = self._make_scanner(yaml_text)
        self.assertEqual(s.regex_stats["valid"], 1)
        self.assertEqual(s.regex_stats["skipped"], 1)
        self.assertIn("missing 'regex' key", s.regex_stats["skip_reasons"][0])

    def test_missing_id_key_skipped(self):
        yaml_text = """
rules:
  - regex: 'ghp_[A-Za-z0-9]{36}'
    description: no id
"""
        s = self._make_scanner(yaml_text)
        self.assertEqual(s.regex_stats["valid"], 0)
        self.assertEqual(s.regex_stats["skipped"], 1)
        self.assertIn("missing 'id' key", s.regex_stats["skip_reasons"][0])

    def test_invalid_regex_skipped(self):
        yaml_text = """
rules:
  - id: good
    regex: 'ghp_[A-Za-z0-9]{36}'
  - id: bad_regex
    regex: '(unclosed_group'
"""
        s = self._make_scanner(yaml_text)
        self.assertEqual(s.regex_stats["valid"], 1)
        self.assertEqual(s.regex_stats["skipped"], 1)
        self.assertIn("invalid regex", s.regex_stats["skip_reasons"][0])

    def test_no_rules_key_config_stays_none(self):
        yaml_text = """
title: broken config
"""
        s = self._make_scanner(yaml_text)
        self.assertIsNone(s.regex_config)
        self.assertEqual(s.regex_stats["valid"], 0)

    def test_empty_rules_list(self):
        yaml_text = """
rules: []
"""
        s = self._make_scanner(yaml_text)
        self.assertIsNotNone(s.regex_config)
        self.assertEqual(s.regex_stats["total"], 0)
        self.assertEqual(s.regex_stats["valid"], 0)

    def test_file_not_found(self):
        scanner = ConfluenceSecretScanner.__new__(ConfluenceSecretScanner)
        scanner.regex_file = "/nonexistent/path/nope.yaml"
        scanner.regex_config = None
        scanner.regex_stats = {"total": 0, "valid": 0, "skipped": 0, "skip_reasons": [], "tags": {}}
        scanner.report = {"tool": "confluence_scanner", "findings": {}}
        scanner._load_regex_config()
        self.assertIsNone(scanner.regex_config)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
