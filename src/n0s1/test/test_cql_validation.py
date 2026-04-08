"""Unit tests for CQL validation, prefetch summary, approval breakpoint, and parallel scanning."""
import logging
import os
import sys
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from n0s1.controllers.confluence_controller import (
        ConfluenceController,
        CQLValidationError,
        CQLSyntaxError,
        CQLPermissionError,
        CQLEmptyResultError,
    )
    import n0s1.scanner as scanner
except ImportError:
    from controllers.confluence_controller import (
        ConfluenceController,
        CQLValidationError,
        CQLSyntaxError,
        CQLPermissionError,
        CQLEmptyResultError,
    )
    import scanner


class TestCQLExceptions(unittest.TestCase):
    """Test that custom CQL exception hierarchy is correct."""

    def test_cql_syntax_error_is_validation_error(self):
        self.assertTrue(issubclass(CQLSyntaxError, CQLValidationError))

    def test_cql_permission_error_is_validation_error(self):
        self.assertTrue(issubclass(CQLPermissionError, CQLValidationError))

    def test_cql_empty_result_error_is_validation_error(self):
        self.assertTrue(issubclass(CQLEmptyResultError, CQLValidationError))

    def test_cql_validation_error_is_exception(self):
        self.assertTrue(issubclass(CQLValidationError, Exception))


class TestValidateCQL(unittest.TestCase):
    """Test ConfluenceController.validate_cql()."""

    def _make_controller(self):
        ctrl = ConfluenceController()
        ctrl._client = MagicMock()
        ctrl._url = "https://example.atlassian.net"
        return ctrl

    def test_validate_cql_success(self):
        ctrl = self._make_controller()
        ctrl._client.cql.return_value = {
            "results": [{"content": {"type": "page", "id": "123"}}]
        }
        result = ctrl.validate_cql("space=SEC AND type=page")
        self.assertTrue(result)

    def test_validate_cql_empty_results(self):
        ctrl = self._make_controller()
        ctrl._client.cql.return_value = {"results": []}
        with self.assertRaises(CQLEmptyResultError):
            ctrl.validate_cql("space=NONEXISTENT AND type=page")

    def test_validate_cql_non_page_results_only(self):
        """CQL returns results but none are pages → should raise CQLEmptyResultError."""
        ctrl = self._make_controller()
        ctrl._client.cql.return_value = {
            "results": [{"content": {"type": "blogpost", "id": "456"}}]
        }
        with self.assertRaises(CQLEmptyResultError):
            ctrl.validate_cql("type=blogpost")

    def test_validate_cql_http_400(self):
        """HTTP 400 → CQLSyntaxError."""
        import requests
        ctrl = self._make_controller()
        response = MagicMock()
        response.status_code = 400
        response.json.return_value = {"message": "Error in the CQL query"}
        response.text = "Error in the CQL query"
        exc = requests.exceptions.HTTPError(response=response)
        ctrl._client.cql.side_effect = exc
        with self.assertRaises(CQLSyntaxError):
            ctrl.validate_cql("INVALID CQL !!!")

    def test_validate_cql_http_403(self):
        """HTTP 403 → CQLPermissionError."""
        import requests
        ctrl = self._make_controller()
        response = MagicMock()
        response.status_code = 403
        response.json.return_value = {"message": "Forbidden"}
        response.text = "Forbidden"
        exc = requests.exceptions.HTTPError(response=response)
        ctrl._client.cql.side_effect = exc
        with self.assertRaises(CQLPermissionError):
            ctrl.validate_cql("space=RESTRICTED AND type=page")

    def test_validate_cql_connection_error(self):
        """ConnectionError → CQLValidationError."""
        import requests
        ctrl = self._make_controller()
        ctrl._client.cql.side_effect = requests.exceptions.ConnectionError("Connection refused")
        with self.assertRaises(CQLValidationError):
            ctrl.validate_cql("space=SEC AND type=page")


class TestGetDataNoFallback(unittest.TestCase):
    """Test that get_data() does NOT silently fall back to unscoped scan on CQL failure."""

    def _make_controller(self):
        ctrl = ConfluenceController()
        ctrl._client = MagicMock()
        ctrl._url = "https://example.atlassian.net"
        ctrl._scan_scope = {"cql": "space=NONEXISTENT AND type=page"}
        return ctrl

    def test_get_data_raises_on_empty_cql(self):
        """When CQL returns 0 pages, get_data should raise CQLEmptyResultError."""
        ctrl = self._make_controller()
        ctrl._client.cql.return_value = {"results": []}
        with self.assertRaises(CQLEmptyResultError):
            list(ctrl.get_data(include_coments=False, limit=50))

    def test_get_data_raises_on_cql_error(self):
        """When CQL API call fails, get_data should raise CQLValidationError."""
        ctrl = self._make_controller()
        ctrl._client.cql.side_effect = RuntimeError("API unavailable")
        with self.assertRaises(CQLValidationError):
            list(ctrl.get_data(include_coments=False, limit=50))


class TestPrefetchScanData(unittest.TestCase):
    """Test SecretScanner.prefetch_scan_data()."""

    def _make_scanner_with_mock_controller(self, tickets):
        s = scanner.SecretScanner.__new__(scanner.SecretScanner)
        s.controller = MagicMock()
        s.controller.get_data.return_value = iter(tickets)
        s.controller.get_name.return_value = "Confluence"
        s.logging_function = scanner.log_message
        s.debug = False
        return s

    def test_prefetch_collects_stats(self):
        tickets = [
            {
                "issue_id": "1",
                "url": "https://example.atlassian.net/wiki/spaces/DEV/pages/1",
                "ticket": {
                    "title": {"name": "title", "data": "Hello World", "data_type": "str"},
                    "description": {"name": "description", "data": "Some description text here", "data_type": "str"},
                    "comments": {"name": "comments", "data": ["comment 1", "comment 2"], "data_type": "list"},
                },
            },
            {
                "issue_id": "2",
                "url": "https://example.atlassian.net/wiki/spaces/SEC/pages/2",
                "ticket": {
                    "title": {"name": "title", "data": "Another Page", "data_type": "str"},
                    "description": {"name": "description", "data": "More content", "data_type": "str"},
                    "comments": {"name": "comments", "data": [], "data_type": "list"},
                },
            },
        ]
        s = self._make_scanner_with_mock_controller(tickets)
        pages, stats = s.prefetch_scan_data(scan_comment=True, limit=50)

        self.assertEqual(len(pages), 2)
        self.assertEqual(stats["num_pages"], 2)
        self.assertIn("DEV", stats["spaces"])
        self.assertIn("SEC", stats["spaces"])
        self.assertEqual(stats["num_spaces"], 2)
        self.assertEqual(stats["num_comments"], 2)
        # Total chars: "Hello World"(11) + "Some description text here"(26) + "comment 1"(9) + "comment 2"(9)
        #            + "Another Page"(12) + "More content"(12)
        expected_chars = 11 + 26 + 9 + 9 + 12 + 12
        self.assertEqual(stats["total_chars"], expected_chars)


class TestDisplayScanSummary(unittest.TestCase):
    """Test SecretScanner.display_scan_summary()."""

    def test_summary_includes_key_fields(self):
        s = scanner.SecretScanner.__new__(scanner.SecretScanner)
        s.regex_config = {"rules": [{"regex": "test"}] * 5}
        s.logging_function = scanner.log_message

        stats = {
            "spaces": ["DEV", "SEC"],
            "num_spaces": 2,
            "num_pages": 100,
            "num_comments": 50,
            "total_chars": 500000,
            "total_mb": 0.48,
        }
        summary = s.display_scan_summary(stats, cql_query="space IN (DEV, SEC)")
        self.assertIn("DEV", summary)
        self.assertIn("SEC", summary)
        self.assertIn("100", summary)
        self.assertIn("50", summary)
        self.assertIn("Regex rules loaded", summary)


class TestPromptUserApproval(unittest.TestCase):
    """Test SecretScanner.prompt_user_approval()."""

    def _make_scanner(self):
        s = scanner.SecretScanner.__new__(scanner.SecretScanner)
        s.logging_function = scanner.log_message
        return s

    def test_auto_approve(self):
        s = self._make_scanner()
        self.assertTrue(s.prompt_user_approval(auto_approve=True))

    @patch("sys.stdin")
    def test_non_tty_auto_approves(self, mock_stdin):
        mock_stdin.isatty.return_value = False
        s = self._make_scanner()
        self.assertTrue(s.prompt_user_approval(auto_approve=False))

    @patch("builtins.input", return_value="n")
    @patch("sys.stdin")
    def test_user_rejects(self, mock_stdin, mock_input):
        mock_stdin.isatty.return_value = True
        s = self._make_scanner()
        self.assertFalse(s.prompt_user_approval(auto_approve=False))

    @patch("builtins.input", return_value="y")
    @patch("sys.stdin")
    def test_user_accepts(self, mock_stdin, mock_input):
        mock_stdin.isatty.return_value = True
        s = self._make_scanner()
        self.assertTrue(s.prompt_user_approval(auto_approve=False))

    @patch("builtins.input", return_value="")
    @patch("sys.stdin")
    def test_user_presses_enter(self, mock_stdin, mock_input):
        mock_stdin.isatty.return_value = True
        s = self._make_scanner()
        self.assertTrue(s.prompt_user_approval(auto_approve=False))


class TestWorkerScanChunk(unittest.TestCase):
    """Test the module-level _worker_scan_chunk function used by ProcessPoolExecutor."""

    def test_worker_finds_secrets(self):
        pages = [
            {
                "issue_id": "1",
                "url": "https://example.atlassian.net/wiki/spaces/DEV/pages/1",
                "ticket": {
                    "title": {"name": "title", "data": "Normal title", "data_type": "str"},
                    "description": {
                        "name": "description",
                        "data": "ghp_ABCDEFghijklmnop1234567890abcdef1234",
                        "data_type": "str",
                    },
                    "comments": {"name": "comments", "data": [], "data_type": "list"},
                },
            }
        ]
        # Use a simple regex that matches the GitHub PAT pattern
        regex_config = {
            "rules": [
                {"id": "github-pat", "description": "GitHub PAT", "regex": r"ghp_[A-Za-z0-9]{36}"}
            ]
        }
        results = scanner._worker_scan_chunk(pages, regex_config, label="n0s1bot")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["secret_found"])

    def test_worker_no_secrets(self):
        pages = [
            {
                "issue_id": "1",
                "url": "https://example.atlassian.net/wiki/spaces/DEV/pages/1",
                "ticket": {
                    "title": {"name": "title", "data": "Clean title", "data_type": "str"},
                    "description": {"name": "description", "data": "Nothing secret here", "data_type": "str"},
                    "comments": {"name": "comments", "data": [], "data_type": "list"},
                },
            }
        ]
        regex_config = {
            "rules": [
                {"id": "github-pat", "description": "GitHub PAT", "regex": r"ghp_[A-Za-z0-9]{36}"}
            ]
        }
        results = scanner._worker_scan_chunk(pages, regex_config, label="n0s1bot")
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
