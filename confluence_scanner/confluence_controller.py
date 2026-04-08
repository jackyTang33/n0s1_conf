"""
confluence_controller.py — Confluence API client for the standalone scanner.

Handles connection, CQL validation, page/comment fetching, and comment posting.
Self-contained: no base-class inheritance, no platform factory.
"""

import html
import logging
import time

import requests
from requests.auth import HTTPBasicAuth
from atlassian import Confluence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom CQL exceptions
# ---------------------------------------------------------------------------

class CQLValidationError(Exception):
    """Base exception for CQL validation failures."""
    pass


class CQLSyntaxError(CQLValidationError):
    """HTTP 400 — malformed CQL query."""
    pass


class CQLPermissionError(CQLValidationError):
    """HTTP 403 — insufficient permissions for the CQL query."""
    pass


class CQLEmptyResultError(CQLValidationError):
    """Valid CQL but zero page results returned."""
    pass


# ---------------------------------------------------------------------------
# Confluence controller
# ---------------------------------------------------------------------------

class ConfluenceController:
    """Thin wrapper around the Confluence REST API (via atlassian-python-api).

    Public API used by the scanner:
        set_config(config)      — connect to Confluence
        is_connected()          — verify credentials & permissions
        validate_cql(cql)       — cheap fail-fast CQL probe
        get_data(...)           — yield page dicts (title, body, comments, url)
        post_comment(page_id, comment_html)
    """

    def __init__(self):
        self._client: Confluence | None = None
        self._config: dict = {}
        self._scan_scope: dict | None = None
        self._url: str = ""
        self._user: str = ""
        self._password: str = ""
        self._requests_counter = 0
        self._check_connection_after = 200

    # ---- configuration & connection ----------------------------------------

    def set_config(self, config: dict) -> bool:
        """Initialise the Confluence client from a config dict."""
        self._config = config
        self._scan_scope = config.get("scan_scope")

        server = config.get("server", "")
        email = config.get("email", "")
        token = config.get("token", "")
        timeout = config.get("timeout", -1)
        verify_ssl = not config.get("insecure", False)

        self._url = server
        self._user = email
        self._password = token

        kwargs = dict(url=server, verify_ssl=verify_ssl)
        if email:
            kwargs.update(username=email, password=token)
        else:
            kwargs["token"] = token
        if timeout and timeout > 0:
            kwargs["timeout"] = timeout

        self._client = Confluence(**kwargs)
        return self.is_connected()

    def _reconnect_if_needed(self):
        """Periodically re-check the connection after many requests."""
        self._requests_counter += 1
        if self._requests_counter > self._check_connection_after:
            self._requests_counter = 0
            if not self.is_connected():
                self._client = None
                self.set_config(self._config)

    def is_connected(self) -> bool:
        """Verify credentials and basic read permissions."""
        if not self._client:
            return False

        user = self._get_current_user()
        if not user:
            logger.error("Unable to connect to Confluence. Check your credentials.")
            return False
        logger.info("Logged to Confluence as %s", user)

        spaces = self._client.get_all_spaces()
        if not spaces:
            logger.error("Unable to connect to Confluence. Check your credentials.")
            return False

        for s in spaces.get("results", []):
            key = s.get("key", "")
            if key:
                pages = self._client.get_all_pages_from_space(key)
                if pages:
                    return True

        logger.error("Unable to list Confluence pages. Check your permissions.")
        return False

    def _get_current_user(self):
        """Return the current API user dict, or None."""
        for path in ["/rest/api/user/current", "/wiki/rest/api/user/current"]:
            url = f"{self._url}{path}"
            resp = self._get_request(url)
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("type"):
                    return data
        return None

    # ---- CQL validation ----------------------------------------------------

    def validate_cql(self, cql: str, limit: int = 1) -> bool:
        """Cheap single-result CQL probe.  Raises on any failure.

        Raises:
            CQLSyntaxError      — HTTP 400
            CQLPermissionError  — HTTP 403
            CQLEmptyResultError — 0 page-type results
            CQLValidationError  — anything else
        """
        try:
            res = self._client.cql(cql, limit=limit)
        except requests.exceptions.HTTPError as exc:
            self._raise_cql_http_error(exc)
        except requests.exceptions.ConnectionError as exc:
            raise CQLValidationError(f"Connection error during CQL validation: {exc}") from exc
        except Exception as exc:
            raise CQLValidationError(f"Unexpected error during CQL validation: {exc}") from exc

        pages_found = sum(
            1 for r in res.get("results", [])
            if (r.get("content", {}).get("type") or "").lower() == "page"
        )
        if pages_found == 0:
            raise CQLEmptyResultError(f"CQL query returned 0 page results: '{cql}'. Nothing to scan.")

        logger.info("CQL query validated successfully (probe returned %d page(s)).", pages_found)
        return True

    # ---- data fetching -----------------------------------------------------

    def get_data(self, include_comments: bool = False, limit: int | None = None):
        """Yield page dicts.  Routes through CQL if a scope query is set,
        otherwise iterates all spaces/pages."""
        if not self._client:
            return

        cql = self._get_cql_from_scope()
        if cql:
            yield from self._get_data_via_cql(cql, include_comments, limit)
        else:
            yield from self._get_data_all_spaces(include_comments, limit)

    def _get_data_via_cql(self, cql, include_comments, limit):
        """Fetch pages matching a CQL query.  Never falls back to unscoped."""
        pages = []
        try:
            res = self._client.cql(cql, limit=limit)
            while res:
                for r in res.get("results", []):
                    ctype = (r.get("content", {}).get("type") or "").lower()
                    if ctype == "page":
                        pages.append(r["content"])

                next_link = res.get("_links", {}).get("next")
                res = None
                if next_link:
                    resp = self._get_request(f"{self._url}/wiki{next_link}")
                    if resp:
                        res = resp.json()

            if not pages:
                raise CQLEmptyResultError(f"CQL query returned 0 page results: '{cql}'. Nothing to scan.")

            yield from self._process_pages(pages, include_comments, limit)

        except (CQLValidationError, CQLSyntaxError, CQLPermissionError, CQLEmptyResultError):
            raise
        except requests.exceptions.HTTPError as exc:
            self._raise_cql_http_error(exc)
        except Exception as e:
            raise CQLValidationError(f"CQL query failed: {e}") from e

    def _get_data_all_spaces(self, include_comments, limit):
        """Iterate every space & page when no CQL scope is provided."""
        for space_batch in self._iter_spaces(limit):
            for space in space_batch:
                key = space if isinstance(space, str) else space.get("key", "")
                if not key:
                    continue
                logger.info("Scanning Confluence space: [%s]...", key)
                for page_batch in self._iter_pages(key, limit):
                    yield from self._process_pages(page_batch, include_comments, limit)

    # ---- internal iterators ------------------------------------------------

    def _iter_spaces(self, limit=None):
        if self._scan_scope and "workspaces" in self._scan_scope:
            yield list(self._scan_scope["workspaces"].keys())
            return

        limit = limit or 50
        start = 0
        while True:
            try:
                self._reconnect_if_needed()
                res = self._client.get_all_spaces(start=start, limit=limit)
                spaces = res.get("results", [])
            except Exception as e:
                logger.warning("%s  get_all_spaces(start=%d, limit=%d)", e, start, limit)
                time.sleep(1)
                continue
            if not spaces:
                break
            yield spaces
            start += limit

    def _iter_pages(self, space_key, limit=None):
        from atlassian.confluence import ApiPermissionError

        if self._scan_scope:
            page_keys = self._scan_scope.get("workspaces", {}).get(space_key, {})
            if page_keys:
                batch = []
                for pk in page_keys:
                    batch.append(self._client.get_page_by_id(pk))
                    if len(batch) >= (limit or 50):
                        yield batch
                        batch = []
                if batch:
                    yield batch
                return

        if not space_key:
            return

        limit = limit or 50
        start = 0
        while True:
            try:
                self._reconnect_if_needed()
                pages = self._client.get_all_pages_from_space(space_key, start=start, limit=limit)
            except ApiPermissionError as e:
                logger.warning("%s  Skipping space %s.", e, space_key)
                break
            except Exception as e:
                logger.warning("%s  get_all_pages_from_space(%s, start=%d)", e, space_key, start)
                time.sleep(1)
                continue
            if not pages:
                break
            yield pages
            start += limit

    def _process_pages(self, pages, include_comments, limit):
        """For each raw page dict, fetch full body & comments and yield a
        normalised ticket dict."""
        limit = limit or 50
        for p in pages:
            page_id = p.get("id", "")
            title = p.get("title", "")
            try:
                self._reconnect_if_needed()
                body = self._client.get_page_by_id(page_id, expand="body.storage")
            except Exception as e:
                logger.warning("%s  get_page_by_id(%s)", e, page_id)
                time.sleep(1)
                continue

            description = body.get("body", {}).get("storage", {}).get("value", "")
            url = body.get("_links", {}).get("base", "") + p.get("_links", {}).get("webui", "")

            comments = []
            if page_id and include_comments:
                comments = self._fetch_comments(page_id, limit)

            yield self._pack(title, description, comments, url, page_id)

    def _fetch_comments(self, page_id, limit):
        comments = []
        start = 0
        while True:
            try:
                self._reconnect_if_needed()
                resp = self._client.get_page_comments(
                    page_id, expand="body.storage", start=start, limit=limit
                )
                results = resp.get("results", [])
            except Exception as e:
                logger.warning("%s  get_page_comments(%s, start=%d)", e, page_id, start)
                time.sleep(1)
                continue
            if not results:
                break
            for c in results:
                comments.append(c.get("body", {}).get("storage", {}).get("value", ""))
            start += limit
        return comments

    # ---- comment posting ---------------------------------------------------

    def post_comment(self, page_id: str, comment_html: str) -> bool:
        if not self._client:
            return False
        safe = html.escape(comment_html.replace("#", "0"), quote=True)
        self._reconnect_if_needed()
        resp = self._client.add_comment(page_id, safe)
        return bool(resp and int(resp.get("id", 0)) > 0)

    # ---- helpers -----------------------------------------------------------

    def _get_cql_from_scope(self):
        """Extract a CQL query string from the scan_scope config."""
        if not self._scan_scope:
            return None
        for key in ("cql", "query", "search"):
            if val := self._scan_scope.get(key):
                return val
        return None

    @staticmethod
    def _raise_cql_http_error(exc: requests.exceptions.HTTPError):
        status = getattr(exc.response, "status_code", None)
        try:
            api_msg = exc.response.json().get("message", str(exc))
        except Exception:
            api_msg = getattr(exc.response, "text", str(exc))
        if status == 400:
            raise CQLSyntaxError(f"CQL syntax error: {api_msg}") from exc
        if status == 403:
            raise CQLPermissionError(f"Insufficient permissions for CQL query: {api_msg}") from exc
        raise CQLValidationError(f"CQL query failed (HTTP {status}): {api_msg}") from exc

    @staticmethod
    def _pack(title, description, comments, url, page_id):
        return {
            "ticket": {
                "title":       {"name": "title",       "data": title,       "data_type": "str"},
                "description": {"name": "description", "data": description, "data_type": "str"},
                "comments":    {"name": "comments",    "data": comments,    "data_type": "list"},
            },
            "url": url,
            "issue_id": page_id,
        }

    def _get_request(self, url):
        try:
            headers = {"Content-Type": "application/json"}
            if self._user:
                return requests.get(url, headers=headers, auth=HTTPBasicAuth(self._user, self._password))
            headers["Authorization"] = f"Bearer {self._password}"
            return requests.get(url, headers=headers)
        except Exception as e:
            logger.warning(str(e))
        return None
