"""
confluence_controller.py — Confluence API client for the standalone scanner.

Handles connection, CQL validation, and page/comment fetching.
Self-contained: no base-class inheritance, no platform factory.
"""

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape as _html_unescape
from html.parser import HTMLParser

import requests
from requests.auth import HTTPBasicAuth
from atlassian import Confluence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reusable HTML-to-text extractor (module-level to avoid re-definition per call)
# ---------------------------------------------------------------------------

class _HtmlTextExtractor(HTMLParser):
    """Extract visible text from Confluence storage-format HTML."""

    def __init__(self):
        super().__init__()
        self._pieces: list[str] = []

    def handle_data(self, data):
        self._pieces.append(data)

    def handle_entityref(self, name):
        self._pieces.append(_html_unescape(f"&{name};"))

    def handle_charref(self, name):
        self._pieces.append(_html_unescape(f"&#{name};"))

    def get_text(self) -> str:
        return " ".join(self._pieces)


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
        self._lock = threading.Lock()

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
        with self._lock:
            self._requests_counter += 1
            if self._requests_counter > self._check_connection_after:
                self._requests_counter = 0
                needs_reconnect = not self.is_connected()
            else:
                needs_reconnect = False
        if needs_reconnect:
            with self._lock:
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

    def get_data(self, include_comments: bool = False, limit: int | None = None,
                 max_fetch_workers: int = 1):
        """Yield page dicts.  Routes through CQL if a scope query is set,
        otherwise iterates all spaces/pages."""
        if not self._client:
            return

        cql = self._get_cql_from_scope()
        if cql:
            yield from self._get_data_via_cql(cql, include_comments, limit, max_fetch_workers)
        else:
            yield from self._get_data_all_spaces(include_comments, limit, max_fetch_workers)

    def _get_data_via_cql(self, cql, include_comments, limit, max_fetch_workers=1):
        """Fetch pages matching a CQL query.  Never falls back to unscoped."""
        _BATCH = 500  # CQL pagination page size (internal)
        pages = []
        try:
            res = self._client.cql(cql, limit=_BATCH)
            while res:
                for r in res.get("results", []):
                    # Can be replaced by adding a "and type=page" to the CQL; currently works as extra safety check
                    ctype = (r.get("content", {}).get("type") or "").lower()
                    if ctype == "page":
                        pages.append(r["content"])

                if limit and len(pages) >= limit:
                    pages = pages[:limit]
                    break

                next_link = res.get("_links", {}).get("next")
                res = None
                if next_link:
                    resp = self._get_request(f"{self._url}/wiki{next_link}")
                    if resp:
                        res = resp.json()

            if not pages:
                raise CQLEmptyResultError(f"CQL query returned 0 page results: '{cql}'. Nothing to scan.")

            if limit:
                logger.info("Limit applied: scanning %d/%d matched pages", len(pages), len(pages))

            yield from self._process_pages(pages, include_comments, max_fetch_workers)

        except (CQLValidationError, CQLSyntaxError, CQLPermissionError, CQLEmptyResultError):
            raise
        except requests.exceptions.HTTPError as exc:
            self._raise_cql_http_error(exc)
        except Exception as e:
            raise CQLValidationError(f"CQL query failed: {e}") from e

    def _get_data_all_spaces(self, include_comments, limit, max_fetch_workers=1):
        """Iterate every space & page when no CQL scope is provided."""
        total_yielded = 0
        for space_batch in self._iter_spaces():
            for space in space_batch:
                key = space if isinstance(space, str) else space.get("key", "")
                if not key:
                    continue
                logger.info("Scanning Confluence space: [%s]...", key)
                for page_batch in self._iter_pages(key):
                    if limit:
                        remaining = limit - total_yielded
                        if remaining <= 0:
                            return
                        page_batch = page_batch[:remaining]
                    for result in self._process_pages(page_batch, include_comments, max_fetch_workers):
                        yield result
                        total_yielded += 1
                        if limit and total_yielded >= limit:
                            return

    # ---- internal iterators ------------------------------------------------

    def _iter_spaces(self):
        if self._scan_scope and "workspaces" in self._scan_scope:
            yield list(self._scan_scope["workspaces"].keys())
            return

        _BATCH = 50
        start = 0
        while True:
            try:
                self._reconnect_if_needed()
                res = self._client.get_all_spaces(start=start, limit=_BATCH)
                spaces = res.get("results", [])
            except Exception as e:
                logger.warning("%s  get_all_spaces(start=%d, limit=%d)", e, start, _BATCH)
                time.sleep(1)
                continue
            if not spaces:
                break
            yield spaces
            start += _BATCH

    def _iter_pages(self, space_key):
        from atlassian.confluence import ApiPermissionError

        _BATCH = 50
        if self._scan_scope:
            page_keys = self._scan_scope.get("workspaces", {}).get(space_key, {})
            if page_keys:
                batch = []
                for pk in page_keys:
                    batch.append(self._client.get_page_by_id(pk))
                    if len(batch) >= _BATCH:
                        yield batch
                        batch = []
                if batch:
                    yield batch
                return

        if not space_key:
            return

        start = 0
        while True:
            try:
                self._reconnect_if_needed()
                pages = self._client.get_all_pages_from_space(space_key, start=start, limit=_BATCH)
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
            start += _BATCH

    def _process_pages(self, pages, include_comments, max_workers=1):
        """For each raw page dict, fetch full body & comments and yield a
        normalised ticket dict.

        When *max_workers* > 1, pages are fetched concurrently using a
        ThreadPoolExecutor (I/O-bound work — GIL releases during HTTP).
        """
        _COMMENT_BATCH = 50
        total = len(pages)
        if total == 0:
            return

        actual_workers = min(max(max_workers, 1), total, 8)

        # Adaptive log interval: ~20 log lines for any size, min 10, max 500
        log_interval = max(10, min(500, total // 20)) if total > 20 else 1

        if actual_workers <= 1:
            # --- sequential path (no threading overhead) ---
            for idx, p in enumerate(pages, 1):
                result = self._fetch_one_page(p, include_comments, _COMMENT_BATCH)
                if idx % log_interval == 0 or idx == total:
                    logger.info("Fetched %d/%d pages", idx, total)
                if result is not None:
                    yield result
            return

        # --- parallel path ---
        logger.info("Starting parallel page fetch: %d pages with %d workers", total, actual_workers)

        lock = threading.Lock()
        initiated = 0
        completed = 0
        succeeded = 0
        results: dict[int, dict | None] = {}

        def _on_submit():
            nonlocal initiated
            with lock:
                initiated += 1
                n = initiated
            if n % log_interval == 0 or n == total:
                logger.info("Initiated %d/%d pages", n, total)

        def _on_complete(ok: bool):
            nonlocal completed, succeeded
            with lock:
                completed += 1
                if ok:
                    succeeded += 1
                n, s = completed, succeeded
            if n % log_interval == 0 or n == total:
                logger.info("Fetched %d/%d pages (%d succeeded)", n, total, s)

        with ThreadPoolExecutor(max_workers=actual_workers) as pool:
            futures = {}
            for idx, p in enumerate(pages):
                fut = pool.submit(self._fetch_one_page, p, include_comments, _COMMENT_BATCH)
                futures[fut] = idx
                _on_submit()

            for fut in as_completed(futures):
                result = fut.result()
                _on_complete(result is not None)
                idx = futures[fut]
                results[idx] = result

        logger.info("Page fetch complete: %d/%d pages fetched successfully", succeeded, total)

        # Yield in original submission order for deterministic output
        for idx in range(total):
            if results.get(idx) is not None:
                yield results[idx]

    def _fetch_one_page(self, page, include_comments, limit):
        """Fetch body & comments for a single page.  Returns a packed dict or None.

        Safe to call from worker threads — uses _api_call_with_retry for
        rate-limit handling (HTTP 429).
        """
        page_id = page.get("id", "")
        title = page.get("title", "")
        try:
            body = self._api_call_with_retry(
                self._client.get_page_by_id, page_id, expand="body.storage"
            )
        except Exception as e:
            logger.warning("%s  get_page_by_id(%s)", e, page_id)
            return None

        description = self._strip_html(body.get("body", {}).get("storage", {}).get("value", ""))
        url = body.get("_links", {}).get("base", "") + page.get("_links", {}).get("webui", "")

        comments = []
        if page_id and include_comments:
            comments = self._fetch_comments(page_id, limit)

        return self._pack(title, description, comments, url, page_id)

    def _api_call_with_retry(self, func, *args, max_retries=3, **kwargs):
        """Call *func* with retry on HTTP 429 (rate limited).

        Uses exponential backoff with jitter.  Other exceptions propagate
        immediately.
        """
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.HTTPError as exc:
                status = getattr(exc.response, "status_code", None)
                if status == 429 and attempt < max_retries:
                    retry_after = exc.response.headers.get("Retry-After")
                    if retry_after:
                        delay = float(retry_after)
                    else:
                        delay = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        "Rate limited (429). Retry %d/%d after %.1fs",
                        attempt + 1, max_retries, delay,
                    )
                    time.sleep(delay)
                    continue
                raise

    def _fetch_comments(self, page_id, limit, max_retries=3):
        comments = []
        start = 0
        consecutive_errors = 0
        while True:
            try:
                self._reconnect_if_needed()
                resp = self._client.get_page_comments(
                    page_id, expand="body.storage", start=start, limit=limit
                )
                results = resp.get("results", [])
                consecutive_errors = 0  # reset on success
            except Exception as e:
                consecutive_errors += 1
                logger.warning("%s  get_page_comments(%s, start=%d)", e, page_id, start)
                if consecutive_errors >= max_retries:
                    logger.warning(
                        "Giving up on comments for page %s after %d consecutive errors. "
                        "Returning %d comment(s) fetched so far.",
                        page_id, consecutive_errors, len(comments),
                    )
                    break
                time.sleep(1)
                continue
            if not results:
                break
            for c in results:
                comments.append(self._strip_html(c.get("body", {}).get("storage", {}).get("value", "")))
            start += limit
        return comments

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
    def _strip_html(html: str) -> str:
        """Extract visible text from Confluence storage-format HTML."""
        if not html:
            return html
        extractor = _HtmlTextExtractor()
        extractor.feed(html)
        return extractor.get_text()

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
            logger.warning("%s requesting %s: %s", type(e).__name__, url, e)
        return None
