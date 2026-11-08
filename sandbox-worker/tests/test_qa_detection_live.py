"""Real detection tests for ``qa.login``, ``qa.password_reset`` and ``qa.search``.

Each check runs in real Chromium against a small site served in-process on 127.0.0.1. Every
case is a hand-written page: a broken variant the check must flag, a healthy variant it must
pass, and edge cases (feature absent, form posting off-origin, a 200 page with an error
message). The server records every request, so tests can also prove what was *not* sent.

Like the live test in ``test_netguard.py`` this needs a browser, so it runs only with
``AGENTGUARD_LIVE_BROWSER=1``. The fake-page tests in ``test_qa_checks_forms.py`` always run.
"""

from __future__ import annotations

import os
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

from checks.context import CheckContext, SameOriginPolicy
from checks.qa import login, password_reset, search
from tests.qa_fakes import assert_contract, titles

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENTGUARD_LIVE_BROWSER") != "1", reason="set AGENTGUARD_LIVE_BROWSER=1"
)

MARK = "agentguard-probe-live1"

Reply = tuple[int, str, dict[str, str]]
Route = Reply | Callable[[dict[str, str]], Reply]


def html(status: int, title: str, body: str, **headers: str) -> Reply:
    page = f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"
    return status, page, {"Content-Type": "text/html; charset=utf-8", **headers}


def redirect(location: str) -> Reply:
    return 302, "", {"Location": location}


TRACEBACK = html(500, "Error", "<pre>Traceback (most recent call last):\nKeyError: 'user'</pre>")


@dataclass
class Site:
    """Routes keyed ``"METHOD /path"``; unknown routes answer 404. ``{port}`` in bodies is
    replaced with the server's port so a page can name an off-origin URL on the same server."""

    routes: dict[str, Route]
    port: int = 0
    hits: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)

    @property
    def target(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def posts(self) -> list[tuple[str, dict[str, str]]]:
        return [(path, data) for method, path, data in self.hits if method == "POST"]

    def gets(self, path: str) -> list[dict[str, str]]:
        return [data for method, p, data in self.hits if method == "GET" and p == path]


def _handler(site: Site) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self, method: str) -> None:
            parts = urlsplit(self.path)
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode()
            else:
                raw = parts.query
            data = dict(parse_qsl(raw, keep_blank_values=True))
            site.hits.append((method, parts.path, data))
            route = site.routes.get(f"{method} {parts.path}")
            if route is None:
                status, body, headers = html(404, "Not found", "<h1>Not found</h1>")
            else:
                status, body, headers = route(data) if callable(route) else route
            payload = body.replace("{port}", str(site.port)).encode()
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            self._serve("POST")

        def log_message(self, *args: Any) -> None:
            pass

    return Handler


@asynccontextmanager
async def live_site(routes: dict[str, Route]) -> AsyncIterator[tuple[Site, Any]]:
    """Serve ``routes`` on 127.0.0.1 and yield ``(site, page)`` from a real Chromium."""
    from playwright.async_api import async_playwright

    site = Site(routes)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(site))
    site.port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            try:
                context = await browser.new_context(service_workers="block")
                yield site, await context.new_page()
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()


def ctx_for(site: Site, page: Any, tmp_path: Path, **params: Any) -> CheckContext:
    return CheckContext(
        target_url=site.target,
        params={"probe_marker": MARK, **params},
        evidence_dir=tmp_path,
        policy=SameOriginPolicy(site.target),
        page=page,
    )


def skips(ctx: CheckContext) -> list[str]:
    return [str(r["skipped"]) for r in ctx.requests if "skipped" in r]


def assert_evidence(found: list[dict[str, Any]], tmp_path: Path, shot: str) -> None:
    """Contract-valid, with the real screenshot written and named in the evidence."""
    for item in found:
        assert item["evidence"] == [shot, "network_summary.json"]
        assert len(item["reproduction"]) >= 2
    assert (tmp_path / "screenshots" / shot).stat().st_size > 0


# --- qa.login ------------------------------------------------------------------------

LOGIN_FORM = html(
    200,
    "Sign in",
    "<h1>Sign in</h1><form method=post action=/login>"
    "<input type=hidden name=csrf value=tok-123>"
    "<label>Email <input name=email type=email></label>"
    "<label>Password <input name=password type=password></label>"
    "<button>Sign in</button></form>",
)
INVALID = html(401, "Sign in", "<p>Invalid email or password.</p>")


async def test_login_healthy_site_has_no_finding(tmp_path: Path) -> None:
    async with live_site({"GET /login": LOGIN_FORM, "POST /login": INVALID}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await login.run(page, ctx) == []
    (_, bad), (_, empty) = site.posts()
    assert bad == {"csrf": "tok-123", "email": f"{MARK}@example.invalid", "password": f"{MARK}-pw"}
    assert empty == {"csrf": "tok-123", "email": "", "password": ""}
    assert skips(ctx) == []


async def test_login_crash_on_bad_credentials_is_detected(tmp_path: Path) -> None:
    async with live_site({"GET /login": LOGIN_FORM, "POST /login": TRACEBACK}) as (site, page):
        found = await login.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Login crashes on invalid credentials (HTTP 500)"]
    assert found[0]["severity"] == "high"
    assert found[0]["url"] == f"{site.target}/login"
    assert found[0]["reproduction"][0] == "Open /login"
    assert_contract(found, "qa.login")
    assert_evidence(found, tmp_path, "login.png")


async def test_login_accepting_unknown_account_is_detected(tmp_path: Path) -> None:
    routes: dict[str, Route] = {"GET /login": LOGIN_FORM, "POST /login": redirect("/dashboard")}
    async with live_site(routes) as (site, page):
        found = await login.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Login appears to accept a non-existent account"]
    assert found[0]["severity"] == "critical" and found[0]["confidence"] < 0.5
    assert "redirecting to /dashboard" in found[0]["reproduction"][-1]
    assert_contract(found, "qa.login")
    assert_evidence(found, tmp_path, "login.png")
    assert site.gets("/dashboard") == []  # redirect was read, never followed


async def test_login_crash_on_empty_fields_is_detected(tmp_path: Path) -> None:
    def handler(data: dict[str, str]) -> Reply:
        return TRACEBACK if data.get("email") == "" else INVALID

    async with live_site({"GET /login": LOGIN_FORM, "POST /login": handler}) as (site, page):
        found = await login.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Login crashes on empty fields (HTTP 500)"]
    assert found[0]["severity"] == "medium"
    assert_contract(found, "qa.login")


async def test_login_redirect_back_to_login_with_error_is_fine(tmp_path: Path) -> None:
    routes: dict[str, Route] = {
        "GET /login": LOGIN_FORM,
        "POST /login": redirect("/login?error=invalid"),
    }
    async with live_site(routes) as (site, page):
        assert await login.run(page, ctx_for(site, page, tmp_path)) == []


async def test_login_form_posting_off_origin_is_skipped_and_never_submitted(
    tmp_path: Path,
) -> None:
    # Same server, other host name: a different origin, so nothing may be posted to it.
    off = html(
        200,
        "Sign in",
        "<form method=post action=http://localhost:{port}/login>"
        "<input name=email><input name=password type=password></form>",
    )
    async with live_site({"GET /login": off, "POST /login": TRACEBACK}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await login.run(page, ctx) == []
    assert skips(ctx) == ["login form posts off-origin"]
    assert site.posts() == []


async def test_login_page_without_form_is_skipped(tmp_path: Path) -> None:
    async with live_site({"GET /login": html(200, "Login", "<p>Use SSO</p>")}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await login.run(page, ctx) == []
    assert skips(ctx) == ["no login form found"]


async def test_login_page_missing_or_crashing(tmp_path: Path) -> None:
    async with live_site({}) as (site, page):
        assert await login.run(page, ctx_for(site, page, tmp_path)) == []  # no login: n/a
        explicit = await login.run(page, ctx_for(site, page, tmp_path, path="/signin"))
    assert titles(explicit) == ["Login page /signin returns HTTP 404"]
    assert explicit[0]["severity"] == "high"
    assert_contract(explicit, "qa.login")

    async with live_site({"GET /login": TRACEBACK}) as (site, page):
        found = await login.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Login page /login returns HTTP 500"]
    assert_contract(found, "qa.login")


# --- qa.password_reset ---------------------------------------------------------------

RESET_FORM = html(
    200,
    "Reset password",
    "<h1>Reset password</h1><form method=post action=/password-reset>"
    "<label>Email <input name=email type=email></label><button>Reset</button></form>",
)
SENT = html(200, "Reset", "<p>If the account exists, we sent a link.</p>")


async def test_password_reset_healthy_site_has_no_finding(tmp_path: Path) -> None:
    def handler(data: dict[str, str]) -> Reply:
        if "@" not in data.get("email", ""):
            return html(422, "Reset", "<p>Enter a valid email address.</p>")
        return SENT

    routes: dict[str, Route] = {"GET /password-reset": RESET_FORM, "POST /password-reset": handler}
    async with live_site(routes) as (site, page):
        assert await password_reset.run(page, ctx_for(site, page, tmp_path)) == []
    assert [data["email"] for _, data in site.posts()] == [
        f"{MARK}@example.invalid",
        "not-an-email",
    ]


async def test_password_reset_crash_for_unknown_address_is_detected(tmp_path: Path) -> None:
    routes: dict[str, Route] = {
        "GET /password-reset": RESET_FORM,
        "POST /password-reset": TRACEBACK,
    }
    async with live_site(routes) as (site, page):
        found = await password_reset.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Password reset fails for an unknown address (HTTP 500)"]
    assert found[0]["severity"] == "high"
    assert found[0]["reproduction"][0] == "Open /password-reset"
    assert_contract(found, "qa.password_reset")
    assert_evidence(found, tmp_path, "password_reset.png")
    assert len(site.posts()) == 1  # stops after the first crash


async def test_password_reset_crash_on_malformed_address_is_detected(tmp_path: Path) -> None:
    def handler(data: dict[str, str]) -> Reply:
        return SENT if "@" in data.get("email", "") else TRACEBACK

    routes: dict[str, Route] = {"GET /password-reset": RESET_FORM, "POST /password-reset": handler}
    async with live_site(routes) as (site, page):
        found = await password_reset.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Password reset crashes on a malformed address (HTTP 500)"]
    assert found[0]["severity"] == "medium"
    assert_contract(found, "qa.password_reset")
    assert_evidence(found, tmp_path, "password_reset.png")


async def test_password_reset_found_on_a_fallback_path(tmp_path: Path) -> None:
    forgot = html(
        200,
        "Forgot password",
        "<form method=post action=/forgot-password><input name=user_email></form>",
    )
    routes: dict[str, Route] = {"GET /forgot-password": forgot, "POST /forgot-password": TRACEBACK}
    async with live_site(routes) as (site, page):
        found = await password_reset.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Password reset fails for an unknown address (HTTP 500)"]
    assert found[0]["url"] == f"{site.target}/forgot-password"
    assert site.posts()[0][1] == {"user_email": f"{MARK}@example.invalid"}


async def test_password_reset_absent_is_skipped_not_a_finding(tmp_path: Path) -> None:
    async with live_site({"GET /": html(200, "Shop", "<p>hi</p>")}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await password_reset.run(page, ctx) == []
    assert skips(ctx) == ["no password reset page found"]
    assert [p for m, p, _ in site.hits if m == "GET" and p != "/favicon.ico"] == list(
        password_reset.DEFAULT_PATHS
    )
    assert site.posts() == []


async def test_password_reset_explicit_page_broken_or_without_form(tmp_path: Path) -> None:
    routes: dict[str, Route] = {
        "GET /forgot": html(200, "Forgot", "<p>Call support.</p>"),
        "GET /password-reset": TRACEBACK,
    }
    async with live_site(routes) as (site, page):
        no_form = await password_reset.run(page, ctx_for(site, page, tmp_path, path="/forgot"))
        crash = await password_reset.run(page, ctx_for(site, page, tmp_path))
        gone = await password_reset.run(page, ctx_for(site, page, tmp_path, path="/reset"))
    assert titles(no_form) == ["Password reset page /forgot has no email form"]
    assert no_form[0]["severity"] == "medium"
    assert titles(crash) == ["Password reset page /password-reset returns HTTP 500"]
    assert crash[0]["severity"] == "high"
    assert titles(gone) == ["Password reset page /reset returns HTTP 404"]
    for found in (no_form, crash, gone):
        assert_contract(found, "qa.password_reset")
    assert site.posts() == []


async def test_password_reset_ignores_login_and_off_origin_forms(tmp_path: Path) -> None:
    page_html = html(
        200,
        "Reset",
        "<form method=post action=/login><input name=email><input name=pw type=password></form>"
        "<form method=post action=http://localhost:{port}/reset><input name=email></form>",
    )
    async with live_site({"GET /password-reset": page_html}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await password_reset.run(page, ctx) == []
    assert skips(ctx) == ["no password reset page found"]
    assert site.posts() == []


# --- qa.search -----------------------------------------------------------------------

# Demo-store markup: an <input name=q> with no type attribute.
HOME = html(
    200,
    "Shop",
    "<h1>Shop</h1><form method=get action=/search><input name=q><button>Search</button></form>",
)


def results(data: dict[str, str]) -> Reply:
    return html(200, "Search", f"<p>No results for {len(data.get('q', ''))}-char query.</p>")


async def test_search_healthy_site_has_no_finding(tmp_path: Path) -> None:
    async with live_site({"GET /": HOME, "GET /search": results}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await search.run(page, ctx) == []
    assert site.gets("/search") == [{"q": MARK}, {"q": ""}]
    assert skips(ctx) == []


async def test_search_server_error_is_detected(tmp_path: Path) -> None:
    async with live_site({"GET /": HOME, "GET /search": TRACEBACK}) as (site, page):
        found = await search.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Search fails with HTTP 500"]
    assert found[0]["severity"] == "high"
    assert found[0]["url"] == f"{site.target}/search?q={MARK}"
    assert found[0]["reproduction"][1] == f"Search for '{MARK}'"
    assert_contract(found, "qa.search")
    assert_evidence(found, tmp_path, "search.png")
    assert site.gets("/search") == [{"q": MARK}]  # stops after the first crash


async def test_search_crash_on_empty_query_is_detected(tmp_path: Path) -> None:
    def handler(data: dict[str, str]) -> Reply:
        return TRACEBACK if data.get("q") == "" else results(data)

    async with live_site({"GET /": HOME, "GET /search": handler}) as (site, page):
        found = await search.run(page, ctx_for(site, page, tmp_path))
    assert titles(found) == ["Search crashes on an empty query (HTTP 500)"]
    assert found[0]["severity"] == "medium"
    assert_contract(found, "qa.search")
    assert_evidence(found, tmp_path, "search.png")


async def test_search_200_page_with_error_text_is_not_flagged(tmp_path: Path) -> None:
    """Documented limit: qa.search judges the HTTP status only. A 200 results page that
    says "something went wrong" is not reported (it would false-positive on pages that
    merely say "no results"); a traceback in a 200 body is security.stack_trace's job."""
    sorry = html(200, "Search", "<p class=error>Sorry, search is unavailable right now.</p>")
    async with live_site({"GET /": HOME, "GET /search": sorry}) as (site, page):
        assert await search.run(page, ctx_for(site, page, tmp_path)) == []
    assert len(site.gets("/search")) == 2


async def test_search_on_explicit_page_with_search_type_input(tmp_path: Path) -> None:
    catalog = html(
        200,
        "Catalog",
        "<form method=get action=/api/find?lang=en><input type=search name=text></form>",
    )
    routes: dict[str, Route] = {"GET /catalog": catalog, "GET /api/find": TRACEBACK}
    async with live_site(routes) as (site, page):
        found = await search.run(page, ctx_for(site, page, tmp_path, path="/catalog"))
    assert titles(found) == ["Search fails with HTTP 500"]
    assert found[0]["reproduction"][0] == "Open /catalog"
    assert site.gets("/api/find")[0] == {"lang": "en", "text": MARK}


async def test_search_absent_or_off_origin_is_skipped(tmp_path: Path) -> None:
    off = html(
        200,
        "Shop",
        "<form method=get action=http://localhost:{port}/search><input name=q></form>"
        "<form method=post action=/search><input name=q></form>",
    )
    async with live_site({"GET /": off, "GET /search": TRACEBACK}) as (site, page):
        ctx = ctx_for(site, page, tmp_path)
        assert await search.run(page, ctx) == []
    assert skips(ctx) == ["no search form found"]
    assert site.gets("/search") == []
