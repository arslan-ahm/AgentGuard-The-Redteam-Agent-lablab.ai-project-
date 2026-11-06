"""Security checks (brief 6.6): headers, cookies, https_redirect, error_leak.

A fake Playwright page serves canned responses; nothing touches the network. The last
section runs the real modules through ``runner.execute`` to prove the output passes the
5.4/5.6 contracts.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest
from agentguard_contracts import FindingDraft, SandboxTaskInput
from playwright.async_api import Error as PlaywrightError

import runner
from checks.context import CheckContext, PolicyViolation, SameOriginPolicy
from checks.security import cookies, error_leak, headers, https_redirect
from checks.security._common import MAX_BODY_CHARS

HTTPS_TARGET = "https://shop.example.com"
HTTP_TARGET = "http://shop.example.com"

GOOD_HEADERS = {
    "content-type": "text/html",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        hdrs: dict[str, str] | None = None,
        body: str = "<html><body>ok</body></html>",
        set_cookies: list[str] | None = None,
    ) -> None:
        self.status = status
        self.url = ""
        self._headers = {k.lower(): v for k, v in (hdrs or {}).items()}
        self._body = body
        self._set_cookies = set_cookies or []

    async def all_headers(self) -> dict[str, str]:
        return dict(self._headers)

    async def headers_array(self) -> list[dict[str, str]]:
        pairs = [{"name": k, "value": v} for k, v in self._headers.items()]
        return pairs + [{"name": "Set-Cookie", "value": c} for c in self._set_cookies]

    async def text(self) -> str:
        return self._body


class FakeAPIResponse:
    def __init__(self, status: int, hdrs: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in (hdrs or {}).items()}


class FakeRequest:
    def __init__(self, routes: dict[str, FakeAPIResponse | Exception]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, int]] = []

    async def get(
        self, url: str, max_redirects: int, timeout: int  # noqa: ASYNC109 - Playwright API
    ) -> FakeAPIResponse:
        self.calls.append((url, max_redirects))
        route = self.routes.get(url, PlaywrightError("net::ERR_CONNECTION_REFUSED"))
        if isinstance(route, Exception):
            raise route
        return route


class FakePage:
    def __init__(
        self,
        routes: dict[str, FakeResponse] | None = None,
        api: dict[str, FakeAPIResponse | Exception] | None = None,
        default: FakeResponse | None = None,
    ) -> None:
        self.routes = routes or {}
        self.default = default or FakeResponse(200, GOOD_HEADERS)
        self.visited: list[str] = []
        self.request = FakeRequest(api or {})

    async def goto(
        self, url: str, timeout: int, wait_until: str  # noqa: ASYNC109 - Playwright API
    ) -> FakeResponse:
        assert timeout > 0
        self.visited.append(url)
        response = self.routes.get(url, self.default)
        response.url = url  # Playwright's Response.url is the requested URL
        return response

    async def screenshot(self, path: str, full_page: bool) -> None:
        await asyncio.to_thread(Path(path).write_bytes, b"png")


def make_ctx(
    tmp_path: Path, page: FakePage, target: str = HTTPS_TARGET, **params: Any
) -> CheckContext:
    return CheckContext(
        target_url=target,
        params=dict(params),
        evidence_dir=tmp_path,
        policy=SameOriginPolicy(target),
        page=page,
    )


def titles(found: list[dict[str, Any]]) -> list[str]:
    return [f["title"] for f in found]


def assert_contract(found: list[dict[str, Any]], check_id: str) -> None:
    for item in found:
        draft = FindingDraft.model_validate(item)
        assert draft.check_id == check_id
        assert draft.category.value == "security"
        assert draft.reproduction and draft.evidence and draft.recommended_fix
        assert "network_summary.json" in draft.evidence


# --- headers -------------------------------------------------------------------------


def test_headers_all_good_no_findings() -> None:
    assert headers.analyse(HTTPS_TARGET + "/", GOOD_HEADERS, ["n.json"]) == []


@pytest.mark.parametrize(
    ("drop", "title"),
    [
        ("content-security-policy", "Missing Content-Security-Policy header"),
        ("strict-transport-security", "Missing Strict-Transport-Security header"),
        ("x-content-type-options", "Missing X-Content-Type-Options: nosniff"),
        ("referrer-policy", "Missing Referrer-Policy header"),
    ],
)
def test_headers_each_missing_header_reported(drop: str, title: str) -> None:
    hdrs = {k: v for k, v in GOOD_HEADERS.items() if k != drop}
    found = headers.analyse(HTTPS_TARGET + "/", hdrs, ["n.json"])
    assert title in titles(found)


def test_headers_missing_csp_also_loses_frame_protection() -> None:
    hdrs = {k: v for k, v in GOOD_HEADERS.items() if k != "content-security-policy"}
    found = titles(headers.analyse(HTTPS_TARGET + "/", hdrs, ["n.json"]))
    assert "Missing clickjacking protection" in found


def test_headers_xfo_satisfies_frame_protection() -> None:
    hdrs = {
        **GOOD_HEADERS,
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
    }
    assert headers.analyse(HTTPS_TARGET + "/", hdrs, ["n.json"]) == []


def test_headers_hsts_not_required_on_plain_http() -> None:
    hdrs = {k: v for k, v in GOOD_HEADERS.items() if k != "strict-transport-security"}
    assert headers.analyse(HTTP_TARGET + "/", hdrs, ["n.json"]) == []


@pytest.mark.parametrize(
    ("hsts", "title"),
    [
        ("max-age=300", "Strict-Transport-Security max-age is too short"),
        ("includeSubDomains", "Missing Strict-Transport-Security header"),
    ],
)
def test_headers_weak_hsts(hsts: str, title: str) -> None:
    found = headers.analyse(
        HTTPS_TARGET, {**GOOD_HEADERS, "strict-transport-security": hsts}, ["n.json"]
    )
    assert titles(found) == [title]


@pytest.mark.parametrize(
    "csp",
    [
        "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    ],
)
def test_headers_unsafe_inline_csp(csp: str) -> None:
    found = headers.analyse(HTTPS_TARGET, {**GOOD_HEADERS, "content-security-policy": csp}, ["n"])
    assert titles(found) == ["Content-Security-Policy allows inline scripts"]


def test_headers_unsafe_inline_styles_only_is_fine() -> None:
    csp = "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    assert (
        headers.analyse(HTTPS_TARGET, {**GOOD_HEADERS, "content-security-policy": csp}, ["n"]) == []
    )


def test_headers_version_disclosure() -> None:
    hdrs = {**GOOD_HEADERS, "server": "nginx/1.18.0", "x-powered-by": "Express"}
    found = headers.analyse(HTTPS_TARGET, hdrs, ["n"])
    assert titles(found) == ["Server software version disclosed in headers"]
    assert found[0]["severity"] == "low"
    assert "nginx/1.18.0" in found[0]["reproduction"][1]


def test_headers_header_names_case_insensitive() -> None:
    hdrs = {k.upper(): v for k, v in GOOD_HEADERS.items()}
    assert headers.analyse(HTTPS_TARGET, hdrs, ["n"]) == []


async def test_headers_run_bare_site(tmp_path: Path) -> None:
    page = FakePage(
        default=FakeResponse(200, {"content-type": "text/html", "set-cookie": "a=SECRET"})
    )
    ctx = make_ctx(tmp_path, page, path="/checkout")
    found = await headers.run(page, ctx)
    assert page.visited == [HTTPS_TARGET + "/checkout"]
    assert len(found) == 5
    assert {f["severity"] for f in found} == {"medium", "low"}
    assert_contract(found, "security.headers")
    assert found[0]["evidence"] == ["headers_page.png", "network_summary.json"]
    assert "SECRET" not in json.dumps(ctx.requests)  # Set-Cookie never copied to evidence


async def test_headers_run_ignores_offsite_path_param(tmp_path: Path) -> None:
    page = FakePage()
    for bad in ("//evil.com/x", "https://evil.com/", "relative"):
        ctx = make_ctx(tmp_path, page, path=bad)
        await headers.run(page, ctx)
    assert set(page.visited) == {HTTPS_TARGET}


# --- cookies -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", ("sid", True, True, "lax")),
        ("theme=dark", ("theme", False, False, None)),
        ("a=b=c; secure; httponly; samesite=None", ("a", True, True, "none")),
        ("  token = x ; HTTPONLY", ("token", False, True, None)),
    ],
)
def test_parse_set_cookie(header: str, expected: tuple[Any, ...]) -> None:
    c = cookies.parse_set_cookie(header)
    assert c is not None
    assert (c.name, c.secure, c.http_only, c.same_site) == expected


@pytest.mark.parametrize("header", ["", "novalue", "=x; Secure"])
def test_parse_set_cookie_rejects_nameless(header: str) -> None:
    assert cookies.parse_set_cookie(header) is None


def _cookie(header: str) -> cookies.SetCookie:
    c = cookies.parse_set_cookie(header)
    assert c is not None
    return c


def test_cookies_good_session_cookie_passes() -> None:
    c = _cookie("__Host-session=x; Secure; HttpOnly; SameSite=Strict; Path=/")
    assert cookies.analyse(HTTPS_TARGET, [c], ["n"]) == []


def test_cookies_insecure_session_cookie_is_medium() -> None:
    found = cookies.analyse(HTTPS_TARGET, [_cookie("sessionid=x; Path=/")], ["n"])
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    for problem in ("Secure is missing", "HttpOnly is missing", "SameSite is not set"):
        assert problem in found[0]["title"]


def test_cookies_non_session_cookie_does_not_need_httponly() -> None:
    found = cookies.analyse(HTTPS_TARGET, [_cookie("theme=dark; Secure; SameSite=Lax")], ["n"])
    assert found == []


def test_cookies_samesite_none_without_secure() -> None:
    found = cookies.analyse(HTTP_TARGET, [_cookie("pref=1; SameSite=None")], ["n"])
    assert "SameSite=None without Secure" in found[0]["title"]
    assert found[0]["severity"] == "low"


def test_cookies_secure_not_required_on_http_target() -> None:
    found = cookies.analyse(HTTP_TARGET, [_cookie("sid=x; HttpOnly; SameSite=Lax")], ["n"])
    assert found == []


async def test_cookies_run_never_records_values(tmp_path: Path) -> None:
    page = FakePage(
        default=FakeResponse(
            200,
            GOOD_HEADERS,
            set_cookies=["connect.sid=s%3ASUPERSECRET; Path=/", "theme=dark; Secure; SameSite=Lax"],
        )
    )
    ctx = make_ctx(tmp_path, page)
    found = await cookies.run(page, ctx)
    assert titles(found) == [
        "Cookie 'connect.sid' has weak flags: Secure is missing, HttpOnly is missing, "
        "SameSite is not set"
    ]
    assert_contract(found, "security.cookies")
    dumped = json.dumps(ctx.requests) + json.dumps(found)
    assert "SUPERSECRET" not in dumped
    assert ctx.requests[-1]["set_cookie"][0]["name"] == "connect.sid"


async def test_cookies_run_reads_guard_headers(tmp_path: Path) -> None:
    """Under the network guard Playwright hides Set-Cookie: the check uses ctx.seen_headers."""
    page = FakePage(default=FakeResponse(200, GOOD_HEADERS))  # no Set-Cookie visible
    ctx = make_ctx(tmp_path, page)
    seen: list[str] = []

    def seen_headers(url: str) -> list[dict[str, str]] | None:
        seen.append(url)
        return [{"name": "set-cookie", "value": "sessionid=X; Path=/"}]

    ctx.seen_headers = seen_headers
    found = await cookies.run(page, ctx)
    assert titles(found) == [
        "Cookie 'sessionid' has weak flags: Secure is missing, HttpOnly is missing, "
        "SameSite is not set"
    ]
    assert seen == page.visited  # looked up by the response URL the guard keyed on


async def test_cookies_run_no_cookies(tmp_path: Path) -> None:
    page = FakePage()
    assert await cookies.run(page, make_ctx(tmp_path, page)) == []


# --- https_redirect ------------------------------------------------------------------


async def test_https_redirect_ok(tmp_path: Path) -> None:
    page = FakePage(
        api={"http://shop.example.com/": FakeAPIResponse(301, {"Location": HTTPS_TARGET + "/"})}
    )
    assert await https_redirect.run(page, make_ctx(tmp_path, page)) == []
    assert page.request.calls == [("http://shop.example.com/", 0)]  # never follows redirects


async def test_https_redirect_relative_location_stays_on_http(tmp_path: Path) -> None:
    page = FakePage(api={"http://shop.example.com/": FakeAPIResponse(308, {"Location": "/"})})
    # A relative Location stays on http: that is NOT an upgrade.
    found = await https_redirect.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["HTTP does not redirect to HTTPS"]


async def test_https_redirect_http_served_in_clear(tmp_path: Path) -> None:
    page = FakePage(api={"http://shop.example.com/": FakeAPIResponse(200)})
    found = await https_redirect.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["HTTP does not redirect to HTTPS"]
    assert found[0]["severity"] == "medium"
    assert_contract(found, "security.https_redirect")


async def test_https_redirect_to_other_host_is_not_ok(tmp_path: Path) -> None:
    page = FakePage(
        api={"http://shop.example.com/": FakeAPIResponse(302, {"Location": "https://evil.com/"})}
    )
    found = await https_redirect.run(page, make_ctx(tmp_path, page))
    assert "evil.com" in found[0]["reproduction"][1]


@pytest.mark.parametrize("route", [PlaywrightError("refused"), FakeAPIResponse(403)])
async def test_https_redirect_http_not_served_is_fine(
    tmp_path: Path, route: FakeAPIResponse | Exception
) -> None:
    page = FakePage(api={"http://shop.example.com/": route})
    assert await https_redirect.run(page, make_ctx(tmp_path, page)) == []


async def test_https_redirect_http_target_without_tls_is_high(tmp_path: Path) -> None:
    page = FakePage(api={"http://shop.example.com/": FakeAPIResponse(200)})
    found = await https_redirect.run(page, make_ctx(tmp_path, page, target=HTTP_TARGET))
    assert titles(found) == ["Site is not available over HTTPS"]
    assert found[0]["severity"] == "high"


async def test_https_redirect_http_target_with_tls_but_no_redirect(tmp_path: Path) -> None:
    page = FakePage(
        api={
            "https://shop.example.com/": FakeAPIResponse(200),
            "http://shop.example.com/": FakeAPIResponse(200),
        }
    )
    found = await https_redirect.run(page, make_ctx(tmp_path, page, target=HTTP_TARGET))
    assert titles(found) == ["HTTP does not redirect to HTTPS"]


async def test_https_redirect_explicit_default_port(tmp_path: Path) -> None:
    page = FakePage(
        api={"http://shop.example.com/": FakeAPIResponse(301, {"Location": HTTPS_TARGET + "/"})}
    )
    ctx = make_ctx(tmp_path, page, target="https://shop.example.com:443")
    assert await https_redirect.run(page, ctx) == []
    assert page.request.calls == [("http://shop.example.com/", 0)]


async def test_https_redirect_ipv6_literal_target(tmp_path: Path) -> None:
    page = FakePage(api={"http://[2001:db8::1]/": FakeAPIResponse(200)})
    ctx = make_ctx(tmp_path, page, target="https://[2001:db8::1]")
    found = await https_redirect.run(page, ctx)
    assert found[0]["url"] == "http://[2001:db8::1]/"


async def test_https_redirect_skips_non_default_port(tmp_path: Path) -> None:
    page = FakePage()
    ctx = make_ctx(tmp_path, page, target="http://shop.example.com:5000")
    assert await https_redirect.run(page, ctx) == []
    assert page.request.calls == []


# --- error_leak ----------------------------------------------------------------------

PY_TRACE = """<pre>Traceback (most recent call last):
  File "/srv/app/shop/views.py", line 88, in checkout
    total = apply_coupon(cart, code)
ValueError: invalid coupon</pre>"""
NODE_TRACE = "Error: boom\n    at applyCoupon (/home/node/app/routes/cart.js:42:13)\n"
JAVA_TRACE = "java.lang.NullPointerException\n\tat com.shop.Cart.total(Cart.java:42)\n"
PHP_ERR = "<b>Fatal error</b>:  Uncaught Error in /var/www/html/cart.php on line <b>12</b>"
DJANGO = "You're seeing this error because you have <code>DEBUG = True</code> in your settings"
MYSQL = "You have an error in your SQL syntax; check the manual near 'x' at line 1"
PG = 'psycopg2.errors.UndefinedTable: relation "orders" does not exist'
SQLITE = "sqlite3.OperationalError: no such column: agentguard"
PATH_ONLY = "Template not found: /var/www/shop/templates/missing.php"
VERSION = "<hr><address>Apache/2.4.41 (Ubuntu) Server at shop.example.com Port 80</address>"


@pytest.mark.parametrize(
    ("body", "status", "key"),
    [
        (PY_TRACE, 500, "stack_trace"),
        (NODE_TRACE, 500, "stack_trace"),
        (JAVA_TRACE, 500, "stack_trace"),
        (PHP_ERR, 500, "stack_trace"),
        (DJANGO, 404, "stack_trace"),
        ("<h1>Werkzeug Debugger</h1>", 500, "stack_trace"),
        (MYSQL, 500, "sql_error"),
        (PG, 500, "sql_error"),
        (SQLITE, 200, "sql_error"),
        ("ORA-00933: SQL command not properly ended", 500, "sql_error"),
        (PATH_ONLY, 500, "internal_path"),
        (VERSION, 404, "version"),
        (PY_TRACE + MYSQL, 500, "stack_trace"),  # most severe wins
    ],
)
def test_error_leak_detect(body: str, status: int, key: str) -> None:
    hit = error_leak.detect(body, status)
    assert hit is not None
    assert hit[0].key == key
    assert len(hit[1]) <= 400


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ("<h1>Page not found</h1><p>Sorry.</p>", 404),
        ("<h1>Something went wrong</h1>", 500),
        (VERSION, 200),  # a normal page mentioning a server version is not an error leak
        (PATH_ONLY, 200),
        ("Our docs explain how a traceback works.", 200),
        ("", 500),
    ],
)
def test_error_leak_detect_clean(body: str, status: int) -> None:
    assert error_leak.detect(body, status) is None


@pytest.mark.parametrize(
    "unit",
    [
        "\n",
        " \n",
        "\t",
        "Warning: ",
        "<b>Fatal error</b>: x",
        "/var/www/",
        "/home/a/",
        "/srv/a",
        "site-packages/",
        "node_modules/",
        "  at x (",
        '  File "',
        "C:\\Users\\",
        "Apache/1.",
        "SQLSTATE[",
    ],
)
def test_error_leak_detect_stays_fast_on_hostile_bodies(unit: str) -> None:
    """Bodies are target-controlled. Regex blow-up would block the event loop, and asyncio
    timeouts cannot interrupt CPU-bound work, so a hostile page could stall the sandbox."""

    def best_time(size: int) -> float:
        body = (unit * (size // len(unit) + 1))[:size]
        runs = []
        for _ in range(3):  # best of 3: ignore scheduler noise from a busy machine
            started = time.process_time()  # CPU time: immune to other busy processes
            error_leak.detect(body, 500)
            runs.append(time.process_time() - started)
        return min(runs)

    # Compare scaling, not wall time (CI speed varies): 4x the input costs ~4x when linear
    # (measured 3.4-5.0x) and ~16x when quadratic (the old patterns took ~30 s at 20k chars).
    quarter = best_time(MAX_BODY_CHARS // 4)
    full = best_time(MAX_BODY_CHARS)
    # Floor of 1 s: Windows CPU clocks tick every ~15 ms, so tiny inputs read as ~0.
    assert full < max(1.0, 10 * quarter), f"{quarter=:.3f}s {full=:.3f}s: superlinear"


def test_error_leak_probe_urls_are_marked_and_same_origin(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, FakePage(), path="/checkout", probe_marker="agentguard-probe-1234")
    urls = dict(error_leak.probe_urls(ctx))
    assert urls == {
        "page": HTTPS_TARGET + "/checkout",
        "missing_page": HTTPS_TARGET + "/agentguard-probe-1234",
        "bad_param": HTTPS_TARGET + "/checkout?id=agentguard-probe-1234",
    }


def test_error_leak_probe_marker_is_sanitised(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, FakePage(), probe_marker="x'/../<script>")
    for _, url in error_leak.probe_urls(ctx):
        assert "'" not in url and "<" not in url and ".." not in url


def test_error_leak_default_marker_is_agentguard_probe(tmp_path: Path) -> None:
    urls = dict(error_leak.probe_urls(make_ctx(tmp_path, FakePage())))
    assert urls["missing_page"].startswith(HTTPS_TARGET + "/agentguard-probe-")


async def test_error_leak_run_reports_each_kind_once(tmp_path: Path) -> None:
    page = FakePage(
        routes={
            HTTPS_TARGET + "/checkout?id=agentguard-probe-1": FakeResponse(500, body=PY_TRACE),
            HTTPS_TARGET + "/agentguard-probe-1": FakeResponse(404, body=PY_TRACE + VERSION),
        }
    )
    ctx = make_ctx(tmp_path, page, path="/checkout", probe_marker="agentguard-probe-1")
    found = await error_leak.run(page, ctx)
    assert titles(found) == ["Error response leaks an internal stack trace"]
    leak = found[0]
    assert leak["severity"] == "high"
    assert leak["url"] == HTTPS_TARGET + "/agentguard-probe-1"
    assert leak["evidence"] == ["error_leak_missing_page.png", "network_summary.json"]
    assert leak["reproduction"][0] == "Open /agentguard-probe-1"
    assert (tmp_path / "screenshots" / "error_leak_missing_page.png").exists()
    assert_contract(found, "security.error_leak")
    assert any(r.get("leak") == "stack_trace" for r in ctx.requests)


async def test_error_leak_run_clean_site(tmp_path: Path) -> None:
    page = FakePage(default=FakeResponse(404, body="<h1>Not found</h1>"))
    assert await error_leak.run(page, make_ctx(tmp_path, page)) == []
    assert len(page.visited) == 3


# --- policy + runner integration --------------------------------------------------------


def test_policy_scheme_switch_only_on_default_ports() -> None:
    policy = SameOriginPolicy(HTTPS_TARGET)
    policy.assert_allowed("http://shop.example.com/")
    for bad in ("http://shop.example.com:8080/", "http://other.example.com/"):
        with pytest.raises(PolicyViolation):
            policy.assert_allowed(bad)
    port_target = SameOriginPolicy("https://shop.example.com:8443")
    with pytest.raises(PolicyViolation):
        port_target.assert_allowed("http://shop.example.com/")


@pytest.mark.parametrize(
    "check_id",
    ["security.headers", "security.cookies", "security.https_redirect", "security.error_leak"],
)
def test_checks_load_through_whitelist(check_id: str) -> None:
    assert runner.load_check(check_id).CHECK_ID == check_id


async def test_runner_executes_real_check_and_validates_contract(tmp_path: Path) -> None:
    task = SandboxTaskInput.model_validate(
        {
            "scan_id": "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d",
            "target_url": HTTPS_TARGET,
            "task": {
                "task_id": "t3",
                "check_id": "security.error_leak",
                "description": "error leak",
                "params": {"path": "/checkout", "probe_marker": "agentguard-probe-0b6c1d2e"},
                "timeout_s": 10,
            },
        }
    )
    page = FakePage(
        routes={
            HTTPS_TARGET + "/checkout?id=agentguard-probe-0b6c1d2e": FakeResponse(500, body=MYSQL)
        }
    )
    module = runner.load_check("security.error_leak")
    result, code = await runner.execute(task, module, page, tmp_path)
    assert (result.status.value, code) == ("failed", 0)
    assert result.findings[0].title == "Error response leaks a database error"
    assert all(e["decision"] == "allowed" for e in result.policy_events)
    summary = json.loads((tmp_path / "network_summary.json").read_text())
    assert any(entry.get("leak") == "sql_error" for entry in summary)
