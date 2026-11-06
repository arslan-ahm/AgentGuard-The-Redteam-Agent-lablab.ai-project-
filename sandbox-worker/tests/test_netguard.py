"""Network guard (brief 6.4/12): every request and every redirect hop is vetted before it
leaves. ``FakeRoute`` records exactly which URLs would have hit the network.

A real-Chromium test at the end runs only with ``AGENTGUARD_LIVE_BROWSER=1`` (CI has no
browser); it serves a local site in-process and proves nothing leaks.
"""

from __future__ import annotations

import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from agentguard_contracts import SandboxTaskInput

import runner
from checks.context import CheckContext, SameOriginPolicy
from checks.netguard import (
    SUBRESOURCE_BLOCKED,
    NetworkGuard,
    blocked_ip_reason,
    guard_websocket,
    ip_literal,
    static_reason,
)

TARGET = "https://shop.example.com"
PUBLIC = "93.184.215.14"


class FakeResolver:
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        if host not in self.answers:
            raise OSError("NXDOMAIN")
        return self.answers[host]


DNS = {
    "shop.example.com": [PUBLIC],
    "cdn.example.net": ["151.101.1.1"],
    "rebind.example.com": ["10.0.0.5"],
    "mixed.example.com": [PUBLIC, "127.0.0.1"],
}


class FakeResp:
    def __init__(
        self, status: int = 200, location: str | None = None, cookies: tuple[str, ...] = ()
    ) -> None:
        self.status = status
        self.headers = {"location": location} if location else {}
        self.headers_array = [{"name": k, "value": v} for k, v in self.headers.items()] + [
            {"name": "Set-Cookie", "value": c} for c in cookies
        ]


class FakeFrame:
    def __init__(self, top: bool) -> None:
        self.parent_frame = None if top else object()


class FakeRequest:
    def __init__(self, url: str, nav: bool, top: bool, method: str, body: bytes | None) -> None:
        self.url = url
        self._nav = nav
        self.frame = FakeFrame(top)
        self.method = method
        self.post_data_buffer = body

    def is_navigation_request(self) -> bool:
        return self._nav


class FakeRoute:
    """``web`` maps URL -> response the network would give. ``fetched`` = what left the box."""

    def __init__(
        self,
        url: str,
        web: dict[str, FakeResp],
        *,
        nav: bool = False,
        top: bool = True,
        method: str = "GET",
        body: bytes | None = None,
    ) -> None:
        self.request = FakeRequest(url, nav, top, method, body)
        self.web = web
        self.fetched: list[tuple[str, str, bytes | None]] = []
        self.outcome: tuple[str, Any] | None = None

    async def fetch(self, **kw: Any) -> FakeResp:
        url = kw.get("url") or self.request.url
        assert kw["max_redirects"] == 0  # the guard must never let the network follow redirects
        method = kw.get("method") or self.request.method
        body = kw["post_data"] if "post_data" in kw else self.request.post_data_buffer
        self.fetched.append((url, method, body))
        if url not in self.web:
            raise RuntimeError("net::ERR_CONNECTION_REFUSED")
        return self.web[url]

    async def fulfill(
        self,
        response: FakeResp | None = None,
        status: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._end("fulfill", response if response is not None else (status, headers))

    async def abort(self, code: str | None = None) -> None:
        self._end("abort", code)

    async def continue_(self) -> None:
        self._end("continue", None)

    def _end(self, kind: str, value: Any) -> None:
        assert self.outcome is None, "route handled twice"
        self.outcome = (kind, value)


def make_guard(dns: dict[str, list[str]] | None = None) -> NetworkGuard:
    return NetworkGuard(SameOriginPolicy(TARGET), FakeResolver(dns or DNS))


def urls(route: FakeRoute) -> list[str]:
    return [u for u, _, _ in route.fetched]


# --- classification ------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",  # noqa: S104 - a blocked destination, not a bind address
        "::1",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "2002:a9fe:a9fe::",
        "64:ff9b::a9fe:a9fe",
        "224.0.0.1",
    ],
)
def test_blocked_ip_reason_blocks(ip: str) -> None:
    assert blocked_ip_reason(ip) is not None


@pytest.mark.parametrize("ip", [PUBLIC, "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8"])
def test_blocked_ip_reason_allows_public(ip: str) -> None:
    assert blocked_ip_reason(ip) is None


@pytest.mark.parametrize(
    ("host", "ip"),
    [
        ("127.1", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("2852039166", "169.254.169.254"),
        ("[::1]", "::1"),
        ("shop.example.com", None),
        ("1.2.3.4.5", None),
    ],
)
def test_ip_literal(host: str, ip: str | None) -> None:
    assert ip_literal(host) == ip


@pytest.mark.parametrize(
    "url",
    [
        "ftp://shop.example.com/",
        "file:///etc/passwd",
        "http://user:pw@shop.example.com/",
        "http://localhost/",
        "http://host.docker.internal/",
        "http://metadata.google.internal/",
        "http://printer.local/",
        "http://postgres/",
        "http://127.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://shop.example.com:99999/",
    ],
)
def test_static_reason_blocks(url: str) -> None:
    assert static_reason(url)[0] is not None


# --- requests and redirects ----------------------------------------------------------


async def test_allowed_request_fetched_once_and_fulfilled() -> None:
    route = FakeRoute(TARGET + "/", {TARGET + "/": FakeResp(200)}, nav=True)
    guard = make_guard()
    await guard.handle(route)
    assert urls(route) == [TARGET + "/"]
    assert route.outcome is not None and route.outcome[0] == "fulfill"
    assert guard.policy.events == []


async def test_same_origin_redirects_followed_by_guard() -> None:
    web = {
        TARGET + "/a": FakeResp(301, "/b"),
        TARGET + "/b": FakeResp(302, "http://shop.example.com/c"),
        "http://shop.example.com/c": FakeResp(200),
    }
    route = FakeRoute(TARGET + "/a", web, nav=True)
    await make_guard().handle(route)
    assert urls(route) == [TARGET + "/a", TARGET + "/b", "http://shop.example.com/c"]
    # Every hop vetted; the browser is sent straight to the vetted final URL so page.url is
    # right (it then makes that one GET itself).
    assert route.outcome == ("fulfill", (302, {"location": "http://shop.example.com/c"}))


async def test_subresource_redirect_served_directly() -> None:
    web = {
        "https://cdn.example.net/a.js": FakeResp(302, "/b.js"),
        "https://cdn.example.net/b.js": FakeResp(200),
    }
    route = FakeRoute("https://cdn.example.net/a.js", web)
    await make_guard().handle(route)
    assert route.outcome == ("fulfill", web["https://cdn.example.net/b.js"])


async def test_post_307_chain_served_directly_never_replayed() -> None:
    web = {TARGET + "/pay": FakeResp(307, "/pay2"), TARGET + "/pay2": FakeResp(200)}
    route = FakeRoute(TARGET + "/pay", web, nav=True, method="POST", body=b"x=1")
    await make_guard().handle(route)
    assert route.outcome == ("fulfill", web[TARGET + "/pay2"])


async def test_headers_for_keeps_set_cookie_of_every_hop() -> None:
    web = {
        TARGET + "/login": FakeResp(302, "/home", cookies=("auth=1; Path=/",)),
        TARGET + "/home": FakeResp(200, cookies=("sid=2; Path=/",)),
    }
    guard = make_guard()
    await guard.handle(FakeRoute(TARGET + "/login", web, nav=True))
    login = guard.headers_for(TARGET + "/login") or []
    home = guard.headers_for(TARGET + "/home") or []
    assert {"name": "Set-Cookie", "value": "auth=1; Path=/"} in login
    assert {"name": "Set-Cookie", "value": "sid=2; Path=/"} in home
    assert guard.headers_for(TARGET + "/never") is None


async def test_headers_memory_is_bounded() -> None:
    from checks import netguard as ng

    guard = make_guard()
    for i in range(ng.MAX_REMEMBERED + 50):
        url = f"{TARGET}/p{i}"
        await guard.handle(FakeRoute(url, {url: FakeResp(200)}))
    assert guard.headers_for(f"{TARGET}/p0") is None
    assert guard.headers_for(f"{TARGET}/p{ng.MAX_REMEMBERED + 49}") is not None


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:6379/",
        "http://localhost/admin",
        "http://0x7f000001/",
        "http://rebind.example.com/",
        "http://mixed.example.com/",
        "file:///etc/passwd",
    ],
)
async def test_navigation_redirect_to_internal_is_blocked_before_request(location: str) -> None:
    web = {TARGET + "/go": FakeResp(302, "/hop"), TARGET + "/hop": FakeResp(302, location)}
    route = FakeRoute(TARGET + "/go", web, nav=True)
    guard = make_guard()
    await guard.handle(route)
    assert urls(route) == [TARGET + "/go", TARGET + "/hop"]  # the bad hop never left
    assert route.outcome == ("abort", "blockedbyclient")
    event = guard.policy.events[-1]
    assert (event["action"], event["decision"]) == ("navigate", "blocked")
    assert event["target"] == location
    assert "redirect hop 2" in event["reason"]


async def test_navigation_to_other_public_origin_blocked() -> None:
    route = FakeRoute(
        TARGET + "/x", {TARGET + "/x": FakeResp(302, "https://cdn.example.net/")}, nav=True
    )
    guard = make_guard()
    await guard.handle(route)
    assert route.outcome == ("abort", "blockedbyclient")
    assert "outside the target origin" in guard.policy.events[-1]["reason"]


async def test_subresource_to_public_cdn_allowed() -> None:
    url = "https://cdn.example.net/app.js"
    route = FakeRoute(url, {url: FakeResp(200)})
    guard = make_guard()
    await guard.handle(route)
    assert route.outcome is not None and route.outcome[0] == "fulfill"
    assert guard.policy.events == []


@pytest.mark.parametrize(
    "url",
    ["http://169.254.169.254/x.png", "http://10.0.0.1/a.js", "http://rebind.example.com/i.png"],
)
async def test_subresource_to_internal_blocked_and_marked(url: str) -> None:
    route = FakeRoute(url, {url: FakeResp(200)})
    guard = make_guard()
    await guard.handle(route)
    assert route.fetched == []
    assert route.outcome == ("abort", "blockedbyclient")
    assert guard.policy.events[-1]["action"] == SUBRESOURCE_BLOCKED


async def test_subresource_redirect_to_internal_blocked() -> None:
    url = "https://cdn.example.net/img"
    route = FakeRoute(url, {url: FakeResp(302, "http://169.254.169.254/secret")})
    guard = make_guard()
    await guard.handle(route)
    assert urls(route) == [url]
    assert route.outcome == ("abort", "blockedbyclient")


async def test_iframe_navigation_is_a_subresource() -> None:
    url = "https://cdn.example.net/embed"
    route = FakeRoute(url, {url: FakeResp(200)}, nav=True, top=False)
    await make_guard().handle(route)
    assert route.outcome is not None and route.outcome[0] == "fulfill"


async def test_redirect_loop_capped() -> None:
    web = {TARGET + "/a": FakeResp(302, "/b"), TARGET + "/b": FakeResp(302, "/a")}
    route = FakeRoute(TARGET + "/a", web, nav=True)
    await make_guard().handle(route)
    assert len(route.fetched) == 6
    assert route.outcome == ("abort", "failed")


async def test_post_303_becomes_get_without_body() -> None:
    web = {TARGET + "/form": FakeResp(303, "/done"), TARGET + "/done": FakeResp(200)}
    route = FakeRoute(TARGET + "/form", web, nav=True, method="POST", body=b"a=1")
    await make_guard().handle(route)
    assert route.fetched[1] == (TARGET + "/done", "GET", None)


async def test_post_307_keeps_method_and_body() -> None:
    web = {TARGET + "/form": FakeResp(307, "/form2"), TARGET + "/form2": FakeResp(200)}
    route = FakeRoute(TARGET + "/form", web, nav=True, method="POST", body=b"a=1")
    await make_guard().handle(route)
    assert route.fetched[1] == (TARGET + "/form2", "POST", b"a=1")


async def test_unreachable_host_aborts_as_failed() -> None:
    route = FakeRoute(TARGET + "/down", {}, nav=True)
    await make_guard().handle(route)
    assert route.outcome == ("abort", "failed")


async def test_unresolvable_host_blocked_without_fetch() -> None:
    url = "https://nope.example.org/x"
    route = FakeRoute(url, {url: FakeResp(200)})
    await make_guard().handle(route)
    assert route.fetched == []
    assert route.outcome == ("abort", "blockedbyclient")


async def test_dns_resolved_once_per_host() -> None:
    resolver = FakeResolver(DNS)
    guard = NetworkGuard(SameOriginPolicy(TARGET), resolver)
    for path in ("/a", "/b", "/c"):
        url = "https://cdn.example.net" + path
        await guard.handle(FakeRoute(url, {url: FakeResp(200)}))
    assert resolver.calls == ["cdn.example.net"]


@pytest.mark.parametrize("url", ["data:text/plain,hi", "blob:https://shop.example.com/x"])
async def test_in_memory_schemes_pass_through(url: str) -> None:
    route = FakeRoute(url, {})
    await make_guard().handle(route)
    assert route.outcome == ("continue", None)
    assert route.fetched == []


async def test_guard_bug_fails_closed() -> None:
    class Broken(FakeRoute):
        async def fetch(self, **kw: Any) -> FakeResp:
            raise AssertionError("unexpected")

    guard = make_guard()

    async def explode(url: str, *, navigation: bool) -> str | None:
        raise KeyError("bug")

    guard.reason_for = explode  # type: ignore[method-assign]
    route = Broken(TARGET + "/", {})
    await guard.handle(route)
    assert route.outcome == ("abort", "failed")


# --- websockets ----------------------------------------------------------------------


class FakeWs:
    def __init__(self, url: str) -> None:
        self.url = url
        self.closed: int | None = None
        self.connected = False

    async def close(self, code: int, reason: str) -> None:
        self.closed = code

    def connect_to_server(self) -> None:
        self.connected = True


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("wss://shop.example.com/live", True),
        ("ws://shop.example.com/live", True),
        ("wss://evil.example.com/", False),
        ("ws://127.0.0.1:6379/", False),
        ("ws://169.254.169.254/", False),
    ],
)
async def test_websocket_guard(url: str, allowed: bool) -> None:
    policy = SameOriginPolicy(TARGET)
    ws = FakeWs(url)
    await guard_websocket(policy, ws)
    assert ws.connected is allowed
    assert (ws.closed == 1008) is (not allowed)


# --- runner escalation rule ----------------------------------------------------------


def _task() -> SandboxTaskInput:
    return SandboxTaskInput.model_validate(
        {
            "scan_id": "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d",
            "target_url": TARGET,
            "task": {
                "task_id": "t1",
                "check_id": "security.headers",
                "description": "x",
                "params": {},
                "timeout_s": 5,
            },
        }
    )


def _check(run: Any) -> Any:
    from types import ModuleType

    module = ModuleType("fake")
    module.CHECK_ID = "security.headers"  # type: ignore[attr-defined]
    module.run = run  # type: ignore[attr-defined]
    return module


async def test_runner_subresource_block_does_not_sink_task(tmp_path: Path) -> None:
    policy = SameOriginPolicy(TARGET)

    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        policy.record(SUBRESOURCE_BLOCKED, "http://localhost/x.png", "internal", blocked=True)
        return []

    result, code = await runner.execute(_task(), _check(run), None, tmp_path, policy=policy)
    assert (result.status.value, code) == ("passed", 0)
    assert result.policy_events[-1]["action"] == SUBRESOURCE_BLOCKED


async def test_runner_blocked_navigation_by_guard_sinks_task(tmp_path: Path) -> None:
    policy = SameOriginPolicy(TARGET)

    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        policy.record("navigate", "http://169.254.169.254/", "redirect hop 1", blocked=True)
        return []

    result, code = await runner.execute(_task(), _check(run), None, tmp_path, policy=policy)
    assert (result.status.value, code) == ("blocked", 3)


# --- real Chromium (opt-in) ----------------------------------------------------------


class _Site(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        _Site.hits.append(f"{self.headers.get('Host', '')}{self.path}")
        port = getattr(self.server, "server_port")  # noqa: B009 - BaseServer lacks the attr
        routes = {
            "/hop1": (302, "/hop2"),
            "/hop2": (302, f"http://127.0.0.2:{port}/internal"),
            "/imgredir": (302, f"http://127.0.0.2:{port}/secret.png"),
        }
        if self.path in routes:
            status, location = routes[self.path]
            self.send_response(status)
            self.send_header("Location", location)
            self.end_headers()
            return
        body = b"ok"
        if self.path == "/page":
            body = (
                f'<img src="http://127.0.0.3:{port}/pixel.png"><img src="/imgredir">'
                f'<script src="/app.js"></script>ok'
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


def _loopback_except_target(ip: str) -> str | None:
    """Test classifier: 127.0.0.1 plays the public target, other 127.x are 'internal'."""
    return None if ip == "127.0.0.1" else blocked_ip_reason(ip)


@pytest.mark.skipif(
    os.environ.get("AGENTGUARD_LIVE_BROWSER") != "1", reason="set AGENTGUARD_LIVE_BROWSER=1"
)
async def test_live_chromium_nothing_leaks() -> None:
    from playwright.async_api import async_playwright

    server = ThreadingHTTPServer(("0.0.0.0", 0), _Site)  # noqa: S104 - loopback test server
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    target = f"http://127.0.0.1:{port}"
    policy = SameOriginPolicy(target)
    guard = NetworkGuard(policy, FakeResolver({}), ip_reason=_loopback_except_target)
    _Site.hits.clear()
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            context = await browser.new_context(service_workers="block")
            page = await context.new_page()
            await page.route("**/*", guard.handle)
            with pytest.raises(Exception, match="ERR_BLOCKED_BY_CLIENT"):
                await page.goto(target + "/hop1", timeout=15000)
            # The blocked tab is still loading Chromium's error page: use a fresh one.
            page = await context.new_page()
            await page.route("**/*", guard.handle)
            await page.goto(target + "/page", timeout=15000)
            await page.wait_for_load_state("load", timeout=15000)
            assert page.url == target + "/page"
            await browser.close()
    finally:
        server.shutdown()
    leaked = [h for h in _Site.hits if not h.startswith(f"127.0.0.1:{port}")]
    assert leaked == []
    assert f"127.0.0.1:{port}/app.js" in _Site.hits  # same-origin subresource still loads
    actions = [(e["action"], e["target"]) for e in policy.events]
    assert ("navigate", f"http://127.0.0.2:{port}/internal") in actions
    assert (SUBRESOURCE_BLOCKED, f"http://127.0.0.3:{port}/pixel.png") in actions
    assert (SUBRESOURCE_BLOCKED, f"http://127.0.0.2:{port}/secret.png") in actions
    await asyncio.sleep(0)
