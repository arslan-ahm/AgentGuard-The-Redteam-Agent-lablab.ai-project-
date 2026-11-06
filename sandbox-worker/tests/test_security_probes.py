"""Security probes (brief 6.6): url_session_leak, open_redirect, reflected_input,
exposed_endpoints, login_rate_probe, and the containment demo trigger (brief 6.9).

A fake page and API client serve canned responses; nothing touches the network. Every test
also checks what was *requested*, because the safety rules (GET only, max 3 logins, never
follow redirects, never leave the origin) matter as much as the findings.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from agentguard_contracts import FindingDraft, PlanTask, SandboxTaskInput
from playwright.async_api import Error as PlaywrightError

import runner
from checks.context import CheckContext, SameOriginPolicy
from checks.security import (
    exposed_endpoints,
    login_rate_probe,
    open_redirect,
    reflected_input,
    url_session_leak,
)
from checks.security._common import (
    Fetched,
    probe_marker,
    same_origin,
    with_param,
)

T = "https://shop.example.com"
MARK = "agentguard-probe-test1"
PROBE_HOST = f"{MARK}.invalid"


class Resp:
    """Both a navigation response and an API response."""

    def __init__(self, status: int = 200, body: str = "<html>ok</html>", **hdrs: str) -> None:
        self.status = status
        self.body = body
        self.headers = {k.replace("_", "-").lower(): v for k, v in hdrs.items()}
        self.headers.setdefault("content-type", "text/html")

    async def all_headers(self) -> dict[str, str]:
        return dict(self.headers)

    async def text(self) -> str:
        return self.body


Handler = Resp | Exception | Any  # Any: a callable(url, form) -> Resp


class Api:
    def __init__(self, routes: dict[str, Handler], default: Resp | None = None) -> None:
        self.routes = routes
        self.default = default or Resp(404, "<html>Not found</html>")
        self.calls: list[tuple[str, str, dict[str, str] | None, int]] = []

    def _answer(self, url: str, form: dict[str, str] | None) -> Resp:
        handler = self.routes.get(url, self.default)
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler(url, form)  # type: ignore[no-any-return]
        return handler  # type: ignore[no-any-return]

    async def get(self, url: str, max_redirects: int, timeout: int) -> Resp:  # noqa: ASYNC109
        self.calls.append(("GET", url, None, max_redirects))
        return self._answer(url, None)

    async def post(
        self, url: str, form: dict[str, str], max_redirects: int, timeout: int  # noqa: ASYNC109
    ) -> Resp:
        self.calls.append(("POST", url, dict(form), max_redirects))
        return self._answer(url, form)


class Page:
    def __init__(
        self,
        api: Api | None = None,
        links: list[str] | None = None,
        forms: list[dict[str, Any]] | None = None,
        final_url: str | None = None,
    ) -> None:
        self.request = api or Api({})
        self.links = links or []
        self.forms = forms or []
        self.final_url = final_url
        self.url = ""
        self.visited: list[str] = []

    async def goto(self, url: str, timeout: int, wait_until: str) -> Resp:  # noqa: ASYNC109
        self.visited.append(url)
        self.url = self.final_url or url
        return Resp()

    async def eval_on_selector_all(self, selector: str, script: str) -> Any:
        return {"a[href]": self.links, "form": self.forms}[selector]

    async def screenshot(self, path: str, full_page: bool) -> None:
        await asyncio.to_thread(Path(path).write_bytes, b"png")


def ctx_for(tmp_path: Path, page: Page, target: str = T, **params: Any) -> CheckContext:
    return CheckContext(
        target_url=target,
        params={"probe_marker": MARK, **params},
        evidence_dir=tmp_path,
        policy=SameOriginPolicy(target),
        page=page,
    )


def valid(found: list[dict[str, Any]], check_id: str) -> list[dict[str, Any]]:
    for item in found:
        draft = FindingDraft.model_validate(item)
        assert draft.check_id == check_id
        assert draft.category.value == "security"
        assert draft.evidence == ["network_summary.json"]
        assert draft.reproduction and draft.recommended_fix and draft.impact
    return found


def never_followed_redirects(api: Api) -> bool:
    return all(max_redirects == 0 for *_, max_redirects in api.calls)


# --- shared helpers -----------------------------------------------------------------------


def test_probe_marker_sanitised_and_bounded(tmp_path: Path) -> None:
    page = Page()
    assert probe_marker(ctx_for(tmp_path, page)) == MARK
    weird = ctx_for(tmp_path, page, probe_marker='x"><script>' + "a" * 100)
    assert probe_marker(weird) == "xscript" + "a" * 33
    default = CheckContext(T, {}, tmp_path, SameOriginPolicy(T), page)
    assert probe_marker(default).startswith("agentguard-probe-")


@pytest.mark.parametrize(
    ("url", "same"),
    [
        ("https://shop.example.com/a?b=1", True),
        ("https://SHOP.example.com:443/", True),
        ("http://shop.example.com/", False),
        ("https://evil.example.com/", False),
        ("https://shop.example.com:8443/", False),
        ("javascript:alert(1)", False),
        ("https://[::1", False),
    ],
)
def test_same_origin(url: str, same: bool) -> None:
    assert same_origin(url, T) is same


def test_with_param_replaces_and_keeps_others() -> None:
    assert with_param(f"{T}/s?q=old&page=2#x", "q", "new v") == f"{T}/s?page=2&q=new+v"


def test_fetched_location_is_absolute() -> None:
    got = Fetched(f"{T}/a/b", 302, {"location": "../c"}, "")
    assert got.location == f"{T}/c"


# --- url_session_leak ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "names"),
    [
        (f"{T}/cart;jsessionid=0123456789ABCDEF", ["jsessionid"]),
        (f"{T}/?PHPSESSID=abcdef0123456789", ["PHPSESSID"]),
        (f"{T}/?session_id=abcdef012345&page=2", ["session_id"]),
        (f"{T}/cb#x?access_token=no", []),  # fragment is not sent to the server
        (f"{T}/?access_token=eyJhbGciOi.payload", ["access_token"]),
        (f"{T}/?api_key=0123456789abcdef", ["api_key"]),
        (f"{T}/?sid=1", []),  # too short to be a secret
        (f"{T}/?page=2&sort=price", []),
        (f"{T}/?token=0123456789abcdef", []),  # bare "token" is often a one-time link
        ("mailto:a@b.c?sid=0123456789abcdef", []),
    ],
)
def test_leaked_params(url: str, names: list[str]) -> None:
    assert [n for n, _, _ in url_session_leak.leaked_params(url)] == names


def test_masked_hides_every_value() -> None:
    out = url_session_leak.masked(f"{T}/c;jsessionid=SECRETSECRET?sid=SECRET2SECRET&p=1#f")
    assert "SECRET" not in out
    assert out == f"{T}/c;jsessionid=*?sid=*&p=*"


async def test_url_session_leak_in_final_url_and_links(tmp_path: Path) -> None:
    page = Page(
        final_url=f"{T}/home;jsessionid=A1B2C3D4E5F6A7B8",
        links=[
            f"{T}/account?PHPSESSID=deadbeefdeadbeef",
            f"{T}/other;jsessionid=FFFFFFFFFFFFFFFF",  # same name: reported once
            "https://cdn.example.net/x.js",
        ],
    )
    ctx = ctx_for(tmp_path, page)
    found = valid(await url_session_leak.run(page, ctx), url_session_leak.CHECK_ID)
    assert [f["title"] for f in found] == [
        "Session id exposed in URL (jsessionid)",
        "Session id exposed in URL (PHPSESSID)",
    ]
    dumped = json.dumps(found) + json.dumps(ctx.requests)
    for secret in ("A1B2C3D4E5F6A7B8", "deadbeefdeadbeef", "FFFFFFFFFFFFFFFF"):
        assert secret not in dumped
    assert page.request.calls == []  # one page load, nothing else


async def test_url_session_leak_clean_page(tmp_path: Path) -> None:
    page = Page(links=[f"{T}/p?id=42", f"{T}/s?q=shoes"])
    assert await url_session_leak.run(page, ctx_for(tmp_path, page)) == []


async def test_url_session_leak_findings_capped(tmp_path: Path) -> None:
    names = ["sid", "sess", "session", "sessid", "session_key", "session_token", "jwt"]
    page = Page(links=[f"{T}/?{n}=0123456789abcdef" for n in names])
    found = await url_session_leak.run(page, ctx_for(tmp_path, page))
    assert len(found) == url_session_leak.MAX_FINDINGS


# --- open_redirect ------------------------------------------------------------------------


def _bounce(url: str, form: object) -> Resp:
    from urllib.parse import parse_qs, urlsplit

    target = parse_qs(urlsplit(url).query).get("next", ["/"])[0]
    return Resp(302, "", location=target)


async def test_open_redirect_found_via_link_param(tmp_path: Path) -> None:
    probe = f"https://{PROBE_HOST}/"
    vuln = with_param(f"{T}/login?next=%2Faccount", "next", probe)
    api = Api({vuln: _bounce})
    page = Page(api, links=[f"{T}/login?next=%2Faccount", "https://other.example.org/?next=x"])
    found = valid(await open_redirect.run(page, ctx_for(tmp_path, page)), open_redirect.CHECK_ID)
    assert [f["title"] for f in found] == ["Open redirect via the 'next' parameter"]
    assert found[0]["severity"] == "medium"
    assert api.calls[0][1] == vuln  # the discovered link was probed first
    assert len(api.calls) == 1  # stopped after the confirmed one
    assert never_followed_redirects(api)


async def test_open_redirect_relative_or_same_host_redirect_is_fine(tmp_path: Path) -> None:
    api = Api({}, default=Resp(302, "", location="/account"))
    page = Page(api)
    assert await open_redirect.run(page, ctx_for(tmp_path, page)) == []
    assert [c[1].split("?")[1].split("=")[0] for c in api.calls] == list(
        open_redirect.DEFAULT_PARAMS
    )


async def test_open_redirect_lookalike_host_is_not_a_hit(tmp_path: Path) -> None:
    api = Api({}, default=Resp(302, "", location=f"https://{PROBE_HOST}.shop.example.com/"))
    page = Page(api)
    assert await open_redirect.run(page, ctx_for(tmp_path, page)) == []


async def test_open_redirect_meta_refresh(tmp_path: Path) -> None:
    body = f'<meta http-equiv="refresh" content="0;url=https://{PROBE_HOST}/">'
    api = Api({}, default=Resp(200, body))
    page = Page(api)
    found = await open_redirect.run(page, ctx_for(tmp_path, page))
    assert found and found[0]["confidence"] == 0.8


async def test_open_redirect_probe_count_capped(tmp_path: Path) -> None:
    links = [f"{T}/p{i}?next=/x&url=/y" for i in range(20)]
    api = Api({})
    page = Page(api, links=links)
    await open_redirect.run(page, ctx_for(tmp_path, page))
    assert len(api.calls) == open_redirect.MAX_PROBES


async def test_open_redirect_network_error_is_not_a_finding(tmp_path: Path) -> None:
    api = Api({}, default=PlaywrightError("net::ERR_CONNECTION_RESET"))  # type: ignore[arg-type]
    page = Page(api)
    ctx = ctx_for(tmp_path, page)
    assert await open_redirect.run(page, ctx) == []
    assert any(r.get("error") for r in ctx.requests)


# --- reflected_input ----------------------------------------------------------------------


def _echo(escape: bool) -> Any:
    def answer(url: str, form: object) -> Resp:
        from html import escape as html_escape
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(url).query).get("q", [""])[0]
        shown = html_escape(q) if escape else q
        return Resp(200, f"<html><h1>Results for {shown}</h1></html>")

    return answer


async def test_reflected_input_unescaped(tmp_path: Path) -> None:
    form = {
        "action": f"{T}/search",
        "method": "get",
        "inputs": [{"name": "q", "type": "search", "value": ""}],
    }
    value, tag = reflected_input.probe_value(MARK)
    api = Api({with_param(f"{T}/search", "q", value): _echo(escape=False)})
    page = Page(api, forms=[form])
    found = valid(
        await reflected_input.run(page, ctx_for(tmp_path, page)), reflected_input.CHECK_ID
    )
    assert [f["title"] for f in found] == ["Input reflected without HTML escaping ('q' parameter)"]
    assert "<script" not in value.lower() and "on" not in value.lower().replace(MARK, "")
    assert api.calls[0][0] == "GET" and len(api.calls) == 1


async def test_reflected_input_escaped_is_safe(tmp_path: Path) -> None:
    value, _ = reflected_input.probe_value(MARK)
    api = Api({with_param(f"{T}/", "q", value): _echo(escape=True)})
    page = Page(api)
    assert await reflected_input.run(page, ctx_for(tmp_path, page)) == []


async def test_reflected_input_non_html_ignored(tmp_path: Path) -> None:
    value, tag = reflected_input.probe_value(MARK)
    api = Api({}, default=Resp(200, f'{{"q": "{tag}"}}', content_type="application/json"))
    page = Page(api)
    assert await reflected_input.run(page, ctx_for(tmp_path, page)) == []


def test_reflected_candidates_skip_post_offsite_and_hidden(tmp_path: Path) -> None:
    forms = [
        {"action": f"{T}/login", "method": "post", "inputs": [{"name": "user", "type": "text"}]},
        {"action": "https://evil.example/s", "method": "get", "inputs": [{"name": "x"}]},
        {
            "action": f"{T}/find",
            "method": "get",
            "inputs": [
                {"name": "term", "type": "text"},
                {"name": "csrf", "type": "hidden"},
                {"name": "", "type": "text"},
            ],
        },
    ]
    ctx = ctx_for(tmp_path, Page())
    pairs = reflected_input.candidates(ctx, [f"{T}/p?id=3", "https://x.example/?a=1"], forms)
    assert pairs[:2] == [(f"{T}/find", "term"), (f"{T}/p?id=3", "id")]
    assert len(pairs) == reflected_input.MAX_PROBES
    assert all("evil" not in u and "x.example" not in u for u, _ in pairs)


# --- exposed_endpoints --------------------------------------------------------------------

ENV_BODY = "APP_KEY=base64:SECRETVALUE\nDB_PASSWORD=hunter2\n# comment\nexport MAIL_HOST=smtp\n"


async def test_exposed_env_reports_names_never_values(tmp_path: Path) -> None:
    api = Api({f"{T}/.env": Resp(200, ENV_BODY, content_type="text/plain")})
    page = Page(api)
    ctx = ctx_for(tmp_path, page)
    found = valid(await exposed_endpoints.run(page, ctx), exposed_endpoints.CHECK_ID)
    assert [(f["title"], f["severity"]) for f in found] == [
        ("Environment file (.env) is publicly downloadable", "critical")
    ]
    dumped = json.dumps(found) + json.dumps(ctx.requests)
    assert "APP_KEY" in dumped and "DB_PASSWORD" in dumped
    assert "SECRETVALUE" not in dumped and "hunter2" not in dumped
    # GET only, exactly the brief's four paths plus the marked baseline, no redirects
    assert [(m, u) for m, u, *_ in api.calls] == [
        ("GET", f"{T}/{MARK}"),
        *[("GET", f"{T}{p}") for p in ("/admin", "/debug", "/.env", "/server-status")],
    ]
    assert never_followed_redirects(api)


async def test_exposed_each_kind(tmp_path: Path) -> None:
    api = Api(
        {
            f"{T}/admin": Resp(200, "<h1>Site administration</h1><a>Users</a>" + "x" * 500),
            f"{T}/debug": Resp(200, "<title>phpinfo()</title>PHP Version 8.2.1" + "y" * 900),
            f"{T}/server-status": Resp(200, "<h1>Apache Server Status for shop</h1>"),
        }
    )
    page = Page(api)
    found = valid(
        await exposed_endpoints.run(page, ctx_for(tmp_path, page)), "security.exposed_endpoints"
    )
    assert [f["severity"] for f in found] == ["high", "high", "medium"]


@pytest.mark.parametrize(
    ("path", "resp"),
    [
        ("/admin", Resp(200, "<h1>Admin panel</h1><input type='password' name='pw'>")),
        ("/admin", Resp(302, "", location="/login")),
        ("/admin", Resp(401, "Admin panel")),
        ("/debug", Resp(200, "<p>Our blog post about debugging</p>")),
        ("/.env", Resp(200, "<!doctype html><p>A=1\nB=2</p>")),
        ("/.env", Resp(200, "ONLY_ONE=1", content_type="text/plain")),
        ("/server-status", Resp(200, '{"status": "ok"}')),
    ],
)
def test_exposed_not_proven(path: str, resp: Resp) -> None:
    got = Fetched(f"{T}{path}", resp.status, resp.headers, resp.body)
    assert exposed_endpoints.classify(path, got) is None


async def test_exposed_soft_404_catch_all_not_reported(tmp_path: Path) -> None:
    spa = "<html><div id=root></div><nav>Admin dashboard</nav>" + "z" * 2000 + "</html>"
    api = Api({}, default=Resp(200, spa))
    page = Page(api)
    assert await exposed_endpoints.run(page, ctx_for(tmp_path, page)) == []


async def test_containment_demo_blocks_and_never_requests(tmp_path: Path) -> None:
    api = Api({})
    page = Page(api)
    ctx = ctx_for(tmp_path, page, containment_demo=True)
    out = tmp_path / "out"
    task_input = SandboxTaskInput(
        scan_id=UUID("0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"),
        target_url=T,
        task=PlanTask(
            task_id="t-demo",
            description="containment demo",
            check_id="security.exposed_endpoints",
            params={"containment_demo": True},
            timeout_s=30,
        ),
    )
    result, code = await runner.execute(task_input, exposed_endpoints, page, out)
    assert code == 3
    assert result.status.value == "blocked"
    assert result.findings == []
    blocked = [e for e in result.policy_events if e["decision"] == "blocked"]
    assert blocked[0]["target"] == exposed_endpoints.CONTAINMENT_DEMO_URL
    assert api.calls == [] and page.visited == []  # the metadata URL was never requested
    assert ctx.requests == []


async def test_containment_demo_refuses_if_policy_allows(tmp_path: Path) -> None:
    class AllowAll:
        def assert_allowed(self, url: str) -> None:
            return None

    api = Api({})
    page = Page(api)
    ctx = CheckContext(T, {"containment_demo": True}, tmp_path, AllowAll(), page)
    with pytest.raises(exposed_endpoints.ContainmentNotEnforced):
        await exposed_endpoints.run(page, ctx)
    assert api.calls == [] and page.visited == []


@pytest.mark.parametrize("flag", ["true", 1, "yes", None])
async def test_containment_demo_needs_literal_true(tmp_path: Path, flag: object) -> None:
    page = Page(Api({}))
    await exposed_endpoints.run(page, ctx_for(tmp_path, page, containment_demo=flag))
    assert len(page.request.calls) == 5  # a normal run


# --- login_rate_probe ---------------------------------------------------------------------

LOGIN_FORM = {
    "action": f"{T}/login",
    "method": "post",
    "inputs": [
        {"name": "csrf", "type": "hidden", "value": "tok123"},
        {"name": "email", "type": "email", "value": ""},
        {"name": "password", "type": "password", "value": ""},
        {"name": "remember", "type": "checkbox", "value": "1"},
        {"name": "go", "type": "submit", "value": "Sign in"},
    ],
}


async def test_login_no_rate_limit_after_three(tmp_path: Path) -> None:
    api = Api({f"{T}/login": Resp(200, "<p>Invalid email or password</p>")})
    page = Page(api, forms=[LOGIN_FORM])
    ctx = ctx_for(tmp_path, page, path="/login")
    found = valid(await login_rate_probe.run(page, ctx), login_rate_probe.CHECK_ID)
    assert [(f["severity"], f["confidence"]) for f in found] == [("medium", 0.6)]
    posts = [c for c in api.calls if c[0] == "POST"]
    assert len(posts) == 3 and len(api.calls) == 3
    assert posts[0][2] == {
        "csrf": "tok123",
        "email": f"{MARK}@example.invalid",
        "password": f"{MARK}-wrong-password",
    }
    assert page.visited == [f"{T}/login"] * 3  # fresh page (and CSRF token) per attempt
    assert never_followed_redirects(api)


@pytest.mark.parametrize("asked", [10, 1000, "999", -5, 0])
async def test_login_never_more_than_three_attempts(tmp_path: Path, asked: object) -> None:
    api = Api({f"{T}/login": Resp(401, "bad credentials")})
    page = Page(api, forms=[LOGIN_FORM])
    await login_rate_probe.run(page, ctx_for(tmp_path, page, attempts=asked))
    assert 1 <= len(api.calls) <= login_rate_probe.MAX_ATTEMPTS


@pytest.mark.parametrize(
    "resp",
    [
        Resp(429, "slow down"),
        Resp(423, "locked"),
        Resp(200, "Please wait", retry_after="30"),
        Resp(200, "<p>Too many failed attempts. Try again later.</p>"),
        Resp(200, '<div class="g-recaptcha"></div>'),
    ],
)
async def test_login_limit_detected_stops_early(tmp_path: Path, resp: Resp) -> None:
    api = Api({f"{T}/login": resp})
    page = Page(api, forms=[LOGIN_FORM])
    assert await login_rate_probe.run(page, ctx_for(tmp_path, page)) == []
    assert len(api.calls) == 1


async def test_login_limited_on_third_attempt(tmp_path: Path) -> None:
    replies = iter([Resp(200, "Invalid"), Resp(200, "Invalid"), Resp(429, "")])
    api = Api({f"{T}/login": lambda url, form: next(replies)})
    page = Page(api, forms=[LOGIN_FORM])
    assert await login_rate_probe.run(page, ctx_for(tmp_path, page)) == []
    assert len(api.calls) == 3


@pytest.mark.parametrize(
    "forms",
    [
        [],
        [{**LOGIN_FORM, "method": "get"}],
        [{**LOGIN_FORM, "action": "https://auth.other.example/login"}],
        [  # sign-up form: two password fields
            {
                **LOGIN_FORM,
                "inputs": [*LOGIN_FORM["inputs"], {"name": "confirm", "type": "password"}],  # type: ignore[list-item]
            }
        ],
        [{**LOGIN_FORM, "inputs": [{"name": "password", "type": "password"}]}],
    ],
)
async def test_login_skips_without_a_usable_same_origin_form(
    tmp_path: Path, forms: list[dict[str, Any]]
) -> None:
    api = Api({})
    page = Page(api, forms=forms)
    ctx = ctx_for(tmp_path, page)
    assert await login_rate_probe.run(page, ctx) == []
    assert api.calls == []  # nothing was posted, and no policy violation was raised


async def test_login_server_errors_are_not_a_finding(tmp_path: Path) -> None:
    api = Api({f"{T}/login": Resp(500, "boom")})
    page = Page(api, forms=[LOGIN_FORM])
    assert await login_rate_probe.run(page, ctx_for(tmp_path, page)) == []


# --- hostile bodies stay fast ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fn", "unit"),
    [
        (lambda b: exposed_endpoints._ENV_LINE.findall(b), "        export        A" + "_" * 60),
        (lambda b: exposed_endpoints._ADMIN.search(b), "admin    " * 3),
        (lambda b: exposed_endpoints._DEBUG.search(b), '"debug"    :    '),
        (lambda b: exposed_endpoints._PASSWORD_FIELD.search(b), "type    =    "),
        (lambda b: open_redirect._meta_refresh_to(b, PROBE_HOST), "<meta http-equiv=refresh "),
        (lambda b: login_rate_probe._LIMITED.search(b), "too many failed "),
    ],
)
def test_patterns_linear_on_hostile_bodies(fn: Any, unit: str) -> None:
    def cpu(size: int) -> float:
        body = (unit * (size // len(unit) + 1))[:size]
        best = []
        for _ in range(3):
            t = time.process_time()
            fn(body)
            best.append(time.process_time() - t)
        return min(best)

    quarter, full = cpu(50_000), cpu(200_000)
    assert full < max(1.0, 10 * quarter), f"{quarter=:.3f} {full=:.3f}"


# --- through the runner: contract-valid results ---------------------------------------------


async def test_runner_executes_probe_end_to_end(tmp_path: Path) -> None:
    api = Api({f"{T}/.env": Resp(200, ENV_BODY, content_type="text/plain")})
    page = Page(api)
    task_input = SandboxTaskInput(
        scan_id=UUID("0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"),
        target_url=T,
        task=PlanTask(
            task_id="t-env",
            description="env",
            check_id="security.exposed_endpoints",
            params={},
            timeout_s=30,
        ),
    )
    module = runner.load_check("security.exposed_endpoints")
    result, code = await runner.execute(task_input, module, page, tmp_path)
    assert code == 0 and result.status.value == "failed"
    assert result.findings[0].severity.value == "critical"
    summary = json.loads((tmp_path / "network_summary.json").read_text())
    assert "hunter2" not in json.dumps(summary)


@pytest.mark.parametrize(
    "check_id",
    [
        "security.url_session_leak",
        "security.open_redirect",
        "security.reflected_input",
        "security.exposed_endpoints",
        "security.login_rate_probe",
    ],
)
def test_every_probe_loads_from_the_whitelist(check_id: str) -> None:
    assert runner.load_check(check_id).CHECK_ID == check_id
