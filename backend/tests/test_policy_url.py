"""URL policy (brief 6.9): static rules, IP classification, DNS answers, redirects.

No network: DNS is a fake resolver and HTTP is ``httpx.MockTransport``.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.interfaces import UrlPolicy
from app.policy.url_policy import (
    PolicyBlocked,
    UrlValidator,
    blocked_ip_reason,
    follow_redirects_safely,
    parse_target,
)

PUBLIC_V4 = "93.184.215.14"
PUBLIC_V6 = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"


class FakeResolver:
    """Answers from a dict; counts lookups. Unknown names raise like getaddrinfo."""

    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    async def resolve(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        if host not in self.answers:
            raise OSError("Name or service not known")
        return self.answers[host]


class SlowResolver:
    async def resolve(self, host: str, port: int) -> list[str]:
        await asyncio.sleep(5)
        return [PUBLIC_V4]


def validator(answers: dict[str, list[str]] | None = None) -> UrlValidator:
    return UrlValidator(FakeResolver(answers or {"demo.example.com": [PUBLIC_V4]}))


async def _blocked(url: str, v: UrlValidator | None = None) -> str:
    with pytest.raises(PolicyBlocked) as info:
        await (v or validator()).assert_allowed(url)
    return info.value.reason


def test_validator_satisfies_url_policy_protocol() -> None:
    policy: UrlPolicy = validator()
    assert policy is not None


# --- allowed -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://demo.example.com",
        "https://demo.example.com/checkout?x=1#frag",
        "http://demo.example.com:8080/",
        "HTTPS://DEMO.EXAMPLE.COM/",
        "https://demo.example.com./",
    ],
)
async def test_assert_allowed_public_host(url: str) -> None:
    v = UrlValidator(
        FakeResolver({"demo.example.com": [PUBLIC_V4], "demo.example.com.": [PUBLIC_V4]})
    )
    await v.assert_allowed(url)


async def test_resolve_allowed_returns_pinnable_addresses() -> None:
    v = validator({"demo.example.com": [PUBLIC_V4, PUBLIC_V6]})
    target = await v.resolve_allowed("https://demo.example.com/x")
    assert (target.scheme, target.host, target.port) == ("https", "demo.example.com", 443)
    assert target.addresses == (PUBLIC_V4, PUBLIC_V6)


async def test_public_ip_literal_skips_dns() -> None:
    resolver = FakeResolver({})
    target = await UrlValidator(resolver).resolve_allowed(f"http://{PUBLIC_V4}/")
    assert target.addresses == (PUBLIC_V4,)
    assert resolver.calls == []


# --- static rules ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "reason_part"),
    [
        ("", "empty"),
        ("ftp://demo.example.com/", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("gopher://demo.example.com/", "scheme"),
        ("data:text/html,hi", "scheme"),
        ("//demo.example.com/", "scheme"),
        ("demo.example.com", "scheme"),
        ("https://user:pw@demo.example.com/", "credentials"),
        ("https://user@demo.example.com/", "credentials"),
        ("https://demo.example.com@169.254.169.254/", "credentials"),
        ("https:///path", "no hostname"),
        ("https://demo.example.com:99999/", "malformed"),
        ("https://demo.example.com:abc/", "malformed"),
        ("https://demo.example.com\\@evil.com/", "backslash"),
        ("https://demo.example.com/\r\nHost: x", "control"),
        (" https://demo.example.com/", "control"),
        ("https://" + "a" * 2100 + ".com/", "too long"),
        ("http://localhost/", "internal hostname"),
        ("http://LOCALHOST:8000/", "internal hostname"),
        ("http://api.localhost/", "internal hostname"),
        ("http://metadata.google.internal/computeMetadata/v1/", "internal hostname"),
        ("http://printer.local/", "internal hostname"),
        ("http://db.corp.internal/", "internal hostname"),
        ("http://router.home.arpa/", "internal hostname"),
        ("http://intranet/", "single-label"),
        ("http://postgres:5432/", "single-label"),
    ],
)
async def test_static_rules_block(url: str, reason_part: str) -> None:
    assert reason_part in await _blocked(url)


def test_parse_target_default_ports() -> None:
    assert parse_target("http://a.example.com") == ("http", "a.example.com", 80)
    assert parse_target("https://a.example.com") == ("https", "a.example.com", 443)


# --- IP classification ---------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.255.255.254",
        "0.0.0.0",  # noqa: S104 - a blocked target, not a bind address
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.169.254",
        "169.254.1.1",
        "192.0.0.8",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fe80::1%eth0",
        "fc00::1",
        "fd12:3456::1",
        "fd00:ec2::254",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "2002:7f00:0001::",
        "2002:a9fe:a9fe::",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::7f00:1",
        "2001:0:4136:e378:8000:63bf:80ff:fffe",
    ],
)
def test_blocked_ip_reason_blocks_non_public(ip: str) -> None:
    assert blocked_ip_reason(ip) is not None


@pytest.mark.parametrize(
    "ip", [PUBLIC_V4, "8.8.8.8", "1.1.1.1", PUBLIC_V6, "::ffff:8.8.8.8", "64:ff9b::808:808"]
)
def test_blocked_ip_reason_allows_public(ip: str) -> None:
    assert blocked_ip_reason(ip) is None


def test_metadata_reason_is_explicit() -> None:
    assert blocked_ip_reason("169.254.169.254") == "cloud metadata address"


def test_blocked_ip_reason_rejects_garbage() -> None:
    assert blocked_ip_reason("not-an-ip") is not None


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.0.0.1:6379/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://192.168.0.1/",
        "http://0.0.0.0/",
        # inet_aton shorthand that resolvers turn into loopback / metadata
        "http://127.1/",
        "http://0x7f.0.0.1/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://017700000001/",
        "http://0177.0.0.1/",
        "http://2852039166/",
        "http://0/",
    ],
)
async def test_ip_literal_targets_blocked_without_dns(url: str) -> None:
    resolver = FakeResolver({})
    reason = await _blocked(url, UrlValidator(resolver))
    assert "address" in reason
    assert resolver.calls == []


# --- DNS answers -------------------------------------------------------------------


@pytest.mark.parametrize(
    "answer",
    [
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["10.0.0.7"],
        ["::1"],
        ["::ffff:192.168.1.1"],
        # rebinding-style mixed answer: one public, one private -> blocked
        [PUBLIC_V4, "127.0.0.1"],
        ["192.168.1.1", PUBLIC_V4],
    ],
)
async def test_hostname_resolving_to_private_is_blocked(answer: list[str]) -> None:
    v = validator({"rebind.example.com": answer})
    assert "address" in await _blocked("https://rebind.example.com/", v)


async def test_unresolvable_hostname_blocked() -> None:
    assert "does not resolve" in await _blocked("https://nope.example.com/")


async def test_empty_dns_answer_blocked() -> None:
    v = validator({"empty.example.com": []})
    assert "does not resolve" in await _blocked("https://empty.example.com/", v)


async def test_dns_timeout_blocked() -> None:
    v = UrlValidator(SlowResolver(), dns_timeout_s=0.05)
    assert "timed out" in await _blocked("https://slow.example.com/", v)


async def test_each_call_resolves_again() -> None:
    """No caching: a later rebinding to a private address is caught on the next check."""
    resolver = FakeResolver({"flip.example.com": [PUBLIC_V4]})
    v = UrlValidator(resolver)
    await v.assert_allowed("https://flip.example.com/")
    resolver.answers["flip.example.com"] = ["127.0.0.1"]
    with pytest.raises(PolicyBlocked):
        await v.assert_allowed("https://flip.example.com/")
    assert resolver.calls == ["flip.example.com", "flip.example.com"]


# --- redirects ---------------------------------------------------------------------


def _client(routes: dict[str, httpx.Response]) -> tuple[httpx.AsyncClient, list[str]]:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(f"{request.method} {request.url}")
        return routes.get(str(request.url), httpx.Response(200))

    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=5), requested


def _redirect(location: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"location": location})


async def test_redirects_followed_and_each_hop_validated() -> None:
    v = validator({"demo.example.com": [PUBLIC_V4], "www.example.com": [PUBLIC_V4]})
    client, requested = _client(
        {
            "http://demo.example.com/": _redirect("https://demo.example.com/", 301),
            "https://demo.example.com/": _redirect("https://www.example.com/home"),
        }
    )
    hops: list[tuple[str, str]] = []

    async def on_hop(src: str, dst: str) -> None:
        hops.append((src, dst))

    async with client:
        target, chain = await follow_redirects_safely(
            "http://demo.example.com/", v, client, on_hop=on_hop
        )
    assert target.url == "https://www.example.com/home"
    assert chain == [
        "http://demo.example.com/",
        "https://demo.example.com/",
        "https://www.example.com/home",
    ]
    assert len(hops) == 2
    assert requested[-1] == "HEAD https://www.example.com/home"


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8000/admin",
        "http://127.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "http://internal.example.com/",
    ],
)
async def test_redirect_to_forbidden_target_blocked_before_request(location: str) -> None:
    v = validator({"demo.example.com": [PUBLIC_V4], "internal.example.com": ["10.0.0.9"]})
    client, requested = _client({"https://demo.example.com/go": _redirect(location)})
    async with client:
        with pytest.raises(PolicyBlocked):
            await follow_redirects_safely("https://demo.example.com/go", v, client)
    # The forbidden hop was never requested.
    assert requested == ["HEAD https://demo.example.com/go"]


async def test_relative_redirect_resolved_against_current_url() -> None:
    v = validator()
    client, _ = _client({"https://demo.example.com/a": _redirect("/b")})
    async with client:
        target, _ = await follow_redirects_safely("https://demo.example.com/a", v, client)
    assert target.url == "https://demo.example.com/b"


async def test_redirect_loop_capped() -> None:
    v = validator()
    client, requested = _client(
        {
            "https://demo.example.com/a": _redirect("/b"),
            "https://demo.example.com/b": _redirect("/a"),
        }
    )
    async with client:
        with pytest.raises(PolicyBlocked, match="redirects"):
            await follow_redirects_safely("https://demo.example.com/a", v, client, max_redirects=3)
    assert len(requested) == 4


async def test_head_not_allowed_falls_back_to_get() -> None:
    v = validator()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(405 if request.method == "HEAD" else 200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5)
    async with client:
        target, chain = await follow_redirects_safely("https://demo.example.com/", v, client)
    assert chain == ["https://demo.example.com/"]


async def test_transport_error_is_blocked_not_raised_raw() -> None:
    v = validator()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5)
    async with client:
        with pytest.raises(PolicyBlocked, match="request failed"):
            await follow_redirects_safely("https://demo.example.com/", v, client)
