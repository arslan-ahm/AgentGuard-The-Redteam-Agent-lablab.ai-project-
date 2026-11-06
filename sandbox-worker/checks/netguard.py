"""In-browser network guard (brief 6.4, 12). Owner: Arslan.

Installed by ``runner.py`` on every page with ``page.route("**/*", guard.handle)``. Every
request the browser makes passes through :meth:`NetworkGuard.handle`, which:

1. checks the URL **before** any byte leaves: http/https only, no internal hostnames, no
   private/loopback/link-local/metadata IPs (literal or after DNS), and for top-level
   navigations the target origin only (``SameOriginPolicy``);
2. fetches it with ``max_redirects=0`` and **follows redirects itself**, checking every hop
   the same way before requesting it. Chromium follows navigation redirects without
   calling the route handler again (measured with Playwright 1.64), so handing a 3xx back
   to the browser would let ``302 -> http://169.254.169.254/`` through;
3. hands the browser only the final response, or aborts.

Blocked top-level navigations are recorded as ``navigate``/``blocked`` and make the whole task
``blocked`` (exit 3, sandbox destroyed). Blocked subresources are aborted and recorded as
``subresource_blocked``: the request never left, so the task carries on.

This is defence in depth inside the container. The outer boundary is the network egress
firewall and the launcher's ``--add-host`` pinning.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import sys
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from checks.context import SameOriginPolicy

MAX_REDIRECTS = 5
MAX_REMEMBERED = 300  # responses whose raw headers are kept for checks (most recent)
FETCH_TIMEOUT_MS = 20_000
DNS_TIMEOUT_S = 3.0
SUBRESOURCE_BLOCKED = "subresource_blocked"

_PASS_THROUGH_SCHEMES = frozenset({"data", "blob", "about"})
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "host.docker.internal",
        "gateway.docker.internal",
    }
)
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_METADATA = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})


def blocked_ip_reason(address: str) -> str | None:
    """Why an IP may not be contacted, or None if it is publicly routable.

    Mirrors ``backend/app/policy/url_policy.py`` (the sandbox image does not ship the backend).
    """
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0].strip("[]"))
    except ValueError:
        return f"not an IP address: {address!r}"
    if isinstance(ip, ipaddress.IPv6Address):
        inner: ipaddress.IPv4Address | None = ip.ipv4_mapped or ip.sixtofour
        if inner is None and ip.teredo is not None:
            inner = ip.teredo[1]
        if inner is None and ip in _NAT64:
            inner = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if inner is not None:
            reason = blocked_ip_reason(str(inner))
            return f"embeds {inner}: {reason}" if reason else None
    if str(ip) in _METADATA:
        return "cloud metadata address"
    if not ip.is_global or ip.is_multicast:
        return f"non-public address {ip}"
    return None


def _ipv4_shorthand(host: str) -> str | None:
    """``127.1``, ``0x7f000001``, ``2130706433``, ``0177.0.0.1`` as a dotted quad, else None."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(not p for p in parts):
        return None
    values: list[int] = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                values.append(int(part, 16))
            elif part.startswith("0") and len(part) > 1:
                values.append(int(part, 8))
            else:
                values.append(int(part, 10))
        except ValueError:
            return None
    *head, last = values
    if any(v > 0xFF for v in head) or last >= 256 ** (4 - len(head)):
        return None
    number = 0
    for v in head:
        number = (number << 8) | v
    number = (number << (8 * (4 - len(head)))) | last
    return str(ipaddress.IPv4Address(number))


def ip_literal(host: str) -> str | None:
    """The IP a hostname literally denotes (incl. shorthand), or None for a real name."""
    try:
        return str(ipaddress.ip_address(host.strip("[]").split("%", 1)[0]))
    except ValueError:
        return _ipv4_shorthand(host)


def static_reason(
    url: str, ip_reason: Callable[[str], str | None] = blocked_ip_reason
) -> tuple[str | None, str | None]:
    """``(reason, host)``: reason is set if the URL is blocked without DNS. Never raises."""
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises on a bad port
    except ValueError as exc:
        return f"malformed URL: {exc}", None
    if parts.scheme not in ("http", "https"):
        return f"scheme {parts.scheme!r} not allowed", None
    if parts.username or parts.password:
        return "credentials in URL", None
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return "no hostname", None
    if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_SUFFIXES):
        return f"internal hostname {host!r}", host
    literal = ip_literal(host)
    if literal is not None:
        return ip_reason(literal), host
    if "." not in host:
        return f"single-label hostname {host!r}", host
    return None, host


class Resolver(Protocol):
    async def resolve(self, host: str) -> list[str]: ...


class SystemResolver:
    """``getaddrinfo`` with a timeout."""

    async def resolve(self, host: str) -> list[str]:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=DNS_TIMEOUT_S
        )
        return sorted({str(info[4][0]) for info in infos})


IpReason = Callable[[str], str | None]


class NetworkGuard:
    """``page.route`` handler that vets every request and every redirect hop."""

    def __init__(
        self,
        policy: SameOriginPolicy,
        resolver: Resolver | None = None,
        ip_reason: IpReason = blocked_ip_reason,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        self.policy = policy
        self._resolver = resolver or SystemResolver()
        self._ip_reason = ip_reason
        self._max_redirects = max_redirects
        self._dns_cache: dict[str, str | None] = {}
        self._seen_headers: OrderedDict[str, list[dict[str, str]]] = OrderedDict()

    def headers_for(self, url: str) -> list[dict[str, str]] | None:
        """Raw response headers the guard received for ``url`` (latest), incl. ``Set-Cookie``.

        Playwright strips ``Set-Cookie`` from responses delivered with ``route.fulfill``, so
        checks that need it (``security.cookies``) read it here via ``ctx.seen_headers``.
        """
        headers = self._seen_headers.get(url)
        return list(headers) if headers is not None else None

    def _remember(self, url: str, response: Any) -> None:
        self._seen_headers[url] = [
            {"name": str(h["name"]), "value": str(h["value"])} for h in response.headers_array
        ]
        self._seen_headers.move_to_end(url)
        while len(self._seen_headers) > MAX_REMEMBERED:
            self._seen_headers.popitem(last=False)

    async def reason_for(self, url: str, *, navigation: bool) -> str | None:
        """Why the browser may not request ``url`` (None = allowed)."""
        reason, host = static_reason(url, self._ip_reason)
        if reason is None and host is not None and ip_literal(host) is None:
            reason = await self._dns_reason(host)
        if reason is None and navigation:
            reason = self.policy.reason_for(url) or None
        return reason

    async def _dns_reason(self, host: str) -> str | None:
        """Resolve once per host per task; any non-public answer blocks the host."""
        if host not in self._dns_cache:
            try:
                addresses = await self._resolver.resolve(host)
            except (OSError, TimeoutError):
                addresses = []
            if not addresses:
                self._dns_cache[host] = "hostname does not resolve"
            else:
                reasons = [r for r in (self._ip_reason(a) for a in addresses) if r]
                self._dns_cache[host] = f"{host} resolves to {reasons[0]}" if reasons else None
        return self._dns_cache[host]

    async def handle(self, route: Any) -> None:
        """Route handler: never raises, always ends in fulfill, continue or abort."""
        try:
            await self._handle(route)
        except Exception as exc:  # a guard bug must fail closed, never let a request through
            print(f"netguard: {type(exc).__name__}: {exc}"[:500], file=sys.stderr)
            await _quiet(route.abort("failed"))

    async def _handle(self, route: Any) -> None:
        request = route.request
        url: str = request.url
        if urlsplit(url).scheme in _PASS_THROUGH_SCHEMES:
            await route.continue_()  # in-memory content, never touches the network
            return
        navigation = _is_top_level_navigation(request)
        method: str = request.method
        body: bytes | None = request.post_data_buffer
        current = url
        for hop in range(self._max_redirects + 1):
            reason = await self.reason_for(current, navigation=navigation)
            if reason is not None:
                self._record_block(current, reason, navigation=navigation, hop=hop, origin=url)
                await route.abort("blockedbyclient")
                return
            try:
                if hop == 0:
                    response = await route.fetch(max_redirects=0, timeout=FETCH_TIMEOUT_MS)
                else:
                    response = await route.fetch(
                        url=current,
                        method=method,
                        post_data=body,
                        max_redirects=0,
                        timeout=FETCH_TIMEOUT_MS,
                    )
            except Exception:  # unreachable host, TLS error, timeout: like a network failure
                await route.abort("failed")
                return
            self._remember(current, response)
            location = response.headers.get("location")
            if not (300 <= response.status < 400 and location):
                if navigation and hop > 0 and method == "GET":
                    # Every hop is vetted. Point the browser straight at the vetted final URL
                    # so page.url and response headers are the real ones (Chromium makes this
                    # one GET itself; a repeat of an idempotent request).
                    await route.fulfill(status=302, headers={"location": current})
                else:
                    await route.fulfill(response=response)
                return
            if response.status in (301, 302, 303) and method not in ("GET", "HEAD"):
                method, body = "GET", None  # what browsers do; 307/308 keep method and body
            current = urljoin(current, location)
        await route.abort("failed")  # redirect loop / too many hops

    def _record_block(
        self, url: str, reason: str, *, navigation: bool, hop: int, origin: str
    ) -> None:
        action = "navigate" if navigation else SUBRESOURCE_BLOCKED
        detail = reason if hop == 0 else f"redirect hop {hop} from {origin}: {reason}"
        self.policy.record(action, url, detail, blocked=True)


def _is_top_level_navigation(request: Any) -> bool:
    try:
        return bool(request.is_navigation_request()) and request.frame.parent_frame is None
    except Exception:  # service-worker requests have no frame: treat as subresource
        return False


async def _quiet(awaitable: Awaitable[Any]) -> None:
    try:
        await awaitable
    except Exception:  # noqa: S110 - the route may already be handled or the page closed
        pass


async def guard_websocket(policy: SameOriginPolicy, ws_route: Any) -> None:
    """``page.route_web_socket`` handler: only the target's own host may be reached."""
    http_url = ws_route.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
    reason = static_reason(http_url)[0] or policy.reason_for(http_url)
    if reason:
        policy.record(SUBRESOURCE_BLOCKED, ws_route.url, f"websocket: {reason}", blocked=True)
        await _quiet(ws_route.close(code=1008, reason="blocked by policy"))
        return
    ws_route.connect_to_server()
