"""Target URL validation (brief 6.9, 12, 13). Owner: Arslan, reviewer: Sarah.

Rules, applied to every scan target and to every redirect hop:

- scheme is ``http`` or ``https``; a hostname is present; the port is valid
- no credentials in the URL (``user:pass@host``)
- the hostname is not a known-internal name (``localhost``, ``*.internal``, metadata names...)
- the hostname resolves, and **every** resolved address is publicly routable. Loopback,
  RFC1918, CGNAT, link-local (incl. ``169.254.169.254``), multicast, reserved, unspecified,
  ULA and IPv4 addresses smuggled inside IPv6 (mapped, 6to4, Teredo, NAT64) are all blocked.

DNS rebinding: a name can resolve to a public address now and a private one a second later.
The validator returns the addresses it approved (:class:`ResolvedTarget`) so the sandbox
launcher can pin them (``docker run --add-host host:ip``), and the container's egress rules
block private ranges regardless. This module is one layer, not the whole boundary.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import httpx

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ALLOWED_SCHEMES = frozenset({"http", "https"})
MAX_URL_LENGTH = 2048
DEFAULT_DNS_TIMEOUT_S = 3.0
DEFAULT_MAX_REDIRECTS = 5

# Names that must never be targets even before DNS is consulted.
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
    }
)
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa")

# Explicitly listed on top of ``is_global`` so intent survives Python version changes.
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "fd00:ec2::254/128",
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class PolicyBlocked(Exception):
    """The URL is not allowed. ``reason`` is safe to show to users and to write to audit."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"blocked: {reason}")
        self.url = url
        self.reason = reason


class Resolver(Protocol):
    """Resolves a hostname to IP address strings. Swapped for a fake in tests."""

    async def resolve(self, host: str, port: int) -> list[str]: ...


class SystemResolver:
    """``getaddrinfo`` on the event loop's executor."""

    async def resolve(self, host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True)
class ResolvedTarget:
    """A URL that passed policy, with the addresses that were checked (pin these)."""

    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 address carried inside an IPv6 one (mapped, 6to4, Teredo, NAT64), if any."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def blocked_ip_reason(address: str | IPAddress) -> str | None:
    """Why ``address`` may not be contacted, or ``None`` if it is publicly routable."""
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return f"not an IP address: {address!r}"
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_ipv4(ip)
        if inner is not None:
            inner_reason = blocked_ip_reason(inner)
            return f"embeds {inner}: {inner_reason}" if inner_reason else None
    if str(ip) in ("169.254.169.254", "fd00:ec2::254"):
        return "cloud metadata address"
    for net in _BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            return f"non-public address {ip} ({net})"
    if not ip.is_global:
        return f"non-public address {ip}"
    return None


def _blocked_hostname_reason(host: str) -> str | None:
    name = host.rstrip(".").lower()
    if name in _BLOCKED_HOSTNAMES or name.endswith(_BLOCKED_SUFFIXES):
        return f"internal hostname {name!r}"
    if "." not in name and ":" not in name and _inet_aton_legacy(name) is None:
        return f"single-label hostname {name!r}"  # resolves via search domains to LAN hosts
    return None


def parse_target(url: str) -> tuple[str, str, int]:
    """Static checks only (no DNS). Returns ``(scheme, host, port)`` or raises PolicyBlocked."""
    if not isinstance(url, str) or not url:
        raise PolicyBlocked(str(url), "empty URL")
    if len(url) > MAX_URL_LENGTH:
        raise PolicyBlocked(url[:100], "URL too long")
    if any(ch in url for ch in ("\\", "\r", "\n", "\t", "\x00")) or url != url.strip():
        raise PolicyBlocked(url, "URL contains control characters or backslashes")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise PolicyBlocked(url, f"malformed URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise PolicyBlocked(url, f"scheme {parts.scheme!r} not allowed")
    if "@" in parts.netloc:
        raise PolicyBlocked(url, "credentials in URL")
    host = parts.hostname
    if not host:
        raise PolicyBlocked(url, "no hostname")
    reason = _blocked_hostname_reason(host)
    if reason:
        raise PolicyBlocked(url, reason)
    return scheme, host, port or (443 if scheme == "https" else 80)


class UrlValidator:
    """Implements ``app.interfaces.UrlPolicy``. Use :meth:`resolve_allowed` to get pinnable IPs."""

    def __init__(
        self,
        resolver: Resolver | None = None,
        dns_timeout_s: float = DEFAULT_DNS_TIMEOUT_S,
    ) -> None:
        self._resolver = resolver or SystemResolver()
        self._dns_timeout_s = dns_timeout_s

    async def resolve_allowed(self, url: str) -> ResolvedTarget:
        """Validate ``url`` fully (static + DNS) and return the approved addresses."""
        scheme, host, port = parse_target(url)
        literal = _ip_literal(host)
        if literal is not None:
            addresses = [literal]
        else:
            try:
                addresses = await asyncio.wait_for(
                    self._resolver.resolve(host, port), timeout=self._dns_timeout_s
                )
            except TimeoutError as exc:
                raise PolicyBlocked(url, "DNS lookup timed out") from exc
            except OSError as exc:
                raise PolicyBlocked(url, "hostname does not resolve") from exc
        if not addresses:
            raise PolicyBlocked(url, "hostname does not resolve")
        # Every address must be public: a mixed answer is how DNS rebinding sneaks in.
        for address in addresses:
            reason = blocked_ip_reason(address)
            if reason:
                raise PolicyBlocked(url, reason)
        return ResolvedTarget(url, scheme, host.lower(), port, tuple(addresses))

    async def assert_allowed(self, url: str) -> None:
        """Raise :class:`PolicyBlocked` if ``url`` is not allowed."""
        await self.resolve_allowed(url)


def _inet_aton_legacy(host: str) -> ipaddress.IPv4Address | None:
    """Parse BSD ``inet_aton`` shorthand the way resolvers do: ``127.1``, ``0x7f.0.0.1``,
    ``017700000001``, ``2130706433``. Done here so the result never depends on the platform."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(not p for p in parts):
        return None
    try:
        values = [
            (
                int(p, 16)
                if p.lower().startswith("0x")
                else int(p, 8 if p.startswith("0") and len(p) > 1 else 10)
            )
            for p in parts
        ]
    except ValueError:
        return None
    *head, last = values
    if any(v > 0xFF for v in head) or last >= 256 ** (4 - len(head)):
        return None
    number = 0
    for v in head:
        number = (number << 8) | v
    number = (number << (8 * (4 - len(head)))) | last
    return ipaddress.IPv4Address(number)


def _ip_literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        legacy = _inet_aton_legacy(host)
        return str(legacy) if legacy is not None else None


RedirectHook = Callable[[str, str], Awaitable[None]]


async def follow_redirects_safely(
    url: str,
    validator: UrlValidator,
    client: httpx.AsyncClient,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    on_hop: RedirectHook | None = None,
) -> tuple[ResolvedTarget, Sequence[str]]:
    """Follow redirects by hand, validating every hop **before** requesting it.

    ``client`` must be created with ``follow_redirects=False`` and a timeout. Returns the final
    target and the chain of URLs visited. ``on_hop(from_url, to_url)`` is awaited per redirect
    (e.g. to write an audit event). Raises :class:`PolicyBlocked` on the first bad hop.
    """
    chain: list[str] = []
    current = url
    for _ in range(max_redirects + 1):
        target = await validator.resolve_allowed(current)
        chain.append(current)
        try:
            response = await client.head(current, follow_redirects=False)
            if response.status_code in (405, 501):  # HEAD not supported: GET without body
                response = await client.get(current, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise PolicyBlocked(current, f"request failed: {type(exc).__name__}") from exc
        location = response.headers.get("location")
        if not response.is_redirect or not location:
            return target, chain
        nxt = urljoin(current, location)
        if on_hop is not None:
            await on_hop(current, nxt)
        current = nxt
    raise PolicyBlocked(current, f"more than {max_redirects} redirects")
