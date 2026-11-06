"""The ``ctx`` object every check receives (brief 5.7).

Check modules live in ``checks/qa/<name>.py`` (Sohaib) and ``checks/security/<name>.py``
(Arslan) and expose::

    CHECK_ID = "security.headers"
    async def run(page, ctx) -> list[dict]:  # Finding dicts without id/scan_id

Always call ``ctx.policy.assert_allowed(url)`` before any navigation or request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit


class PolicyViolation(Exception):
    """Raised when a check tries to reach a URL outside policy. The sandbox exits with code 3."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"blocked {url}: {reason}")
        self.url = url
        self.reason = reason


class Policy(Protocol):
    def assert_allowed(self, url: str) -> None: ...


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str | None, int | None]:
    """(scheme, host, port) with the scheme's default port filled in. Raises ValueError."""
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port or _DEFAULT_PORTS.get(parts.scheme)


def _scheme_switch(url: str, target_url: str) -> bool:
    """Same host, http<->https, both on their scheme's default port (needed by
    ``security.https_redirect``). Any explicit non-default port is still a different origin."""
    scheme, host, port = _origin(url)
    t_scheme, t_host, t_port = _origin(target_url)
    return (
        host is not None
        and host == t_host
        and port == _DEFAULT_PORTS.get(scheme)
        and t_port == _DEFAULT_PORTS.get(t_scheme)
    )


@dataclass
class SameOriginPolicy:
    """Placeholder in-sandbox guard: only the target's own scheme, host and port are allowed.

    Deliberately stricter than the final policy. Owner: Arslan (Policy + audit) replaces or
    extends it with DNS resolution and private/loopback/link-local/metadata IP blocking. The
    real containment boundary is the container's network egress rules, not this check.
    """

    target_url: str
    events: list[dict[str, Any]] = field(default_factory=list)

    def assert_allowed(self, url: str) -> None:
        reason = ""
        try:
            wanted = urlsplit(url)
            if wanted.scheme not in _DEFAULT_PORTS:
                reason = f"scheme {wanted.scheme!r} not allowed"
            elif wanted.username or wanted.password:
                reason = "credentials in URL"
            elif _origin(url) != _origin(self.target_url) and not _scheme_switch(
                url, self.target_url
            ):
                reason = "outside the target origin"
        except ValueError as exc:  # malformed URL or port: never allowed
            reason = f"malformed URL: {exc}"
        decision = "blocked" if reason else "allowed"
        self.events.append(
            {
                "actor": "sandbox",
                "action": "navigate",
                "target": url,
                "decision": decision,
                "reason": reason or "same origin as target",
            }
        )
        if reason:
            raise PolicyViolation(url, reason)


_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


@dataclass
class CheckContext:
    """Runtime context handed to ``run(page, ctx)``."""

    target_url: str
    params: dict[str, Any]
    evidence_dir: Path
    policy: Policy
    page: Any = None
    requests: list[dict[str, Any]] = field(default_factory=list)

    async def screenshot(self, name: str) -> str:
        """Save a full-page screenshot into ``evidence_dir/screenshots`` and return its filename.

        The filename is what goes into a finding's ``evidence`` list.
        """
        if not _SAFE_NAME.fullmatch(name):
            raise ValueError(f"unsafe screenshot name: {name!r}")
        filename = name if name.endswith(".png") else f"{name}.png"
        target = self.evidence_dir / "screenshots" / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        await self.page.screenshot(path=str(target), full_page=True)
        return filename

    def record_request(self, entry: dict[str, Any]) -> None:
        """Add one entry to ``network_summary.json``. Never pass secrets, cookies or tokens."""
        self.requests.append(entry)
