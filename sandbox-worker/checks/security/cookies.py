"""security.cookies: Secure / HttpOnly / SameSite flags on cookies the site sets (brief 3, 6.6).

Parses the raw ``Set-Cookie`` headers of one page load, so the result reflects exactly what
the server sent. Cookie **values are never recorded**, only names and flags.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    finding,
    navigate,
    screenshot_or_none,
    target_path_url,
)

CHECK_ID = "security.cookies"

_SESSIONISH = re.compile(
    r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf|phpsessid|jsessionid|connect\.sid)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SetCookie:
    """Name and flags of one ``Set-Cookie`` header. The value is deliberately not kept."""

    name: str
    secure: bool
    http_only: bool
    same_site: str | None  # "strict" | "lax" | "none" | None (absent)

    @property
    def session_like(self) -> bool:
        return bool(_SESSIONISH.search(self.name)) or self.name.startswith(("__Host-", "__Secure-"))


def parse_set_cookie(header: str) -> SetCookie | None:
    """Parse one Set-Cookie header value. Returns None if it has no cookie name."""
    first, *attrs = header.split(";")
    if "=" not in first:
        return None
    name = first.split("=", 1)[0].strip()
    if not name:
        return None
    flags: dict[str, str] = {}
    for attr in attrs:
        key, _, value = attr.strip().partition("=")
        flags[key.strip().lower()] = value.strip().lower()
    return SetCookie(
        name=name[:100],
        secure="secure" in flags,
        http_only="httponly" in flags,
        same_site=flags.get("samesite") or None,
    )


def analyse(url: str, cookies: list[SetCookie], evidence: list[str]) -> list[dict[str, Any]]:
    """One finding per cookie with missing/weak flags. Pure function."""
    https = url.lower().startswith("https://")
    found: list[dict[str, Any]] = []
    for cookie in cookies:
        problems: list[str] = []
        if https and not cookie.secure:
            problems.append("Secure is missing")
        if cookie.session_like and not cookie.http_only:
            problems.append("HttpOnly is missing")
        if cookie.same_site is None:
            problems.append("SameSite is not set")
        elif cookie.same_site == "none" and not cookie.secure:
            problems.append("SameSite=None without Secure (browsers reject or downgrade it)")
        if not problems:
            continue
        serious = cookie.session_like and (
            "Secure is missing" in problems or "HttpOnly is missing" in problems
        )
        found.append(
            finding(
                check_id=CHECK_ID,
                title=f"Cookie '{cookie.name}' has weak flags: {', '.join(problems)}",
                severity="medium" if serious or "Secure is missing" in problems else "low",
                url=url,
                evidence=evidence,
                reproduction=[
                    f"Request {url}",
                    f"Inspect the Set-Cookie header for '{cookie.name}'",
                    f"Observe: {'; '.join(problems)}",
                ],
                impact=(
                    "A session cookie readable by scripts or sent over plain HTTP can be stolen "
                    "through XSS or network interception."
                    if cookie.session_like
                    else "Weak cookie flags widen the exposure of whatever the cookie holds."
                ),
                recommended_fix=(
                    f"Set '{cookie.name}' with Secure; HttpOnly; SameSite=Lax "
                    "(or Strict), and the __Host- prefix for session cookies."
                ),
                confidence=0.95 if cookie.session_like else 0.8,
            )
        )
    return found


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Load the page once and check the flags of every cookie it sets."""
    url = target_path_url(ctx)
    response = await navigate(page, ctx, url)
    if response is None:
        return []
    raw = [h["value"] for h in await response.headers_array() if h["name"].lower() == "set-cookie"]
    cookies = [c for c in (parse_set_cookie(v) for v in raw) if c is not None]
    ctx.record_request(
        {
            "url": url,
            "set_cookie": [
                {
                    "name": c.name,
                    "secure": c.secure,
                    "http_only": c.http_only,
                    "same_site": c.same_site,
                }
                for c in cookies
            ],
        }
    )
    if not cookies:
        return []
    evidence = [*await screenshot_or_none(ctx, "cookies_page"), NETWORK_SUMMARY]
    return analyse(url, cookies, evidence)
