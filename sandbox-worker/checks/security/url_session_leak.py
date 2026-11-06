"""security.url_session_leak: session ids or auth tokens carried in URLs (brief 3, 6.6).

One page load. The final page URL (after redirects) and every link on the page are checked
for session/token parameters, including ``;jsessionid=`` path parameters. Values are never
copied into evidence: only the parameter name and the value's length.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    finding,
    navigate,
    page_links,
    path_of,
    target_path_url,
)

CHECK_ID = "security.url_session_leak"

MIN_VALUE_LEN = 8
"""Shorter values (``sid=1``, ``token=abc``) are too short to be a usable secret."""
MAX_FINDINGS = 5

_SESSION = re.compile(
    r"(?i)^(?:jsessionid|phpsessid|aspsessionid\w{0,20}|cfid|cftoken|sid|sess|session|"
    r"session[-_]?(?:id|key|token)|sessid)$"
)
_TOKEN = re.compile(
    r"(?i)^(?:access[-_]?token|auth[-_]?token|id[-_]?token|refresh[-_]?token|bearer|jwt|"
    r"api[-_]?key|apikey|auth)$"
)
_PATH_PARAM = re.compile(r"(?i);(jsessionid|phpsessid|sid|sessionid)=([^;/?#]{1,512})")


def leaked_params(url: str) -> list[tuple[str, str, int]]:
    """``(name, kind, value_length)`` for each secret-looking parameter in ``url``.

    ``kind`` is ``"session"`` or ``"token"``.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    if parts.scheme not in ("http", "https"):
        return []
    out: list[tuple[str, str, int]] = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if len(value) < MIN_VALUE_LEN:
            continue
        if _SESSION.match(name):
            out.append((name, "session", len(value)))
        elif _TOKEN.match(name):
            out.append((name, "token", len(value)))
    for match in _PATH_PARAM.finditer(parts.path):
        if len(match.group(2)) >= MIN_VALUE_LEN:
            out.append((match.group(1), "session", len(match.group(2))))
    return out


def masked(url: str) -> str:
    """``url`` with every query/path parameter value replaced by ``*``: safe for evidence."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "(unparseable URL)"
    path = _PATH_PARAM.sub(lambda m: f";{m.group(1)}=*", parts.path)
    query = "&".join(f"{k}=*" for k, _ in parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Load the page, then check its final URL and its links for secrets in the URL."""
    start = target_path_url(ctx)
    await navigate(page, ctx, start)
    final_url = str(getattr(page, "url", "") or start)
    candidates = [("page_url", final_url)] + [("link", h) for h in await page_links(page)]

    found: dict[str, dict[str, Any]] = {}
    for where, url in candidates:
        for name, kind, length in leaked_params(url):
            key = name.lower()
            if key in found or len(found) >= MAX_FINDINGS:
                continue
            shown = masked(url)
            ctx.record_request(
                {"url": shown, "leaked_param": name, "value_length": length, "found_in": where}
            )
            seen = "the address bar after loading" if where == "page_url" else "a link on"
            found[key] = finding(
                check_id=CHECK_ID,
                title=f"{'Session id' if kind == 'session' else 'Auth token'} exposed in URL "
                f"({name})",
                severity="high",
                url=shown,
                evidence=[NETWORK_SUMMARY],
                reproduction=[
                    f"Open {path_of(start)}",
                    f"Observe parameter {name!r} ({length} characters) in {seen} the page",
                ],
                impact="URLs end up in browser history, server and proxy logs, analytics and "
                "the Referer header sent to other sites, so anyone who sees the URL can take "
                "over the session.",
                recommended_fix="Keep session ids and tokens in Secure, HttpOnly cookies or "
                "an Authorization header, never in URLs; disable URL session rewriting "
                "(e.g. tracking-mode COOKIE, session.use_trans_sid=0).",
                confidence=0.9 if kind == "session" else 0.8,
            )
    return list(found.values())
