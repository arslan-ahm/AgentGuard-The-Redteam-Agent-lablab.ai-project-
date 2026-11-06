"""security.error_leak: error pages leaking stack traces, SQL errors, paths, versions (brief 3).

Three harmless GETs on the target origin: the page itself, a clearly marked missing page
(``/agentguard-probe-<marker>``) and the page with a marked non-numeric ``id`` value. No
quotes, no injection payloads, nothing that changes data.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from checks.context import CheckContext
from checks.security._common import (
    MAX_BODY_CHARS,
    NETWORK_SUMMARY,
    finding,
    navigate,
    path_of,
    screenshot_or_none,
    snippet,
    target_path_url,
    with_path,
)

CHECK_ID = "security.error_leak"


@dataclass(frozen=True)
class LeakKind:
    key: str
    title: str
    severity: str
    impact: str
    fix: str
    patterns: tuple[re.Pattern[str], ...]
    errors_only: bool = False
    """Only look for this kind in error responses (status >= 400): a normal page may
    legitimately mention a path or a server version in its content."""


def _p(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns)


# Ordered by severity: the first kind that matches a body wins for that body.
# Bodies are attacker-controlled: every repetition is bounded and whitespace runs never cross
# lines, so matching stays fast (tests/test_security_checks.py times hostile bodies).
LEAK_KINDS: tuple[LeakKind, ...] = (
    LeakKind(
        "stack_trace",
        "Error response leaks an internal stack trace",
        "high",
        "Attackers learn internal file paths, libraries and code structure, which makes "
        "targeted attacks much easier.",
        "Return a generic error page; log details server-side only; disable debug mode "
        "(DEBUG=False, FLASK_DEBUG=0, NODE_ENV=production) in production.",
        _p(
            r"Traceback \(most recent call last\)",
            r"^[ \t]+File \"[^\"\n]{1,300}\", line \d+, in ",
            r"Werkzeug Debugger",
            r"Exception in thread \"",
            r"^[ \t]+at [\w$.]+\([\w$]+\.java:\d+\)",
            r"^[ \t]+at [^\n]{1,200} \((?:/|[A-Za-z]:\\|node:|file:)[^)\n]{1,300}:\d+:\d+\)",
            r"Server Error in '[^']*' Application",
            r"(?:Fatal error|Parse error|Warning)</b>?:[^\n]{1,500}? on line <b>?\d+",
            r"Stack trace:[ \t]*\n?[ \t]*#0 ",
            r"You're seeing this error because you have <code>DEBUG = True</code>",
            r"ActionController::RoutingError|ActiveRecord::\w+Error",
            r"System\.\w+Exception: ",
        ),
    ),
    LeakKind(
        "sql_error",
        "Error response leaks a database error",
        "high",
        "Database errors reveal the schema and query structure, the first step toward SQL "
        "injection.",
        "Catch database exceptions, return a generic error, and use parameterized queries.",
        _p(
            r"You have an error in your SQL syntax",
            r"SQLSTATE\[\w+\]",
            r"\bORA-\d{5}\b",
            r"psycopg2?\.errors\.\w+",
            r"sqlite3\.(?:Operational|Integrity|Programming)Error",
            r"\bPG::\w+Error",
            r"Unclosed quotation mark after the character string",
            r"SequelizeDatabaseError|PrismaClient\w*Error",
            r"\bpg_query\(\): |\bmysqli?_\w+\(\): ",
        ),
    ),
    LeakKind(
        "internal_path",
        "Error response leaks internal file paths",
        "medium",
        "Server paths reveal the deployment layout and usernames.",
        "Return generic error messages and keep file paths out of responses.",
        _p(
            r"(?:/home/[\w.-]{1,64}|/var/www|/usr/(?:local/)?lib/python\d|/srv/[\w.-]{1,64}"
            r"|/opt/[\w.-]{1,64})/[\w./-]{1,200}\.(?:py|js|ts|php|rb|java)\b",
            r"[A-Za-z]:\\(?:inetpub|Users|Program Files)\\[^\s<\"]{1,200}",
            r"site-packages/[\w./-]{1,200}\.py",
            r"node_modules/[\w@./-]{1,200}\.js",
        ),
        errors_only=True,
    ),
    LeakKind(
        "version",
        "Error page discloses server software version",
        "low",
        "Exact versions help attackers pick known exploits.",
        "Use custom error pages and turn off version banners (ServerTokens Prod, "
        "server_tokens off, expose_php Off).",
        _p(
            r"(?:Apache|nginx|Microsoft-IIS|LiteSpeed|Jetty|Tomcat|Werkzeug)/\d+\.\d+[\w.]*",
            r"X-Powered-By: [\w.-]+/\d",
            r"PHP/\d+\.\d+\.\d+",
        ),
        errors_only=True,
    ),
)


def detect(body: str, status: int) -> tuple[LeakKind, str] | None:
    """The most severe leak in ``body`` and an evidence snippet, or None."""
    text = body[:MAX_BODY_CHARS]
    for kind in LEAK_KINDS:
        if kind.errors_only and status < 400:
            continue
        for pattern in kind.patterns:
            match = pattern.search(text)
            if match:
                return kind, snippet(text, match.start(), match.end())
    return None


def probe_urls(ctx: CheckContext) -> list[tuple[str, str]]:
    """``(label, url)`` for the page, a marked missing page and a marked bad parameter."""
    marker = str(ctx.params.get("probe_marker") or f"agentguard-probe-{secrets.token_hex(4)}")
    marker = re.sub(r"[^a-zA-Z0-9-]", "", marker)[:64] or "agentguard-probe"
    page_url = target_path_url(ctx)
    parts = urlsplit(page_url)
    bad_param = urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", urlencode({"id": marker}), "")
    )
    return [
        ("page", page_url),
        ("missing_page", with_path(ctx.target_url, f"/{marker}")),
        ("bad_param", bad_param),
    ]


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Request each probe URL and report each kind of leak once (first URL that shows it)."""
    found: dict[str, dict[str, Any]] = {}
    for label, url in probe_urls(ctx):
        response = await navigate(page, ctx, url)
        if response is None:
            continue
        try:
            body = await response.text()
        except Exception as exc:  # binary or aborted body: nothing to scan
            ctx.record_request({"url": url, "body_unreadable": type(exc).__name__})
            continue
        hit = detect(body, response.status)
        if hit is None or hit[0].key in found:
            continue
        kind, excerpt = hit
        ctx.record_request(
            {"url": url, "status": response.status, "leak": kind.key, "excerpt": excerpt}
        )
        shots = await screenshot_or_none(ctx, f"error_leak_{label}")
        found[kind.key] = finding(
            check_id=CHECK_ID,
            title=kind.title,
            severity=kind.severity,
            url=url,
            evidence=[*shots, NETWORK_SUMMARY],
            reproduction=[
                f"Open {path_of(url)}",
                f"Observe HTTP {response.status} with "
                f"{kind.key.replace('_', ' ')} details in the body",
            ],
            impact=kind.impact,
            recommended_fix=kind.fix,
            confidence=0.9 if kind.severity in ("high", "medium") else 0.75,
        )
    return list(found.values())
