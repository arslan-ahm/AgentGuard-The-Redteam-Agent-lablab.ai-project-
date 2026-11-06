"""security.exposed_endpoints: public admin/debug endpoints (brief 3, 6.6).

Exactly the four paths from the brief, GET only, redirects not followed: ``/admin``,
``/debug``, ``/.env``, ``/server-status``. A marked missing page is fetched first so a site
that answers 200 to everything (SPA catch-all, soft 404) isn't reported. A 200 alone is not
a finding: each path needs content that proves exposure. ``.env`` values are never copied
into evidence, only the variable names.

**Containment demo trigger (brief 6.9).** With ``params: {"containment_demo": true}`` the
check first tries to reach the cloud metadata service (``CONTAINMENT_DEMO_URL``). The policy
blocks it, the task ends ``blocked`` (exit 3), the event is audited and the sandbox is
destroyed. The URL is a constant: params can switch the demo on, never choose its target.
"""

from __future__ import annotations

import re
from typing import Any

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    Fetched,
    fetch,
    finding,
    probe_marker,
    with_path,
)

CHECK_ID = "security.exposed_endpoints"

ENDPOINTS = ("/admin", "/debug", "/.env", "/server-status")
CONTAINMENT_DEMO_URL = "http://169.254.169.254/latest/meta-data/"


class ContainmentNotEnforced(RuntimeError):
    """The policy allowed the metadata URL. The check refuses to request it and errors."""


_ENV_LINE = re.compile(r"^[ \t]{0,8}(?:export[ \t]{1,8})?([A-Z][A-Z0-9_]{1,63})[ \t]{0,8}=", re.M)
_SERVER_STATUS = re.compile(
    r"Apache Server Status for|Server uptime:|Total accesses: \d|Scoreboard Key|"
    r"Active connections: \d+[ \t]{0,8}\r?\nserver accepts handled",
    re.IGNORECASE,
)
_DEBUG = re.compile(
    r"Werkzeug Debugger|Django Debug Toolbar|id=\"djDebug\"|<title>phpinfo\(\)|"
    r"PHP Version \d+\.\d+|Symfony Profiler|Laravel Telescope|"
    r"\"(?:debug|DEBUG)\"[ \t]{0,4}:[ \t]{0,4}true|Types of profiles available|"
    r"Environment Variables</h|Request Headers</h",
    re.IGNORECASE,
)
_ADMIN = re.compile(
    r"\b(?:admin(?:istration)?[ \t]{1,4}(?:panel|dashboard|console|area)|Django administration|"
    r"Site administration|manage users|user management|wp-admin)\b",
    re.IGNORECASE,
)
_PASSWORD_FIELD = re.compile(r"type[ \t]{0,4}=[ \t]{0,4}[\"']?password", re.IGNORECASE)


def _catch_all(got: Fetched, baseline: Fetched | None, marker: str) -> bool:
    """True if ``got`` looks like the same page the site serves for a made-up path."""
    if baseline is None or baseline.status != 200:
        return False
    a = baseline.body.replace(marker, "")
    b = got.body
    return a == b or abs(len(a) - len(b)) <= max(64, len(a) // 50)


def classify(path: str, got: Fetched) -> tuple[str, str, str, str, str] | None:
    """``(title, severity, observed, impact, fix)`` if ``got`` proves exposure, else None."""
    if got.status != 200:
        return None
    body = got.body
    if path == "/.env":
        if body.lstrip().startswith("<"):
            return None
        names = list(dict.fromkeys(_ENV_LINE.findall(body)))
        if len(names) < 2:
            return None
        shown = ", ".join(names[:15])
        return (
            "Environment file (.env) is publicly downloadable",
            "critical",
            f"{len(names)} variables, values withheld: {shown}",
            "The .env file usually holds database passwords, API keys and signing secrets; "
            "anyone can download it and take over the application and its data.",
            "Block dotfiles at the web server, keep .env outside the web root, and rotate "
            "every secret it contained.",
        )
    if path == "/server-status" and _SERVER_STATUS.search(body):
        return (
            "Server status page is public (/server-status)",
            "medium",
            "server status/statistics page returned with HTTP 200",
            "It reveals client IPs, requested URLs (sometimes with tokens), virtual hosts "
            "and server internals.",
            "Restrict /server-status to localhost or admin IPs "
            "(Require local / allow 127.0.0.1), or disable mod_status.",
        )
    if path == "/debug" and _DEBUG.search(body):
        return (
            "Debug endpoint is publicly accessible (/debug)",
            "high",
            "debug/diagnostic output returned with HTTP 200",
            "Debug pages expose configuration, environment variables and sometimes code "
            "execution consoles.",
            "Disable debug tooling in production or restrict it to authenticated admins on "
            "an internal network.",
        )
    if path == "/admin" and _ADMIN.search(body) and not _PASSWORD_FIELD.search(body):
        return (
            "Admin area reachable without logging in (/admin)",
            "high",
            "admin interface content returned with HTTP 200 and no login form",
            "Anyone on the internet can use administrative functions.",
            "Require authentication (and ideally an IP allow-list or SSO) for every admin "
            "route, enforced server-side.",
        )
    return None


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """GET each endpoint (no redirects) and report the ones that prove exposure."""
    if ctx.params.get("containment_demo") is True:
        ctx.policy.assert_allowed(CONTAINMENT_DEMO_URL)  # raises: task blocked, exit 3
        raise ContainmentNotEnforced(f"policy allowed {CONTAINMENT_DEMO_URL}")

    marker = probe_marker(ctx)
    baseline = await fetch(page, ctx, with_path(ctx.target_url, f"/{marker}"))
    found: list[dict[str, Any]] = []
    for path in ENDPOINTS:
        url = with_path(ctx.target_url, path)
        got = await fetch(page, ctx, url)
        if got is None:
            continue
        hit = classify(path, got)
        if hit is None or (path != "/.env" and _catch_all(got, baseline, marker)):
            continue
        title, severity, observed, impact, fix = hit
        ctx.record_request({"url": url, "exposed": path, "observed": observed})
        found.append(
            finding(
                check_id=CHECK_ID,
                title=title,
                severity=severity,
                url=url,
                evidence=[NETWORK_SUMMARY],
                reproduction=[f"Request GET {path} without logging in", f"Observe {observed}"],
                impact=impact,
                recommended_fix=fix,
                confidence=0.9,
            )
        )
    return found
