"""What the planner may ask for: the check catalog, profile scopes and safe task params.

Source of truth for the whitelist is the frozen contract (``ALLOWED_CHECK_IDS``, brief 6.3).
This module adds what the planner needs on top: a one-line description of each check for the
prompt, which checks each profile may use, default timeouts and the params a plan may set.
"""

from __future__ import annotations

from typing import Final

from agentguard_contracts import (
    ALLOWED_CHECK_IDS,
    QA_CHECK_IDS,
    SECURITY_CHECK_IDS,
    ScanProfile,
)

CHECK_DESCRIPTIONS: Final[dict[str, str]] = {
    "qa.pages_load": "Key pages load with a 2xx status, a title and visible content",
    "qa.links_assets": "Links and images/scripts/styles on the page are not broken",
    "qa.forms": "A form rejects invalid input and accepts valid input without a server error",
    "qa.login": "The login form works and failed logins give a clear error",
    "qa.password_reset": "The password reset page exists and responds sensibly",
    "qa.search": "Search returns a results page without errors",
    "qa.checkout": "The checkout / order flow completes without a server error",
    "qa.console_network_errors": "No JavaScript console errors or failed requests on load",
    "qa.accessibility": "Basics: image alt text, form labels, page title, contrast",
    "security.https_redirect": "Plain HTTP redirects to HTTPS",
    "security.headers": "Security headers are present (CSP, HSTS, X-Frame-Options...)",
    "security.cookies": "Session cookies use Secure, HttpOnly and SameSite",
    "security.url_session_leak": "No session ids or tokens in URLs",
    "security.error_leak": "Error pages do not leak stack traces or internals",
    "security.open_redirect": "Redirect parameters do not send users to other sites",
    "security.reflected_input": "A harmless marker sent in input is not reflected unescaped",
    "security.exposed_endpoints": "Admin/debug/config paths are not publicly exposed (GET only)",
    "security.login_rate_probe": "Login slows down or locks after a few failed attempts (max 3)",
}
if set(CHECK_DESCRIPTIONS) != ALLOWED_CHECK_IDS:  # import-time guard, survives python -O
    raise RuntimeError("agent catalog must cover exactly the contract's check whitelist")

PROFILE_CHECKS: Final[dict[ScanProfile, frozenset[str]]] = {
    ScanProfile.SMOKE: frozenset(
        {
            "qa.pages_load",
            "qa.links_assets",
            "qa.console_network_errors",
            "security.https_redirect",
            "security.headers",
            "security.error_leak",
        }
    ),
    ScanProfile.QA: QA_CHECK_IDS,
    ScanProfile.SECURITY: SECURITY_CHECK_IDS,
    ScanProfile.FULL: ALLOWED_CHECK_IDS,
}
"""Checks each profile may contain. A security scan never runs QA flows and vice versa."""

DEFAULT_TIMEOUT_S: Final = 90
MIN_TIMEOUT_S: Final = 15
MAX_TIMEOUT_S: Final = 180
"""Per-task timeout bounds; the sandbox launcher still enforces its own hard wall clock."""

TIMEOUTS: Final[dict[str, int]] = {
    "qa.links_assets": 120,
    "qa.checkout": 120,
    "qa.accessibility": 120,
    "security.exposed_endpoints": 60,
    "security.https_redirect": 30,
    "security.headers": 30,
    "security.cookies": 45,
}

MAX_PATH_LEN: Final = 200
MAX_PATHS: Final = 10
MAX_LOGIN_ATTEMPTS: Final = 3  # brief 6.6: login_rate_probe makes at most 3 attempts

PARAMS_BY_CHECK: Final[dict[str, frozenset[str]]] = {
    check_id: frozenset({"path"}) for check_id in ALLOWED_CHECK_IDS
} | {
    "security.exposed_endpoints": frozenset({"paths"}),
    "security.login_rate_probe": frozenset({"path", "attempts"}),
}
"""Params a plan may set per check. Everything else (``probe_marker``, ``containment_demo``,
credentials...) is set by the system or never at all, so the LLM cannot control it."""


def timeout_for(check_id: str) -> int:
    return TIMEOUTS.get(check_id, DEFAULT_TIMEOUT_S)
