"""Deterministic fallback plan per profile (brief 6.3): the demo never depends on the LLM.

Used when inference is not configured, times out, errors, or returns a plan that is still
invalid after one repair round. Every fallback plan goes through the same validator as an
LLM plan, so it obeys the same whitelist, profile scope and task cap.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID

from agentguard_contracts import ScanProfile, TestPlan

from app.agent.plan_schema import validate_plan_payload

FALLBACK_CHECKS: Final[dict[ScanProfile, tuple[str, ...]]] = {
    ScanProfile.SMOKE: (
        "qa.pages_load",
        "qa.console_network_errors",
        "security.https_redirect",
        "security.headers",
        "security.error_leak",
    ),
    ScanProfile.QA: (
        "qa.pages_load",
        "qa.links_assets",
        "qa.forms",
        "qa.login",
        "qa.password_reset",
        "qa.search",
        "qa.checkout",
        "qa.console_network_errors",
        "qa.accessibility",
    ),
    ScanProfile.SECURITY: (
        "security.https_redirect",
        "security.headers",
        "security.cookies",
        "security.url_session_leak",
        "security.error_leak",
        "security.open_redirect",
        "security.reflected_input",
        "security.exposed_endpoints",
        "security.login_rate_probe",
    ),
    ScanProfile.FULL: (
        "qa.pages_load",
        "qa.links_assets",
        "qa.forms",
        "qa.login",
        "qa.password_reset",
        "qa.search",
        "qa.checkout",
        "qa.console_network_errors",
        "qa.accessibility",
        "security.https_redirect",
        "security.headers",
        "security.cookies",
        "security.url_session_leak",
        "security.error_leak",
        "security.open_redirect",
        "security.reflected_input",
        "security.exposed_endpoints",
        "security.login_rate_probe",
    ),
}
"""Order matters: cheap page-level checks first, so a slow flow can't starve them."""


def fallback_plan(target_url: str, profile: ScanProfile, scan_id: UUID | None = None) -> TestPlan:
    """The fixed plan for ``profile``. Never calls the network."""
    payload = {"tasks": [{"check_id": c} for c in FALLBACK_CHECKS[profile]]}
    return validate_plan_payload(payload, target_url=target_url, profile=profile, scan_id=scan_id)
