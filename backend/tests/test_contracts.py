"""The shared contract models accept the brief's own examples and reject drift."""

from __future__ import annotations

from typing import Any

import pytest
from agentguard_contracts import (
    ALLOWED_CHECK_IDS,
    MAX_TASKS_PER_PROFILE,
    SEVERITY_WEIGHTS,
    AuditEvent,
    Finding,
    FindingDraft,
    Recommendation,
    SandboxResult,
    ScanProfile,
    ScanStatus,
    Severity,
    TestPlan,
)
from pydantic import ValidationError

BRIEF_FINDING: dict[str, Any] = {
    "id": "6f1c1a52-0a4b-4c55-9a39-6a8f1f6f1b10",
    "scan_id": "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d",
    "title": "Error response leaks internal stack trace",
    "category": "security",
    "severity": "high",
    "confidence": 0.94,
    "url": "https://demo.example.com/checkout",
    "evidence": ["screenshot_3.png", "network_summary.json"],
    "reproduction": [
        "Open /checkout",
        "Submit invalid coupon",
        "Observe HTTP 500 response with stack trace",
    ],
    "impact": "Attackers can learn internal implementation details.",
    "recommended_fix": "Return a generic error response; log details server-side; "
    "disable debug mode in production.",
    "check_id": "security.error_leak",
    "verified": False,
}

BRIEF_PLAN: dict[str, Any] = {
    "scan_id": "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d",
    "target_url": "https://demo.example.com",
    "profile": "full",
    "tasks": [
        {
            "task_id": "t1",
            "check_id": "qa.forms",
            "description": "Submit contact form with valid and invalid data",
            "params": {"path": "/contact"},
            "timeout_s": 90,
        }
    ],
}


def test_finding_accepts_brief_example() -> None:
    finding = Finding.model_validate(BRIEF_FINDING)
    assert finding.severity is Severity.HIGH
    assert finding.model_dump(mode="json") == BRIEF_FINDING


def test_finding_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**BRIEF_FINDING, "cvss": 7.5})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "info"),
        ("category", "performance"),
        ("confidence", 1.2),
        ("confidence", -0.1),
        ("check_id", "error_leak"),
    ],
)
def test_finding_rejects_out_of_contract_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**BRIEF_FINDING, field: value})


def test_finding_draft_has_no_id_or_scan_id() -> None:
    draft = {k: v for k, v in BRIEF_FINDING.items() if k not in {"id", "scan_id"}}
    FindingDraft.model_validate(draft)
    with pytest.raises(ValidationError):
        FindingDraft.model_validate(BRIEF_FINDING)


def test_plan_accepts_brief_example() -> None:
    plan = TestPlan.model_validate(BRIEF_PLAN)
    assert plan.profile is ScanProfile.FULL
    assert plan.tasks[0].check_id in ALLOWED_CHECK_IDS


def test_brief_example_check_ids_are_whitelisted() -> None:
    assert {"qa.forms", "security.headers", "security.error_leak"} <= ALLOWED_CHECK_IDS
    assert len(ALLOWED_CHECK_IDS) == 18


def test_enums_match_brief() -> None:
    assert [p.value for p in ScanProfile] == ["smoke", "qa", "security", "full"]
    assert [s.value for s in ScanStatus] == [
        "queued",
        "planning",
        "running",
        "verifying",
        "awaiting_approval",
        "completed",
        "failed",
        "blocked",
    ]
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low"]


def test_profile_task_limits_match_brief() -> None:
    assert MAX_TASKS_PER_PROFILE == {
        ScanProfile.SMOKE: 5,
        ScanProfile.QA: 12,
        ScanProfile.SECURITY: 12,
        ScanProfile.FULL: 20,
    }


def test_score_constants_match_brief() -> None:
    assert SEVERITY_WEIGHTS == {
        Severity.CRITICAL: 25,
        Severity.HIGH: 12,
        Severity.MEDIUM: 5,
        Severity.LOW: 1,
    }
    assert Recommendation.FIX_FIRST.value == "Fix high-priority issues before release"


def test_sandbox_result_shape() -> None:
    result = SandboxResult.model_validate(
        {
            "task_id": "t1",
            "status": "blocked",
            "findings": [],
            "duration_ms": 12,
            "policy_events": [{"action": "navigate", "decision": "blocked"}],
        }
    )
    assert result.status.value == "blocked"
    with pytest.raises(ValidationError):
        SandboxResult.model_validate(
            {
                "task_id": "t1",
                "status": "skipped",
                "findings": [],
                "duration_ms": 0,
                "policy_events": [],
            }
        )


def test_audit_event_task_id_optional() -> None:
    event = AuditEvent.model_validate(
        {
            "ts": "2026-11-06T10:00:00Z",
            "scan_id": BRIEF_PLAN["scan_id"],
            "actor": "policy",
            "action": "navigate",
            "target": "http://169.254.169.254/",
            "decision": "blocked",
            "reason": "cloud metadata address",
        }
    )
    assert event.task_id is None
