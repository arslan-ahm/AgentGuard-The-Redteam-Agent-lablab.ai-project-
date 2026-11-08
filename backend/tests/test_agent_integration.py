"""The real planner inside the real orchestrator and wiring (fake sandbox, scripted model)."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from agentguard_contracts import (
    FindingCategory,
    FindingDraft,
    SandboxResult,
    SandboxResultStatus,
    SandboxTaskInput,
    ScanProfile,
    ScanStatus,
    Severity,
)
from pydantic import SecretStr
from sqlalchemy import select

from app.agent.fallback import FALLBACK_CHECKS
from app.agent.inference import InferenceError, VultrInferenceClient
from app.agent.planner import AgentPlanner
from app.agent.verifier import EvidenceVerifier
from app.config import Settings
from app.db.models import FindingRow, Scan, ScanTask
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.services import build_services
from tests.conftest import make_services
from tests.test_agent_planner import ScriptedModel


async def _scan(
    tmp_path: Path, planner: AgentPlanner, profile: ScanProfile
) -> tuple[Scan, list[str]]:
    services = make_services(tmp_path, planner=planner)
    scan_id = uuid4()
    with services.session_factory() as db:
        db.add(
            Scan(
                id=scan_id,
                owner="alice@example.com",
                target_url="https://shop.example.com",
                profile=profile,
            )
        )
        db.commit()
    await Orchestrator(services).run_scan(scan_id)
    with services.session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        checks = [
            t.check_id
            for t in db.scalars(
                select(ScanTask).where(ScanTask.scan_id == scan_id).order_by(ScanTask.position)
            )
        ]
    return scan, checks


async def test_fallback_planner_drives_a_full_scan(tmp_path: Path) -> None:
    scan, checks = await _scan(tmp_path, AgentPlanner(None), ScanProfile.FULL)
    assert checks == list(FALLBACK_CHECKS[ScanProfile.FULL])
    assert scan.status is ScanStatus.AWAITING_APPROVAL
    assert scan.score is not None and scan.summary and "fake" not in scan.summary.lower()


async def test_llm_plan_drives_a_scan(tmp_path: Path) -> None:
    answer = json.dumps(
        {"tasks": [{"check_id": "security.error_leak"}, {"check_id": "security.headers"}]}
    )
    model = ScriptedModel(answer, "Stack traces leak on errors. Fix them first.")
    scan, checks = await _scan(tmp_path, AgentPlanner(model), ScanProfile.SECURITY)
    assert checks == ["security.error_leak", "security.headers"]
    assert scan.summary == "Stack traces leak on errors. Fix them first."


async def test_model_outage_still_completes_the_scan(tmp_path: Path) -> None:
    model = ScriptedModel(InferenceError("down"), InferenceError("down"))
    scan, checks = await _scan(tmp_path, AgentPlanner(model), ScanProfile.SMOKE)
    assert checks == list(FALLBACK_CHECKS[ScanProfile.SMOKE])
    assert scan.status is ScanStatus.AWAITING_APPROVAL
    assert scan.summary and scan.summary.startswith("3 confirmed issues")


@pytest.fixture
def no_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTGUARD_USE_FAKES", raising=False)


def test_build_services_wires_the_real_planner(tmp_path: Path, no_fakes: None) -> None:
    base = {"_env_file": None, "database_url": f"sqlite:///{tmp_path / 'a.db'}"}
    services = build_services(Settings(**base))  # type: ignore[arg-type]
    assert isinstance(services.planner, AgentPlanner) and services.planner.model is None

    configured = Settings(
        **base,  # type: ignore[arg-type]
        vultr_inference_base_url="https://api.vultrinference.example/v1",
        vultr_inference_api_key=SecretStr("k"),
        vultr_inference_model="llama",
    )
    services = build_services(configured)
    assert isinstance(services.planner, AgentPlanner)
    assert isinstance(services.planner.model, VultrInferenceClient)
    assert isinstance(services.verifier, EvidenceVerifier)
    assert services.verifier.model is services.planner.model


class EvidenceSandbox:
    """Writes evidence like the real launcher (``<root>/<scan>/<task>/out``) and returns
    findings: a corroborated leak (twice: a duplicate) and an unsupported finding."""

    def __init__(self, root: Path) -> None:
        self.root = root

    async def run(self, task: SandboxTaskInput) -> SandboxResult:
        out = self.root / str(task.scan_id) / task.task.task_id / "out"
        out.mkdir(parents=True, exist_ok=True)
        url = task.target_url + "/checkout"
        (out / "network_summary.json").write_text(
            json.dumps([{"url": url, "status": 500, "leak": "stack_trace"}])
        )
        drafts = []
        if task.task.check_id == "security.error_leak":
            drafts.append(_draft("security.error_leak", "Stack trace leak", url, 0.9))
        if task.task.check_id == "security.headers":
            drafts.append(_draft("security.error_leak", "Stack trace leak", url + "/", 0.8))
            drafts.append(_draft("qa.forms", "Maybe a broken form", task.target_url + "/x", 0.55))
        return SandboxResult(
            task_id=task.task.task_id,
            status=SandboxResultStatus.FAILED if drafts else SandboxResultStatus.PASSED,
            findings=drafts,
            duration_ms=1,
            policy_events=[],
        )


def _draft(check_id: str, title: str, url: str, confidence: float) -> FindingDraft:
    return FindingDraft(
        title=title,
        category=FindingCategory.SECURITY,
        severity=Severity.CRITICAL,  # clamped by the verifier
        confidence=confidence,
        url=url,
        evidence=["network_summary.json"],
        reproduction=["Open the page"],
        impact="i",
        recommended_fix="f",
        check_id=check_id,
    )


async def test_verifier_results_are_persisted_and_scored(tmp_path: Path) -> None:
    services = make_services(tmp_path)
    services.planner = AgentPlanner(
        ScriptedModel(
            json.dumps(
                {"tasks": [{"check_id": "security.error_leak"}, {"check_id": "security.headers"}]}
            ),
            InferenceError("no summary today"),
        )
    )
    services.sandbox = EvidenceSandbox(services.evidence_root)
    services.verifier = EvidenceVerifier(services.evidence_root)
    scan_id = uuid4()
    with services.session_factory() as db:
        db.add(
            Scan(
                id=scan_id,
                owner="alice@example.com",
                target_url="https://shop.example.com",
                profile=ScanProfile.SECURITY,
            )
        )
        db.commit()
    await Orchestrator(services).run_scan(scan_id)

    with services.session_factory() as db:
        rows = db.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
        scan = db.get(Scan, scan_id)
    assert scan is not None
    by_title = {r.title: r for r in rows}
    assert len(rows) == 2  # the duplicate leak was merged away
    leak = by_title["Stack trace leak"]
    assert leak.verified is True and leak.severity is Severity.HIGH and not leak.needs_review
    assert sorted(leak.evidence) == ["t1__network_summary.json", "t2__network_summary.json"]
    form = by_title["Maybe a broken form"]
    assert form.needs_review is True and form.verified is False and form.confidence < 0.5
    assert scan.score == 88  # one confirmed high finding
    assert scan.summary and scan.summary.startswith("1 confirmed issue")
    events = [(e.action, e.reason) for _, e in services.audit_store.events_since(scan_id)]
    assert ("verify.done", "1 need review, 1 duplicate(s) merged") in events
    ok, _ = await services.audit.verify()
    assert ok
