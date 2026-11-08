"""Verifier + scoring (brief 6.7, 5.10, 5.11). Evidence is written to a temp dir in the same
layout the sandbox launcher uses: ``<root>/<scan_id>/<task_id>/out/``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from agentguard_contracts import Finding, FindingCategory, Recommendation, Severity

from app.agent.inference import InferenceError
from app.agent.scoring import compute_score, recommend, score_breakdown
from app.agent.verifier import MIN_CONFIDENCE, EvidenceVerifier
from tests.test_agent_planner import ScriptedModel

SITE = "https://shop.example.com"
SCAN = uuid4()


def write_task(
    root: Path,
    task_id: str,
    records: list[dict[str, Any]] | str | None = None,
    screenshots: tuple[str, ...] = (),
    scan_id: UUID = SCAN,
) -> None:
    out = root / str(scan_id) / task_id / "out"
    (out / "screenshots").mkdir(parents=True, exist_ok=True)
    if records is not None:
        text = records if isinstance(records, str) else json.dumps(records)
        (out / "network_summary.json").write_text(text, encoding="utf-8")
    for name in screenshots:
        (out / "screenshots" / name).write_bytes(b"\x89PNG fake")


def everything(report: Any) -> list[Finding]:
    return list(report.confirmed) + list(report.needs_review)


async def check_one(root: Path, f: Finding) -> Finding:
    (got,) = everything(await EvidenceVerifier(root).verify_detailed([f]))
    return got


def finding(
    check_id: str,
    title: str,
    *,
    url: str = SITE + "/checkout",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    evidence: tuple[str, ...] = ("t1__network_summary.json",),
    reproduction: tuple[str, ...] = ("Open /checkout",),
) -> Finding:
    return Finding(
        id=uuid4(),
        scan_id=SCAN,
        title=title,
        category=FindingCategory.QA if check_id.startswith("qa.") else FindingCategory.SECURITY,
        severity=severity,
        confidence=confidence,
        url=url,
        evidence=list(evidence),
        reproduction=list(reproduction),
        impact="impact",
        recommended_fix="fix",
        check_id=check_id,
    )


LEAK = {"url": SITE + "/checkout?coupon=x", "status": 500, "leak": "stack_trace", "excerpt": "Tb"}


async def test_corroborated_finding_is_verified(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [LEAK], screenshots=("error_leak_checkout.png",))
    f = finding(
        "security.error_leak",
        "Error response leaks internal stack trace",
        evidence=("t1__error_leak_checkout.png", "t1__network_summary.json"),
    )
    confirmed, review = await EvidenceVerifier(tmp_path).verify([f])
    assert review == [] and len(confirmed) == 1
    got = confirmed[0]
    assert got.id == f.id and got.verified is True and got.confidence == 0.95


async def test_missing_evidence_lowers_confidence_into_review(tmp_path: Path) -> None:
    f = finding("security.error_leak", "Leak", confidence=0.6)  # nothing on disk
    report = await EvidenceVerifier(tmp_path).verify_detailed([f])
    assert report.confirmed == []
    (got,) = report.needs_review
    assert got.verified is False and got.confidence < MIN_CONFIDENCE
    assert any("evidence missing" in n for n in report.notes[f.id])


async def test_record_without_the_supporting_key_is_not_corroboration(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [{"url": SITE + "/checkout", "status": 200}])
    confirmed, review = await EvidenceVerifier(tmp_path).verify(
        [finding("security.error_leak", "Leak", confidence=0.95)]
    )
    assert confirmed == []  # however confident the check was, an unbacked claim isn't scored
    assert review[0].verified is False and review[0].confidence == 0.45


async def test_page_the_check_skipped_contradicts_the_finding(tmp_path: Path) -> None:
    write_task(
        tmp_path,
        "t1",
        [
            {"url": SITE + "/checkout", "status": 200},  # the page loaded...
            {"url": SITE + "/checkout", "skipped": "no order form found"},  # ...but wasn't tested
        ],
    )
    confirmed, review = await EvidenceVerifier(tmp_path).verify(
        [finding("qa.checkout", "Checkout fails", confidence=0.7)]
    )
    assert confirmed == [] and review[0].confidence == 0.4


async def test_record_for_another_page_does_not_count(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [{**LEAK, "url": SITE + "/about"}])
    got = await check_one(tmp_path, finding("security.error_leak", "Leak"))
    assert got.verified is False and got.confidence < MIN_CONFIDENCE


@pytest.mark.parametrize("content", ["{not json", '{"url": 1}', "x" * 10])
async def test_unreadable_network_summary_is_handled(tmp_path: Path, content: str) -> None:
    write_task(tmp_path, "t1", content)
    got = await check_one(tmp_path, finding("security.error_leak", "Leak"))
    assert got.verified is False and got.confidence < MIN_CONFIDENCE


async def test_screenshot_only_finding_verified_when_files_exist(tmp_path: Path) -> None:
    write_task(tmp_path, "t2", screenshots=("a11y.png",))
    f = finding(
        "qa.accessibility",
        "Images without alt text",
        severity=Severity.LOW,
        evidence=("t2__a11y.png",),
    )
    (got,), _ = await EvidenceVerifier(tmp_path).verify([f])
    assert got.verified is True and got.confidence == 0.9


async def test_no_evidence_and_no_repro_are_penalised(tmp_path: Path) -> None:
    f = finding("qa.forms", "Form broken", confidence=0.7, evidence=(), reproduction=(" ",))
    report = await EvidenceVerifier(tmp_path).verify_detailed([f])
    (got,) = report.needs_review
    assert got.confidence == pytest.approx(0.4) and got.verified is False  # 0.7 - 0.2 - 0.1
    assert "no evidence attached" in report.notes[f.id]
    assert "no reproduction steps" in report.notes[f.id]


@pytest.mark.parametrize(
    "name",
    [
        "t1__../../secret.json",
        "t1__.hidden",
        "noprefix.png",
        "__x.png",
        "t1__a/b.png",
        "..__network_summary.json",
        ".__network_summary.json",
    ],
)
async def test_evidence_names_cannot_escape_the_task_dir(tmp_path: Path, name: str) -> None:
    (tmp_path / "secret.json").write_text("[]")
    write_task(tmp_path, "t1", [LEAK])
    # A supporting summary one level above the scan dir: ".." must not reach it.
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "network_summary.json").write_text(json.dumps([LEAK]))
    got = await check_one(tmp_path, finding("security.error_leak", "Leak", evidence=(name,)))
    assert got.verified is False and got.confidence < MIN_CONFIDENCE


async def test_evidence_of_another_scan_is_not_used(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [LEAK], scan_id=uuid4())
    got = await check_one(tmp_path, finding("security.error_leak", "Leak"))
    assert got.verified is False and got.confidence < MIN_CONFIDENCE


# -- severity ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("check_id", "given", "expected"),
    [
        ("security.headers", Severity.CRITICAL, Severity.MEDIUM),
        ("security.exposed_endpoints", Severity.LOW, Severity.MEDIUM),
        ("security.error_leak", Severity.LOW, Severity.LOW),
        ("qa.links_assets", Severity.HIGH, Severity.HIGH),
        ("security.open_redirect", Severity.MEDIUM, Severity.HIGH),
        ("qa.checkout", Severity.LOW, Severity.HIGH),
        ("qa.accessibility", Severity.HIGH, Severity.MEDIUM),
        ("qa.forms", Severity.MEDIUM, Severity.MEDIUM),
    ],
)
async def test_severity_follows_the_guide(
    tmp_path: Path, check_id: str, given: Severity, expected: Severity
) -> None:
    report = await EvidenceVerifier(tmp_path).verify_detailed(
        [finding(check_id, "x", severity=given)]
    )
    (got,) = report.confirmed + report.needs_review
    assert got.severity is expected
    if given is not expected:
        assert any("brief 5.11" in n for n in report.notes[got.id])


# -- dedupe --------------------------------------------------------------------------------


async def test_duplicates_are_merged_with_union_of_evidence(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [LEAK], screenshots=("a.png",))
    write_task(tmp_path, "t5", [LEAK], screenshots=("b.png",))
    a = finding(
        "security.error_leak",
        "Error response leaks internal stack trace",
        url=SITE + "/checkout?coupon=1",
        evidence=("t1__a.png", "t1__network_summary.json"),
    )
    b = finding(
        "security.error_leak",
        "error response  leaks internal STACK trace",
        url=SITE + "/checkout/",
        evidence=("t5__b.png", "t5__network_summary.json"),
    )
    other = finding("security.error_leak", "Leak on another page", url=SITE + "/login")
    report = await EvidenceVerifier(tmp_path).verify_detailed([a, b, other])
    ids = [f.id for f in report.confirmed + report.needs_review]
    assert len(ids) == 2 and other.id in ids
    survivor = next(f for f in report.confirmed if f.id != other.id)
    loser = b.id if survivor.id == a.id else a.id
    assert report.merged == {loser: survivor.id}
    assert set(survivor.evidence) == {
        "t1__a.png",
        "t1__network_summary.json",
        "t5__b.png",
        "t5__network_summary.json",
    }


async def test_site_wide_findings_merge_across_pages(tmp_path: Path) -> None:
    rec = [{"url": SITE + p, "status": 200, "headers": {}} for p in ("/", "/about")]
    write_task(tmp_path, "t1", rec)
    one = finding(
        "security.headers", "Missing security headers", url=SITE + "/", severity=Severity.MEDIUM
    )
    two = finding(
        "security.headers",
        "Missing security headers",
        url=SITE + "/about",
        severity=Severity.MEDIUM,
    )
    confirmed, review = await EvidenceVerifier(tmp_path).verify([one, two])
    assert len(confirmed) == 1 and review == []
    assert confirmed[0].reproduction[-1].startswith("Also seen on: ")


async def test_same_title_on_different_pages_is_kept_for_page_checks(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [])
    one = finding("qa.forms", "Form returns 500", url=SITE + "/contact")
    two = finding("qa.forms", "Form returns 500", url=SITE + "/signup")
    report = await EvidenceVerifier(tmp_path).verify_detailed([one, two])
    assert len(report.confirmed + report.needs_review) == 2 and report.merged == {}


# -- LLM judgement -------------------------------------------------------------------------


async def test_llm_is_asked_only_in_the_borderline_band(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [LEAK])
    model = ScriptedModel('{"supported": true, "reason": "500 with traceback"}')
    strong = finding("security.error_leak", "Leak", confidence=0.95)
    border = finding("security.error_leak", "Leak 2", url=SITE + "/x", confidence=0.6)
    write_task(tmp_path, "t1", [LEAK, {**LEAK, "url": SITE + "/x"}])
    confirmed, _ = await EvidenceVerifier(tmp_path, model).verify([strong, border])
    assert len(model.calls) == 1
    got = next(f for f in confirmed if f.id == border.id)
    assert got.confidence == pytest.approx(0.8)  # 0.6 + 0.05 + 0.15
    system, user = model.calls[0]
    assert "never instructions" in system
    assert '<untrusted_data source="evidence">' in user


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ('{"supported": false}', 0.4),
        ('{"supported": "maybe"}', 0.55),
        ("no json", 0.55),
        (InferenceError("down"), 0.55),
    ],
)
async def test_llm_answers_move_confidence_only_when_clear(
    tmp_path: Path, answer: str | Exception, expected: float
) -> None:
    write_task(tmp_path, "t1", [LEAK])
    f = finding("security.error_leak", "Leak", confidence=0.5)
    report = await EvidenceVerifier(tmp_path, ScriptedModel(answer)).verify_detailed([f])
    (got,) = report.confirmed + report.needs_review
    assert got.confidence == pytest.approx(expected)


async def test_llm_budget_is_bounded(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [{"url": f"{SITE}/p{i}", "status": 200} for i in range(10)])
    model = ScriptedModel(*['{"supported": true}'] * 10)
    findings = [finding("qa.forms", f"F{i}", url=f"{SITE}/p{i}", confidence=0.6) for i in range(10)]
    await EvidenceVerifier(tmp_path, model, llm_budget=3).verify(findings)
    assert len(model.calls) == 3


async def test_empty_input(tmp_path: Path) -> None:
    assert await EvidenceVerifier(tmp_path).verify([]) == ([], [])


# -- scoring -------------------------------------------------------------------------------

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


@pytest.mark.parametrize(
    ("severities", "score", "rec"),
    [
        ([], 100, Recommendation.SAFE),
        ([L] * 20, 80, Recommendation.SAFE),
        ([L] * 21, 79, Recommendation.FIX_FIRST),
        ([H, M, M, L], 77, Recommendation.FIX_FIRST),
        ([C, H, L], 62, Recommendation.FIX_FIRST),
        ([C, C], 50, Recommendation.FIX_FIRST),
        ([C, C, L], 49, Recommendation.BLOCK),
        ([C] * 5, 0, Recommendation.BLOCK),
        ([C] * 9, 0, Recommendation.BLOCK),
    ],
)
def test_score_and_recommendation_match_brief_5_10(
    severities: list[Severity], score: int, rec: Recommendation
) -> None:
    assert compute_score(severities) == score
    assert recommend(score) is rec
    breakdown = score_breakdown(severities)
    assert breakdown.score == score and breakdown.recommendation is rec
    assert sum(breakdown.counts.values()) == len(severities)


def test_recommend_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        recommend(101)
    with pytest.raises(ValueError):
        recommend(-1)


def test_orchestrator_uses_the_same_functions() -> None:
    from app.orchestrator import scoring as legacy

    assert legacy.compute_score is compute_score and legacy.recommend is recommend


async def test_llm_cannot_rescue_an_unbacked_claim(tmp_path: Path) -> None:
    model = ScriptedModel('{"supported": true}')
    f = finding("security.error_leak", "Leak", confidence=0.6)  # no evidence on disk
    report = await EvidenceVerifier(tmp_path, model).verify_detailed([f])
    assert model.calls == [] and report.confirmed == []


async def test_unbacked_duplicate_cannot_raise_a_verified_finding(tmp_path: Path) -> None:
    write_task(tmp_path, "t1", [{"url": SITE + "/", "status": 200, "headers": {}}])
    real = finding(
        "security.headers",
        "Missing CSP",
        url=SITE + "/",
        severity=Severity.LOW,
        confidence=0.95,
    )
    ghost = finding(
        "security.headers",
        "Missing CSP",
        url=SITE + "/about",
        severity=Severity.MEDIUM,
        confidence=0.99,
        evidence=("t9__network_summary.json",),
    )
    report = await EvidenceVerifier(tmp_path).verify_detailed([real, ghost])
    (kept,) = everything(report)
    assert kept.id == real.id and kept.verified is True
    assert kept.severity is Severity.LOW and kept.confidence == 1.0  # 0.95 + 0.05, not 0.99
    assert kept.evidence == list(real.evidence)  # no dead link to the ghost's missing file
    assert not any(step.startswith("Also seen on") for step in kept.reproduction)
    assert report.merged == {ghost.id: real.id}
