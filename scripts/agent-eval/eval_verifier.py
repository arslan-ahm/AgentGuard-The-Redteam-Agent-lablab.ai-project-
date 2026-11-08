"""Step 2 of the verifier eval: score the verifier on real check output.

Reads the run written by ``run_checks.py``, labels every finding against
``ground_truth.json`` and compares, on the same input:

- **before**: the orchestrator's old default (confidence >= 0.5, nothing re-checked);
- **after**: ``EvidenceVerifier`` (evidence re-check, severity guide, dedupe; no LLM).

Then it injects six realistic faults built from that real run (a task whose evidence was
never written, a claim about a page the check never recorded, a page the check skipped, a
retried task's duplicate, a finding with no evidence or steps, an unsupported endpoint
claim) and measures how many of them still reach the score.

    uv run --project backend python scripts/agent-eval/eval_verifier.py --work .agent-eval
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from agentguard_contracts import Finding, FindingCategory, SandboxResult, Severity

from app.agent.scoring import score_breakdown
from app.agent.verifier import EvidenceVerifier
from app.orchestrator.verify import ConfidenceVerifier

HERE = Path(__file__).resolve().parent


def load_findings(scan_dir: Path) -> list[tuple[str, Finding]]:
    """Findings as the orchestrator stores them (evidence names ``<task_id>__<file>``)."""
    scan_id = UUID(scan_dir.name)
    out: list[tuple[str, Finding]] = []
    for result_file in sorted(
        scan_dir.glob("t*/out/result.json"), key=lambda p: int(p.parts[-3][1:])
    ):
        result = SandboxResult.model_validate_json(result_file.read_text())
        for draft in result.findings:
            data = draft.model_dump()
            data["evidence"] = [f"{result.task_id}__{e}" for e in draft.evidence]
            out.append((result.task_id, Finding(id=uuid4(), scan_id=scan_id, **data)))
    return out


def _path(url: str) -> str:
    return urlsplit(url).path.rstrip("/") or "/"


def label(f: Finding, truth: dict[str, Any]) -> str | None:
    """Ground-truth id the finding matches, or None (a false positive)."""
    title = f.title.lower()
    for flaw in truth["planted"]:
        if f.check_id == flaw["check_id"] and _path(f.url) == flaw["path"]:
            if "title" not in flaw or flaw["title"] in title:
                return str(flaw["id"])
    for extra in truth["confirmed_extra"]:
        if f.check_id == extra["check_id"] and extra["title"] in title:
            return str(extra["id"])
    return None


def inject_faults(real: list[tuple[str, Finding]], scan_dir: Path) -> list[tuple[str, Finding]]:
    """Six labelled false positives / duplicates derived from the real run."""
    by_check = {f.check_id: (t, f) for t, f in real}
    faults: list[tuple[str, Finding]] = []

    def fake(kind: str, base: Finding, **update: Any) -> None:
        faults.append((kind, base.model_copy(update={"id": uuid4(), **update})))

    template = real[0][1]
    origin = f"{urlsplit(template.url).scheme}://{urlsplit(template.url).netloc}"
    fake(
        "fault:evidence_never_written",
        template,
        title="Order history page leaks other users' orders",
        url=origin + "/orders",
        evidence=["t99__orders.png", "t99__network_summary.json"],
        check_id="qa.pages_load",
        category=FindingCategory.QA,
    )
    tasks = json.loads((scan_dir / "tasks.json").read_text())
    task_of = {check: task for task, check in tasks.items()}
    error_task = task_of["security.error_leak"]
    fake(
        "fault:claim_on_unrecorded_page",
        template,
        title="Error response leaks internal stack trace",
        url=origin + "/contact",
        evidence=[f"{error_task}__network_summary.json"],
        check_id="security.error_leak",
        severity=Severity.HIGH,
    )
    skipped = _skipped_record(scan_dir)
    if skipped is not None:
        task_id, check_id, url = skipped
        fake(
            "fault:page_check_skipped",
            template,
            title="Form fails on submit",
            url=url,
            evidence=[f"{task_id}__network_summary.json"],
            check_id=check_id,
            category=FindingCategory.QA,
            confidence=0.75,
        )
    if "qa.checkout" in by_check:
        _, checkout = by_check["qa.checkout"]
        fake("fault:retried_task_duplicate", checkout)
    fake(
        "fault:no_evidence_no_steps",
        template,
        title="Search is slow",
        url=origin + "/search",
        evidence=[],
        reproduction=[],
        check_id="qa.search",
        category=FindingCategory.QA,
        confidence=0.7,
    )
    if "security.exposed_endpoints" in by_check:
        task_id, admin = by_check["security.exposed_endpoints"]
        fake(
            "fault:unsupported_endpoint_claim",
            admin,
            title="Backup archive reachable (/backup.zip)",
            url=origin + "/backup.zip",
            evidence=[f"{task_id}__network_summary.json"],
        )
    return faults


def _skipped_record(scan_dir: Path) -> tuple[str, str, str] | None:
    """A real ``skipped`` record from a QA check, so the fault is a claim the check disproves."""
    tasks = json.loads((scan_dir / "tasks.json").read_text())
    for task_id, check_id in tasks.items():
        if not check_id.startswith("qa."):
            continue
        path = scan_dir / task_id / "out" / "network_summary.json"
        if not path.is_file():
            continue
        for record in json.loads(path.read_text() or "[]"):
            if (
                isinstance(record, dict)
                and "skipped" in record
                and isinstance(record.get("url"), str)
            ):
                return task_id, check_id, str(record["url"])
    return None


def _score(findings: Iterable[Finding]) -> str:
    b = score_breakdown(f.severity for f in findings)
    return f"{b.score} ({b.recommendation.value})"


async def evaluate(scan_dir: Path, evidence_root: Path) -> str:
    truth = json.loads((HERE / "ground_truth.json").read_text())
    real = load_findings(scan_dir)
    labels = {f.id: label(f, truth) for _, f in real}
    faults = inject_faults(real, scan_dir)
    fault_kind = {f.id: kind for kind, f in faults}
    lines: list[str] = []

    found = {lab for lab in labels.values() if lab}
    planted = [flaw["id"] for flaw in truth["planted"]]
    lines += [
        "## Real run (18 real checks against the demo store)",
        "",
        f"- Findings produced by the checks: **{len(real)}**",
        f"- Matching a planted flaw: {sum(1 for v in labels.values() if v in planted)}, "
        f"real but not in the planted list (confirmed by hand): "
        f"{sum(1 for v in labels.values() if v and v not in planted)}, "
        f"false positives: {sum(1 for v in labels.values() if v is None)}",
        f"- Planted flaws found: {len(found & set(planted))} of {len(planted)} "
        f"(missed: {', '.join(sorted(set(planted) - found)) or 'none'})",
        "",
    ]

    async def run(findings: list[Finding]) -> dict[str, Any]:
        before_c, before_r = await ConfidenceVerifier().verify(findings)
        report = await EvidenceVerifier(evidence_root).verify_detailed(findings)
        return {"before": (before_c, before_r), "after": report}

    lines += [
        "| | Before (confidence rule only) | After (EvidenceVerifier) |",
        "|---|---|---|",
    ]
    r = await run([f for _, f in real])
    before_c, _ = r["before"]
    after = r["after"]
    original = {f.id: f for _, f in real}
    sev_changes = sum(
        1 for f in after.confirmed + after.needs_review if f.severity != original[f.id].severity
    )
    lines += [
        f"| Findings that count toward the score | {len(before_c)} | {len(after.confirmed)} |",
        f"| Marked `verified` (evidence re-checked) | {sum(f.verified for f in before_c)} | "
        f"{sum(f.verified for f in after.confirmed)} |",
        f"| True findings lost | 0 | " f"{sum(1 for f in after.needs_review if labels[f.id])} |",
        f"| Severity corrected to the brief 5.11 guide | 0 | {sev_changes} |",
        f"| Release score | {_score(before_c)} | {_score(after.confirmed)} |",
        "",
        "## With injected faults (6 realistic false positives / duplicates added to the real run)",
        "",
        "| Fault | Before | After |",
        "|---|---|---|",
    ]
    mixed = [f for _, f in real] + [f for _, f in faults]
    r = await run(mixed)
    before_c, _ = r["before"]
    after = r["after"]
    before_ids = {f.id for f in before_c}
    confirmed_ids = {f.id for f in after.confirmed}
    review_ids = {f.id for f in after.needs_review}
    for kind, f in faults:
        if f.id in after.merged:
            outcome = "merged into the original"
        elif f.id in confirmed_ids:
            outcome = "**still counted**"
        elif f.id in review_ids:
            outcome = "needs manual review (not scored)"
        else:
            outcome = "dropped"
        lines.append(
            f"| {kind.removeprefix('fault:').replace('_', ' ')} | "
            f"{'counted' if f.id in before_ids else 'not counted'} | {outcome} |"
        )
    fp_before = sum(1 for f in before_c if f.id in fault_kind)
    fp_after = sum(1 for f in after.confirmed if f.id in fault_kind)
    lost = sum(1 for f in after.needs_review if labels.get(f.id))
    lines += [
        "",
        f"- Faults that reached the score: **{fp_before} of {len(faults)} before, "
        f"{fp_after} of {len(faults)} after**",
        f"- Real findings lost to review or merging: {lost}",
        f"- Release score: before {_score(before_c)}, after {_score(after.confirmed)} "
        f"(true score of the real findings alone: "
        f"{_score(f for f in r['after'].confirmed if f.id not in fault_kind)})",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, default=Path(".agent-eval"))
    args = parser.parse_args()
    work = args.work.resolve()
    scan_dir = work / (work / "latest.txt").read_text().strip()
    print(asyncio.run(evaluate(scan_dir, work)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
