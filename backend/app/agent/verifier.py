"""Verifier (brief 6.7): re-check, dedupe, confidence, severity, "needs manual review".

The verifier never contacts the target. Containment (brief 12) means only the sandbox talks
to scanned sites, so the backend re-validates each finding against the evidence that sandbox
captured on disk:

1. **Evidence check**: every cited file must exist inside that task's ``out/`` directory.
2. **Response re-check**: the task's ``network_summary.json`` must hold a record for the
   finding's page that supports it (a ``leak`` entry for ``error_leak``, ``exposed`` for
   ``exposed_endpoints``, ``set_cookie`` for ``cookies``...). A record saying the check
   *skipped* that page contradicts the finding.
   A claim the evidence does not back is capped below ``MIN_CONFIDENCE``: it can never
   count toward the score, only go to manual review.
3. **Optional LLM judgement** (corroborated findings with borderline confidence only,
   bounded budget): the model sees
   the finding's claim and the redacted, fenced evidence text, nothing else, and answers
   ``{"supported": true|false}``. Any failure leaves the finding unchanged.
4. **Severity** is clamped to the range brief 5.11 gives each kind of issue.
5. **Dedupe**: same check, same page (or same site for site-wide checks), same title are
   merged into one finding with the union of the evidence.

``verified`` is True only when the evidence exists and was corroborated. Findings under
``MIN_CONFIDENCE`` go to the "needs manual review" bucket: kept, never scored.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit
from uuid import UUID

from agentguard_contracts import Finding, Severity

from app.agent.inference import ChatModel, InferenceError, extract_json
from app.agent.plan_schema import clean_text
from app.agent.untrusted import UNTRUSTED_RULES, untrusted_block

log = logging.getLogger(__name__)

MIN_CONFIDENCE: Final = 0.5
NETWORK_SUMMARY: Final = "network_summary.json"
MAX_SUMMARY_BYTES: Final = 2_000_000
LLM_BAND: Final = (0.35, 0.7)
"""Only findings whose confidence is in this band are worth an LLM opinion."""
DEFAULT_LLM_BUDGET: Final = 8

MISSING_EVIDENCE: Final = 0.25
NO_EVIDENCE: Final = 0.2
NO_RECORD: Final = 0.1
SKIPPED_PAGE: Final = 0.3
NO_REPRO: Final = 0.1
CORROBORATED: Final = 0.05
LLM_STEP: Final = 0.15
UNCORROBORATED_CAP: Final = 0.45
"""A claim the evidence does not back (missing files, no supporting record, a page the check
skipped) can never be scored: it goes to manual review, whatever the check's own confidence."""

_ORDER: Final = list(Severity)  # critical first
_TASK_DIR_UNSAFE = re.compile(r"[^a-zA-Z0-9_.-]")  # same rule as the launcher and the API

SEVERITY_BOUNDS: Final[dict[str, tuple[Severity, Severity]]] = {
    # (lowest, highest) per brief 5.11: critical = immediate risk (exposed admin, broken auth),
    # high = likely exploitable or revenue-impacting, medium = hygiene, low = improvement.
    # Every range contains every severity the check modules themselves emit (checked against
    # sandbox-worker/checks), so bounds only correct clear guide violations: an open redirect
    # is high, missing headers are never critical, a failed checkout is never minor.
    "security.exposed_endpoints": (Severity.MEDIUM, Severity.CRITICAL),
    "security.error_leak": (Severity.LOW, Severity.HIGH),
    "security.open_redirect": (Severity.HIGH, Severity.HIGH),
    "security.reflected_input": (Severity.MEDIUM, Severity.HIGH),
    "security.url_session_leak": (Severity.MEDIUM, Severity.HIGH),
    "security.login_rate_probe": (Severity.MEDIUM, Severity.HIGH),
    "security.https_redirect": (Severity.MEDIUM, Severity.HIGH),
    "security.headers": (Severity.LOW, Severity.MEDIUM),
    "security.cookies": (Severity.LOW, Severity.HIGH),
    "qa.checkout": (Severity.HIGH, Severity.CRITICAL),
    "qa.login": (Severity.MEDIUM, Severity.CRITICAL),
    "qa.password_reset": (Severity.LOW, Severity.HIGH),
    "qa.pages_load": (Severity.LOW, Severity.HIGH),
    "qa.forms": (Severity.LOW, Severity.HIGH),
    "qa.search": (Severity.LOW, Severity.HIGH),
    "qa.links_assets": (Severity.LOW, Severity.HIGH),
    "qa.console_network_errors": (Severity.LOW, Severity.MEDIUM),
    "qa.accessibility": (Severity.LOW, Severity.MEDIUM),
}

SUPPORT_KEYS: Final[dict[str, tuple[str, ...]]] = {
    "security.error_leak": ("leak",),
    "security.exposed_endpoints": ("exposed",),
    "security.cookies": ("set_cookie",),
    "security.headers": ("headers", "status"),
    "security.https_redirect": ("status",),
}
"""Keys a network record must carry to support a finding of that check. Checks not listed
are supported by any non-skipped record for the page."""

SITE_WIDE: Final = frozenset({"security.headers", "security.https_redirect"})
"""Checks whose findings describe the whole site: one finding per site, not per page."""

VERIFY_SYSTEM = f"""You double-check one finding from an automated website QA/security test.
Decide only whether the evidence text supports the claim. Answer with ONE JSON object:
{{"supported": true or false, "reason": "<one short sentence>"}}
{UNTRUSTED_RULES}"""


@dataclass
class Verdict:
    """What the verifier concluded about one finding."""

    finding: Finding
    notes: list[str] = field(default_factory=list)
    merged: list[UUID] = field(default_factory=list)


@dataclass
class VerificationReport:
    confirmed: list[Finding]
    needs_review: list[Finding]
    merged: dict[UUID, UUID]
    """Duplicate finding id -> id of the finding it was merged into."""
    notes: dict[UUID, list[str]]


def _norm_url(url: str, site_wide: bool) -> str:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return url.strip().lower()
    default = {"http": 80, "https": 443}.get(parts.scheme.lower())
    netloc = host if port in (None, default) else f"{host}:{port}"
    if site_wide:
        return netloc
    path = parts.path.rstrip("/") or "/"
    return f"{netloc}{path}"


def _bounded(severity: Severity, check_id: str) -> Severity:
    low, high = SEVERITY_BOUNDS.get(check_id, (Severity.LOW, Severity.CRITICAL))
    idx = _ORDER.index(severity)
    return _ORDER[min(max(idx, _ORDER.index(high)), _ORDER.index(low))]


def _task_dir(name: str) -> str | None:
    task_id, sep, _ = name.partition("__")
    if not sep or not task_id:
        return None
    task_dir = _TASK_DIR_UNSAFE.sub("-", task_id)
    return None if set(task_dir) <= {"."} else task_dir  # "." / ".." would leave the scan dir


class EvidenceVerifier:
    """Implements the orchestrator's ``Verifier`` protocol."""

    def __init__(
        self,
        evidence_root: Path,
        model: ChatModel | None = None,
        *,
        llm_budget: int = DEFAULT_LLM_BUDGET,
    ) -> None:
        self.evidence_root = evidence_root
        self.model = model
        self.llm_budget = llm_budget

    # -- evidence on disk -------------------------------------------------------------------

    def _out_dir(self, scan_id: UUID, task_dir: str) -> Path:
        return (self.evidence_root / str(scan_id) / task_dir / "out").resolve()

    def _evidence_file(self, scan_id: UUID, name: str) -> Path | None:
        task_dir = _task_dir(name)
        if task_dir is None:
            return None
        file_name = name.partition("__")[2]
        if not file_name or file_name.startswith(".") or "/" in file_name or "\\" in file_name:
            return None
        out = self._out_dir(scan_id, task_dir)
        for candidate in (out / "screenshots" / file_name, out / file_name):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if candidate.resolve().is_relative_to(out) and candidate.stat().st_size > 0:
                return candidate
        return None

    def _records(self, path: Path, cache: dict[Path, list[dict[str, Any]] | None]) -> Any:
        if path not in cache:
            records: list[dict[str, Any]] | None = None
            try:
                if path.stat().st_size <= MAX_SUMMARY_BYTES:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        records = [r for r in data if isinstance(r, dict)]
            except (OSError, ValueError):
                records = None
            cache[path] = records
        return cache[path]

    # -- one finding ------------------------------------------------------------------------

    def _check(
        self, f: Finding, cache: dict[Path, list[dict[str, Any]] | None]
    ) -> tuple[float, bool, list[str], list[dict[str, Any]]]:
        """Deterministic re-check: (confidence delta, corroborated, notes, supporting records)."""
        notes: list[str] = []
        delta = 0.0
        if not f.evidence:
            delta -= NO_EVIDENCE
            notes.append("no evidence attached")
        files = {name: self._evidence_file(f.scan_id, name) for name in f.evidence}
        missing = [name for name, path in files.items() if path is None]
        if missing:
            delta -= MISSING_EVIDENCE
            notes.append(f"evidence missing: {', '.join(missing[:3])}")
        if not [s for s in f.reproduction if s.strip()]:
            delta -= NO_REPRO
            notes.append("no reproduction steps")

        summaries = [
            path
            for name, path in files.items()
            if path is not None and name.partition("__")[2] == NETWORK_SUMMARY
        ]
        if not summaries:
            # Screenshot-only evidence (DOM checks): corroborated when every file exists.
            return delta, bool(f.evidence) and not missing, notes, []

        page = _norm_url(f.url, False)
        matching = [
            r
            for path in summaries
            for r in (self._records(path, cache) or [])
            if isinstance(r.get("url"), str) and _norm_url(r["url"], False) == page
        ]
        keys = SUPPORT_KEYS.get(f.check_id)
        support = [
            r
            for r in matching
            if "skipped" not in r and (keys is None or any(r.get(k) is not None for k in keys))
        ]
        if any("skipped" in r for r in matching):
            # Checks record a page load, then "skipped" when there was nothing to test there
            # (no form, no search box): the check itself says it never tested this page.
            notes.append("the check recorded that it skipped this page")
            return delta - SKIPPED_PAGE, False, notes, []
        if support:
            return delta + CORROBORATED, not missing, notes, support
        notes.append("no network record supports this finding")
        return delta - NO_RECORD, False, notes, []

    async def _llm_opinion(self, f: Finding, records: list[dict[str, Any]]) -> float:
        if self.model is None:
            return 0.0
        claim = {
            "title": f.title,
            "check": f.check_id,
            "severity": f.severity.value,
            "impact": f.impact,
            "reproduction": f.reproduction[:6],
        }
        user = (
            "Claim:\n"
            + untrusted_block("finding", json.dumps(claim, indent=1), 1500)
            + "\n\nEvidence records:\n"
            + untrusted_block("evidence", json.dumps(records[:5], indent=1), 3000)
        )
        try:
            answer = extract_json(await self.model.complete(VERIFY_SYSTEM, user))
        except (InferenceError, ValueError) as exc:
            log.info("verifier LLM opinion skipped: %s", exc)
            return 0.0
        supported = answer.get("supported") if isinstance(answer, dict) else None
        if supported is True:
            return LLM_STEP
        if supported is False:
            return -LLM_STEP
        return 0.0

    # -- the protocol -----------------------------------------------------------------------

    async def verify(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        report = await self.verify_detailed(findings)
        return report.confirmed, report.needs_review

    async def verify_detailed(self, findings: list[Finding]) -> VerificationReport:
        cache: dict[Path, list[dict[str, Any]] | None] = {}
        budget = self.llm_budget
        verdicts: list[Verdict] = []
        for f in findings:
            delta, corroborated, notes, records = self._check(f, cache)
            confidence = min(1.0, max(0.0, f.confidence + delta))
            if not corroborated:
                confidence = min(confidence, UNCORROBORATED_CAP)
            elif self.model is not None and budget > 0 and LLM_BAND[0] <= confidence < LLM_BAND[1]:
                # The model may only weigh evidence that exists; it can't rescue a claim
                # the evidence does not back.
                budget -= 1
                step = await self._llm_opinion(f, records)
                if step:
                    confidence = min(1.0, max(0.0, confidence + step))
                    notes.append("LLM: evidence supports it" if step > 0 else "LLM: not supported")
            severity = _bounded(f.severity, f.check_id)
            if severity is not f.severity:
                notes.append(f"severity {f.severity.value} -> {severity.value} (brief 5.11)")
            updated = f.model_copy(
                update={
                    "confidence": round(confidence, 2),
                    "severity": severity,
                    "verified": corroborated and confidence >= MIN_CONFIDENCE,
                }
            )
            verdicts.append(Verdict(updated, notes))

        kept = dedupe(verdicts)
        merged = {dup: v.finding.id for v in kept for dup in v.merged}
        confirmed = [v.finding for v in kept if v.finding.confidence >= MIN_CONFIDENCE]
        review = [v.finding for v in kept if v.finding.confidence < MIN_CONFIDENCE]
        notes_by_id = {v.finding.id: v.notes for v in kept if v.notes}
        log.info(
            "verified %d findings: %d confirmed, %d need review, %d merged",
            len(findings),
            len(confirmed),
            len(review),
            len(merged),
        )
        return VerificationReport(confirmed, review, merged, notes_by_id)


def _dedupe_key(f: Finding) -> tuple[str, str, str]:
    title = " ".join(clean_text(f.title, 300).lower().split())
    return f.check_id, _norm_url(f.url, f.check_id in SITE_WIDE), title


def dedupe(verdicts: Iterable[Verdict]) -> list[Verdict]:
    """Merge duplicates. The strongest finding (severity, then confidence) represents the
    group; it takes the union of the evidence, the best confidence, and ``verified`` if any
    member was verified. Order of first appearance is kept."""
    groups: dict[tuple[str, str, str], list[Verdict]] = {}
    for v in verdicts:
        groups.setdefault(_dedupe_key(v.finding), []).append(v)
    out: list[Verdict] = []
    for members in groups.values():
        if len(members) == 1:
            out.append(members[0])
            continue
        # A verified member always represents the group: an unbacked duplicate must not lend
        # its severity or confidence to it.
        best = min(
            members,
            key=lambda v: (
                not v.finding.verified,
                _ORDER.index(v.finding.severity),
                -v.finding.confidence,
            ),
        )
        peers = [v for v in members if v.finding.verified == best.finding.verified]
        # Only peers (same verified status as the representative) contribute: an unbacked
        # duplicate's evidence may not exist, and its pages were never confirmed.
        evidence = list(dict.fromkeys(e for v in peers for e in v.finding.evidence))
        others = sorted({v.finding.url for v in peers if v.finding.url != best.finding.url})
        reproduction = list(best.finding.reproduction)
        if others:
            reproduction.append(
                "Also seen on: " + ", ".join(clean_text(u, 200) for u in others[:5])
            )
        finding = best.finding.model_copy(
            update={
                "evidence": evidence,
                "confidence": max(v.finding.confidence for v in peers),
                "reproduction": reproduction,
            }
        )
        notes = [n for v in members for n in v.notes]
        notes.append(f"merged {len(members) - 1} duplicate(s)")
        merged = [v.finding.id for v in members if v is not best]
        out.append(Verdict(finding, list(dict.fromkeys(notes)), merged))
    return out
