"""Agent planner (brief 6.3). Implements ``app.interfaces.Planner``.

``plan()``: ask the model for a structured plan, validate it, give it one repair round with
the exact validation errors, and fall back to the deterministic plan for anything else.
``summarize()``: a short executive summary; the deterministic summary is always computed and
used whenever the model is unavailable or answers badly.

The model never sees credentials, cookies or secrets: the prompt carries only the target's
origin and path (no userinfo, query or fragment), the profile, the check catalog and,
optionally, page text, which is redacted, truncated and fenced as untrusted data.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Literal

from agentguard_contracts import (
    MAX_TASKS_PER_PROFILE,
    Finding,
    ScanProfile,
    Severity,
    TestPlan,
)

from app.agent.catalog import CHECK_DESCRIPTIONS, PARAMS_BY_CHECK, PROFILE_CHECKS
from app.agent.fallback import fallback_plan
from app.agent.inference import ChatModel, InferenceError, extract_json
from app.agent.plan_schema import PlanValidationError, clean_text, validate_plan_payload
from app.agent.untrusted import UNTRUSTED_RULES, safe_url, untrusted_block

log = logging.getLogger(__name__)

PlanSource = Literal["llm", "llm_repaired", "fallback"]

MAX_SUMMARY_CHARS = 1200
MAX_FINDINGS_IN_PROMPT = 40
PAGE_CONTEXT_LIMIT = 3000
_LINK = re.compile(r"https?://|www\.|\b[a-z0-9-]+\.(?:com|net|org|io|ru|xyz|top)\b")

PLAN_SYSTEM = f"""You plan safe, non-destructive QA and security checks for a website.
Answer with ONE JSON object and nothing else:
{{"tasks": [{{"check_id": "<id from the catalog>", "description": "<short reason>",
"params": {{}}}}]}}
Rules:
- Use only check ids from the catalog you are given, at most once each unless the params
  differ, and never more tasks than the limit.
- Allowed params: "path" (a relative path such as "/checkout"), "paths" (list of relative
  paths, only for security.exposed_endpoints), "attempts" (1-3, only for
  security.login_rate_probe). Omit params when unsure.
- Put the most important checks first.
{UNTRUSTED_RULES}"""

SUMMARY_SYSTEM = f"""You write the executive summary of a website QA and security report for
a product manager. Plain English, 3 to 5 sentences, no lists, no markdown, no URLs. Say what
matters most and what to fix first. Use only the findings given; do not invent issues.
{UNTRUSTED_RULES}"""


def _plan_prompt(target_url: str, profile: ScanProfile, page_context: str | None) -> str:
    catalog = "\n".join(
        f"- {check_id}: {CHECK_DESCRIPTIONS[check_id]} (params: "
        f"{', '.join(sorted(PARAMS_BY_CHECK[check_id])) or 'none'})"
        for check_id in sorted(PROFILE_CHECKS[profile])
    )
    parts = [
        f"Target: {safe_url(target_url)}",
        f"Profile: {profile.value} (at most {MAX_TASKS_PER_PROFILE[profile]} tasks)",
        f"Catalog:\n{catalog}",
    ]
    if page_context:
        parts.append(
            "Home page text:\n" + untrusted_block("home_page", page_context, PAGE_CONTEXT_LIMIT)
        )
    return "\n\n".join(parts)


def _repair_prompt(original: str, answer: str, errors: list[str]) -> str:
    listed = "\n".join(f"- {clean_text(e, 200)}" for e in errors[:20])
    return (
        f"{original}\n\nYour previous answer was rejected:\n{listed}\n\n"
        f"Previous answer (for reference):\n{answer[:2000]}\n\n"
        "Return a corrected JSON object only."
    )


def deterministic_summary(findings: list[Finding]) -> str:
    """Summary built from counts and titles only. Never fails, never calls the network."""
    if not findings:
        return "No confirmed issues were found by the checks that ran."
    order = list(Severity)
    counts = Counter(f.severity for f in findings)
    parts = [f"{counts[s]} {s.value}" for s in order if counts[s]]
    ranked = sorted(findings, key=lambda f: (order.index(f.severity), -f.confidence))
    top = list(dict.fromkeys(clean_text(f.title, 120) for f in ranked))[:3]
    noun = "issue" if len(findings) == 1 else "issues"
    text = f"{len(findings)} confirmed {noun} ({', '.join(parts)}). Fix first: {'; '.join(top)}."
    if counts[Severity.CRITICAL] or counts[Severity.HIGH]:
        text += " The critical and high issues should be fixed before release."
    return text


class AgentPlanner:
    """The real planner. ``model=None`` means inference is not configured: fallback only."""

    def __init__(self, model: ChatModel | None, *, repair_rounds: int = 1) -> None:
        self.model = model
        self.repair_rounds = max(0, repair_rounds)

    async def plan(
        self, target_url: str, profile: ScanProfile, page_context: str | None = None
    ) -> TestPlan:
        plan, source, reason = await self.plan_with_source(target_url, profile, page_context)
        log.info("plan for %s (%s): %s, %s", safe_url(target_url), profile.value, source, reason)
        return plan

    async def plan_with_source(
        self, target_url: str, profile: ScanProfile, page_context: str | None = None
    ) -> tuple[TestPlan, PlanSource, str]:
        """Plan plus where it came from and why (for logs, tests and the eval)."""
        if self.model is None:
            return fallback_plan(target_url, profile), "fallback", "inference not configured"
        prompt = _plan_prompt(target_url, profile, page_context)
        user = prompt
        for round_no in range(self.repair_rounds + 1):
            try:
                answer = await self.model.complete(PLAN_SYSTEM, user)
            except InferenceError as exc:
                return fallback_plan(target_url, profile), "fallback", str(exc)
            try:
                plan = validate_plan_payload(
                    extract_json(answer), target_url=target_url, profile=profile
                )
                return plan, ("llm" if round_no == 0 else "llm_repaired"), "valid"
            except PlanValidationError as exc:
                errors = exc.errors
            except ValueError as exc:
                errors = [str(exc)]
            log.warning("plan round %d rejected: %s", round_no + 1, "; ".join(errors)[:300])
            user = _repair_prompt(prompt, answer, errors)
        return fallback_plan(target_url, profile), "fallback", "invalid after repair"

    async def summarize(self, findings: list[Finding]) -> str:
        fallback = deterministic_summary(findings)
        if self.model is None or not findings:
            return fallback
        rows = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "check": f.check_id,
                "page": safe_url(f.url, 120),
            }
            for f in sorted(findings, key=lambda f: list(Severity).index(f.severity))
        ][:MAX_FINDINGS_IN_PROMPT]
        user = "Findings:\n" + untrusted_block("findings", json.dumps(rows, indent=1), 6000)
        try:
            answer = await self.model.complete(SUMMARY_SYSTEM, user)
        except InferenceError as exc:
            log.warning("summary fell back: %s", exc)
            return fallback
        text = clean_text(answer, MAX_SUMMARY_CHARS + 1)
        lowered = text.lower()
        # A summary with links or fence tags is either off-brief or echoing injected content.
        if (
            not text
            or len(text) > MAX_SUMMARY_CHARS
            or "untrusted_data" in lowered
            or _LINK.search(lowered)
        ):
            log.warning("summary rejected, using the deterministic one")
            return fallback
        return text
