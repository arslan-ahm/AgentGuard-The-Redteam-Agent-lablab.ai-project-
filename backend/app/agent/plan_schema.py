"""Plan schema + validator (brief 5.5, 6.3).

Turns whatever the LLM returned into a contract ``TestPlan`` or a list of precise errors (fed
back to the model in the repair prompt). Nothing the model says is trusted:

- only whitelisted check ids, and only the ones the scan's profile allows;
- at most ``MAX_TASKS_PER_PROFILE[profile]`` tasks, no duplicates;
- params limited to an allowlist per check; paths must be same-origin relative paths;
- task ids, timeouts and the target URL are set here, never taken from the model.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from uuid import UUID, uuid4

from agentguard_contracts import (
    ALLOWED_CHECK_IDS,
    MAX_TASKS_PER_PROFILE,
    PlanTask,
    ScanProfile,
    TestPlan,
)

from app.agent.catalog import (
    CHECK_DESCRIPTIONS,
    MAX_LOGIN_ATTEMPTS,
    MAX_PATH_LEN,
    MAX_PATHS,
    MAX_TIMEOUT_S,
    MIN_TIMEOUT_S,
    PARAMS_BY_CHECK,
    PROFILE_CHECKS,
    timeout_for,
)

MAX_DESCRIPTION = 200
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$")
"""A relative path (optionally with a query). No scheme, no host, no spaces, no fragments."""


class PlanValidationError(ValueError):
    """The payload is not a valid plan. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def clean_text(value: str, limit: int) -> str:
    """Printable single-line text: control and format characters removed, length bounded."""
    out = "".join(
        " " if ch in "\r\n\t" else ch
        for ch in value
        if ch in "\r\n\t" or unicodedata.category(ch)[0] != "C"
    )
    return " ".join(out.split())[:limit]


def safe_path(value: object) -> str | None:
    """``value`` if it is a same-origin relative path the sandbox checks accept, else None."""
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LEN:
        return None
    if value.startswith("//") or "\\" in value or ".." in value.split("?", 1)[0].split("/"):
        return None
    return value if _PATH.fullmatch(value) else None


def _params(check_id: str, raw: object, where: str, errors: list[str]) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append(f"{where}: params must be an object")
        return {}
    allowed = PARAMS_BY_CHECK[check_id]
    params: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in allowed:
            errors.append(f"{where}: param '{key}' is not allowed for {check_id}")
        elif key == "path":
            path = safe_path(value)
            if path is None:
                errors.append(f"{where}: path must be a relative path like /checkout")
            else:
                params["path"] = path
        elif key == "paths":
            if not isinstance(value, list) or not value or len(value) > MAX_PATHS:
                errors.append(f"{where}: paths must be a list of 1-{MAX_PATHS} relative paths")
                continue
            paths = [safe_path(p) for p in value]
            if any(p is None for p in paths):
                errors.append(f"{where}: every entry in paths must be a relative path")
            else:
                params["paths"] = list(dict.fromkeys(p for p in paths if p))
        elif key == "attempts":
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                errors.append(f"{where}: attempts must be a positive integer")
            else:
                params["attempts"] = min(value, MAX_LOGIN_ATTEMPTS)
    return params


def validate_plan_payload(
    payload: object,
    *,
    target_url: str,
    profile: ScanProfile,
    scan_id: UUID | None = None,
) -> TestPlan:
    """Validate a model's JSON (``{"tasks": [{"check_id", "description"?, "params"?}]}``).

    Raises ``PlanValidationError`` with every problem, so one repair round can fix them all.
    """
    errors: list[str] = []
    if not isinstance(payload, dict):
        raise PlanValidationError(['the answer must be a JSON object with a "tasks" list'])
    raw_tasks = payload.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise PlanValidationError(['"tasks" must be a non-empty list'])

    cap = MAX_TASKS_PER_PROFILE[profile]
    if len(raw_tasks) > cap:
        errors.append(f"{len(raw_tasks)} tasks; the {profile.value} profile allows at most {cap}")

    allowed_here = PROFILE_CHECKS[profile]
    tasks: list[PlanTask] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_tasks[: cap * 2], start=1):  # bound work on huge answers
        where = f"task {i}"
        if not isinstance(raw, dict):
            errors.append(f"{where}: must be an object")
            continue
        check_id = raw.get("check_id")
        if not isinstance(check_id, str) or check_id not in ALLOWED_CHECK_IDS:
            errors.append(f"{where}: unknown check_id {str(check_id)[:60]!r}")
            continue
        if check_id not in allowed_here:
            errors.append(f"{where}: {check_id} is not part of the {profile.value} profile")
            continue
        params = _params(check_id, raw.get("params"), where, errors)
        key = f"{check_id}|{sorted(params.items())!r}"
        if key in seen:
            errors.append(f"{where}: duplicate of an earlier task ({check_id})")
            continue
        seen.add(key)
        description = raw.get("description")
        text = clean_text(description, MAX_DESCRIPTION) if isinstance(description, str) else ""
        timeout = min(max(timeout_for(check_id), MIN_TIMEOUT_S), MAX_TIMEOUT_S)
        tasks.append(
            PlanTask(
                task_id=f"t{len(tasks) + 1}",
                check_id=check_id,
                description=text or CHECK_DESCRIPTIONS[check_id],
                params=params,
                timeout_s=timeout,
            )
        )

    if errors:
        raise PlanValidationError(errors)
    return TestPlan(scan_id=scan_id or uuid4(), target_url=target_url, profile=profile, tasks=tasks)
