"""Sandbox entry point (brief 5.6). Owner: Arslan (Sandbox executor), reviewer: Ayesha.

Reads ``/in/task.json``, runs one whitelisted check module with Playwright, writes
``/out/result.json``, ``console.json``, ``network_summary.json`` and ``screenshots/``.
Exit codes: 0 ok, 2 check error, 3 policy violation.

The pure part (``execute``) takes the page and the check module as arguments so it can be
tested without a browser. ``main`` only wires up Playwright and the filesystem.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

from agentguard_contracts import (
    ALLOWED_CHECK_IDS,
    FindingDraft,
    SandboxExitCode,
    SandboxResult,
    SandboxResultStatus,
    SandboxTaskInput,
)
from pydantic import ValidationError

from checks.context import CheckContext, PolicyViolation, SameOriginPolicy


def load_check(check_id: str) -> ModuleType:
    """Import ``checks/<category>/<name>.py`` for a whitelisted check id."""
    if check_id not in ALLOWED_CHECK_IDS:
        raise LookupError(f"check id not whitelisted: {check_id}")
    category, name = check_id.split(".", 1)
    module = importlib.import_module(f"checks.{category}.{name}")
    if getattr(module, "CHECK_ID", None) != check_id or not callable(getattr(module, "run", None)):
        raise LookupError(f"checks.{category}.{name} must define CHECK_ID={check_id!r} and run()")
    return module


async def execute(
    task_input: SandboxTaskInput, check: ModuleType, page: Any, out_dir: Path
) -> tuple[SandboxResult, int]:
    """Run one check and build its ``result.json`` and exit code. Never raises."""
    task = task_input.task
    policy = SameOriginPolicy(task_input.target_url)
    ctx = CheckContext(
        target_url=task_input.target_url,
        params=task.params,
        evidence_dir=out_dir,
        policy=policy,
        page=page,
    )
    started = time.monotonic()
    findings: list[FindingDraft] = []
    try:
        raw = await asyncio.wait_for(check.run(page, ctx), timeout=task.timeout_s)
        findings = [FindingDraft.model_validate(item) for item in raw]
        status = SandboxResultStatus.FAILED if findings else SandboxResultStatus.PASSED
        code = SandboxExitCode.OK
    except PolicyViolation:
        status, code = SandboxResultStatus.BLOCKED, SandboxExitCode.POLICY_VIOLATION
    except Exception as exc:  # timeout, bad finding shape, or a bug in the check: reported
        print(f"check {task.check_id} failed: {type(exc).__name__}: {exc}"[:2000], file=sys.stderr)
        status, code = SandboxResultStatus.ERROR, SandboxExitCode.CHECK_ERROR

    # A check must not be able to swallow a PolicyViolation and carry on: any blocked
    # decision makes the whole task blocked, so the sandbox self-terminates (exit 3).
    if any(event.get("decision") == "blocked" for event in policy.events):
        status, code = SandboxResultStatus.BLOCKED, SandboxExitCode.POLICY_VIOLATION
        findings = []

    result = SandboxResult(
        task_id=task.task_id,
        status=status,
        findings=findings,
        duration_ms=int((time.monotonic() - started) * 1000),
        policy_events=policy.events,
    )
    await asyncio.to_thread(out_dir.mkdir, parents=True, exist_ok=True)
    summary = json.dumps(ctx.requests, indent=2)
    await asyncio.to_thread((out_dir / "network_summary.json").write_text, summary)
    return result, code


def write_result(result: SandboxResult, out_dir: Path) -> None:
    """Write ``result.json`` (5.6 shape)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "result.json").write_text(result.model_dump_json(indent=2))


async def _run_in_browser(task_input: SandboxTaskInput, out_dir: Path) -> int:
    from playwright.async_api import async_playwright  # imported lazily: tests need no browser

    try:
        check = load_check(task_input.task.check_id)
    except (LookupError, ImportError) as exc:
        print(f"cannot load check: {exc}", file=sys.stderr)
        write_result(
            SandboxResult(
                task_id=task_input.task.task_id,
                status=SandboxResultStatus.ERROR,
                findings=[],
                duration_ms=0,
                policy_events=[],
            ),
            out_dir,
        )
        return SandboxExitCode.CHECK_ERROR

    console: list[dict[str, str]] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:
            page = await browser.new_page()
            page.on("console", lambda m: console.append({"type": m.type, "text": m.text[:2000]}))
            result, code = await execute(task_input, check, page, out_dir)
        finally:
            await browser.close()
    (out_dir / "console.json").write_text(json.dumps(console, indent=2))
    write_result(result, out_dir)
    return code


def main() -> int:
    """Container entry point."""
    in_file = Path(os.environ.get("AGENTGUARD_IN", "/in")) / "task.json"
    out_dir = Path(os.environ.get("AGENTGUARD_OUT", "/out"))
    try:
        task_input = SandboxTaskInput.model_validate_json(in_file.read_text())
    except (OSError, ValidationError) as exc:
        print(f"invalid task input: {exc}", file=sys.stderr)
        return SandboxExitCode.CHECK_ERROR
    try:
        return asyncio.run(_run_in_browser(task_input, out_dir))
    except Exception as exc:  # e.g. the browser failed to launch: keep exit codes in contract
        print(f"sandbox failure: {type(exc).__name__}: {exc}"[:2000], file=sys.stderr)
        return SandboxExitCode.CHECK_ERROR


if __name__ == "__main__":
    sys.exit(main())
