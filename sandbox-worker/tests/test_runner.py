"""Runner behaviour against fake check modules and a fake page (no browser, no network)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from agentguard_contracts import SandboxResult, SandboxTaskInput

import runner
from checks.context import CheckContext, PolicyViolation, SameOriginPolicy

TARGET = "https://demo.example.com"
FINDING: dict[str, Any] = {
    "title": "Missing Content-Security-Policy header",
    "category": "security",
    "severity": "medium",
    "confidence": 0.9,
    "url": "https://demo.example.com/",
    "evidence": ["network_summary.json"],
    "reproduction": ["Open /", "Inspect response headers"],
    "impact": "No defence-in-depth against XSS.",
    "recommended_fix": "Send a restrictive Content-Security-Policy header.",
    "check_id": "security.headers",
}


class FakePage:
    def __init__(self) -> None:
        self.screenshots: list[str] = []

    async def screenshot(self, path: str, full_page: bool) -> None:
        await asyncio.to_thread(Path(path).write_bytes, b"fake-png")
        self.screenshots.append(path)


def make_task(timeout_s: int = 5) -> SandboxTaskInput:
    return SandboxTaskInput.model_validate(
        {
            "scan_id": "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d",
            "target_url": TARGET,
            "task": {
                "task_id": "t1",
                "check_id": "security.headers",
                "description": "headers",
                "params": {},
                "timeout_s": timeout_s,
            },
        }
    )


def make_check(run: Any) -> ModuleType:
    module = ModuleType("fake_check")
    module.CHECK_ID = "security.headers"  # type: ignore[attr-defined]
    module.run = run  # type: ignore[attr-defined]
    return module


async def _execute(run: Any, tmp_path: Path, timeout_s: int = 5) -> tuple[SandboxResult, int]:
    return await runner.execute(make_task(timeout_s), make_check(run), FakePage(), tmp_path)


async def test_execute_no_findings_passes(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        ctx.policy.assert_allowed(TARGET + "/")
        return []

    result, code = await _execute(run, tmp_path)
    assert (result.status.value, code) == ("passed", 0)
    assert result.task_id == "t1"
    assert result.policy_events[0]["decision"] == "allowed"
    assert json.loads((tmp_path / "network_summary.json").read_text()) == []


async def test_execute_findings_fail_and_record_evidence(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        shot = await ctx.screenshot("home")
        ctx.record_request({"url": TARGET, "status": 200})
        return [{**FINDING, "evidence": [shot, "network_summary.json"]}]

    result, code = await _execute(run, tmp_path)
    assert (result.status.value, code) == ("failed", 0)
    assert result.findings[0].evidence == ["home.png", "network_summary.json"]
    assert (tmp_path / "screenshots" / "home.png").exists()
    assert json.loads((tmp_path / "network_summary.json").read_text()) == [
        {"url": TARGET, "status": 200}
    ]


async def test_execute_policy_violation_blocks_with_exit_3(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        ctx.policy.assert_allowed("http://169.254.169.254/latest/meta-data/")
        return [FINDING]

    result, code = await _execute(run, tmp_path)
    assert (result.status.value, code) == ("blocked", 3)
    assert result.findings == []
    assert result.policy_events[-1]["decision"] == "blocked"
    assert result.policy_events[-1]["target"] == "http://169.254.169.254/latest/meta-data/"


async def test_execute_check_exception_is_error_exit_2(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        raise RuntimeError("boom")

    result, code = await _execute(run, tmp_path)
    assert (result.status.value, code) == ("error", 2)


async def test_execute_invalid_finding_is_error(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        return [{**FINDING, "severity": "info"}]

    result, code = await _execute(run, tmp_path)
    assert (result.status.value, code) == ("error", 2)
    assert result.findings == []


async def test_execute_timeout_is_error(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        await asyncio.sleep(5)
        return []

    result, code = await _execute(run, tmp_path, timeout_s=1)
    assert (result.status.value, code) == ("error", 2)
    assert result.duration_ms >= 900


def test_result_file_matches_contract(tmp_path: Path) -> None:
    result = SandboxResult(
        task_id="t1",
        status="passed",
        findings=[],
        duration_ms=3,
        policy_events=[],
    )
    runner.write_result(result, tmp_path)
    data = json.loads((tmp_path / "result.json").read_text())
    assert set(data) == {"task_id", "status", "findings", "duration_ms", "policy_events"}


@pytest.mark.parametrize("check_id", ["security.rce", "qa.forms; rm -rf /", "os.path"])
def test_load_check_rejects_non_whitelisted(check_id: str) -> None:
    with pytest.raises(LookupError):
        runner.load_check(check_id)


def test_load_check_whitelisted_but_missing_module() -> None:
    with pytest.raises(ImportError):
        runner.load_check("security.login_rate_probe")


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://demo.example.com/checkout", True),
        ("https://demo.example.com", True),
        ("http://demo.example.com/", True),  # same host, http<->https on default ports
        ("https://demo.example.com:8443/", False),
        ("https://evil.example.com/", False),
        ("https://demo.example.com.evil.com/", False),
        ("https://user:pw@demo.example.com/", False),
        ("http://localhost/", False),
        ("http://127.0.0.1/", False),
        ("http://169.254.169.254/", False),
        ("file:///etc/passwd", False),
        ("javascript:alert(1)", False),
    ],
)
def test_same_origin_policy(url: str, allowed: bool) -> None:
    policy = SameOriginPolicy(TARGET)
    if allowed:
        policy.assert_allowed(url)
    else:
        with pytest.raises(PolicyViolation):
            policy.assert_allowed(url)
    assert policy.events[-1]["decision"] == ("allowed" if allowed else "blocked")


@pytest.mark.parametrize("name", ["../escape", "a/b", "", "x" * 81, "shot name"])
async def test_screenshot_rejects_unsafe_names(tmp_path: Path, name: str) -> None:
    ctx = CheckContext(
        target_url=TARGET,
        params={},
        evidence_dir=tmp_path,
        policy=SameOriginPolicy(TARGET),
        page=FakePage(),
    )
    with pytest.raises(ValueError):
        await ctx.screenshot(name)


def test_main_rejects_invalid_task_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "task.json").write_text('{"task_id": "t1"}')
    monkeypatch.setenv("AGENTGUARD_IN", str(tmp_path))
    monkeypatch.setenv("AGENTGUARD_OUT", str(tmp_path / "out"))
    assert runner.main() == 2


async def test_execute_swallowed_policy_violation_still_blocks(tmp_path: Path) -> None:
    async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
        try:
            ctx.policy.assert_allowed("http://localhost/admin")
        except Exception:  # noqa: S110 - a misbehaving check hides the violation
            pass
        return [FINDING]

    result, code = await _execute(run, tmp_path)
    assert (result.status.value, code) == ("blocked", 3)
    assert result.findings == []


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://demo.example.com:443/", True),
        ("https://DEMO.example.com/", True),
        ("http://demo.example.com:443/", False),
        ("https://demo.example.com:abc/", False),
        ("https://demo.example.com:99999/", False),
    ],
)
def test_same_origin_policy_ports_and_case(url: str, allowed: bool) -> None:
    policy = SameOriginPolicy(TARGET)
    if allowed:
        policy.assert_allowed(url)
    else:
        with pytest.raises(PolicyViolation):
            policy.assert_allowed(url)


def test_main_maps_browser_failure_to_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "task.json").write_text(make_task().model_dump_json())
    monkeypatch.setenv("AGENTGUARD_IN", str(tmp_path))
    monkeypatch.setenv("AGENTGUARD_OUT", str(tmp_path / "out"))

    async def broken(*_: object) -> int:
        raise RuntimeError("chromium failed to launch")

    monkeypatch.setattr(runner, "_run_in_browser", broken)
    assert runner.main() == 2
