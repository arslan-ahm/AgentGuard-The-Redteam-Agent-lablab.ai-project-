"""Sandbox launcher (brief 6.4): docker argv, lifecycle, teardown, result handling, audit.

No Docker needed: ``FakeCommands`` plays the container and writes ``result.json`` into the
``/out`` bind mount exactly like the real sandbox would.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from agentguard_contracts import AuditEvent, SandboxResult, SandboxTaskInput

from app.config import Settings
from app.interfaces import SandboxRunner
from app.sandbox.launcher import (
    BROWSER_STARTUP_GRACE_S,
    DockerSandboxRunner,
    SandboxLimits,
    SubprocessRunner,
    build_docker_run_args,
    container_name,
    refuse_unsafe_mount,
    sanitize_out_dir,
)

SCAN = "0b6c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"
TARGET = "https://demo.example.com"
FINDING: dict[str, Any] = {
    "title": "Missing Content-Security-Policy header",
    "category": "security",
    "severity": "medium",
    "confidence": 0.9,
    "url": TARGET + "/",
    "evidence": ["network_summary.json"],
    "reproduction": ["Open /"],
    "impact": "x",
    "recommended_fix": "y",
    "check_id": "security.headers",
}


def make_task(task_id: str = "t1", timeout_s: int = 60) -> SandboxTaskInput:
    return SandboxTaskInput.model_validate(
        {
            "scan_id": SCAN,
            "target_url": TARGET,
            "task": {
                "task_id": task_id,
                "check_id": "security.headers",
                "description": "headers",
                "params": {},
                "timeout_s": timeout_s,
            },
        }
    )


def result_json(status: str = "passed", task_id: str = "t1", **extra: Any) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "status": status,
        "findings": [],
        "duration_ms": 12,
        "policy_events": [],
        **extra,
    }


Container = Callable[[Path, Path], int]


class FakeCommands:
    """Records every argv. ``docker run`` calls ``container(in_dir, out_dir)``."""

    def __init__(self, container: Container | None = None, *, hang: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []
        self.container = container or (lambda i, o: _write(o, result_json()))
        self.hang = hang
        self.fail_rm = False

    async def run(self, args: Sequence[str], timeout_s: float) -> tuple[int, str]:
        self.calls.append(list(args))
        self.timeouts.append(timeout_s)
        if args[:2] == ["docker", "rm"]:
            if self.fail_rm:
                raise OSError("docker daemon gone")
            return 0, ""
        if self.hang:
            raise TimeoutError
        mounts = [args[i + 1] for i, a in enumerate(args) if a == "--mount"]
        src = {
            m.split("target=")[1].split(",")[0]: m.split("source=")[1].split(",")[0] for m in mounts
        }
        task = json.loads((Path(src["/in"]) / "task.json").read_text())
        assert task["scan_id"] == SCAN
        return self.container(Path(src["/in"]), Path(src["/out"])), "stderr tail"

    @property
    def run_calls(self) -> list[list[str]]:
        return [c for c in self.calls if c[:2] == ["docker", "run"]]

    @property
    def rm_calls(self) -> list[list[str]]:
        return [c for c in self.calls if c[:2] == ["docker", "rm"]]


def _write(out: Path, data: dict[str, Any], code: int = 0) -> int:
    (out / "result.json").write_text(json.dumps(data))
    return code


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> None:
        self.events.append(event)

    def actions(self) -> list[tuple[str, str]]:
        return [(e.action, e.decision.value) for e in self.events]


class FakePolicy:
    def __init__(self, blocked: bool = False) -> None:
        self.blocked = blocked
        self.checked: list[str] = []

    async def assert_allowed(self, url: str) -> None:
        self.checked.append(url)
        if self.blocked:
            err = ValueError("blocked")
            err.reason = "non-public address 127.0.0.1"  # type: ignore[attr-defined]
            raise err


def make_runner(
    tmp_path: Path,
    commands: FakeCommands,
    *,
    policy: FakePolicy | None = None,
    limits: SandboxLimits | None = None,
) -> tuple[DockerSandboxRunner, FakeAudit]:
    audit = FakeAudit()
    runner = DockerSandboxRunner(
        image="agentguard-sandbox:test",
        work_root=tmp_path / "work",
        limits=limits or SandboxLimits(),
        policy=policy or FakePolicy(),
        audit=audit,
        commands=commands,
    )
    return runner, audit


# --- docker argv ---------------------------------------------------------------------


def _args(tmp_path: Path, **kw: Any) -> list[str]:
    (tmp_path / "in").mkdir(exist_ok=True)
    (tmp_path / "out").mkdir(exist_ok=True)
    return build_docker_run_args(
        name="ag-test",
        image="agentguard-sandbox:test",
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        limits=SandboxLimits(cpus="0.5", memory="512m", pids=128),
        **kw,
    )


def _flag(args: list[str], flag: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == flag]


def test_args_contain_every_containment_flag(tmp_path: Path) -> None:
    args = _args(tmp_path)
    assert args[:3] == ["docker", "run", "--rm"]
    for flag in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
        assert flag in args
    assert _flag(args, "--cpus") == ["0.5"]
    assert _flag(args, "--memory") == ["512m"]
    assert _flag(args, "--memory-swap") == ["512m"]  # no swap beyond the memory limit
    assert _flag(args, "--pids-limit") == ["128"]
    assert _flag(args, "--network") == ["agentguard-sandbox"]
    assert _flag(args, "--tmpfs") == ["/tmp:rw,noexec,nosuid,nodev,size=256m"]  # noqa: S108
    assert args[-1] == "agentguard-sandbox:test"


def test_args_mount_only_in_readonly_and_out(tmp_path: Path) -> None:
    args = _args(tmp_path)
    mounts = _flag(args, "--mount")
    assert len(mounts) == 2
    assert mounts[0].endswith("target=/in,readonly")
    assert mounts[1].endswith("target=/out")
    assert "-v" not in args and "--volume" not in args and "--volumes-from" not in args
    joined = " ".join(args)
    assert "docker.sock" not in joined
    for forbidden in ("--privileged", "--cap-add", "--pid", "--ipc", "--userns", "--device"):
        assert not any(a == forbidden or a.startswith(forbidden + "=") for a in args)


def test_args_never_carry_secrets(tmp_path: Path) -> None:
    envs = _flag(_args(tmp_path), "--env")
    assert envs == ["HOME=/tmp", "AGENTGUARD_IN=/in", "AGENTGUARD_OUT=/out"]


def test_args_pin_hosts_and_labels(tmp_path: Path) -> None:
    args = _args(
        tmp_path,
        pinned_hosts={"demo.example.com": ["93.184.215.14", "2606:2800::1"]},
        labels={"agentguard.scan_id": SCAN},
    )
    assert _flag(args, "--add-host") == [
        "demo.example.com:93.184.215.14",
        "demo.example.com:2606:2800::1",
    ]
    assert _flag(args, "--label") == [f"agentguard.scan_id={SCAN}"]


@pytest.mark.parametrize("network", ["host", "bridge", "default", "container:postgres"])
def test_args_refuse_unfiltered_networks(tmp_path: Path, network: str) -> None:
    with pytest.raises(ValueError, match="network"):
        _args(tmp_path, network=network)


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/etc",
        "/etc/passwd",
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/user/1000",
        "/proc/1/root",
        "/sys/fs",
        "/dev/sda",
        "/root/.ssh",
        "/var/lib/docker/volumes",
        "/home",
        "/srv/agentguard/docker.sock",
    ],
)
def test_refuse_unsafe_mount_blocks(path: str) -> None:
    with pytest.raises(ValueError, match="refusing to mount"):
        refuse_unsafe_mount(PurePosixPath(path))


@pytest.mark.parametrize(
    "path",
    ["/var/lib/agentguard/work/scan/t1/in", "/srv/agentguard/x", "/home/ag/etcetera/out"],
)
def test_refuse_unsafe_mount_allows_work_dirs(path: str) -> None:
    refuse_unsafe_mount(PurePosixPath(path))


def test_args_refuse_docker_socket_anywhere(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="refusing to mount"):
        build_docker_run_args(
            name="x",
            image="i",
            in_dir=tmp_path / "docker.sock",
            out_dir=tmp_path,
            limits=SandboxLimits(),
        )


def test_container_name_is_unique_and_docker_safe() -> None:
    task = make_task(task_id="t1; rm -rf / $(x)")
    a, b = container_name(task), container_name(task)
    assert a != b
    assert a.startswith("ag-0b6c1d2e-")
    assert all(ch.isalnum() or ch in "_.-" for ch in a)


def test_limits_from_settings() -> None:
    settings = Settings(sandbox_cpu_limit="2", sandbox_mem_limit="2g", sandbox_timeout_s=90)
    assert SandboxLimits.from_settings(settings) == SandboxLimits(
        cpus="2", memory="2g", max_wall_s=90
    )


# --- lifecycle -----------------------------------------------------------------------


def test_runner_satisfies_protocol(tmp_path: Path) -> None:
    runner: SandboxRunner = make_runner(tmp_path, FakeCommands())[0]
    assert runner is not None


async def test_run_passed_returns_result_and_destroys(tmp_path: Path) -> None:
    commands = FakeCommands()
    runner, audit = make_runner(tmp_path, commands)
    result = await runner.run(make_task())
    assert isinstance(result, SandboxResult)
    assert (result.status.value, result.task_id) == ("passed", "t1")
    name = _flag(commands.run_calls[0], "--name")[0]
    assert commands.rm_calls == [["docker", "rm", "-f", name]]
    assert audit.actions() == [("sandbox_launched", "allowed"), ("sandbox_destroyed", "allowed")]
    assert all(str(e.scan_id) == SCAN and e.task_id == "t1" for e in audit.events)


async def test_run_writes_task_json_and_keeps_evidence(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        (out_dir / "screenshots").mkdir()
        (out_dir / "screenshots" / "home.png").write_bytes(b"png")
        return _write(out_dir, result_json("failed", findings=[FINDING]))

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    task = make_task()
    result = await runner.run(task)
    in_dir, out_dir = runner.task_dirs(task)
    assert SandboxTaskInput.model_validate_json((in_dir / "task.json").read_text()) == task
    assert (out_dir / "screenshots" / "home.png").read_bytes() == b"png"
    assert result.findings[0].check_id == "security.headers"


async def test_retry_starts_with_clean_out_dir(tmp_path: Path) -> None:
    runner, _ = make_runner(tmp_path, FakeCommands())
    _, out_dir = runner.task_dirs(make_task())
    out_dir.mkdir(parents=True)
    (out_dir / "stale.png").write_bytes(b"old")
    await runner.run(make_task())
    assert not (out_dir / "stale.png").exists()


async def test_run_wall_clock_is_task_timeout_plus_grace_capped(tmp_path: Path) -> None:
    commands = FakeCommands()
    runner, _ = make_runner(tmp_path, commands, limits=SandboxLimits(max_wall_s=120))
    await runner.run(make_task(timeout_s=30))
    await runner.run(make_task(timeout_s=600))
    run_timeouts = [
        t for c, t in zip(commands.calls, commands.timeouts, strict=True) if c[1] == "run"
    ]
    assert run_timeouts == [30 + BROWSER_STARTUP_GRACE_S, 120]


async def test_timeout_kills_and_destroys(tmp_path: Path) -> None:
    commands = FakeCommands(hang=True)
    runner, audit = make_runner(tmp_path, commands)
    result = await runner.run(make_task())
    assert result.status.value == "error"
    assert result.policy_events[0]["action"] == "timeout_kill"
    assert len(commands.rm_calls) == 1
    assert ("timeout_kill", "blocked") in audit.actions()
    assert audit.actions()[-1] == ("sandbox_destroyed", "allowed")


async def test_policy_violation_exit_3_is_blocked_and_audited(tmp_path: Path) -> None:
    event = {
        "actor": "sandbox",
        "action": "navigate",
        "target": "http://169.254.169.254/latest/meta-data/",
        "decision": "blocked",
        "reason": "cloud metadata address",
    }

    def container(in_dir: Path, out_dir: Path) -> int:
        return _write(out_dir, result_json("blocked", policy_events=[event]), code=3)

    commands = FakeCommands(container)
    runner, audit = make_runner(tmp_path, commands)
    result = await runner.run(make_task())
    assert result.status.value == "blocked"
    blocked = [e for e in audit.events if e.decision.value == "blocked"]
    assert len(blocked) == 1
    assert blocked[0].actor.value == "policy"
    assert blocked[0].target == "http://169.254.169.254/latest/meta-data/"
    assert blocked[0].reason == "cloud metadata address"
    assert len(commands.rm_calls) == 1  # the containment moment: sandbox destroyed
    assert audit.actions()[-1] == ("sandbox_destroyed", "allowed")


async def test_exit_3_overrides_result_that_claims_success(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        return _write(out_dir, result_json("failed", findings=[FINDING]), code=3)

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    result = await runner.run(make_task())
    assert result.status.value == "blocked"
    assert result.findings == []


async def test_nonzero_exit_with_passed_result_is_error(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        return _write(out_dir, result_json("passed"), code=137)

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    assert (await runner.run(make_task())).status.value == "error"


async def test_exit_2_error_result_kept(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        return _write(out_dir, result_json("error"), code=2)

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    assert (await runner.run(make_task())).status.value == "error"


@pytest.mark.parametrize(
    "writer",
    [
        lambda out: None,  # no result.json at all (container crashed)
        lambda out: (out / "result.json").write_text("{not json"),
        lambda out: (out / "result.json").write_text(json.dumps({"task_id": "t1"})),
        lambda out: (out / "result.json").write_text(
            json.dumps(result_json(findings=[{**FINDING, "severity": "info"}]))
        ),
        lambda out: (out / "result.json").write_text(json.dumps(result_json(extra_field=1))),
    ],
)
async def test_missing_or_invalid_result_is_error(
    tmp_path: Path, writer: Callable[[Path], object]
) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        writer(out_dir)
        return 0

    commands = FakeCommands(container)
    runner, _ = make_runner(tmp_path, commands)
    result = await runner.run(make_task())
    assert result.status.value == "error"
    assert result.findings == []
    assert len(commands.rm_calls) == 1


async def test_result_for_other_task_is_rejected(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        return _write(out_dir, result_json("failed", task_id="t2", findings=[FINDING]))

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    result = await runner.run(make_task())
    assert result.status.value == "error"
    assert result.findings == []


async def test_policy_refusal_never_launches_a_container(tmp_path: Path) -> None:
    commands = FakeCommands()
    policy = FakePolicy(blocked=True)
    runner, audit = make_runner(tmp_path, commands, policy=policy)
    result = await runner.run(make_task())
    assert result.status.value == "blocked"
    assert commands.calls == []
    assert policy.checked == [TARGET]
    assert audit.actions() == [("launch", "blocked")]
    assert audit.events[0].reason == "non-public address 127.0.0.1"


async def test_failing_teardown_does_not_mask_result(tmp_path: Path) -> None:
    commands = FakeCommands()
    commands.fail_rm = True
    runner, _ = make_runner(tmp_path, commands)
    assert (await runner.run(make_task())).status.value == "passed"


async def test_container_exception_still_destroys(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        raise RuntimeError("docker CLI missing")

    commands = FakeCommands(container)
    runner, audit = make_runner(tmp_path, commands)
    with pytest.raises(RuntimeError):
        await runner.run(make_task())
    assert len(commands.rm_calls) == 1
    assert audit.actions()[-1] == ("sandbox_destroyed", "allowed")


# --- real subprocess runner (local python, no docker, no network) -----------------------


async def test_subprocess_runner_returns_exit_code_and_stderr() -> None:
    code, stderr = await SubprocessRunner().run(
        [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"], timeout_s=30
    )
    assert (code, stderr) == (3, "boom")


async def test_subprocess_runner_kills_on_timeout() -> None:
    with pytest.raises(TimeoutError):
        await SubprocessRunner().run(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout_s=0.5
        )


# --- untrusted out/ dir --------------------------------------------------------------


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this OS/user cannot create symlinks (runs on Linux CI)")


async def test_symlinked_result_is_never_followed(tmp_path: Path) -> None:
    secret = tmp_path / "host_secret.json"
    secret.write_text(json.dumps(result_json("failed", findings=[FINDING])))

    def container(in_dir: Path, out_dir: Path) -> int:
        _symlink_or_skip(out_dir / "result.json", secret)
        return 0

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    result = await runner.run(make_task())
    assert result.status.value == "error"  # the host file's content was NOT read as a result
    _, out_dir = runner.task_dirs(make_task())
    assert not (out_dir / "result.json").exists()
    assert secret.exists()  # the link was removed, never its target


def test_sanitize_removes_links_keeps_regular_files(tmp_path: Path) -> None:
    (tmp_path / "screenshots").mkdir()
    (tmp_path / "screenshots" / "home.png").write_bytes(b"png")
    (tmp_path / "result.json").write_text("{}")
    _symlink_or_skip(tmp_path / "screenshots" / "evil.png", Path("/etc/passwd"))
    removed = sanitize_out_dir(tmp_path)
    assert removed == ["screenshots/evil.png"]
    assert (tmp_path / "screenshots" / "home.png").exists()
    assert (tmp_path / "result.json").exists()


def test_sanitize_clean_dir_removes_nothing(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.png").write_bytes(b"x")
    assert sanitize_out_dir(tmp_path) == []


async def test_oversized_result_is_not_read(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        with (out_dir / "result.json").open("wb") as fh:
            fh.truncate(6 * 1024 * 1024)  # sparse: 6 MiB without writing 6 MiB
        return 0

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    result = await runner.run(make_task())
    assert result.status.value == "error"
    assert "ValueError" in result.policy_events[0]["reason"]


# --- DNS pinning (--add-host) ---------------------------------------------------------


class PinningPolicy:
    """Like app.policy.url_policy.UrlValidator: resolve_allowed returns approved IPs."""

    def __init__(self, host: str, addresses: tuple[str, ...]) -> None:
        self.host = host
        self.addresses = addresses

    async def assert_allowed(self, url: str) -> None:
        raise AssertionError("resolve_allowed must be preferred when available")

    async def resolve_allowed(self, url: str) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(host=self.host, addresses=self.addresses)


def _make(tmp_path: Path, policy: Any) -> tuple[DockerSandboxRunner, FakeCommands]:
    commands = FakeCommands()
    runner = DockerSandboxRunner(
        image="agentguard-sandbox:test",
        work_root=tmp_path / "work",
        policy=policy,
        commands=commands,
    )
    return runner, commands


def _add_hosts(commands: FakeCommands) -> list[str]:
    args = commands.run_calls[0]
    return [args[i + 1] for i, a in enumerate(args) if a == "--add-host"]


async def test_target_pinned_to_approved_addresses(tmp_path: Path) -> None:
    policy = PinningPolicy("demo.example.com", ("93.184.215.14", "2606:2800::1"))
    runner, commands = _make(tmp_path, policy)
    await runner.run(make_task())
    assert _add_hosts(commands) == [
        "demo.example.com:93.184.215.14",
        "demo.example.com:2606:2800::1",
    ]


async def test_ip_literal_target_not_pinned(tmp_path: Path) -> None:
    runner, commands = _make(tmp_path, PinningPolicy("93.184.215.14", ("93.184.215.14",)))
    await runner.run(make_task())
    assert _add_hosts(commands) == []


async def test_policy_without_addresses_refuses_launch(tmp_path: Path) -> None:
    runner, commands = _make(tmp_path, PinningPolicy("demo.example.com", ()))
    result = await runner.run(make_task())
    assert result.status.value == "blocked"
    assert commands.calls == []


async def test_plain_url_policy_enforced_but_not_pinned(tmp_path: Path) -> None:
    runner, commands = _make(tmp_path, FakePolicy())
    await runner.run(make_task())
    assert _add_hosts(commands) == []


async def test_real_url_validator_pins_and_blocks(tmp_path: Path) -> None:
    from app.policy.url_policy import UrlValidator

    class Dns:
        def __init__(self, answers: list[str]) -> None:
            self.answers = answers

        async def resolve(self, host: str, port: int) -> list[str]:
            return self.answers

    runner, commands = _make(tmp_path, UrlValidator(Dns(["93.184.215.14"])))
    await runner.run(make_task())
    assert _add_hosts(commands) == ["demo.example.com:93.184.215.14"]

    rebound, commands2 = _make(tmp_path / "2", UrlValidator(Dns(["169.254.169.254"])))
    result = await rebound.run(make_task())
    assert result.status.value == "blocked"
    assert commands2.calls == []  # never launched
    assert result.policy_events[0]["reason"] == "cloud metadata address"


# --- evidence redaction ----------------------------------------------------------------


async def test_evidence_and_result_redacted_before_use(tmp_path: Path) -> None:
    leaky_url = "https://demo.example.com/reset?token=SECRET123456"
    finding = {**FINDING, "url": leaky_url, "reproduction": [f"Open {leaky_url}"]}

    def container(in_dir: Path, out_dir: Path) -> int:
        (out_dir / "network_summary.json").write_text(
            json.dumps([{"url": leaky_url, "headers": {"Authorization": "Bearer abc123def"}}])
        )
        (out_dir / "console.json").write_text(
            json.dumps([{"type": "log", "text": "login ok password=hunter2"}])
        )
        events = [{"action": "navigate", "target": leaky_url, "decision": "allowed"}]
        return _write(out_dir, result_json("failed", findings=[finding], policy_events=events))

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    result = await runner.run(make_task())
    _, out_dir = runner.task_dirs(make_task())
    on_disk = (out_dir / "network_summary.json").read_text() + (
        out_dir / "console.json"
    ).read_text()
    for secret in ("SECRET123456", "abc123def", "hunter2"):
        assert secret not in on_disk
        assert secret not in result.model_dump_json()
    assert result.findings[0].url == "https://demo.example.com/reset?token=[REDACTED]"
    assert result.status.value == "failed"  # redaction never changes the verdict


async def test_unparseable_evidence_is_blanked_not_kept(tmp_path: Path) -> None:
    def container(in_dir: Path, out_dir: Path) -> int:
        (out_dir / "console.json").write_text("not json, Cookie: sid=TOPSECRET")
        return _write(out_dir, result_json())

    runner, _ = make_runner(tmp_path, FakeCommands(container))
    await runner.run(make_task())
    _, out_dir = runner.task_dirs(make_task())
    assert json.loads((out_dir / "console.json").read_text()) == []
