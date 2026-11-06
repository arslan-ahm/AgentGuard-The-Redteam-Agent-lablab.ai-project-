"""Orchestration-side sandbox launcher (brief 6.4, 12). Owner: Arslan, reviewer: Sarah.

``DockerSandboxRunner`` implements ``app.interfaces.SandboxRunner``: one fresh container per
task, locked down, destroyed on completion, failure, timeout and policy violation.

Containment flags (all built by :func:`build_docker_run_args`, every one asserted in tests):

- ``--rm`` plus an explicit ``docker rm -f`` in ``finally``: the container never outlives the task
- ``--read-only`` root FS; writable ``/tmp`` only as ``noexec,nosuid`` tmpfs
- ``--cap-drop=ALL``, ``--security-opt=no-new-privileges``, non-root user from the image
- ``--cpus``, ``--memory`` (= ``--memory-swap``, so no swap), ``--pids-limit``, ``--ulimit nofile``
- mounts: only the task dir at ``/in`` (read-only) and the evidence dir at ``/out``. Never the
  Docker socket and never any other host path (enforced by :func:`_assert_safe_mount`)
- a dedicated network whose host firewall rules drop traffic to private, loopback,
  link-local and metadata ranges (``scripts/sandbox-egress.sh``); target hosts can be pinned
  to policy-approved IPs with ``--add-host`` so DNS rebinding inside the container can't win
- a hard wall-clock limit: past it the container is killed
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import shutil
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from agentguard_contracts import (
    AuditActor,
    AuditDecision,
    AuditEvent,
    SandboxExitCode,
    SandboxResult,
    SandboxResultStatus,
    SandboxTaskInput,
)
from pydantic import ValidationError

from app.config import Settings
from app.interfaces import AuditSink, UrlPolicy

DEFAULT_NETWORK = "agentguard-sandbox"
BROWSER_STARTUP_GRACE_S = 30
"""Time on top of the task's ``timeout_s`` for container start and browser launch."""
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 5 * 1024 * 1024
"""``result.json`` is written by an untrusted container: never read more than this."""

_NAME_SAFE = re.compile(r"[^a-zA-Z0-9_.-]")
_FORBIDDEN_MOUNT_ROOTS = tuple(
    PurePosixPath(p)
    for p in (
        "/proc",
        "/sys",
        "/dev",
        "/etc",
        "/run",
        "/var/run",
        "/boot",
        "/root",
        "/var/lib/docker",
    )
)


@dataclass(frozen=True)
class SandboxLimits:
    """Resource limits for one sandbox container."""

    cpus: str = "1.0"
    memory: str = "1g"
    pids: int = 256
    nofile: int = 1024
    tmpfs_size: str = "256m"
    shm_size: str = "256m"
    max_wall_s: int = 120

    @classmethod
    def from_settings(cls, settings: Settings) -> SandboxLimits:
        """``SANDBOX_CPU_LIMIT``, ``SANDBOX_MEM_LIMIT``, ``SANDBOX_TIMEOUT_S`` (brief 5.12)."""
        return cls(
            cpus=settings.sandbox_cpu_limit,
            memory=settings.sandbox_mem_limit,
            max_wall_s=settings.sandbox_timeout_s,
        )


def container_name(task: SandboxTaskInput) -> str:
    """Unique, docker-safe name: ``ag-<scan8>-<task>-<random>``."""
    task_part = _NAME_SAFE.sub("-", task.task.task_id)[:32]
    return f"ag-{str(task.scan_id)[:8]}-{task_part}-{secrets.token_hex(4)}"


def refuse_unsafe_mount(resolved: PurePosixPath) -> None:
    """Only per-task work dirs may be mounted: never ``/``, system dirs or a Docker socket."""
    if len(resolved.parts) < 3 or "docker.sock" in resolved.name:
        raise ValueError(f"refusing to mount {str(resolved)!r} into a sandbox")
    for root in _FORBIDDEN_MOUNT_ROOTS:
        if resolved == root or root in resolved.parents:
            raise ValueError(f"refusing to mount {str(resolved)!r} into a sandbox")


def _assert_safe_mount(host_path: Path) -> None:
    refuse_unsafe_mount(PurePosixPath(host_path.resolve().as_posix()))


def build_docker_run_args(
    *,
    name: str,
    image: str,
    in_dir: Path,
    out_dir: Path,
    limits: SandboxLimits,
    network: str = DEFAULT_NETWORK,
    pinned_hosts: Mapping[str, Sequence[str]] | None = None,
    labels: Mapping[str, str] | None = None,
) -> list[str]:
    """The full ``docker run`` argv (no shell involved). Pure: easy to audit and test."""
    for path in (in_dir, out_dir):
        _assert_safe_mount(path)
    if network in ("host", "bridge", "default") or network.startswith("container:"):
        raise ValueError(f"sandbox must use the dedicated egress-filtered network, not {network!r}")
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_size}",  # noqa: S108 - in-container
        "--shm-size",
        limits.shm_size,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--cpus",
        limits.cpus,
        "--memory",
        limits.memory,
        "--memory-swap",
        limits.memory,
        "--pids-limit",
        str(limits.pids),
        "--ulimit",
        f"nofile={limits.nofile}:{limits.nofile}",
        "--network",
        network,
        "--env",
        "HOME=/tmp",
        "--env",
        "AGENTGUARD_IN=/in",
        "--env",
        "AGENTGUARD_OUT=/out",
        "--mount",
        f"type=bind,source={in_dir.resolve()},target=/in,readonly",
        "--mount",
        f"type=bind,source={out_dir.resolve()},target=/out",
    ]
    for host, addresses in sorted((pinned_hosts or {}).items()):
        for address in addresses:
            args += ["--add-host", f"{host}:{address}"]
    for key, value in sorted((labels or {}).items()):
        args += ["--label", f"{key}={value}"]
    args.append(image)
    return args


class CommandRunner(Protocol):
    """Runs an argv without a shell. Swapped for a fake in tests."""

    async def run(self, args: Sequence[str], timeout_s: float) -> tuple[int, str]:
        """Return ``(exit_code, stderr_tail)``. Raise ``TimeoutError`` past ``timeout_s``."""
        ...


class SubprocessRunner:
    """Real runner: ``asyncio.create_subprocess_exec`` (never a shell)."""

    async def run(self, args: Sequence[str], timeout_s: float) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        return proc.returncode or 0, stderr[-MAX_OUTPUT_BYTES:].decode(errors="replace")


@dataclass
class DockerSandboxRunner:
    """Runs one task per fresh container. Implements ``app.interfaces.SandboxRunner``."""

    image: str
    work_root: Path
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    network: str = DEFAULT_NETWORK
    policy: UrlPolicy | None = None
    audit: AuditSink | None = None
    commands: CommandRunner = field(default_factory=SubprocessRunner)

    def task_dirs(self, task: SandboxTaskInput) -> tuple[Path, Path]:
        """``<work_root>/<scan_id>/<task_id>/{in,out}``. ``out`` holds the task's evidence."""
        task_dir = self.work_root / str(task.scan_id) / _NAME_SAFE.sub("-", task.task.task_id)
        return task_dir / "in", task_dir / "out"

    async def run(self, task: SandboxTaskInput) -> SandboxResult:
        """Launch, wait, collect ``result.json`` and always destroy the container."""
        name = container_name(task)
        if self.policy is not None:
            try:
                await self.policy.assert_allowed(task.target_url)
            except Exception as exc:  # any policy failure refuses the launch
                reason = getattr(exc, "reason", None) or type(exc).__name__
                await self._audit(task, AuditActor.POLICY, "launch", task.target_url, False, reason)
                return _synthetic(task, SandboxResultStatus.BLOCKED, "launch refused", reason)

        in_dir, out_dir = self.task_dirs(task)
        await asyncio.to_thread(_prepare_dirs, in_dir, out_dir, task)
        args = build_docker_run_args(
            name=name,
            image=self.image,
            in_dir=in_dir,
            out_dir=out_dir,
            limits=self.limits,
            network=self.network,
            labels={"agentguard.scan_id": str(task.scan_id), "agentguard.task_id": name},
        )
        wall_s = min(task.task.timeout_s + BROWSER_STARTUP_GRACE_S, self.limits.max_wall_s)
        await self._audit(
            task, AuditActor.SANDBOX, "sandbox_launched", name, True, "fresh container"
        )
        try:
            try:
                code, stderr = await self.commands.run(args, timeout_s=wall_s)
            except TimeoutError:
                result = _synthetic(
                    task, SandboxResultStatus.ERROR, "timeout_kill", f"exceeded {wall_s}s"
                )
                await self._audit(
                    task, AuditActor.SANDBOX, "timeout_kill", name, False, "wall clock"
                )
                return result
            result = await asyncio.to_thread(_read_result, out_dir, task, code, stderr)
            if (
                code == SandboxExitCode.POLICY_VIOLATION
                or result.status is SandboxResultStatus.BLOCKED
            ):
                blocked = [e for e in result.policy_events if e.get("decision") == "blocked"]
                target = str(blocked[-1].get("target", "")) if blocked else name
                reason = str(blocked[-1].get("reason", "")) if blocked else "policy violation"
                await self._audit(task, AuditActor.POLICY, "navigate", target, False, reason)
            return result
        finally:
            await self._destroy(name)
            await self._audit(
                task, AuditActor.SANDBOX, "sandbox_destroyed", name, True, "task ended"
            )

    async def _destroy(self, name: str) -> None:
        """``docker rm -f``. Already gone (``--rm``) is fine; never raises."""
        try:
            await self.commands.run(["docker", "rm", "-f", name], timeout_s=30)
        except Exception as exc:  # teardown must not mask the task's own outcome
            print(f"sandbox {name}: rm -f failed: {type(exc).__name__}", file=sys.stderr)

    async def _audit(
        self,
        task: SandboxTaskInput,
        actor: AuditActor,
        action: str,
        target: str,
        allowed: bool,
        reason: str,
    ) -> None:
        if self.audit is None:
            return
        await self.audit.append(
            AuditEvent(
                ts=datetime.now(UTC),
                scan_id=task.scan_id,
                task_id=task.task.task_id,
                actor=actor,
                action=action,
                target=target[:500],
                decision=AuditDecision.ALLOWED if allowed else AuditDecision.BLOCKED,
                reason=reason[:500],
            )
        )


def _prepare_dirs(in_dir: Path, out_dir: Path, task: SandboxTaskInput) -> None:
    if out_dir.exists():  # a retried task starts from a clean evidence dir
        shutil.rmtree(out_dir)
    in_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True)
    (in_dir / "task.json").write_text(task.model_dump_json())
    if os.name == "posix":
        # The container runs as the image's non-root user, a different uid from this process.
        in_dir.chmod(0o755)
        (in_dir / "task.json").chmod(0o644)
        out_dir.chmod(0o777)  # noqa: S103 - per-task scratch dir, only mounted into its sandbox


def sanitize_out_dir(out_dir: Path) -> list[str]:
    """Remove everything in ``out/`` that is not a regular file or directory.

    The sandbox is untrusted and ``out/`` is a host bind mount: a symlink written there
    (``result.json -> /etc/shadow``) would be followed by the worker or the evidence API on
    the host. Symlinks, FIFOs, sockets and devices are deleted, never followed. Returns the
    removed paths (relative) for logging.
    """
    removed: list[str] = []
    for root, dirs, files in os.walk(out_dir, followlinks=False):
        for name in [*dirs, *files]:
            entry = Path(root) / name
            if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
                entry.unlink()
                removed.append(entry.relative_to(out_dir).as_posix())
    return removed


def _read_result(out_dir: Path, task: SandboxTaskInput, code: int, stderr: str) -> SandboxResult:
    """Validate ``result.json`` against the contract. Anything off becomes an ``error`` result."""
    removed = sanitize_out_dir(out_dir)
    if removed:
        print(f"sandbox out/: removed non-regular entries {removed[:20]}", file=sys.stderr)
    path = out_dir / "result.json"
    try:
        if path.stat().st_size > MAX_RESULT_BYTES:
            raise ValueError("result.json too large")
        result = SandboxResult.model_validate_json(path.read_bytes())
    except (OSError, ValidationError, ValueError) as exc:
        detail = f"exit {code}: no valid result.json ({type(exc).__name__}); {stderr[-300:]}"
        return _synthetic(task, SandboxResultStatus.ERROR, "result_missing", detail)
    if result.task_id != task.task.task_id:
        return _synthetic(task, SandboxResultStatus.ERROR, "result_mismatch", "wrong task_id")
    if (
        code == SandboxExitCode.POLICY_VIOLATION
        and result.status is not SandboxResultStatus.BLOCKED
    ):
        # Exit 3 always wins: the sandbox reported a violation, whatever the JSON says.
        return result.model_copy(update={"status": SandboxResultStatus.BLOCKED, "findings": []})
    if code not in (SandboxExitCode.OK, SandboxExitCode.POLICY_VIOLATION) and (
        result.status in (SandboxResultStatus.PASSED, SandboxResultStatus.FAILED)
    ):
        return result.model_copy(update={"status": SandboxResultStatus.ERROR})
    return result


def _synthetic(
    task: SandboxTaskInput, status: SandboxResultStatus, action: str, reason: str
) -> SandboxResult:
    """A launcher-made result when the sandbox didn't produce a usable one."""
    event: dict[str, Any] = {
        "actor": "sandbox",
        "action": action,
        "target": task.target_url,
        "decision": "blocked" if status is SandboxResultStatus.BLOCKED else "allowed",
        "reason": reason[:500],
    }
    return SandboxResult(
        task_id=task.task.task_id,
        status=status,
        findings=[],
        duration_ms=0,
        policy_events=[event],
    )


def describe_args(args: Sequence[str]) -> str:
    """Human-readable command for logs and docs (paths kept, nothing secret is in argv)."""
    return " ".join(json.dumps(a) if " " in a else a for a in args)


__all__ = [
    "DEFAULT_NETWORK",
    "CommandRunner",
    "DockerSandboxRunner",
    "SandboxLimits",
    "SubprocessRunner",
    "build_docker_run_args",
    "container_name",
    "describe_args",
    "refuse_unsafe_mount",
    "sanitize_out_dir",
]
