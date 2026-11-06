# Sandbox launcher (brief 6.4)

Owner: Arslan · Reviewer: Sarah

`DockerSandboxRunner` implements `app.interfaces.SandboxRunner`. It starts one fresh container per task and always destroys it afterwards.

```python
from app.config import get_settings
from app.sandbox.launcher import DockerSandboxRunner, SandboxLimits

settings = get_settings()
runner = DockerSandboxRunner(
    image=settings.sandbox_image,
    work_root=Path("/var/lib/agentguard/work"),   # same path on host and in the worker
    limits=SandboxLimits.from_settings(settings),
    policy=url_validator,                         # app.interfaces.UrlPolicy
    audit=audit_sink,                             # app.interfaces.AuditSink
)
result = await runner.run(task_input)             # SandboxResult (brief 5.6)
```

## Lifecycle

1. Re-check `target_url` against the URL policy. If it's blocked, nothing is launched, the result is `blocked`, and the audit event is `launch / blocked`.
2. Write `<work_root>/<scan_id>/<task_id>/in/task.json` and create an empty `out/`. The `out/` folder is the task's evidence directory.
3. `docker run` with the flags below, killed after `min(task.timeout_s + 30, SANDBOX_TIMEOUT_S)` seconds.
4. Remove any symlinks or special files from `out/`, then read `out/result.json` and validate it against the contract:
   - Missing, invalid or wrong-task results become `error`.
   - Exit `3` always becomes `blocked`, with findings dropped.
   - A non-zero exit that claims `passed` becomes `error`.
5. `docker rm -f` runs in `finally`, on completion, failure, timeout and policy violation alike.

Audit events (`actor`, `action`, `decision`): `sandbox launched/allowed`, `policy navigate/blocked` (with the URL that was blocked and the reason), `sandbox timeout_kill/blocked`, `sandbox sandbox_destroyed/allowed`.

## Containment flags

| Control | Flag |
|---|---|
| Destroyed after use | `--rm` + explicit `docker rm -f` |
| Read-only root FS | `--read-only`, `/tmp` as `noexec,nosuid,nodev` tmpfs |
| No privileges | `--cap-drop=ALL`, `--security-opt=no-new-privileges`, non-root image user |
| Resource limits | `--cpus`, `--memory` = `--memory-swap`, `--pids-limit 256`, `--ulimit nofile` |
| Mounts | only `/in` (read-only) and `/out`; `/`, system dirs and any `docker.sock` are refused |
| Network | dedicated `agentguard-sandbox` network (never `host`/`bridge`/`container:`). **Pending:** the host firewall rules that drop private, loopback, link-local and metadata ranges for that network (`scripts/sandbox-egress.sh`, next sandbox branch). Until then the in-sandbox same-origin policy is the only egress guard |
| DNS rebinding | `build_docker_run_args(pinned_hosts=...)` emits `--add-host host:ip`. **Not wired into `run()` yet:** it needs `ResolvedTarget` from the policy branch (`feat/policy-url-validator`) |
| Untrusted output | after exit, symlinks, FIFOs and devices in `out/` are deleted, never followed; `result.json` over 5 MiB is not read |
| Secrets | none in argv or env; only `HOME`, `AGENTGUARD_IN`, `AGENTGUARD_OUT` |

## Deployment note

The worker container talks to Docker to start sandboxes. Bind-mount sources are resolved **on the host**, so `work_root` must be the same absolute path on the host and inside the worker (for example `/var/lib/agentguard/work:/var/lib/agentguard/work`). The sandbox containers themselves never get Docker access.

## Tests

```bash
cd backend && uv run pytest tests/test_sandbox_launcher.py
```

`FakeCommands` plays the container. Docker is not needed.
