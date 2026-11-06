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
| Network | dedicated `agentguard-sandbox` network (never `host`/`bridge`/`container:`), firewalled by `scripts/sandbox-egress.sh` (below) |
| DNS rebinding | the policy's `resolve_allowed` result is pinned with `--add-host host:ip`, so the container never re-resolves the target. A policy without `resolve_allowed` is enforced but not pinned |
| Untrusted output | after exit, symlinks, FIFOs and devices in `out/` are deleted, never followed; `result.json` over 5 MiB is not read |
| Secrets | none in argv or env; only `HOME`, `AGENTGUARD_IN`, `AGENTGUARD_OUT` |

## Egress firewall (`scripts/sandbox-egress.sh`)

On the Docker host, once: `sudo bash scripts/sandbox-egress.sh apply`, plus `scripts/agentguard-egress.service` so it comes back after a reboot. It creates the `agentguard-sandbox` network (no IPv6, no container-to-container traffic) and iptables rules for its bridge:

| Traffic from a sandbox to | Result |
|---|---|
| loopback, RFC1918, CGNAT, link-local / `169.254.169.254`, reserved, multicast | dropped |
| the host itself (gateway, public IP, published ports) | dropped |
| the host's upstream DNS servers, port 53 only | allowed |
| any other public address over TCP | allowed |
| UDP, ICMP, anything else | dropped |

Inside the container, `sandbox-worker/checks/netguard.py` vets every browser request and redirect hop before it leaves, so this firewall is the second layer, not the only one.

`--dry-run` prints the commands without root; `sandbox-worker/tests/test_egress_script.py` checks rule order and coverage that way. **Not yet run on a real Linux host:** verify with `status` after the first deploy.

## Deployment note

The worker container talks to Docker to start sandboxes. Bind-mount sources are resolved **on the host**, so `work_root` must be the same absolute path on the host and inside the worker (for example `/var/lib/agentguard/work:/var/lib/agentguard/work`). The sandbox containers themselves never get Docker access.

## Tests

```bash
cd backend && uv run pytest tests/test_sandbox_launcher.py
```

`FakeCommands` plays the container. Docker is not needed.
