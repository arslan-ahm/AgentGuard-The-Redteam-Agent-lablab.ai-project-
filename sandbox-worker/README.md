# Sandbox worker

One container runs one scan task (brief 5.6 and 6.4).

- Input: `/in/task.json` (a `SandboxTaskInput`: `scan_id`, `target_url`, `task`)
- Output: `/out/result.json`, `console.json`, `network_summary.json`, `screenshots/*.png`
- Exit codes: `0` ok, `2` check error, `3` policy violation

`runner.py` only loads check ids on the whitelist in `agentguard_contracts.ALLOWED_CHECK_IDS`, runs the check under the task's `timeout_s`, and validates every finding against the contract. Anything that doesn't match is reported as `error`.

## Adding a check

Create `checks/<category>/<name>.py` for an id on the whitelist:

```python
from typing import Any
from checks.context import CheckContext

CHECK_ID = "security.headers"

async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    ctx.policy.assert_allowed(ctx.target_url)      # before every navigation
    response = await page.goto(ctx.target_url)
    shot = await ctx.screenshot("headers_home")
    ctx.record_request({"url": ctx.target_url, "status": response.status})
    return []  # Finding dicts without id/scan_id (see FindingDraft)
```

Test checks with a fake page and a fake `ctx` (see `tests/test_runner.py`). Unit tests never hit real sites.

## Policy placeholder

`checks/context.py:SameOriginPolicy` allows only the target's own scheme, host and port. It is a strict placeholder. Arslan replaces it with the full policy (DNS resolution, private/loopback/link-local/metadata blocking). The real boundary is the container's network egress rules, enforced by the launcher.

## Run

```bash
uv sync && uv run pytest
docker compose build sandbox     # from the repo root
```
