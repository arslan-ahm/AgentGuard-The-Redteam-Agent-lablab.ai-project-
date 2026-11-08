"""Step 1 of the verifier eval: run every real check module against the local demo store.

Uses the sandbox runner's own ``execute()`` (real check code, real Playwright + Chromium,
same-origin policy, same ``result.json`` / ``network_summary.json`` / screenshots) and writes
each task in the launcher's layout: ``<work>/<scan_id>/<task_id>/out/``.

The production sandbox also installs a network guard that refuses loopback and private
addresses, which is exactly why a scan of ``127.0.0.1`` is blocked there. This harness leaves
that guard out so the checks can reach the local demo store, and for that reason it refuses
any target other than ``http://127.0.0.1`` / ``http://localhost``. Product code is unchanged.

    cd scripts/demo-store && uv run python app.py            # terminal 1
    uv run --project sandbox-worker python scripts/agent-eval/run_checks.py \
        --target http://127.0.0.1:5050 --work .agent-eval     # terminal 2
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sandbox-worker"))

from agentguard_contracts import (  # noqa: E402
    PlanTask,
    SandboxTaskInput,
)
from checks.context import SameOriginPolicy  # noqa: E402
from runner import execute, load_check, write_result  # noqa: E402

CHECKS = [
    *(
        f"qa.{n}"
        for n in (
            "pages_load",
            "links_assets",
            "forms",
            "login",
            "password_reset",
            "search",
            "checkout",
            "console_network_errors",
            "accessibility",
        )
    ),
    *(
        f"security.{n}"
        for n in (
            "https_redirect",
            "headers",
            "cookies",
            "url_session_leak",
            "error_leak",
            "open_redirect",
            "reflected_input",
            "exposed_endpoints",
            "login_rate_probe",
        )
    ),
]


async def run_all(target: str, work: Path) -> Path:
    from playwright.async_api import async_playwright

    scan_id = uuid.uuid4()
    scan_dir = work / str(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "tasks.json").write_text(
        json.dumps({f"t{i}": c for i, c in enumerate(CHECKS, start=1)}, indent=1)
    )
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:
            for i, check_id in enumerate(CHECKS, start=1):
                task_id = f"t{i}"
                out_dir = scan_dir / task_id / "out"
                task_input = SandboxTaskInput(
                    scan_id=scan_id,
                    target_url=target,
                    task=PlanTask(
                        task_id=task_id, check_id=check_id, description=check_id, timeout_s=120
                    ),
                )
                context = await browser.new_context(service_workers="block")
                page = await context.new_page()
                result, code = await execute(
                    task_input,
                    load_check(check_id),
                    page,
                    out_dir,
                    policy=SameOriginPolicy(target),
                )
                await context.close()
                write_result(result, out_dir)
                print(
                    f"{task_id:4} {check_id:32} exit={code} {result.status.value:7} "
                    f"findings={len(result.findings)}"
                )
        finally:
            await browser.close()
    (work / "latest.txt").write_text(str(scan_id))
    return scan_dir


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://127.0.0.1:5050")
    parser.add_argument("--work", type=Path, default=Path(".agent-eval"))
    args = parser.parse_args()
    parts = urlsplit(args.target)
    if parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "localhost"}:
        sys.exit("run_checks.py runs only against the local demo store (http://127.0.0.1)")
    scan_dir = asyncio.run(run_all(args.target, args.work.resolve()))
    print(f"scan dir: {scan_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
