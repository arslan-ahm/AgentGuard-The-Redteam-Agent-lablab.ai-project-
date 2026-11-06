"""Deployment invariants (brief 6.4, 6.10), checked on the *resolved* compose file.

Uses ``docker compose config`` (no daemon needed), so it tests what Docker will actually run,
not our reading of the YAML. Skipped only when the docker CLI is missing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
ENV_TEMPLATE = REPO / "deploy" / "dotenv.example"
BRIEF_VARS = (
    "DATABASE_URL REDIS_URL SECRET_KEY VULTR_INFERENCE_BASE_URL VULTR_INFERENCE_API_KEY "
    "VULTR_INFERENCE_MODEL SANDBOX_IMAGE SANDBOX_CPU_LIMIT SANDBOX_MEM_LIMIT SANDBOX_TIMEOUT_S "
    "ALLOWED_ORIGINS GITHUB_TOKEN PUBLIC_BASE_URL"
).split()
SECRET_VARS = ("SECRET_KEY", "POSTGRES_PASSWORD", "VULTR_INFERENCE_API_KEY", "GITHUB_TOKEN")
DUMMY_ENV = {
    "POSTGRES_USER": "t",
    "POSTGRES_PASSWORD": "t",
    "POSTGRES_DB": "t",
    "SECRET_KEY": "t",
    "ALLOWED_ORIGINS": "http://localhost",
    "PUBLIC_BASE_URL": "http://localhost",
}


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker CLI not installed")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTGUARD_")}
    env.update(DUMMY_ENV)
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [docker, "compose", "--profile", "build-only", "config", "--format", "json"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    data: dict[str, Any] = json.loads(out.stdout)
    return data


def services(compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = compose["services"]
    return result


def test_only_web_publishes_ports_80_and_443(compose: dict[str, Any]) -> None:
    published = {name: svc.get("ports") or [] for name, svc in services(compose).items()}
    assert {n for n, p in published.items() if p} == {"web"}
    assert sorted(int(p["published"]) for p in published["web"]) == [80, 443]


def test_docker_socket_only_in_proxy_and_read_only(compose: dict[str, Any]) -> None:
    for name, svc in services(compose).items():
        socks = [v for v in svc.get("volumes", []) if "docker.sock" in str(v.get("source", ""))]
        if name == "docker-proxy":
            assert len(socks) == 1 and socks[0].get("read_only") is True
        else:
            assert socks == [], f"{name} must not get the docker socket"


def test_docker_proxy_is_internal_only_and_minimal(compose: dict[str, Any]) -> None:
    proxy = services(compose)["docker-proxy"]
    assert set(proxy["networks"]) == {"docker-api"}
    assert compose["networks"]["docker-api"].get("internal") is True
    env = {k: str(v) for k, v in proxy["environment"].items()}
    assert env["CONTAINERS"] == "1" and env["POST"] == "1"
    for denied in ("IMAGES", "EXEC", "BUILD", "NETWORKS", "VOLUMES", "SYSTEM", "SWARM", "AUTH"):
        assert env[denied] == "0", denied
    assert proxy.get("read_only") is True
    assert re.fullmatch(r"tecnativa/docker-socket-proxy:v\d+\.\d+\.\d+", proxy["image"])


def test_only_worker_can_reach_the_docker_proxy(compose: dict[str, Any]) -> None:
    on_api = {n for n, s in services(compose).items() if "docker-api" in (s.get("networks") or {})}
    assert on_api == {"worker", "docker-proxy"}


def test_worker_uses_proxy_and_same_path_work_dir(compose: dict[str, Any]) -> None:
    worker = services(compose)["worker"]
    env = worker["environment"]
    assert env["DOCKER_HOST"] == "tcp://docker-proxy:2375"
    root = env["AGENTGUARD_WORK_ROOT"]
    assert root.startswith("/")
    mounts = [v for v in worker["volumes"] if v["target"] == root]
    assert mounts and mounts[0]["source"] == root and not mounts[0].get("read_only")
    assert worker["build"]["dockerfile"] == "deploy/worker.Dockerfile"
    assert worker["build"]["additional_contexts"] == {"backend-image": "service:backend"}


def test_backend_reads_evidence_read_only(compose: dict[str, Any]) -> None:
    backend = services(compose)["backend"]
    root = backend["environment"]["AGENTGUARD_WORK_ROOT"]
    mounts = [v for v in backend["volumes"] if v["target"] == root]
    assert mounts and mounts[0]["source"] == root and mounts[0].get("read_only") is True


def test_sandbox_image_is_build_only_with_no_mounts(compose: dict[str, Any]) -> None:
    sandbox = services(compose)["sandbox"]
    assert sandbox["profiles"] == ["build-only"]
    assert not sandbox.get("volumes") and not sandbox.get("ports")


def test_datastores_have_healthchecks_and_volumes(compose: dict[str, Any]) -> None:
    for name in ("postgres", "redis"):
        svc = services(compose)[name]
        assert svc["healthcheck"]["test"]
        assert any(v["type"] == "volume" for v in svc["volumes"])


def _template() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in ENV_TEMPLATE.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#?\s*([A-Z][A-Z0-9_]+)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def test_env_template_lists_every_brief_variable() -> None:
    missing = [v for v in BRIEF_VARS if v not in _template()]
    assert missing == []


def test_env_template_has_no_secret_values() -> None:
    values = _template()
    for name in SECRET_VARS:
        assert values[name] == "", f"{name} must be empty in the template"


def test_every_compose_variable_is_documented() -> None:
    used = set(re.findall(r"\$\{([A-Z][A-Z0-9_]+)", (REPO / "docker-compose.yml").read_text()))
    assert used - set(_template()) == set()
