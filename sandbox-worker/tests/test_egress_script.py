"""scripts/sandbox-egress.sh (brief 6.4/12): the host firewall for the sandbox network.

Runs the real script with ``--dry-run`` (prints the docker/iptables commands, executes
nothing, needs no root) and checks the rule order and coverage.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sandbox-egress.sh"


def _bash() -> str | None:
    """A working bash: Git Bash on Windows (``bash`` on PATH there may be a broken WSL)."""
    candidates = [r"C:\Program Files\Git\bin\bash.exe"] if os.name == "nt" else []
    candidates.append(shutil.which("bash") or "")
    for path in candidates:
        if path and Path(path).exists():
            try:
                subprocess.run([path, "-c", "true"], check=True, timeout=20)  # noqa: S603
            except (OSError, subprocess.SubprocessError):
                continue
            return path
    return None


BASH = _bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="no usable bash")


def dry_run(*args: str, dns: str = "108.61.10.10,1.1.1.1") -> list[str]:
    assert BASH is not None
    env = {**os.environ, "AGENTGUARD_SANDBOX_DNS": dns}
    proc = subprocess.run(  # noqa: S603 - fixed script path, fixed args
        [BASH, SCRIPT.as_posix(), *args, "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=True,
    )
    return [line[2:] for line in proc.stdout.splitlines() if line.startswith("+ ")]


def chain_rules(lines: list[str], chain: str) -> list[str]:
    prefix = f"iptables -A {chain} "
    return [line[len(prefix) :] for line in lines if line.startswith(prefix)]


def test_apply_creates_isolated_network() -> None:
    create = next(line for line in dry_run("apply") if line.startswith("docker network create"))
    assert "--subnet 172.31.250.0/24" in create
    assert "com.docker.network.bridge.enable_icc=false" in create
    assert "com.docker.network.bridge.name=br-agsandbox" in create
    assert "--ipv6" not in create
    assert create.endswith(" agentguard-sandbox")  # = launcher.DEFAULT_NETWORK


def test_forward_chain_order_and_default_drop() -> None:
    rules = chain_rules(dry_run("apply"), "AGENTGUARD-SANDBOX")
    assert rules[0] == "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    tcp_allow = rules.index("-p tcp -j RETURN")
    drops = [i for i, r in enumerate(rules) if re.fullmatch(r"-d \S+ -j DROP", r)]
    assert drops and max(drops) < tcp_allow  # every private range dropped before TCP allowed
    assert rules[-1] == "-j DROP"  # UDP, ICMP, everything else
    assert tcp_allow == len(rules) - 2


def test_dns_allowed_only_to_upstreams_on_port_53() -> None:
    rules = chain_rules(dry_run("apply"), "AGENTGUARD-SANDBOX")
    dns_rules = [r for r in rules if "--dport 53" in r]
    assert dns_rules == [
        "-d 108.61.10.10 -p udp --dport 53 -j RETURN",
        "-d 108.61.10.10 -p tcp --dport 53 -j RETURN",
        "-d 1.1.1.1 -p udp --dport 53 -j RETURN",
        "-d 1.1.1.1 -p tcp --dport 53 -j RETURN",
    ]
    assert not any("--dport" in r and "53" not in r for r in rules)


def _blocked_networks() -> list[ipaddress.IPv4Network]:
    rules = chain_rules(dry_run("apply"), "AGENTGUARD-SANDBOX")
    nets = []
    for rule in rules:
        m = re.fullmatch(r"-d (\S+) -j DROP", rule)
        if m:
            nets.append(ipaddress.IPv4Network(m.group(1)))
    return nets


@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",  # cloud metadata (Vultr, AWS, GCP, Azure)
        "100.100.100.200",  # Alibaba metadata
        "127.0.0.1",
        "10.0.0.5",
        "172.17.0.1",  # docker0 / other containers
        "172.31.250.1",  # this sandbox network's own gateway
        "192.168.1.1",
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104 - a destination under test, not a bind address
        "224.0.0.251",
        "255.255.255.255",
    ],
)
def test_internal_destinations_dropped(ip: str) -> None:
    assert any(ipaddress.IPv4Address(ip) in net for net in _blocked_networks())


@pytest.mark.parametrize("ip", ["93.184.215.14", "8.8.8.8", "151.101.1.1", "45.32.1.1"])
def test_public_destinations_not_dropped(ip: str) -> None:
    assert not any(ipaddress.IPv4Address(ip) in net for net in _blocked_networks())


def test_host_itself_unreachable_and_jumps_installed() -> None:
    lines = dry_run("apply")
    assert chain_rules(lines, "AGENTGUARD-SANDBOX-IN") == [
        "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
        "-j DROP",
    ]
    assert "iptables -I DOCKER-USER 1 -i br-agsandbox -j AGENTGUARD-SANDBOX" in lines
    assert "iptables -I INPUT 1 -i br-agsandbox -j AGENTGUARD-SANDBOX-IN" in lines


def test_no_dns_configured_still_drops_everything_private() -> None:
    rules = chain_rules(dry_run("apply", dns=" "), "AGENTGUARD-SANDBOX")
    assert not any("--dport 53" in r for r in rules)
    assert rules[-1] == "-j DROP"


def test_bad_arguments_rejected() -> None:
    assert BASH is not None
    proc = subprocess.run(  # noqa: S603
        [BASH, SCRIPT.as_posix(), "flush-everything"], capture_output=True, timeout=30
    )
    assert proc.returncode == 64
