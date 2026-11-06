#!/usr/bin/env bash
# Post-deploy / uptime check for AgentGuard (brief 6.10). Exit 0 only if everything is up.
#   bash scripts/deploy/healthcheck.sh https://agentguard.example.com
# Checks: the public /healthz over HTTPS (certificate verified), every compose service
# running and healthy, the sandbox image present, the egress firewall active, and that
# postgres/redis/docker-proxy are NOT reachable from outside.
set -uo pipefail

BASE_URL="${1:?usage: healthcheck.sh <public base url>}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
failures=0

ok()   { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; failures=$((failures + 1)); }

echo "public endpoint"
if body="$(curl -fsS --max-time 10 "$BASE_URL/healthz" 2>&1)" && [[ "$body" == *'"ok"'* ]]; then
  ok "$BASE_URL/healthz -> $body"
else
  fail "$BASE_URL/healthz -> ${body:-no answer}"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "services"
  for svc in web backend worker postgres redis docker-proxy; do
    state="$(docker compose --project-directory "$REPO_DIR" ps --format '{{.State}} {{.Health}}' "$svc" 2>/dev/null)"
    if [[ "$state" == running* && "$state" != *unhealthy* && "$state" != *starting* ]]; then
      ok "$svc: $state"
    else
      fail "$svc: ${state:-not running}"
    fi
  done

  echo "sandbox"
  image="$(grep -E '^SANDBOX_IMAGE=' "$REPO_DIR/.env" 2>/dev/null | cut -d= -f2-)"
  image="${image:-agentguard-sandbox:local}"
  if docker image inspect "$image" >/dev/null 2>&1; then
    ok "image $image"
  else
    fail "image $image missing (docker compose --profile build-only build sandbox)"
  fi
  if [[ -x /opt/agentguard/scripts/sandbox-egress.sh ]] \
    && /opt/agentguard/scripts/sandbox-egress.sh status >/dev/null 2>&1; then
    ok "egress firewall active"
  else
    fail "egress firewall not active (scripts/sandbox-egress.sh apply)"
  fi

  echo "exposure (published ports)"
  # Containers with a host-published port ("0.0.0.0:80->80/tcp"), other than the web proxy.
  unexpected="$(docker ps --format '{{.Names}} {{.Ports}}' | grep -E -- '->' | grep -vE '^[^ ]*-web-[0-9]+ ' || true)"
  if [[ -n "$unexpected" ]]; then
    fail "unexpected published ports: $(tr '\n' ';' <<<"$unexpected")"
  else
    ok "only web publishes ports"
  fi
else
  echo "(docker not available here: only the public endpoint was checked)"
fi

if [[ $failures -eq 0 ]]; then
  echo "HEALTHY"
else
  echo "UNHEALTHY: $failures check(s) failed"
fi
exit $(( failures > 0 ))
