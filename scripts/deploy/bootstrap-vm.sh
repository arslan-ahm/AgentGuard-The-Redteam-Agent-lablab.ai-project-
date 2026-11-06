#!/usr/bin/env bash
# One-time setup of a fresh Vultr Ubuntu 24.04 VM for AgentGuard (brief 6.10). Run as root:
#   sudo bash scripts/deploy/bootstrap-vm.sh [--ssh-from <your-ip/32>]
# Idempotent: safe to run again. Installs Docker Engine from Docker's apt repo, a host
# firewall (ufw: 22, 80, 443 only), the work dir, the sandbox egress firewall service and
# the daily DB backup timer. It does not touch .env or start the stack.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_ROOT="${AGENTGUARD_WORK_ROOT:-/var/lib/agentguard/work}"
BACKUP_DIR="${AGENTGUARD_BACKUP_DIR:-/var/backups/agentguard}"
WORKER_UID=10001   # the backend image's "agentguard" user (backend/Dockerfile)
SSH_FROM="any"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-from) SSH_FROM="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

log() { printf '\n== %s\n' "$*"; }

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg ufw iptables unattended-upgrades

if ! command -v docker >/dev/null 2>&1; then
  log "docker engine (download.docker.com apt repo)"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  # shellcheck disable=SC1091
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker

log "host firewall (ufw): ssh, http, https only"
ufw default deny incoming
ufw default allow outgoing
if [[ "$SSH_FROM" == "any" ]]; then
  ufw allow 22/tcp
else
  ufw allow from "$SSH_FROM" to any port 22 proto tcp
fi
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
# Docker publishes ports past ufw. Only "web" publishes (80/443); postgres, redis, backend
# and docker-proxy stay on internal compose networks. Keep it that way.

log "work dir ${WORK_ROOT} (worker uid ${WORKER_UID})"
install -d -m 0750 -o "$WORKER_UID" -g "$WORKER_UID" "$WORK_ROOT"

log "backup dir ${BACKUP_DIR}"
install -d -m 0700 -o root -g root "$BACKUP_DIR"

log "sandbox egress firewall (scripts/sandbox-egress.sh)"
if [[ -f "$REPO_DIR/scripts/sandbox-egress.sh" ]]; then
  install -d /opt/agentguard/scripts
  install -m 0755 "$REPO_DIR/scripts/sandbox-egress.sh" /opt/agentguard/scripts/sandbox-egress.sh
  install -m 0644 "$REPO_DIR/scripts/agentguard-egress.service" /etc/systemd/system/agentguard-egress.service
  systemctl daemon-reload
  systemctl enable --now agentguard-egress.service
  /opt/agentguard/scripts/sandbox-egress.sh status
else
  echo "MISSING scripts/sandbox-egress.sh: merge feat/sandbox-network-guard first." >&2
  echo "Do not run scans until the egress firewall is active." >&2
fi

log "daily DB backup (03:15, keeps 14 days)"
cat > /etc/systemd/system/agentguard-backup.service <<EOF
[Unit]
Description=AgentGuard Postgres backup
After=docker.service

[Service]
Type=oneshot
Environment=AGENTGUARD_BACKUP_DIR=${BACKUP_DIR}
ExecStart=/bin/bash ${REPO_DIR}/scripts/deploy/backup-db.sh
EOF
cat > /etc/systemd/system/agentguard-backup.timer <<'EOF'
[Unit]
Description=Daily AgentGuard Postgres backup

[Timer]
OnCalendar=*-*-* 03:15:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now agentguard-backup.timer

log "done. Next: cp deploy/dotenv.example .env, fill it in, then follow docs/deploy-vultr.md"
