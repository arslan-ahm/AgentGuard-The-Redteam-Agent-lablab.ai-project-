#!/usr/bin/env bash
# Postgres backup for AgentGuard (brief 6.10). Run from anywhere on the VM, as root:
#   bash scripts/deploy/backup-db.sh            # dump now, keep the last 14 days
#   bash scripts/deploy/backup-db.sh --restore /var/backups/agentguard/agentguard-<ts>.sql.gz
# Dumps run inside the postgres container (pg_dump, credentials from its own env), so
# no password ever appears on a command line. Files are root-only (0600).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKUP_DIR="${AGENTGUARD_BACKUP_DIR:-/var/backups/agentguard}"
KEEP_DAYS="${AGENTGUARD_BACKUP_KEEP_DAYS:-14}"

compose() { docker compose --project-directory "$REPO_DIR" "$@"; }

if [[ "${1:-}" == "--restore" ]]; then
  file="${2:?usage: backup-db.sh --restore <file.sql.gz>}"
  [[ -f "$file" ]] || { echo "no such file: $file" >&2; exit 1; }
  echo "Restoring $file into the running postgres container. This REPLACES current data."
  read -r -p "Type RESTORE to continue: " answer
  [[ "$answer" == "RESTORE" ]] || { echo "aborted"; exit 1; }
  compose stop backend worker
  # shellcheck disable=SC2016  # $POSTGRES_* expand inside the container, not here
  gunzip -c "$file" | compose exec -T postgres sh -c \
    'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
  compose start backend worker
  echo "restored"
  exit 0
fi

umask 077
mkdir -p "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/agentguard-$stamp.sql.gz"
tmp="$out.partial"
trap 'rm -f "$tmp"' EXIT   # a failed dump never leaves a half-written file behind

# --clean --if-exists: the dump can be restored over an existing database.
# shellcheck disable=SC2016  # $POSTGRES_* expand inside the container, not here
compose exec -T postgres sh -c \
  'pg_dump --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  | gzip -9 > "$tmp"
# A dump that is empty or failed mid-way must never replace a good one.
if ! gunzip -t "$tmp" || [[ "$(gunzip -c "$tmp" | head -c 200 | wc -c)" -lt 100 ]]; then
  rm -f "$tmp"
  echo "backup FAILED: empty or corrupt dump" >&2
  exit 1
fi
mv "$tmp" "$out"
find "$BACKUP_DIR" -name 'agentguard-*.sql.gz' -type f -mtime +"$KEEP_DAYS" -delete
echo "backup ok: $out ($(du -h "$out" | cut -f1))"
