#!/usr/bin/env bash
# AgentGuard sandbox egress firewall (brief 6.4, 12). Owner: Arslan.
#
# Creates the dedicated Docker network every sandbox container joins (`agentguard-sandbox`,
# see backend/app/sandbox/launcher.py) and host firewall rules so that, whatever happens
# inside the container, traffic from that network can only reach PUBLIC addresses over TCP:
#
#   - dropped: loopback, RFC1918, CGNAT, link-local (incl. 169.254.169.254 metadata),
#     benchmark/reserved, multicast, the host itself (INPUT), other containers (ICC off)
#   - dropped: all UDP and other protocols (no QUIC or WebRTC; Chromium falls back to TCP),
#     except port 53 to the host's own upstream DNS servers: recent Docker sends the embedded
#     resolver's upstream queries from the container's namespace, so they cross this firewall
#   - no IPv6 on the network at all
#
# Usage (on the Docker host, as root):
#   sudo bash scripts/sandbox-egress.sh apply    # create network + rules (idempotent)
#   sudo bash scripts/sandbox-egress.sh status   # show network and rules
#   sudo bash scripts/sandbox-egress.sh remove   # delete the rules (network is kept)
#   add --dry-run to print the commands without running anything (no root needed)
# Env: AGENTGUARD_SANDBOX_DNS="ip,ip" overrides the upstream DNS list (default: the host's).
# Rules don't survive a reboot by themselves: install scripts/agentguard-egress.service.
set -euo pipefail

NETWORK="${AGENTGUARD_SANDBOX_NETWORK:-agentguard-sandbox}"
SUBNET="${AGENTGUARD_SANDBOX_SUBNET:-172.31.250.0/24}"
BRIDGE="${AGENTGUARD_SANDBOX_BRIDGE:-br-agsandbox}"
CHAIN="AGENTGUARD-SANDBOX"
CHAIN_IN="AGENTGUARD-SANDBOX-IN"

# Destinations a sandbox must never reach (IPv4). Public internet is everything else.
BLOCKED_CIDRS=(
  0.0.0.0/8        # "this network"
  10.0.0.0/8       # RFC1918
  100.64.0.0/10    # CGNAT (also Alibaba metadata 100.100.100.200)
  127.0.0.0/8      # loopback
  169.254.0.0/16   # link-local, cloud metadata 169.254.169.254
  172.16.0.0/12    # RFC1918 (includes Docker's own networks and this sandbox subnet)
  192.0.0.0/24     # IETF protocol assignments
  192.0.2.0/24     # TEST-NET-1
  192.168.0.0/16   # RFC1918
  198.18.0.0/15    # benchmarking
  198.51.100.0/24  # TEST-NET-2
  203.0.113.0/24   # TEST-NET-3
  224.0.0.0/4      # multicast
  240.0.0.0/4      # reserved + broadcast
)

# Upstream DNS servers the sandboxes' embedded resolver may query (port 53 only).
# Default: the host's real upstreams (systemd-resolved's list first; loopback entries skipped).
dns_servers() {
  if [ -n "${AGENTGUARD_SANDBOX_DNS:-}" ]; then
    local ip
    for ip in ${AGENTGUARD_SANDBOX_DNS//,/ }; do echo "$ip"; done
    return
  fi
  local f
  for f in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
    if [ -r "$f" ]; then
      awk '$1 == "nameserver" && $2 !~ /^127\./ && $2 !~ /:/ { print $2 }' "$f"
      return
    fi
  done
}

DRY_RUN=0
ACTION=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    apply|remove|status) ACTION="$arg" ;;
    *) echo "usage: $0 apply|remove|status [--dry-run]" >&2; exit 64 ;;
  esac
done
[ -n "$ACTION" ] || { echo "usage: $0 apply|remove|status [--dry-run]" >&2; exit 64; }

run() {
  echo "+ $*"
  if [ "$DRY_RUN" = 0 ]; then "$@"; fi
}

# Succeeds only when really executing and the probe succeeds (dry runs assume "absent").
probe() {
  [ "$DRY_RUN" = 0 ] && "$@" >/dev/null 2>&1
}

require_root() {
  if [ "$DRY_RUN" = 0 ] && [ "$(id -u)" != 0 ]; then
    echo "must run as root (sudo $0 $ACTION)" >&2
    exit 77
  fi
}

create_network() {
  if probe docker network inspect "$NETWORK"; then
    local subnet
    subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$NETWORK")
    if [ "$subnet" != "$SUBNET" ]; then
      echo "network $NETWORK exists with subnet $subnet, expected $SUBNET: remove it first" >&2
      exit 1
    fi
    echo "network $NETWORK already exists ($SUBNET)"
    return
  fi
  run docker network create \
    --driver bridge \
    --subnet "$SUBNET" \
    --opt com.docker.network.bridge.name="$BRIDGE" \
    --opt com.docker.network.bridge.enable_icc=false \
    --opt com.docker.network.bridge.enable_ip_masquerade=true \
    --label agentguard.role=sandbox \
    "$NETWORK"
}

ensure_chain() {  # ensure_chain <chain>: exists and is empty
  if probe iptables -n -L "$1"; then
    run iptables -F "$1"
  else
    run iptables -N "$1"
  fi
}

ensure_jump() {  # ensure_jump <parent> <child>: first rule of parent jumps for our bridge
  if ! probe iptables -C "$1" -i "$BRIDGE" -j "$2"; then
    run iptables -I "$1" 1 -i "$BRIDGE" -j "$2"
  fi
}

apply_rules() {
  # Forwarded traffic (sandbox -> anywhere). DOCKER-USER is evaluated before Docker's rules.
  if ! probe iptables -n -L DOCKER-USER; then run iptables -N DOCKER-USER; fi
  ensure_chain "$CHAIN"
  run iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  local dns found=0
  for dns in $(dns_servers); do
    found=1
    run iptables -A "$CHAIN" -d "$dns" -p udp --dport 53 -j RETURN
    run iptables -A "$CHAIN" -d "$dns" -p tcp --dport 53 -j RETURN
  done
  if [ "$found" = 0 ]; then
    echo "warning: no upstream DNS found; sandboxes can only use pinned hosts" >&2
  fi
  for cidr in "${BLOCKED_CIDRS[@]}"; do
    run iptables -A "$CHAIN" -d "$cidr" -j DROP
  done
  run iptables -A "$CHAIN" -p tcp -j RETURN   # public TCP: continue to Docker's rules
  run iptables -A "$CHAIN" -j DROP            # UDP, ICMP and anything else
  ensure_jump DOCKER-USER "$CHAIN"

  # Traffic addressed to the host itself (gateway IP, public IP, published ports).
  ensure_chain "$CHAIN_IN"
  run iptables -A "$CHAIN_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  run iptables -A "$CHAIN_IN" -j DROP
  ensure_jump INPUT "$CHAIN_IN"

  # Belt and braces: the network has no IPv6, but drop any that appears.
  if command -v ip6tables >/dev/null 2>&1; then
    if ! probe ip6tables -C FORWARD -i "$BRIDGE" -j DROP; then
      run ip6tables -I FORWARD 1 -i "$BRIDGE" -j DROP
    fi
    if ! probe ip6tables -C INPUT -i "$BRIDGE" -j DROP; then
      run ip6tables -I INPUT 1 -i "$BRIDGE" -j DROP
    fi
  fi
}

remove_rules() {
  while probe iptables -C DOCKER-USER -i "$BRIDGE" -j "$CHAIN"; do
    run iptables -D DOCKER-USER -i "$BRIDGE" -j "$CHAIN"
  done
  while probe iptables -C INPUT -i "$BRIDGE" -j "$CHAIN_IN"; do
    run iptables -D INPUT -i "$BRIDGE" -j "$CHAIN_IN"
  done
  for c in "$CHAIN" "$CHAIN_IN"; do
    if probe iptables -n -L "$c"; then
      run iptables -F "$c"
      run iptables -X "$c"
    fi
  done
  if command -v ip6tables >/dev/null 2>&1; then
    while probe ip6tables -C FORWARD -i "$BRIDGE" -j DROP; do
      run ip6tables -D FORWARD -i "$BRIDGE" -j DROP
    done
    while probe ip6tables -C INPUT -i "$BRIDGE" -j DROP; do
      run ip6tables -D INPUT -i "$BRIDGE" -j DROP
    done
  fi
}

case "$ACTION" in
  apply)
    require_root
    create_network
    apply_rules
    echo "sandbox egress firewall applied: $NETWORK ($SUBNET) on $BRIDGE"
    ;;
  remove)
    require_root
    remove_rules
    echo "sandbox egress rules removed (network $NETWORK kept)"
    ;;
  status)
    run docker network inspect "$NETWORK" --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}} icc={{index .Options "com.docker.network.bridge.enable_icc"}}'
    run iptables -n -v -L "$CHAIN"
    run iptables -n -v -L "$CHAIN_IN"
    ;;
esac
