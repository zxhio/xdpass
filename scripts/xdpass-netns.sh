#!/usr/bin/env bash
#
# xdpass-netns.sh — local network namespace test environment for xdpass-agent.
#
# Topology:
#   bridge: br-xdpass (10.0.1.1/24)
#   ns-xdpass1: eth0 10.0.1.2/24 via 10.0.1.1
#   ns-xdpass2: eth0 10.0.1.3/24 via 10.0.1.1
#   host veth: veth-xdpass1, veth-xdpass2 (both attached to br-xdpass)
#
# Usage:
#   sudo scripts/xdpass-netns.sh setup
#   sudo scripts/xdpass-netns.sh cleanup
#   sudo scripts/xdpass-netns.sh reset
#   sudo scripts/xdpass-netns.sh status
#   sudo scripts/xdpass-netns.sh ping

set -euo pipefail

BRIDGE="br-xdpass"
NS1="ns-xdpass1"
NS2="ns-xdpass2"
VETH1="veth-xdpass1"
VETH2="veth-xdpass2"
VETH1_PEER="veth-xd1p"
VETH2_PEER="veth-xd2p"
BRIDGE_IP="10.0.1.1/24"
NS1_IP="10.0.1.2/24"
NS2_IP="10.0.1.3/24"
GATEWAY="10.0.1.1"

die() { echo "error: $*" >&2; exit 1; }

check_root() {
    [[ $(id -u) -eq 0 ]] || die "must be run as root"
}

check_deps() {
    command -v ip >/dev/null 2>&1 || die "'ip' command not found (install iproute2)"
}

# Remove a resource if it exists, ignoring errors.
safe_del_br()  { ip link show "$1" &>/dev/null && ip link del "$1" || true; }
safe_del_ns()  { ip netns list 2>/dev/null | grep -qw "$1" && ip netns del "$1" || true; }
safe_del_veth(){ ip link show "$1" &>/dev/null && ip link del "$1" || true; }

cleanup() {
    safe_del_br  "$BRIDGE"
    safe_del_veth "$VETH1"
    safe_del_veth "$VETH2"
    safe_del_veth "$VETH1_PEER"
    safe_del_veth "$VETH2_PEER"
    safe_del_ns  "$NS1"
    safe_del_ns  "$NS2"
}

setup() {
    cleanup

    # Bridge
    ip link add "$BRIDGE" type bridge
    ip addr add "$BRIDGE_IP" dev "$BRIDGE"
    ip link set "$BRIDGE" up

    # Namespace 1
    ip netns add "$NS1"
    ip link add "$VETH1" type veth peer name "$VETH1_PEER"
    ip link set "$VETH1" master "$BRIDGE"
    ip link set "$VETH1" up
    ip link set "$VETH1_PEER" netns "$NS1"
    ip netns exec "$NS1" ip link set lo up
    ip netns exec "$NS1" ip link set "$VETH1_PEER" name eth0
    ip netns exec "$NS1" ip addr add "$NS1_IP" dev eth0
    ip netns exec "$NS1" ip link set eth0 up
    ip netns exec "$NS1" ip route add default via "$GATEWAY"

    # Namespace 2
    ip netns add "$NS2"
    ip link add "$VETH2" type veth peer name "$VETH2_PEER"
    ip link set "$VETH2" master "$BRIDGE"
    ip link set "$VETH2" up
    ip link set "$VETH2_PEER" netns "$NS2"
    ip netns exec "$NS2" ip link set lo up
    ip netns exec "$NS2" ip link set "$VETH2_PEER" name eth0
    ip netns exec "$NS2" ip addr add "$NS2_IP" dev eth0
    ip netns exec "$NS2" ip link set eth0 up
    ip netns exec "$NS2" ip route add default via "$GATEWAY"

    echo ""
    echo "=== netns setup complete ==="
    echo ""
    echo "Bridge:   $BRIDGE  ($BRIDGE_IP)"
    echo "NS1:      $NS1     ($NS1_IP)"
    echo "NS2:      $NS2     ($NS2_IP)"
    echo ""
    echo "Next steps:"
    echo "  # Ping ns2 from ns1:"
    echo "  sudo scripts/xdpass-netns.sh ping"
    echo ""
    echo "  # Start agent (in a separate terminal):"
    echo "  sudo ./build/xdpass-agent"
    echo ""
    echo "  # Run API smoke test:"
    echo "  python3 scripts/xdpass-api-cli.py smoke"
    echo ""
    echo "  # Cleanup when done:"
    echo "  sudo scripts/xdpass-netns.sh cleanup"
}

status() {
    echo "=== Bridge ==="
    ip link show "$BRIDGE" 2>/dev/null || echo "  (not found)"
    echo ""
    echo "=== Bridge address ==="
    ip -4 addr show "$BRIDGE" 2>/dev/null | grep inet || echo "  (no address)"
    echo ""
    echo "=== Namespaces ==="
    for ns in "$NS1" "$NS2"; do
        if ip netns list 2>/dev/null | grep -qw "$ns"; then
            echo "  $ns: exists"
            ip netns exec "$ns" ip -4 addr show eth0 2>/dev/null | grep inet | sed 's/^/    /'
            ip netns exec "$ns" ip route show default 2>/dev/null | sed 's/^/    /'
        else
            echo "  $ns: not found"
        fi
    done
    echo ""
    echo "=== Host veths ==="
    for v in "$VETH1" "$VETH2"; do
        ip link show "$v" 2>/dev/null | head -1 | sed 's/^/  /' || echo "  $v: not found"
    done
}

ping_test() {
    ip netns list 2>/dev/null | grep -qw "$NS1" || die "$NS1 does not exist; run 'setup' first"
    echo "Pinging 10.0.1.3 from $NS1 ..."
    ip netns exec "$NS1" ping -c 3 -W 2 10.0.1.3
}

case "${1:-}" in
    setup)   check_root; check_deps; setup ;;
    cleanup) check_root; check_deps; cleanup; echo "cleanup done" ;;
    reset)   check_root; check_deps; cleanup; setup ;;
    status)  check_deps; status ;;
    ping)    check_root; check_deps; ping_test ;;
    *)       die "usage: $0 {setup|cleanup|reset|status|ping}" ;;
esac
