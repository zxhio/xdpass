#!/usr/bin/env python3
"""
xdpass-cli.py — CLI tool for xdpass-agent HTTP API.

All commands call xdpass-agent HTTP API. No direct netns/BPF/XSK/NIC operations.

Usage:
    python3 scripts/xdpass-cli.py health
    python3 scripts/xdpass-cli.py status
    python3 scripts/xdpass-cli.py attach --iface br-xdpass
    python3 scripts/xdpass-cli.py detach --iface br-xdpass
    python3 scripts/xdpass-cli.py ruleset-apply
    python3 scripts/xdpass-cli.py stats
    python3 scripts/xdpass-cli.py smoke
"""

import argparse
import json
import socket
import sys
import urllib.error
import urllib.request


def make_request(addr, method, path, body=None):
    """Send HTTP request and return (status, body_dict_or_raw)."""
    url = addr.rstrip("/") + path
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            status = resp.status
            try:
                return status, json.loads(raw)
            except json.JSONDecodeError:
                return status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            resp_body = json.loads(raw)
        except json.JSONDecodeError:
            resp_body = raw
        return e.code, resp_body
    except urllib.error.URLError as e:
        return 0, str(e.reason)


def print_result(method, path, status, body):
    """Print request result."""
    print(f"{method} {path} -> {status}")
    if isinstance(body, dict):
        print(json.dumps(body, indent=2))
    elif body:
        print(body)


def resolve_ifindex(iface):
    """Resolve interface name to ifindex."""
    try:
        return socket.if_nametoindex(iface)
    except OSError:
        print(f"error: interface '{iface}' not found", file=sys.stderr)
        sys.exit(1)


def cmd_health(addr, _args):
    status, body = make_request(addr, "GET", "/api/v1/health")
    print_result("GET", "/api/v1/health", status, body)
    return 0 if 200 <= status < 300 else 1


def cmd_status(addr, _args):
    status, body = make_request(addr, "GET", "/api/v1/status")
    print_result("GET", "/api/v1/status", status, body)
    return 0 if 200 <= status < 300 else 1


def cmd_attach(addr, args):
    ifindex = resolve_ifindex(args.iface)
    body = {
        "ifindex": ifindex,
        "ifname": args.iface,
        "attach_mode": args.mode,
    }
    status, resp = make_request(addr, "POST", "/api/v1/attachments", body)
    print_result("POST", "/api/v1/attachments", status, resp)
    return 0 if 200 <= status < 300 else 1


def cmd_detach(addr, args):
    if args.ifindex:
        ifindex = args.ifindex
    elif args.iface:
        ifindex = resolve_ifindex(args.iface)
    else:
        print("error: --iface or --ifindex required", file=sys.stderr)
        return 1

    path = f"/api/v1/attachments/{ifindex}"
    status, resp = make_request(addr, "DELETE", path)
    print_result("DELETE", path, status, resp)
    return 0 if 200 <= status < 300 else 1


def cmd_ruleset_apply(addr, _args):
    rules = [
        {
            "rule_id": 1,
            "priority": 100,
            "match": {"protocol": "icmp"},
            "response": {"action": "alert"},
        },
        {
            "rule_id": 2,
            "priority": 200,
            "match": {"protocol": "arp", "arp_op": "request"},
            "response": {"action": "arp_reply"},
        },
    ]
    status, resp = make_request(addr, "PUT", "/api/v1/ruleset", {"rules": rules})
    print_result("PUT", "/api/v1/ruleset", status, resp)
    return 0 if 200 <= status < 300 else 1


def cmd_stats(addr, _args):
    status, body = make_request(addr, "GET", "/api/v1/stats")
    print_result("GET", "/api/v1/stats", status, body)
    return 0 if 200 <= status < 300 else 1


def cmd_smoke(addr, args):
    """Run smoke test: health, status, attach, ruleset-apply, stats."""
    iface = getattr(args, "iface", None) or "br-xdpass"
    failures = 0

    print(f"=== smoke test (addr={addr}, iface={iface}) ===\n")

    print("[1/5] health")
    if cmd_health(addr, args):
        failures += 1
        print("  FAIL\n")
    else:
        print("  OK\n")

    print("[2/5] status")
    if cmd_status(addr, args):
        failures += 1
        print("  FAIL\n")
    else:
        print("  OK\n")

    print("[3/5] attach")
    args.iface = iface
    args.mode = "generic"
    if cmd_attach(addr, args):
        failures += 1
        print("  FAIL\n")
    else:
        print("  OK\n")

    print("[4/5] ruleset-apply")
    if cmd_ruleset_apply(addr, args):
        failures += 1
        print("  FAIL\n")
    else:
        print("  OK\n")

    print("[5/5] stats")
    if cmd_stats(addr, args):
        failures += 1
        print("  FAIL\n")
    else:
        print("  OK\n")

    # TODO(phase-02): real response verification
    # - ping 10.0.1.3 from ns-xdpass1
    # - verify ARP reply and ICMP echo reply via stats counters
    # - requires: agent running with XSK enabled, bridge XDP attach

    print(f"=== smoke result: {5 - failures}/5 passed ===")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description="xdpass-agent API CLI")
    parser.add_argument("--addr", default="http://127.0.0.1:9527",
                        help="agent API address (default: http://127.0.0.1:9527)")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("health", help="GET /api/v1/health")
    sub.add_parser("status", help="GET /api/v1/status")

    p_attach = sub.add_parser("attach", help="POST /api/v1/attachments")
    p_attach.add_argument("--iface", required=True, help="interface name")
    p_attach.add_argument("--mode", default="generic", help="attach mode (default: generic)")

    p_detach = sub.add_parser("detach", help="DELETE /api/v1/attachments/{ifindex}")
    p_detach.add_argument("--iface", help="interface name")
    p_detach.add_argument("--ifindex", type=int, help="interface index")

    sub.add_parser("ruleset-apply", help="PUT /api/v1/ruleset with minimal rules")
    sub.add_parser("stats", help="GET /api/v1/stats")

    p_smoke = sub.add_parser("smoke", help="run full smoke test")
    p_smoke.add_argument("--iface", default="br-xdpass", help="interface for attach (default: br-xdpass)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "health": cmd_health,
        "status": cmd_status,
        "attach": cmd_attach,
        "detach": cmd_detach,
        "ruleset-apply": cmd_ruleset_apply,
        "stats": cmd_stats,
        "smoke": cmd_smoke,
    }

    return handlers[args.command](args.addr, args)


if __name__ == "__main__":
    sys.exit(main())
