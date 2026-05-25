#!/usr/bin/env python3
"""
xdpass-cli.py -- CLI for xdpass-agent HTTP API.

All commands call xdpass-agent HTTP API.
No direct netns / BPF / XSK / NIC operations.

Usage:
    python3 scripts/xdpass-cli.py <command> [options]
    python3 scripts/xdpass-cli.py attachments list
    python3 scripts/xdpass-cli.py attach --ifname br-xdpass
    python3 scripts/xdpass-cli.py smoke --ifname br-xdpass
"""

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def api_request(addr, method, path, body=None):
    """Send HTTP request to agent API.

    Returns (status_code, body).
    - 204: body is None.
    - JSON response: body is dict or list.
    - Problem Details: body is dict with 'title'/'detail'/'code'.
    - Connection error: status_code is 0, body is error string.
    """
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
            if not raw:
                return resp.status, None
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        if not raw:
            return e.code, None
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except urllib.error.URLError as e:
        return 0, str(e.reason)


def print_response(method, path, status, body):
    """Print API response in a consistent format."""
    print(f"{method} {path} -> {status}")
    if body is None:
        return
    if isinstance(body, (dict, list)):
        print(json.dumps(body, indent=2))
    else:
        print(body)


def print_error(method, path, status, body):
    """Print API error, extracting Problem Details fields if present."""
    print(f"{method} {path} -> {status}", file=sys.stderr)
    if isinstance(body, dict):
        for key in ("title", "detail", "code"):
            if key in body:
                print(f"  {key}: {body[key]}", file=sys.stderr)
    elif body:
        print(f"  {body}", file=sys.stderr)


def is_success(status):
    return 200 <= status < 300


def resolve_ifindex(ifname):
    """Resolve interface name to ifindex via OS."""
    try:
        return socket.if_nametoindex(ifname)
    except OSError:
        print(f"error: interface '{ifname}' not found", file=sys.stderr)
        sys.exit(1)


def attachment_ifindex(args):
    """Resolve an attachment command target to ifindex."""
    if getattr(args, "ifindex", None):
        return args.ifindex
    if getattr(args, "ifindex_arg", None):
        return args.ifindex_arg
    if getattr(args, "ifname", None):
        return resolve_ifindex(args.ifname)
    print("error: --ifname or --ifindex required", file=sys.stderr)
    sys.exit(1)


def parse_queues(raw):
    """Parse comma-separated XSK queue IDs."""
    if not raw:
        return None
    queues = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            queue = int(item)
        except ValueError:
            print(f"error: invalid queue '{item}'", file=sys.stderr)
            sys.exit(1)
        if queue < 0:
            print(f"error: invalid queue '{item}'", file=sys.stderr)
            sys.exit(1)
        queues.append(queue)
    return queues


def parse_rx_queue_count(raw):
    """Parse enabled RX queue count."""
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid RX queue count '{raw}'")
    if value < 0:
        raise argparse.ArgumentTypeError("RX queue count must be >= 0")
    return value


def load_json_file(path):
    """Load JSON from a file path, or stdin when path is '-'."""
    try:
        if path == "-":
            return json.load(sys.stdin)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        print(f"error: cannot read JSON file '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON in '{path}': {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Command handlers (stubs -- filled in Phase 2-4)
# ---------------------------------------------------------------------------

def cmd_health(addr, _args):
    method, path = "GET", "/api/v1/health"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_status(addr, _args):
    method, path = "GET", "/api/v1/status"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_attachments_list(addr, _args):
    method, path = "GET", "/api/v1/attachments"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_attachments_get(addr, args):
    args.ifindex = attachment_ifindex(args)
    path = f"/api/v1/attachments/{args.ifindex}"
    method = "GET"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_attachments_create(addr, args):
    ifindex = attachment_ifindex(args)
    body = {"ifindex": ifindex, "attach_mode": args.mode}
    if args.miss_verdict:
        body["miss_verdict"] = args.miss_verdict
    if getattr(args, "rx_queues", None) is not None:
        body["channels"] = {"rx_queue_count": args.rx_queues}
    queues = parse_queues(getattr(args, "xsk_queues", None))
    xsk_enabled = bool(getattr(args, "xsk", False))
    if queues is not None:
        xsk_enabled = True
    if xsk_enabled:
        body["xsk"] = {"enabled": True}
        if queues is not None:
            body["xsk"]["queues"] = queues
    path = "/api/v1/attachments"
    if args.dry_run:
        path += "?dry_run=true"
    method = "POST"
    status, resp = api_request(addr, method, path, body)
    if is_success(status):
        print_response(method, "/api/v1/attachments", status, resp)
        if not xsk_enabled:
            print("note: XSK is disabled; userspace response actions need --xsk", file=sys.stderr)
        return 0
    print_error(method, "/api/v1/attachments", status, resp)
    return 1


def cmd_attachments_set_enabled(addr, args):
    args.ifindex = attachment_ifindex(args)
    path = f"/api/v1/attachments/{args.ifindex}"
    method = "PATCH"
    status, body = api_request(addr, method, path, {"enabled": args.enabled})
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_attachments_delete(addr, args):
    args.ifindex = attachment_ifindex(args)
    path = f"/api/v1/attachments/{args.ifindex}"
    method = "DELETE"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print(f"DELETE {path} -> {status}")
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_ruleset_get(addr, _args):
    method, path = "GET", "/api/v1/ruleset"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_ruleset_put(addr, args):
    if getattr(args, "file", None):
        req = load_json_file(args.file)
        if not isinstance(req, dict) or "rules" not in req:
            print("error: ruleset file must be a JSON object with a 'rules' field", file=sys.stderr)
            return 1
    else:
        req = {
            "rules": [
                {
                    "rule_id": 1,
                    "priority": 100,
                    "match": {"protocol": "icmp"},
                    "response": {"action": "alert"},
                },
                {
                    "rule_id": 2,
                    "priority": 200,
                    "match": {"protocol": "arp", "arp": {"op": "request"}},
                    "response": {
                        "action": "arp_reply",
                        "params": {
                            "hardware_addr": "02:00:00:00:00:20",
                            "sender_ipv4": "192.168.1.20",
                        },
                    },
                },
            ]
        }
    path = "/api/v1/ruleset"
    if args.dry_run:
        path += "?dry_run=true"
    method = "PUT"
    status, body = api_request(addr, method, path, req)
    if is_success(status):
        print_response(method, "/api/v1/ruleset", status, body)
        return 0
    print_error(method, "/api/v1/ruleset", status, body)
    return 1


def cmd_ruleset_delete(addr, _args):
    method, path = "DELETE", "/api/v1/ruleset"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print(f"DELETE {path} -> {status}")
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_stats(addr, _args):
    method, path = "GET", "/api/v1/stats"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        if isinstance(body, dict):
            xsk_redirect = body.get("xsk_redirect") or {}
            if xsk_redirect.get("error_packets", 0) > 0:
                print(
                    "note: xsk_redirect.error_packets > 0; userspace response needs attachment XSK enabled",
                    file=sys.stderr,
                )
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_response_egress_get(addr, _args):
    method, path = "GET", "/api/v1/response/egress"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_response_egress_put(addr, args):
    ifindex = resolve_ifindex(args.ifname)
    body = {"ifindex": ifindex, "ifname": args.ifname}
    if args.vlan_mode:
        body["vlan_mode"] = args.vlan_mode
    method, path = "PUT", "/api/v1/response/egress"
    status, resp = api_request(addr, method, path, body)
    if is_success(status):
        print_response(method, path, status, resp)
        return 0
    print_error(method, path, status, resp)
    return 1


def cmd_response_egress_delete(addr, _args):
    method, path = "DELETE", "/api/v1/response/egress"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print(f"DELETE {path} -> {status}")
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_dispatch_get(addr, _args):
    method, path = "GET", "/api/v1/dispatch"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print_response(method, path, status, body)
        return 0
    print_error(method, path, status, body)
    return 1


def cmd_dispatch_put(addr, args):
    ifindex = resolve_ifindex(args.ifname)
    body = {"enabled": args.enabled, "ifindex": ifindex, "ifname": args.ifname}
    if args.queue_size:
        body["queue_size"] = args.queue_size
    method, path = "PUT", "/api/v1/dispatch"
    status, resp = api_request(addr, method, path, body)
    if is_success(status):
        print_response(method, path, status, resp)
        return 0
    print_error(method, path, status, resp)
    return 1


def cmd_dispatch_delete(addr, _args):
    method, path = "DELETE", "/api/v1/dispatch"
    status, body = api_request(addr, method, path)
    if is_success(status):
        print(f"DELETE {path} -> {status}")
        return 0
    print_error(method, path, status, body)
    return 1


# ---------------------------------------------------------------------------
# Compatible aliases (attach / detach / ruleset-apply)
# ---------------------------------------------------------------------------

def cmd_attach(addr, args):
    """Alias for 'attachments create'."""
    return cmd_attachments_create(addr, args)


def cmd_detach(addr, args):
    """Alias for 'attachments delete'."""
    return cmd_attachments_delete(addr, args)


def cmd_ruleset_apply(addr, args):
    """Alias for 'ruleset put'."""
    return cmd_ruleset_put(addr, args)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def cmd_events_stream(addr, args):
    """Connect to /api/v1/events/stream and print events."""
    raw_sse = getattr(args, "raw_sse", False)
    count = getattr(args, "count", None)
    timeout = getattr(args, "timeout", None)

    # Force line-buffered stdout so each event is flushed immediately,
    # even when piped (e.g. xdpass-cli events stream | jq).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    url = addr.rstrip("/") + "/api/v1/events/stream"
    req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})

    try:
        resp = urllib.request.urlopen(req, timeout=None)
    except urllib.error.URLError as e:
        print(f"error: {e.reason}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    received = 0
    start = time.monotonic()

    try:
        while True:
            if timeout is not None and (time.monotonic() - start) >= timeout:
                break
            if count is not None and received >= count:
                break

            line = resp.readline()
            if not line:
                break

            line = line.decode("utf-8", errors="replace").rstrip("\r\n")

            if raw_sse:
                print(line, flush=True)
                continue

            # In JSON mode, only print the data payload.
            if line.startswith("data: "):
                payload = line[6:]
                try:
                    json.loads(payload)  # validate
                    print(payload, flush=True)
                    received += 1
                except json.JSONDecodeError:
                    print(f"warning: non-JSON data: {payload}", file=sys.stderr)

    except KeyboardInterrupt:
        pass
    finally:
        resp.close()

    return 0


def cmd_events(addr, args):
    """Dispatch events subcommands."""
    ev_cmd = getattr(args, "ev_cmd", None)
    if ev_cmd == "stream":
        return cmd_events_stream(addr, args)
    # No subcommand -- help is printed by argparse.
    return 1


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def cmd_smoke(addr, args):
    """Run smoke test against agent API."""
    ifname = getattr(args, "ifname", None)
    if not ifname:
        print("error: --ifname required", file=sys.stderr)
        return 1

    steps = [
        ("health", lambda: cmd_health(addr, args)),
        ("status", lambda: cmd_status(addr, args)),
        ("attachments create", lambda: _smoke_attach(addr, args, ifname)),
        ("ruleset put", lambda: _smoke_ruleset(addr, args)),
        ("stats", lambda: cmd_stats(addr, args)),
    ]

    failures = 0
    print(f"=== smoke test (addr={addr}, ifname={ifname}) ===\n")
    for i, (name, fn) in enumerate(steps, 1):
        print(f"[{i}/{len(steps)}] {name}")
        if fn():
            failures += 1
            print("  FAIL\n")
        else:
            print("  OK\n")

    print(f"=== smoke result: {len(steps) - failures}/{len(steps)} passed ===")
    return 1 if failures else 0


def _smoke_attach(addr, args, ifname):
    args.ifname = ifname
    args.ifindex = None
    args.mode = "generic"
    args.dry_run = False
    args.miss_verdict = None
    args.rx_queues = None
    args.xsk = True
    args.xsk_queues = None
    return cmd_attachments_create(addr, args)


def _smoke_ruleset(addr, args):
    args.dry_run = False
    args.file = None
    return cmd_ruleset_put(addr, args)


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="xdpass-cli",
        description="CLI for xdpass-agent HTTP API.",
        epilog="All commands call xdpass-agent HTTP API. "
               "No direct netns/BPF/XSK/NIC operations.",
    )
    parser.add_argument(
        "--addr", default="http://127.0.0.1:9346",
        help="agent API address (default: http://127.0.0.1:9346)",
    )

    sub = parser.add_subparsers(dest="command")

    # -- basic --
    sub.add_parser("health", help="GET /api/v1/health  -- process liveness check")
    sub.add_parser("status", help="GET /api/v1/status  -- runtime overview")

    # -- attachments --
    att = sub.add_parser("attachments", help="manage XDP attachments")
    att_sub = att.add_subparsers(dest="att_cmd")

    att_sub.add_parser("list", help="GET /api/v1/attachments")

    p_att_get = att_sub.add_parser("get", help="GET /api/v1/attachments/{ifindex}")
    p_att_get.add_argument("ifindex_arg", nargs="?", type=int, help="interface index")
    p_att_get.add_argument("--ifname", help="interface name")
    p_att_get.add_argument("--ifindex", type=int, help="interface index")

    p_att_create = att_sub.add_parser("create", help="POST /api/v1/attachments")
    p_att_create.add_argument("--ifname", help="interface name")
    p_att_create.add_argument("--ifindex", type=int, help="interface index")
    p_att_create.add_argument("--mode", default="generic",
                              help="attach mode: generic/native/driver (default: generic)")
    p_att_create.add_argument("--miss-verdict", dest="miss_verdict",
                              choices=["pass", "drop"], help="miss verdict (default: pass)")
    p_att_create.add_argument("--rx-queues", dest="rx_queues", type=parse_rx_queue_count,
                              help="enabled RX queue count")
    p_att_create.add_argument("--xsk", dest="xsk", action="store_true",
                              help="enable XSK for userspace response actions")
    p_att_create.add_argument("--xsk-queues", dest="xsk_queues",
                              help="comma-separated XSK queues, implies --xsk")
    p_att_create.add_argument("--dry-run", dest="dry_run", action="store_true",
                              help="POST /api/v1/attachments?dry_run=true")

    p_att_enable = att_sub.add_parser("set-enabled",
                                      help="PATCH /api/v1/attachments/{ifindex}")
    p_att_enable.add_argument("ifindex_arg", nargs="?", type=int, help="interface index")
    p_att_enable.add_argument("--ifname", help="interface name")
    p_att_enable.add_argument("--ifindex", type=int, help="interface index")
    p_att_enable.add_argument("--enabled", type=bool, required=True,
                              help="true/false")

    p_att_del = att_sub.add_parser("delete", help="DELETE /api/v1/attachments/{ifindex}")
    p_att_del.add_argument("ifindex_arg", nargs="?", type=int, help="interface index")
    p_att_del.add_argument("--ifname", help="interface name")
    p_att_del.add_argument("--ifindex", type=int, help="interface index")

    # -- compatible alias: attach --
    p_attach = sub.add_parser("attach",
                              help="(alias) POST /api/v1/attachments")
    p_attach.add_argument("--ifname", help="interface name")
    p_attach.add_argument("--ifindex", type=int, help="interface index")
    p_attach.add_argument("--mode", default="generic",
                          help="attach mode (default: generic)")
    p_attach.add_argument("--dry-run", dest="dry_run", action="store_true",
                          help="dry-run mode")
    p_attach.add_argument("--miss-verdict", dest="miss_verdict",
                          choices=["pass", "drop"], help="miss verdict")
    p_attach.add_argument("--rx-queues", dest="rx_queues", type=parse_rx_queue_count,
                          help="enabled RX queue count")
    p_attach.add_argument("--xsk", dest="xsk", action="store_true",
                          help="enable XSK (default for attach)")
    p_attach.add_argument("--no-xsk", dest="xsk", action="store_false",
                          help="disable XSK")
    p_attach.add_argument("--xsk-queues", dest="xsk_queues",
                          help="comma-separated XSK queues, implies --xsk")
    p_attach.set_defaults(xsk=True)

    # -- compatible alias: detach --
    p_detach = sub.add_parser("detach",
                              help="(alias) DELETE /api/v1/attachments/{ifindex}")
    p_detach.add_argument("--ifname", help="interface name")
    p_detach.add_argument("--ifindex", type=int, help="interface index")

    # -- ruleset --
    rs = sub.add_parser("ruleset", help="manage runtime ruleset")
    rs_sub = rs.add_subparsers(dest="rs_cmd")

    rs_sub.add_parser("get", help="GET /api/v1/ruleset")

    p_rs_put = rs_sub.add_parser("put", help="PUT /api/v1/ruleset")
    p_rs_put.add_argument("--file", "-f", dest="file",
                          help="ruleset JSON file, or '-' for stdin")
    p_rs_put.add_argument("--dry-run", dest="dry_run", action="store_true",
                          help="PUT /api/v1/ruleset?dry_run=true")

    rs_sub.add_parser("delete", help="DELETE /api/v1/ruleset")

    # -- compatible alias: ruleset-apply --
    p_rs_apply = sub.add_parser("ruleset-apply",
                                help="(alias) PUT /api/v1/ruleset")
    p_rs_apply.add_argument("--file", "-f", dest="file",
                            help="ruleset JSON file, or '-' for stdin")
    p_rs_apply.add_argument("--dry-run", dest="dry_run", action="store_true",
                            help="dry-run mode")

    # -- stats --
    sub.add_parser("stats", help="GET /api/v1/stats")

    # -- response egress --
    re_eg = sub.add_parser("response-egress", help="manage response egress config")
    re_sub = re_eg.add_subparsers(dest="re_cmd")

    re_sub.add_parser("get", help="GET /api/v1/response/egress")

    p_re_put = re_sub.add_parser("put", help="PUT /api/v1/response/egress")
    p_re_put.add_argument("--ifname", required=True, help="egress interface name")
    p_re_put.add_argument("--vlan-mode", dest="vlan_mode",
                          choices=["preserve", "access"],
                          help="VLAN mode (default: preserve)")

    re_sub.add_parser("delete", help="DELETE /api/v1/response/egress")

    # -- dispatch --
    dp = sub.add_parser("dispatch", help="manage dispatch config")
    dp_sub = dp.add_subparsers(dest="dp_cmd")

    dp_sub.add_parser("get", help="GET /api/v1/dispatch")

    p_dp_put = dp_sub.add_parser("put", help="PUT /api/v1/dispatch")
    p_dp_put.add_argument("--ifname", required=True, help="dispatch interface name")
    p_dp_put.add_argument("--enabled", type=bool, default=True,
                          help="enable dispatch (default: true)")
    p_dp_put.add_argument("--queue-size", dest="queue_size", type=int,
                          help="dispatch queue size (default: 4096)")

    dp_sub.add_parser("delete", help="DELETE /api/v1/dispatch")

    # -- events --
    ev = sub.add_parser("events", help="subscribe to event stream")
    ev_sub = ev.add_subparsers(dest="ev_cmd")

    p_ev_stream = ev_sub.add_parser("stream", help="GET /api/v1/events/stream")
    p_ev_stream.add_argument("--raw-sse", dest="raw_sse", action="store_true",
                             help="print raw SSE lines instead of JSON only")
    p_ev_stream.add_argument("--count", type=int, help="stop after N events")
    p_ev_stream.add_argument("--timeout", type=float, help="stop after SEC seconds")

    # -- smoke --
    p_smoke = sub.add_parser("smoke", help="run smoke test against agent API")
    p_smoke.add_argument("--ifname", required=True, help="interface name for attach")

    return parser


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

COMMANDS = {
    "health": cmd_health,
    "status": cmd_status,
    "attachments": None,
    "attach": cmd_attach,
    "detach": cmd_detach,
    "ruleset": None,
    "ruleset-apply": cmd_ruleset_apply,
    "stats": cmd_stats,
    "response-egress": None,
    "dispatch": None,
    "events": cmd_events,
    "smoke": cmd_smoke,
}

ATTACHMENTS_COMMANDS = {
    "list": cmd_attachments_list,
    "get": cmd_attachments_get,
    "create": cmd_attachments_create,
    "set-enabled": cmd_attachments_set_enabled,
    "delete": cmd_attachments_delete,
}

RULESET_COMMANDS = {
    "get": cmd_ruleset_get,
    "put": cmd_ruleset_put,
    "delete": cmd_ruleset_delete,
}

RESPONSE_EGRESS_COMMANDS = {
    "get": cmd_response_egress_get,
    "put": cmd_response_egress_put,
    "delete": cmd_response_egress_delete,
}

DISPATCH_COMMANDS = {
    "get": cmd_dispatch_get,
    "put": cmd_dispatch_put,
    "delete": cmd_dispatch_delete,
}


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    addr = args.addr

    if args.command in ("attachments",):
        if not args.att_cmd:
            parser.parse_args([args.command, "--help"])
            return 1
        return ATTACHMENTS_COMMANDS[args.att_cmd](addr, args)

    if args.command in ("ruleset",):
        if not args.rs_cmd:
            parser.parse_args([args.command, "--help"])
            return 1
        return RULESET_COMMANDS[args.rs_cmd](addr, args)

    if args.command in ("response-egress",):
        if not args.re_cmd:
            parser.parse_args([args.command, "--help"])
            return 1
        return RESPONSE_EGRESS_COMMANDS[args.re_cmd](addr, args)

    if args.command in ("dispatch",):
        if not args.dp_cmd:
            parser.parse_args([args.command, "--help"])
            return 1
        return DISPATCH_COMMANDS[args.dp_cmd](addr, args)

    if args.command in ("events",):
        if not args.ev_cmd:
            parser.parse_args([args.command, "--help"])
            return 1
        return cmd_events(addr, args)

    return COMMANDS[args.command](addr, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
