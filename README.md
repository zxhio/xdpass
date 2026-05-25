# xdpass

English | [中文](README.zh-CN.md)

`xdpass` is an XDP-based bypass traffic processing service for rule matching, event reporting, statistics queries, and active responses.

## Agent Architecture

```text
+------------+         +----------------------------+
|  HTTP API  |-------->|       Agent Runtime        |
+------------+         +-------------+--------------+
                                     |
                                     v
                       +----------------------------+
                       |          BPF Maps          |
                       +-------------+--------------+
                                     |
                                     v
                       +----------------------------+
                       |          XDP Prog          |
                       +-------------+--------------+
                                     |
           +-------------------------+-------------------------+
           |                         |                         |
           v                         v                         v
+---------------------+   +---------------------+   +---------------------+
|   Kernel Response   |   | Userspace Response  |   |   Events / Stats    |
|   XDP_TX/redirect   |   |   XSK RX -> worker  |   |    ringbuf/maps     |
+----------+----------+   +----------+----------+   +----------+----------+
           |                         |                         |
           v                         |                         v
+---------------------+              |              +---------------------+
|    Response NIC     |              |              |   HTTP stats/SSE    |
+---------------------+              |              +---------------------+
                                     |
                         +-----------+-----------+
                         |                       |
                         v                       v
             +---------------------+   +---------------------+
             |  XSK TX/AF_PACKET   |   |   Dispatch Queue    |
             +-----------+---------+   +----------+----------+
                         |                        |
                         v                        v
             +---------------------+   +---------------------+
             |    Response NIC     |   |      AF_PACKET      |
             +---------------------+   +----------+----------+
                                                  |
                                                  v
                                       +---------------------+
                                       |    Dispatch NIC     |
                                       +---------------------+
```

## Features

xdpass-agent supports:

- Attaching, detaching, starting, and stopping XDP programs
- Active response actions for TCP, ICMP, ARP, DNS, and related protocols
- Hit event delivery over SSE
- Dispatching userspace-path hit packets

## Quick Start

### Requirements

- Linux kernel >= 5.8
- Go >= 1.22
- clang / llvm for BPF compilation
- root privileges, or the runtime capabilities required by the deployment, such as `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`, and `CAP_SYS_ADMIN`

### Build

```bash
make build
```

The build artifact is:

```text
build/xdpass-agent
```

For release builds, set the version explicitly:

```bash
make build VERSION=v0.1.0
./build/xdpass-agent --version
```

### Test

```bash
make test
```

`make test` generates BPF code first, then runs the Go tests.

## Configuration

The agent startup configuration is only used for the HTTP server and logging. Runtime resources such as attachments, rulesets, response egress, and dispatch are not stored in the configuration file and must be configured through the HTTP API.

After the agent process restarts, runtime resources return to an empty or default state and must be pushed again by the manager or caller.

Minimal configuration example:

```yaml
server:
  listen_addr: "127.0.0.1:9346"

logging:
  level: info
  file_path: /var/log/xdpass/agent.log
  max_size_mb: 100
  max_backups: 7
  max_age_days: 30
  compress: true
```

See `deploy/config/agent/config.yaml` for the default configuration template, and `specs/agent/config.md` for field semantics.

## Deployment

The project provides a systemd deployment script. The recommended flow is to package first, then run the installer on the target machine:

```bash
make pack VERSION=v0.1.0
tar -xzf build/xdpass-v0.1.0-linux-amd64.tar.gz
cd xdpass-v0.1.0-linux-amd64
sudo scripts/install-systemd.sh --enable --start
```

The installer writes:

- `bin/xdpass-agent` to `/usr/local/bin/xdpass-agent`
- `deploy/config/agent/config.yaml` to `/etc/xdpass/agent/config.yaml`
- `deploy/systemd/xdpass-agent.service` to `/etc/systemd/system/xdpass-agent.service`

Existing configuration files are not overwritten by default. Pass `--force` to overwrite them:

```bash
sudo scripts/install-systemd.sh --force --enable --start
```

View installer options:

```bash
scripts/install-systemd.sh --help
```

## Usage Examples

Start the agent by following the deployment section first. The examples below assume the agent is listening on `127.0.0.1:9346`.

Health check:

```bash
curl http://127.0.0.1:9346/api/v1/health
```

View the runtime overview:

```bash
curl http://127.0.0.1:9346/api/v1/status
```

Create an attachment. Replace the example `ifindex` with the ifindex of the target NIC, which can be inspected with `ip link`:

```bash
curl -X POST 'http://127.0.0.1:9346/api/v1/attachments' \
  -H 'Content-Type: application/json' \
  -d '{
    "ifindex": 3,
    "attach_mode": "generic",
    "miss_verdict": "pass",
    "channels": {
      "rx_queue_count": 1
    },
    "xsk": {
      "enabled": true,
      "queues": [0]
    }
  }'
```

Push a ruleset:

```bash
curl -X PUT 'http://127.0.0.1:9346/api/v1/ruleset' \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [
      {
        "rule_id": 1001,
        "priority": 10,
        "match": {
          "protocol": "tcp",
          "dst_cidrs": ["192.0.2.10/32"],
          "dst_ports": [80]
        },
        "response": {
          "action": "tcp_reset"
        }
      }
    ]
  }'
```

View statistics:

```bash
curl http://127.0.0.1:9346/api/v1/stats
```

View the event stream:

```bash
curl -N http://127.0.0.1:9346/api/v1/events/stream
```

See `specs/agent-api.md` for more API routes. For day-to-day operations, you can also refer to `scripts/xdpass-cli.py`, which wraps the agent HTTP API calls.
