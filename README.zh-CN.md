# xdpass

中文 | [English](README.md)

`xdpass` 是一个基于 XDP 的旁路流量处理服务，用于规则匹配、事件上报、统计查询和主动响应。

## Agent 架构

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

## 功能

xdpass-agent 支持：

- XDP 程序挂载、卸载和启停控制
- TCP、ICMP、ARP、DNS 等主动响应动作
- 命中事件 SSE 推送
- userspace path 命中包 dispatch 分发

## 快速开始

### 环境要求

- Linux kernel >= 5.8
- Go >= 1.22
- clang / llvm，用于 BPF 编译
- root 权限，或具备 `CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_BPF`、`CAP_SYS_ADMIN` 等运行所需 capability

### 构建

```bash
make build
```

构建产物为：

```text
build/xdpass-agent
```

发布构建可以显式写入版本号：

```bash
make build VERSION=v0.1.0
./build/xdpass-agent --version
```

### 测试

```bash
make test
```

`make test` 会先生成 BPF 代码，再运行 Go 测试。

## 配置

agent 启动配置只用于 HTTP server 和日志。attachments、ruleset、response egress、dispatch 等运行态资源不写入配置文件，需要通过 HTTP API 下发。

agent 进程重启后，运行态资源会回到空状态或默认状态，需要由 mgr 或调用方重新下发。

最小配置示例：

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

默认配置模板见 `deploy/config/agent/config.yaml`，字段语义见 `specs/agent/config.md`。

## 部署

项目提供 systemd 部署脚本。推荐先打包，再在目标机器上执行安装脚本：

```bash
make pack VERSION=v0.1.0
tar -xzf build/xdpass-v0.1.0-linux-amd64.tar.gz
cd xdpass-v0.1.0-linux-amd64
sudo scripts/install-systemd.sh --enable --start
```

安装脚本会安装：

- `bin/xdpass-agent` 到 `/usr/local/bin/xdpass-agent`
- `deploy/config/agent/config.yaml` 到 `/etc/xdpass/agent/config.yaml`
- `deploy/systemd/xdpass-agent.service` 到 `/etc/systemd/system/xdpass-agent.service`

默认不会覆盖已有配置文件；需要覆盖时传入 `--force`：

```bash
sudo scripts/install-systemd.sh --force --enable --start
```

查看脚本参数：

```bash
scripts/install-systemd.sh --help
```

## 使用示例

请先按部署章节启动 agent。以下示例假设 agent 监听 `127.0.0.1:9346`。

健康检查：

```bash
curl http://127.0.0.1:9346/api/v1/health
```

查看运行态总览：

```bash
curl http://127.0.0.1:9346/api/v1/status
```

创建 attachment。请将示例中的 `ifindex` 替换为目标网卡的 ifindex，可通过 `ip link` 查看：

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

下发 ruleset：

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

查看统计：

```bash
curl http://127.0.0.1:9346/api/v1/stats
```

查看事件流：

```bash
curl -N http://127.0.0.1:9346/api/v1/events/stream
```

更多 API 路由见 `specs/agent-api.md`。日常操作也可以参考 `scripts/xdpass-cli.py`，它封装了 agent HTTP API 调用。
