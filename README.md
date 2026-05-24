# xdpass

`xdpass` 是一个基于 XDP 技术的旁路流量处理轻量服务，用于规则匹配和主动响应。

## 环境要求

- Linux kernel >= 5.8
- Go >= 1.22
- clang/llvm (BPF 编译)
- libbpf-dev (可选，用于系统 libbpf)

## 构建

```bash
make build
```

产物：`build/xdpass-agent`

`make build` 会写入版本信息；发布构建可显式传入版本号：

```bash
make build VERSION=v0.1.0
./build/xdpass-agent --version
```

## 测试

```bash
make test
```

包含 BPF 代码生成和所有单元测试。

## 运行

```bash
# 使用默认配置 (127.0.0.1:9527)
sudo ./build/xdpass-agent

# 使用配置文件
sudo ./build/xdpass-agent --config /etc/xdpass/agent/config.yaml
```

需要 root 或 `CAP_NET_ADMIN` + `CAP_BPF` 权限。

## systemd 部署

```bash
# 先构建 build/xdpass-agent
make build

# 打包 bin/xdpass-agent 和部署文件
make pack VERSION=0.0.1

# 解包后安装 xdpass，并启用/启动服务
tar -xzf build/xdpass-0.0.1-linux-amd64.tar.gz
cd xdpass-0.0.1-linux-amd64
sudo scripts/install-systemd.sh --enable --start
```

脚本默认读取包根下的 `bin/xdpass-agent`、`deploy/config/agent/config.yaml` 和 `deploy/systemd/xdpass-agent.service`。
默认不覆盖已有 `/etc/xdpass/agent/config.yaml`；需要覆盖时传 `--force`。

日志默认写入 `/var/log/xdpass/agent.log`，systemd unit 通过 `LogsDirectory=xdpass` 自动创建目录。

## API

HTTP API 默认监听 `127.0.0.1:9527`，详见 `specs/agent/` 目录。

主要端点：

- `GET /api/v1/health` - 健康检查
- `GET /api/v1/status` - 服务状态（含 `issues[]` degraded 诊断）
- `/api/v1/attachments` - 网卡 attachment 管理
- `/api/v1/ruleset` - 规则集管理
- `/api/v1/stats` - 统计信息
- `/api/v1/events/stream` - SSE 事件流
- `/api/v1/response/egress` - 响应出口配置

## 本地 netns 测试环境

提供 `scripts/xdpass-netns.sh` 创建本地 network namespace 拓扑，用于手动验证 attach、ruleset 和响应行为。

拓扑：

```
bridge: br-xdpass (10.0.1.1/24)
  ├── veth-xdpass1 <-> ns-xdpass1:eth0 (10.0.1.2/24)
  └── veth-xdpass2 <-> ns-xdpass2:eth0 (10.0.1.3/24)
```

```bash
# 创建环境
sudo scripts/xdpass-netns.sh setup

# 验证连通性
sudo scripts/xdpass-netns.sh ping

# 查看状态
sudo scripts/xdpass-netns.sh status

# 清理
sudo scripts/xdpass-netns.sh cleanup
```

## CLI

`scripts/xdpass-cli.py` 封装 agent HTTP API 调用，无需手写 curl。所有命令通过 xdpass-agent HTTP API 实现，不直接操作 netns、BPF、XSK 或网卡。

依赖 Python 3 标准库，无需安装第三方包。

```bash
# 基础命令
python3 scripts/xdpass-cli.py health
python3 scripts/xdpass-cli.py status
python3 scripts/xdpass-cli.py stats

# attachments
python3 scripts/xdpass-cli.py attachments list
python3 scripts/xdpass-cli.py attachments create --ifname br-xdpass --xsk
python3 scripts/xdpass-cli.py attachments delete --ifname br-xdpass
python3 scripts/xdpass-cli.py attach --ifname br-xdpass      # 兼容短命令
python3 scripts/xdpass-cli.py detach --ifname br-xdpass      # 兼容短命令

# ruleset
python3 scripts/xdpass-cli.py ruleset get
python3 scripts/xdpass-cli.py ruleset put
python3 scripts/xdpass-cli.py ruleset-apply                  # 兼容短命令

# response egress / dispatch
python3 scripts/xdpass-cli.py response-egress get
python3 scripts/xdpass-cli.py dispatch get

# events
python3 scripts/xdpass-cli.py events stream                     # 实时 JSON 事件流
python3 scripts/xdpass-cli.py events stream --raw-sse           # 原始 SSE 格式
python3 scripts/xdpass-cli.py events stream --count 10          # 收到 10 条后退出
python3 scripts/xdpass-cli.py events stream --timeout 30        # 30 秒后退出

# smoke test
python3 scripts/xdpass-cli.py smoke --ifname br-xdpass

# 查看所有命令
python3 scripts/xdpass-cli.py --help
```

`attach` 快捷命令默认启用 XSK，适合测试 userspace response。直接使用
`attachments create` 时如需 userspace response，请显式加 `--xsk`。

典型手动验证流程：

```bash
# 1. 创建 netns 环境
sudo scripts/xdpass-netns.sh reset

# 2. 启动 agent（另一个终端）
sudo ./build/xdpass-agent

# 3. 运行 smoke test
python3 scripts/xdpass-cli.py smoke --ifname br-xdpass

# 4. 验证连通性
sudo scripts/xdpass-netns.sh ping

# 5. 清理
sudo scripts/xdpass-netns.sh cleanup
```

## 已知约束

- `attach_mode` 支持 `generic` / `native` / `driver`，默认 `generic`。
- XSK（AF_XDP）需要 root 权限和真实网卡（driver mode XDP）。
- 运行态无持久化，重启后需重新下发配置。
