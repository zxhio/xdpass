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
sudo ./build/xdpass-agent -config /etc/xdpass/agent/config.yaml
```

需要 root 或 `CAP_NET_ADMIN` + `CAP_BPF` 权限。

## systemd 部署

```bash
# 安装二进制
sudo cp build/xdpass-agent /usr/local/bin/

# 安装配置
sudo mkdir -p /etc/xdpass/agent
sudo cp deploy/config/agent/config.yaml /etc/xdpass/agent/config.yaml

# 安装 systemd unit
sudo cp deploy/systemd/xdpass-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xdpass-agent
```

日志默认写入 `/var/log/xdpass/agent.log`，systemd unit 通过 `LogsDirectory=xdpass` 自动创建目录。

## API

HTTP API 默认监听 `127.0.0.1:9527`，详见 `specs/agent/` 目录。

主要端点：

- `GET /api/v1/health` - 健康检查
- `GET /api/v1/status` - 服务状态
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

## API CLI smoke test

提供 `scripts/xdpass-api-cli.py` 封装常用 API 调用，无需手写 curl。

依赖 Python 3 标准库，无需安装第三方包。

```bash
# 单个命令
python3 scripts/xdpass-api-cli.py health
python3 scripts/xdpass-api-cli.py status
python3 scripts/xdpass-api-cli.py attach --iface br-xdpass
python3 scripts/xdpass-api-cli.py detach --iface br-xdpass
python3 scripts/xdpass-api-cli.py ruleset-apply
python3 scripts/xdpass-api-cli.py stats

# 完整 smoke test（默认 attach 到 br-xdpass）
python3 scripts/xdpass-api-cli.py smoke
```

典型手动验证流程：

```bash
# 1. 创建 netns 环境
sudo scripts/xdpass-netns.sh reset

# 2. 启动 agent（另一个终端）
sudo ./build/xdpass-agent

# 3. 运行 API smoke test
python3 scripts/xdpass-api-cli.py smoke

# 4. 验证连通性
sudo scripts/xdpass-netns.sh ping

# 5. 清理
sudo scripts/xdpass-netns.sh cleanup
```

## 已知约束

- `attach_mode` MVP 仅支持 `generic`。
- XSK（AF_XDP）需要 root 权限和真实网卡（driver mode XDP）。
- kernel response 完整构包未实现，当前走 BPF failure path。
- dispatch 模块暂缓设计，未实现。
- 运行态无持久化，重启后需重新下发配置。
