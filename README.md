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
sudo ./build/xdpass-agent -config /etc/xdpass-agent/config.yaml
```

需要 root 或 `CAP_NET_ADMIN` + `CAP_BPF` 权限。

## systemd 部署

```bash
# 安装二进制
sudo cp build/xdpass-agent /usr/local/bin/

# 安装配置
sudo mkdir -p /etc/xdpass-agent
sudo cp deploy/config/xdpass-agent.yaml /etc/xdpass-agent/config.yaml

# 安装 systemd unit
sudo cp deploy/systemd/xdpass-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xdpass-agent
```

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

## 已知约束

- `attach_mode` MVP 仅支持 `generic`。
- XSK（AF_XDP）需要 root 权限和真实网卡（driver mode XDP）。
- kernel response 完整构包未实现，当前走 BPF failure path。
- dispatch 模块暂缓设计，未实现。
- 运行态无持久化，重启后需重新下发配置。
