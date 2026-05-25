# agent config

## 定位

`config` 定义 `agent` 启动配置。

- 配置只在进程启动时读取
- 配置不包含运行态资源
- 配置不保存 `attachments`、`ruleset`、`response`
- 运行态资源由 HTTP API 下发

---

## 配置文件路径

- agent 默认配置路径：`/etc/xdpass/agent/config.yaml`
- 未显式传入 `--config` / `-c` 时读取默认配置路径
- 配置文件读取失败时启动失败

---

## 配置结构

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

---

## 字段约定

### `server.listen_addr`

- 必填
- HTTP server 监听地址
- 使用 Go `net.Listen` 可接受的 address 格式

### `logging.level`

- 可选，默认 `info`
- 可选值：`trace`、`debug`、`info`、`warn`、`error`、`fatal`、`panic`

### `logging.file_path`

- 可选，部署配置默认 `/var/log/xdpass/agent.log`
- 日志文件路径，空值或未配置 `logging` 时仅输出到 stdio
- stdio 和 file 二选一；配置 `file_path` 时只写文件，不同时写 stdio
- 部署时需确保目录可写，systemd unit 使用 `LogsDirectory=xdpass` 自动创建

### `logging.max_size_mb`

- 可选，默认 `100`
- 日志文件轮转大小上限（MB）
- 通过 lumberjack 执行文件轮转

### `logging.max_backups`

- 可选，默认 `7`
- 保留的旧日志文件数量
- 通过 lumberjack 执行文件轮转

### `logging.max_age_days`

- 可选，默认 `30`
- 旧日志文件保留天数
- 通过 lumberjack 执行文件轮转

### `logging.compress`

- 可选，默认 `true`
- 是否压缩轮转后的日志文件
- 通过 lumberjack 执行文件轮转

---

## 非配置项

以下内容不进入启动配置：

- `attachments`
- `ruleset`
- `response_egress`
- `dispatch`
- XDP attach 状态
- XSK runtime 状态
- 历史 stats / events

---

## 资源边界

- 启动配置只决定 agent 进程如何启动 HTTP server 和日志。
- 运行态状态见 `runtime-lifecycle.md`。
- API 资源见 `agent-api.md` 和 `agent/` 下各资源文档。
