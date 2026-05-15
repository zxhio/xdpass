---
name: rest-api
description: 当设计或实现 REST 风格 HTTP API 时使用。覆盖路由、响应体、状态码、API 目录、DTO、服务接口和 handler 命名。
---

## 权威来源

先看匹配的 API spec。

- Agent HTTP 约定：`specs/agent/http.md`
- Agent 路由：`specs/agent-api.md`
- 资源合同：`specs/agent/`

如果本 skill 和 spec 冲突，以 spec 为准，并更新本 skill。

## 路由

路径按资源组织，不在 URL 中使用动词。

### 推荐

```text
POST   /api/v1/attachments
GET    /api/v1/attachments
GET    /api/v1/attachments/:ifindex
PATCH  /api/v1/attachments/:ifindex
DELETE /api/v1/attachments/:ifindex
GET    /api/v1/status
PUT    /api/v1/ruleset?dry_run=true
```

### 避免

```text
GET  /api/v1/getAttachments
POST /api/v1/createAttachment
POST /api/v1/deleteAttachment?ifindex=3
POST /api/v1/attachments/:ifindex/enable
POST /api/v1/attachments/:ifindex/disable
```

## 响应体

成功响应直接返回资源对象，不包 `data` envelope。

单个资源：

```json
{"id": "r1", "name": "rule-1"}
```

集合：

```json
[{"id": "r1"}, {"id": "r2"}]
```

空集合：

```json
[]
```

错误响应：

```json
{
  "type": "about:blank",
  "title": "Validation failed",
  "status": 400,
  "detail": "name is required",
  "code": "validation_failed"
}
```

错误响应使用 Problem Details 风格。`code` 是稳定的 snake_case 字符串。

删除成功或不需要返回资源的成功操作，使用 `204 No Content`，不返回 body。

## 分页

集合分页使用 query 参数：

- `limit`：返回数量上限，只在 API 合同定义时使用
- `cursor`：上一页返回的不透明游标

分页响应使用集合对象：

```json
{
  "items": [{"id": "r1"}, {"id": "r2"}],
  "next_cursor": "abc"
}
```

规则：

- 默认使用 cursor 分页。
- 除非 spec 明确要求兼容旧格式，不要在新响应里放 `page`、`page_size`、`total` 或 `data`。
- 使用 `next_cursor`；没有下一页时设为空字符串。
- `cursor` 对客户端是不透明值，客户端不能解析。
- `limit` 的默认值和最大值以 API 合同为准。

## 状态码

- `200`：`GET`、`PUT`、`PATCH` 成功
- `201`：资源创建成功
- `204`：成功且无响应体
- `400`：请求 body 或参数无效
- `404`：资源不存在
- `409`：资源冲突
- `500`：内部错误

## Gin 实现

### 目录

Gin HTTP 代码放在 `api/` 下。

```text
api/
  router.go
  handler.go
  services.go
  dto.go
  error.go
  <resources>.go
```

规则：

- `router.go`：路由注册和 router 构造。
- `handler.go`：`Handler` 结构、构造函数和共享 handler helper。
- `services.go`：API handler 依赖的 service interface。
- `dto.go`：共享 request / response DTO。
- `error.go`：API 错误码和错误到响应的映射。
- `<resources>.go`：资源 endpoint handler；文件名用复数，例如 `attachments.go`。

### 命名

- endpoint handler 使用 `Handler`。
- 构造函数使用 `NewHandler` / `NewRouter` 或本地等价命名。
- API 面向 service interface 使用 `<Resource>Service`。
- 请求 / 响应结构使用 `<Action><Resource>Request` / `<Resource>Response`。
- Handler 方法使用 `CreateResource`、`ListResources`、`GetResource`、`PatchResource`、`DeleteResource`。

### Handler 结构

Handler 负责解析 path / query / body，校验传输层输入，将 DTO 映射到内部值，调用 service，再将 service 结果映射成响应 DTO 并写出 HTTP 响应。

```go
type Handler struct{ svc ItemService }

func (h *Handler) CreateItem(c *gin.Context) {
	var req CreateItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "validation_failed", "Validation failed", err.Error())
		return
	}
	item, err := h.svc.Create(c.Request.Context(), newItem(req))
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "Internal error", err.Error())
		return
	}
	c.JSON(http.StatusCreated, newItemResponse(*item))
}
```

### Service Interface

`api` 依赖 service interface。interface 放在靠近 handler 的 `services.go` 中。

```go
type ResourceService interface {
	Validate(ctx context.Context, resource resource.Resource) (*resource.Resource, error)
	Create(ctx context.Context, resource resource.Resource) (*resource.Resource, error)
	List(ctx context.Context) ([]resource.Resource, error)
	Get(ctx context.Context, id int) (*resource.Resource, error)
	SetEnabled(ctx context.Context, id int, enabled bool) (*resource.Resource, error)
	Delete(ctx context.Context, id int) error
}
```

规则：

- 方法按资源操作建模。
- 使用明确参数或内部 resource 类型。
- 不要把 HTTP request DTO 传进 service 方法。
- 生命周期切换使用明确方法，例如 `SetEnabled(ctx, id, enabled)`。

### Request / Response 结构

- API 自己定义 request 和 response struct，放在 `api/`；不要直接返回内部 resource 类型。
- 所有字段都加 `json` tag。
- Request 使用 `<Action><Resource>Request`，例如 `CreateAttachmentRequest`。
- Response 使用 `<Resource>Response`，例如 `AttachmentResponse`。
- 只有同一资源存在多种响应形状时，才使用 `<Action><Resource>Response`。
- `PATCH` request DTO 只包含该 endpoint 允许修改的字段。

不要让 request DTO 穿过 service 边界：

```go
SetEnabled(ctx, PatchResourceRequest)
```

### 映射函数

- `newResource`：API request DTO -> 内部 resource 类型。
- `newResourceResponse`：内部 resource 类型 -> API response DTO。
- `newResourceResponses`：内部 resource slice -> API response DTO slice。
- slice 字段需要防御性复制：`append([]T(nil), src...)`。

### 调用流程

```text
POST /api/v1/resources?dry_run=true
  -> api.CreateResource
  -> service.Validate
  -> return response DTO

POST /api/v1/resources
  -> api.CreateResource
  -> service.Create
  -> return response DTO

PATCH /api/v1/resources/{id}
  -> api.PatchResource
  -> service.SetEnabled
  -> return response DTO

DELETE /api/v1/resources/{id}
  -> api.DeleteResource
  -> service.Delete
  -> return HTTP status
```

`dry_run=true` 是 API query 参数。service 负责定义 dry-run 下需要做哪些校验。

### 检查表

- Handler 只调用 service interface。
- Service interface 不接收 HTTP DTO。
- Request / response DTO 留在 `api/`。
- 文件名和类型名使用同一个资源词。
- `PATCH` 只修改明确允许的字段。
