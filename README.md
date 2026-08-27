# MyGoTunnel

## 日志

项目使用 Go 标准库 `log/slog` 输出结构化、分级日志，不需要额外的第三方日志依赖。日志写入标准错误流，默认使用 `text` 格式和 `info` 级别。

客户端和服务端都支持以下参数：

- `-log-level debug|info|warn|error`：设置最低日志级别。
- `-log-format text|json`：选择便于人工阅读的文本格式，或便于日志采集系统处理的 JSON 格式。

示例：

```powershell
go run ./cmd/client -config configs/client.json -log-level debug -log-format text
go run ./cmd/server -config configs/server.json -log-level info -log-format json
```

每条日志都带有 `component` 字段；连接日志还会按阶段带上 `client_addr`、`remote_addr`、`target_addr`、`upload_bytes`、`download_bytes`、`duration` 和 `error` 等字段。认证令牌及原始认证内容不会写入日志。
