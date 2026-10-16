# MyGoTunnel

## SOCKS5 UDP

The local SOCKS5 listener supports `CONNECT` and `UDP ASSOCIATE`. Configure the existing `socks_auth` object with `username` and `password` to require SOCKS5 username/password authentication; the legacy `socks_username` and `socks_password` fields are also read. When credentials are configured, the client rejects no-auth fallback.

UDP packets are relayed through the existing TLS/TCP tunnel using length-prefixed datagram frames, then sent to their destinations with UDP by the server. Keep the SOCKS5 TCP control connection open for the lifetime of a UDP association. Fragmented SOCKS5 UDP packets are dropped.

UDP packets must come from the same IP address as their SOCKS5 TCP control connection. A nonzero source port in the association request is enforced; otherwise the first valid packet binds the source port. Invalid packets cannot claim the association. Failed server-side destination sockets are recreated on a subsequent packet. Closing either the control connection or the remote tunnel stops the association and its workers. Both tunnel directions enforce the same 65,000-byte limit, including the SOCKS5 UDP header.

Because UDP datagrams share a TCP stream, packet loss and retransmission on that stream can delay later packets. This mode improves UDP application compatibility, while latency-sensitive traffic may perform better with a future native UDP transport.

Each datagram's length header and payload are written together to reduce TLS records. Up to 32 already-queued packets are batched per flush, with no delay to wait for more packets. The client uses bounded queues (256 outgoing packets, 128 incoming packets); full queues drop packets instead of accumulating stale UDP traffic. The server queues up to 256 packets per direction and reclaims destination sockets after two minutes of inactivity, checked every 15 seconds. Each association can hold at most 256 destination sockets. Session-close logs include packet and drop counters after all workers exit. Client uploads count packets accepted into the tunnel queue; downloads count successful local UDP writes, and `udp_write_errors` counts failed local UDP writes. A successful UDP write does not guarantee receipt by the application. The wire format remains compatible with the original UDP implementation.

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
