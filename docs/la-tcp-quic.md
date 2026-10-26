# LA 可选 TCP-over-QUIC 实验

普通 TCP CONNECT 默认仍经 uTLS/TCP，UDP 继续由 `udp_transport` 独立选择。本实验不把业务 TCP 放入不可靠 DATAGRAM，也不把 UDP 串入可靠 Stream。

服务端可增加独立 UDP 监听：

```json
"tcp_quic_listen_addr": ":18445"
```

客户端显式选择：

```json
"tcp_transport": "quic",
"tcp_quic_remote_addr": "node.example:18445"
```

`tcp_transport` 缺省/空值为 `tcp`，只接受 `tcp`/`quic`；独立远端缺省使用 `remote_addr`。新字段不进入连接码。TCP QUIC 与 UDP QUIC 目前是独立 UDP socket，不能配置同一个监听地址端口；本实验没有将二者多路复用到同一 UDP 入口。监听失败会使整个服务退出，不静默丢失入口。

载体使用 TLS 1.3、独立 ALPN `mygotunnel-tcp/1`、原 CA/SNI 或指纹验证，不使用 TLS 恢复或应用0-RTT。每请求新建一个双向可靠 Stream，并完整执行原 AUTH+CONNECT/OK/ERR；认证轮换、限速、目标错误码、目标拨号和 reader 预读按原逻辑处理。已验证的物理连接可复用，AUTH 仍逐 Stream 检查，因此过期 token 不因复用而继续有效。无自动切回 TCP，没有在失败后重放业务数据。

客户端惰性创建最多2条物理连接，每连接最多64个活跃 Stream，选择较空闲连接。socket预算不足时可使用已有且通过验证的连接。Open等待受调用者 context 约束，所有拨号及地址尝试共享5秒上限；仅超时允许尝试另一个地址，证书错误不换地址绕过。新物理连接失败不会关闭其他已交接 Stream。

服务端最多 min(32,max-connections) 条物理 QUIC 连接；握手并发最多 min(32,max-setup)，同时有有界来源IP握手guard与Retry。新连接首个成功AUTH最长5秒，否则关闭整个连接；每Stream仍单独AUTH，并通过与TLS/TCP、UDP入口相同的全局应用连接/setup admission及认证限速。QUIC的连接/握手限制是额外的独立传输层上限，不冒充应用admission计数。未认证时不拨号目标。

Stream窗口从256KiB起步，最大8MiB；连接窗口从1MiB起步，最大32MiB，最多64个双向Stream，不接受单向流。窗口由库按接收消费自动调整，两个物理连接仍共享实际网络容量。QUIC库、流控缓冲、内核缓冲和元数据不属于UDP managed payload预算，不能宣称这些配置限制整个RSS。

正常 EOF 仅半关闭当前 Stream 写方向，反向数据继续排空；错误、取消、deadline关闭当前 Stream，不关闭其他Stream或重放负载。关闭监听只停止新Stream交接；进程停止时保留底层transport直到配置的shutdown grace结束，给已入队的可靠数据和FIN排空时间，到期强制关闭。客户端停止接单后进入drain，最后才回收物理连接。没有跨服务器迁移或无损断网恢复承诺。

`tcp_quic_reused` 表示该请求使用已有QUIC连接，不等于原TCP预连接池命中；`tcp_quic_handshake_duration` 只记录新QUIC握手。原 `pool_*` 继续描述TLS/TCP预连接，`quic_pool_*` 继续描述UDP预连接；`tcp_quic_connections/streams` 为TCP QUIC当前资源快照。`tcp_tunnel_transport=tcp/quic` 区分载体。

健康检查对所选TCP载体做证书和AUTH验证，不拨业务目标；QUIC失败使用 `REMOTE_TCP_QUIC_UNHEALTHY` / `TCP_QUIC_LISTENER_UNHEALTHY`。若同时启用UDP QUIC，还需通过其原有探测。

性能结论必须分别比较冷连接、已预热的建连、单流/多流吞吐、并发下载下小请求P95/P99、CPU及失败率。不能把QUIC连接复用和TLS冷握手比较后就宣称QUIC全面更快；Reno与内核BBR的差异也可能影响结果。正式切换需要独立端口验证，实验不改现有生产配置。
