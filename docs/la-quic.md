# LA 分支的可选 QUIC UDP 传输

`feat/la-quic-udp` 从完整功能分支发展，增加 UDP 专用的 QUIC 入口。普通 TCP CONNECT 继续使用既有 TLS/TCP 隧道；UDP 可在原传输与 QUIC DATAGRAM 之间显式选择。现有配置缺省保持原传输，不根据 IP、地区、运营商或线路标签自动改变行为。

该分支引入 quic-go v0.64.1，构建最低要求 Go 1.26；原分支的工具链要求不因此改变。LA 的部署配置与代码在本分支单独维护，`remote_addr` 仍明确指定该客户端的 TCP 节点，不自动在 ARM64 与 LA 之间分流或切换。

QUIC DATAGRAM 的目标是避免某个丢失报文让后续 UDP 报文等待底层 TCP 重传。它保留不可靠数据报语义，可能丢失、乱序，仍受拥塞控制；不保证降低基础 RTT、增加带宽或改善通过 TCP 转发的视频播放。CN2 GIA 标签不能替代从实际客户端对去程、回程和晚高峰表现的测量。

## 配置

服务端在原有配置中增加 UDP 监听地址，例如：

```json
{
  "listen_addr": ":8443",
  "udp_quic_listen_addr": ":8443",
  "auth_token": "REPLACE_WITH_A_RANDOM_TOKEN",
  "cert_file": "certs/fullchain.pem",
  "key_file": "certs/key.pem"
}
```

TCP 与 UDP 使用独立 socket，可以使用相同数字端口。`udp_quic_listen_addr` 缺省或为空时不启动 QUIC 入口。端口必须为纯数字；监听地址沿用既有离线校验规则，允许通配地址和端口0。实际部署应选择固定非零端口，并按部署环境放行对应 UDP；程序不会修改防火墙或路由器。

客户端在原有配置中增加：

```json
{
  "local_addr": "127.0.0.1:1080",
  "remote_addr": "tunnel.example.com:8443",
  "auth_token": "REPLACE_WITH_THE_SAME_TOKEN",
  "sni": "tunnel.example.com",
  "trust_mode": "ca",
  "udp_transport": "quic",
  "udp_quic_remote_addr": "tunnel.example.com:8443"
}
```

`udp_transport` 仅接受 `tcp` 或 `quic`，缺省/空值为 `tcp`。`udp_quic_remote_addr` 缺省/空值使用 `remote_addr` 的主机与数字端口，经 UDP 连接；显式地址必须包含主机及1～65535的纯数字端口。指定另一个 QUIC 地址时仍使用现有 SNI、证书信任模式和认证配置，应显式检查它们适用于该入口。证书或认证失败不会通过降级绕过验证。

初版没有 QUIC 自动回退：选择 `quic` 后，入口不可达或握手失败会明确拒绝该 UDP 关联。切回 `"udp_transport": "tcp"` 并重启客户端，可恢复原 UDP 隧道。不会把已发送的业务数据跨节点重放，也不会将同一报文同时发送到两个出口。

这三个新字段属于部署配置。连接码保持原版本与内容，不携带 QUIC 选择或独立 UDP 地址；导入连接码后仍须手动补充以上配置。原 SOCKS 用户名密码、strict/nat 来源规则、客户端 UDP relay 端口范围及其他配置继续按原规则设置。

## 协议与资源边界

QUIC 入口使用 TLS 1.3 加密和现有 CA/域名或固定指纹信任。可靠控制流负责认证及关联管理，业务数据走 QUIC DATAGRAM；不会把所有 UDP 数据重新串进一条可靠 QUIC stream。不使用应用0-RTT，也不在认证前拨号或转发目标。

QUIC 监听启用源地址 Retry 验证；传输层连接数受 `-max-connections` 限制，正在握手的连接数受 `-max-setup` 限制且不超过总连接上限。握手保护还限制每个来源 IP 最多8个并发、每秒4次尝试、突发16次。握手后 TCP 与 QUIC 继续共享应用层总连接/setup 准入和认证失败限速，QUIC 不获得额外认证权限。控制错误回复来不及送达时，认证拒绝或超时也通过 QUIC 应用关闭原因反馈，客户端可据此明确分类。

客户端在进程内缓存服务端签发的地址验证 `NEW_TOKEN`，最多16个端点/信任范围、每范围4枚令牌；取用后移除，每枚只提交一次。缓存按远端地址、SNI及系统 CA/具体证书指纹隔离，不写磁盘、连接码或日志，也不增加部署配置。有效令牌可让后续新 QUIC 关联省去重复 Retry 往返；它不恢复 TLS 会话，每条连接仍完成证书验证和 AUTH，不启用0-RTT。首次连接、令牌过期、出口 IP 改变或服务端重启导致令牌失效时，仍按服务端要求执行 Retry。

QUIC 自身有握手与报文特征；该入口没有复用 TCP uTLS 的 Chrome ClientHello，也不等于 HTTP/3 或浏览器伪装。TCP 入口的 HTTPS 网页回退不会自动出现在 UDP 入口。

双方通过 TLS ALPN 优先协商 `mygotunnel-udp/2`，保留 `mygotunnel-udp/1` 兼容旧端。v2 可将完整 SOCKS UDP 帧加2字节头直接装入一个 DATAGRAM；仅在认证及 UDP setup 成功后收发，不增加控制往返。发送从1200字节 QUIC 包起步，启用库内路径 MTU 探测，不强制公网 IP 分片；路径装不下或包更大时仍使用 v1 分片。库明确拒绝超尺寸包且尚未入队时才重试原格式，不重放已发送的业务。尺寸拒绝后最多每秒重新尝试一次更大整包，其余包按已知限额处理。路径支持时1200字节 UDP 负载可减少为一份 DATAGRAM，1400字节及 IPv6/域名封装仍可能分片，不能保证任意路径均减少包数。

v1 每个 DATAGRAM 应用数据最多1100字节（12字节头+1088字节负载），保留最大65000字节 SOCKS UDP 帧、最多60片；v2 整包帧最多1415字节，实际发送仍受库报告的路径上限约束。两种格式共享原有进程 payload 预算、认证、来源规则和期限。每关联最多16个未完成重组、64个去重ID、16项接收队列；不扩大队列或延长250ms默认本地队列期限。大包新突发开始时先沿用v1发送3个平滑RTT（下限50ms、上限1秒），随后才使用整包，避免在拥塞窗口起步时立即改变包布局；这里不暂停、不额外缓存业务，空闲1秒后重新判断。接收完整包每8项最多主动让出一次调度机会，使已唤醒的下游能及时排空16项队列。重组仍有独立2秒期限。应用 SOCKS5 `FRAG` 仍拒绝。协商旧 ALPN 时只使用原分片格式，普通 TCP 不受影响。


每个 SOCKS UDP association 使用一条 QUIC 连接，不为每个目标分别建连接。关联随本地 SOCKS TCP 控制连接结束而终止；它没有跨关联共享已使用的 QUIC 连接或跨节点迁移已有 UDP 会话的行为。

## QUIC 预连接

客户端在选择 `udp_transport=quic` 时默认通过 `-quic-pool-size 2` 初始准备最多两条已完成完整 TLS、证书验证和 AUTH 的备用 QUIC 控制连接；0 关闭，范围0～32，硬上限固定且不随既有 TCP 池扩容；默认取用量策略可将低需求目标降至1，窗口规则见README的突发握手/低需求章节。普通 TCP 的 `-pool-size` / `-pool-max` 仍独立生效，没有新增 JSON 配置或连接码字段。两类备用连接在服务端共用 `-max-idle`，仍占总连接名额；客户端 QUIC socket 使用同一进程 Resources 预算。

实际备用上限不超过 `udp_max_sockets-1`；后台 QUIC socket 申请在同一资源锁内至少留一个名额给本地 SOCKS UDP relay，避免低预算时空闲池先占满全部 socket。此为进程进度余量，不保证任意并发关联都能获准；已有活跃业务仍按进程总预算限制。日志 `quic_pool_max` 显示实际容量。

备用通过 `AUTH` 与 `PREPARE ACK` 协商，服务端返回 `OK` / `READY ACK` 后释放 setup 名额；客户端取用时发送 `UDP`，服务端重新申请 setup 后返回 `ACK` 及原 UDP 成功响应。准备和等待期间不启用业务 DATAGRAM，不拨号目标。服务端空闲期限仍为60秒，客户端备用默认在36～45秒内到期、提前错峰补充；后台守护读在移交前停止并 join，同一个 Reader 继续用于控制响应。已取用连接不再回池，池关闭或替换不得关闭它。

QUIC 池复用原池的有界补充、失败退避与关闭清理。未命中时前台立即走普通 QUIC，不等待后台；取用后仅在没有发送业务数据且发生传输故障时，允许同一远端/同一证书策略的一次普通 QUIC 重建。明确认证拒绝、资源上限、协议错误和请求取消不重试，不改为 TCP。旧 QUIC 服务端不支持 PREPARE 时后台退避，普通 QUIC UDP 仍可用。QUIC 资源拒绝同时使用独立应用关闭码，避免立即关闭连接时控制行尚未送达而被误认为普通 EOF。

该优化将握手及认证移至后台，目的是减少新 SOCKS 关联等待，不改变线路基础 RTT，也不启用 TLS 恢复或0-RTT。命中时前台 `udp_quic_handshake_duration=0`，后台 Debug 的同名字段记录实际握手成本。每30秒独立输出 `quic_pool_idle/max/filling`、`quic_pool_hits/misses/fallbacks/hit_rate`、`quic_pool_renewed/retry`；原 `pool_*` stats 只统计 TCP 池，单会话 `pool_hit/fallback` 根据实际传输解释。需同时看命中率、失败数和逐包 RTT，不能将建立时间改善当成每个数据报都提速。

应用侧进程 UDP 缓冲预算、socket 预算、目标回收、公平响应队列和过期丢弃继续有效。每条 QUIC 连接另内嵌1100字节发送暂存区，不计入 `datagram.Resources`，其数量受关联连接数限制；QUIC 库、加密、协议元数据及内核 socket 的内存也不等于原 `udp_memory_limit_bytes` 管理的缓冲容量，不能把该配置当成全部应用内存或整个进程 RSS 上限。

UDP 会话日志保留 `transport=udp`，并通过 `udp_tunnel_transport=tcp/quic` 区分实际隧道载体。`udp_quic_handshake_duration` 为完整 QUIC 拨号与握手耗时；`tcp_duration`、`tls_duration` 保持既有 TCP 路径的分阶段含义，在 QUIC 关联中为0，不把 QUIC 整体耗时塞进 TCP TLS 字段。

`quic_*` 计数记录认证前拒绝、畸形分片、资源拒绝、重组上限、队列容量/过期及不完整重组到期等本地事件。计数可能分别按分片、完整报文或拒绝事件统计，不能直接相加或当作线路丢包率；`quic_received_fragments` 是收到的隧道 DATAGRAM 数（含v2整包），`quic_enqueued_fragments` 只表示隧道 DATAGRAM 进入本地 QUIC 发送队列，不证明对端收到或目标应用处理。

## 健康检查

`-check-config` 仍只做离线校验。客户端配置 `udp_transport=quic` 时，`-health` 在原 TCP 认证控制检查成功后，额外完成 QUIC 证书验证、AUTH 与 UDP setup 两条成功响应；失败返回固定错误码 `REMOTE_UDP_QUIC_UNHEALTHY`。服务端配置 QUIC 监听时，在原 TCP 监听检查成功后，用配置中证书的 SHA-256 指纹与当前 token 检查本机 QUIC 入口，失败返回 `UDP_QUIC_LISTENER_UNHEALTHY`。通配监听地址转为同地址族回环，IPv6 `::` 使用 `::1`。

每次 QUIC 探测最多3秒，并遵守调用者更短的期限；取消会关闭连接并等待清理。探测使用独立的小型 UDP 资源预算，不发送业务 UDP，不拨号目标，因此只证明认证控制及关联建立正常，不证明目标 UDP 或整条业务路径可用。服务端可能记录该次短关联的建立与结束，应与实际用户流量区分。诊断输出仅含固定结果码，不包含 token、证书指纹或原始错误报文。

## 上线前比较

先在同一 LA 节点、同一客户端、相同业务负载下比较 UDP-over-TCP 与 QUIC DATAGRAM，再比较不同节点。覆盖双向小包、大包、空闲及 TCP 下载并发、断网恢复和晚高峰；记录发送数、实际接收数、超时、乱序/重复、成功包 P50/P95/P99、吞吐及 CPU/内存。成功包的低 P99 必须和丢失率一起判断，不能只统计送达样本就认定体验改善。

生产入口切换前应先使用独立测试端口，完成认证/证书拒绝、控制连接关闭、资源耗尽和大包兼容验证。更换节点会改变 UDP 出口及已有 NAT 状态，现有会话应由应用重建。
