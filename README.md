# MyGoTunnel

## 连接码快速配置

在服务端执行（将 `example.com:9001` 替换成客户端能够访问的域名或 IP 和端口）：

```sh
go run ./cmd/server -init -public-addr example.com:9001
```

自动生成随机 token、自签名 ECDSA 证书、私钥及 `configs/server.json`，输出一行 `mygotunnel://...` 连接码，然后退出。用 `-listen :9001` 指定监听地址；用 `-config` 指定配置路径。初始化不会覆盖已有文件。证书和私钥保存在配置文件旁，服务端配置记录它们的绝对路径，移动部署时需同步修改路径。

启动服务端：

```sh
go run ./cmd/server
```

在客户端执行以下命令，粘贴连接码并回车：

```sh
go run ./cmd/client -import
```

导入会生成 `configs/client.json` 并退出，默认本地 SOCKS5 地址为 `127.0.0.1:1080`。之后直接启动：

```sh
go run ./cmd/client
```

导入拒绝覆盖已有配置，切换节点时用 `-config configs/other-client.json` 保存新配置，再用同一路径启动。连接码从标准输入读取，避免出现在命令行参数和 shell 历史中。

已有服务端无需重新生成 token 或证书，可导出连接码：

```sh
go run ./cmd/server -export -config configs/server.json -public-addr example.com:9001
```

连接码是带版本号的 JSON 经 Base64URL 编码，包含远端地址、token、SNI 和服务端叶证书 DER 的 SHA-256 指纹，不包含私钥。它包含访问凭据，应通过可信渠道传递；编码不等于加密。导出仅在显式执行 `-init` / `-export` 时输出到 stdout，不写入运行日志。生成的凭据文件使用 0600 权限（Windows 下需按系统 ACL 管理）。

客户端新增 `certificate_fingerprint` 配置项：导入后使用固定证书指纹验证服务端，替代公共 CA 验证；证书变更后需重新导出、导入。没有指纹的旧配置改为使用系统 CA 及主机名验证，因此旧的自签名部署需要先导出连接码再导入。SNI 默认取远端地址中的主机名。没有新增协议消息，AUTH/CONNECT 保持不变。


## SOCKS5 UDP

SOCKS5 同时支持 TCP CONNECT 与 UDP ASSOCIATE。UDP 经现有 TLS/TCP 隧道按长度封装，在服务端还原为 UDP；保留 TCP 控制连接。UDP 使用与 TCP 相同的证书指纹/CA 校验、认证、控制阶段超时、预连接池、连接准入和优雅退出，不额外退回跳过证书验证。普通建连可合并发送 AUTH 与 UDP，备用命中只发送 UDP。进入转发前释放 setup 名额；UDP association 仍占总连接名额。

UDP ASSOCIATE 声明的来源地址和端口用于限制客户端 UDP 数据报来源。全零/空地址表示客户端尚不知道 UDP 端点，此时使用 SOCKS TCP 对端 IP；具体 IP 或域名则只接受该 IP（域名在成功回复前解析一次，最长5秒），不要求它与 TCP 对端相同，以兼容 TCP 与 UDP 走不同 NAT 映射的客户端。域名解析失败返回 REP=4，域名无可用地址返回 REP=2。非零来源端口会被约束；端口为0时，第一个合法数据报固定来源端口，关联期间不允许切换来源。来源校验和 SOCKS 报文校验通过后才绑定端口；空目标域名、控制字符/地址分隔符、目标端口0、畸形报文、未声明来源、分片报文与含 SOCKS 头超过 65000 字节的报文均丢弃；ASSOCIATE 源端口0及零长度UDP负载保留。客户端 legacy socks_username/socks_password 仍可读取，嵌套 socks_auth 优先；认证禁止免认证降级。

出错目标 socket 下次发包重建，空闲 2 分钟后回收（15 秒扫描），每会话最多 256 个目标 worker，退出中的 worker 也占名额。各目标独立解析和发送，慢目标不会阻塞其他目标的分发；域名初始化并发最多 16，数字 IP 不占 DNS 名额。同一目标初始化期间复用待发送队列，保持该目标的发送顺序。目标拨号（包括等待 DNS 名额）与写入各受 5 秒期限约束，断开隧道取消解析、关闭目标 socket 并等待所有 worker。进程取消后，已建立会话继续到 grace 结束或正常断开；不会在进程取消瞬间无条件中断所有 UDP。

目标表达到256项时，会先回收已失败或已闲置的项再判断新目标准入，无需等下次15秒扫描；关闭中的worker仍占独立名额，直到全部I/O结束。帧边界EOF才记为正常关闭；长度头已完整到达后，body缺失或被截断（包括预算不足时丢弃body）均记为truncated错误。

客户端出站/入站队列为 256/128 包，服务端收发各 256 包；每队列默认还限制 1 MiB 数据，入队和出队都会丢弃等待满 250 ms 的旧报文，再按容量决定是否接收新包。服务端每目标待发送队列最多 32 包、64 KiB UDP 负载，所有目标待发送队列另共享 1 MiB 负载预算，不能随目标数量无限扩张。目标初始化等待计入队列年龄，转入目标队列不会重置年龄。每批最多刷新 32 个已排队帧，不等待凑批。缓冲写入直接复用 bufio 帧头空间，不再为每个包复制整帧；客户端本地入队、服务端响应入队在容量不足时不复制负载。

客户端、服务端 JSON 均可独立设置以下本地策略，不进入连接码；缺省或 0 使用默认值。旧配置无需修改：

```json
{
  "udp_queue_max_bytes": 1048576,
  "udp_queue_max_age_ms": 250,
  "udp_write_timeout_ms": 5000,
  "udp_max_sockets": 1024,
  "udp_memory_limit_bytes": 67108864
}
```

`udp_queue_max_bytes` 范围 65000～67108864，同时控制各方向队列与服务端共享目标预算；目标单队列仍受 64 KiB 限制。`udp_queue_max_age_ms` 范围 1～60000，可根据业务容忍度调高。年龄只在应用入队/出队时检查，不是网络 RTT 或送达期限，不能清除 TLS/TCP/内核已接收的积压；慢 DNS 期间超过年龄的待发送包同样会丢弃。队列和 worker 元数据、帧头、读缓冲及在途包不计入负载预算，不能把 1 MiB 当作整个关联的内存上限。

两端每次 UDP 隧道 TLS Write 使用独立的 `udp_write_timeout_ms`，默认 5000ms，非零范围 1～600000；空闲时不计时，不限制读取。它与 250ms 队列年龄分开。超时或写错误会终止整个 UDP association、关闭底层连接并等待 worker 退出；不能跳过部分写出的帧继续复用该 TLS 流，应用需重建 association。它限制本地 Write 阻塞，不保证对端已收到，也不消除 TCP 重传的队头等待。TCP CONNECT 转发的期限和半关闭语义不变。

每个进程共享 `udp_max_sockets`（默认1024，非零1～65536）和 `udp_memory_limit_bytes`（默认64MiB，非零262144～1073741824字节）。socket 预算包括客户端 UDP relay 和服务端初始化/转发/退出中的目标；各进程独立计数。内存预算按512、2048、8192、32768、65536字节分级缓冲的实际容量计费，包含活跃帧、在途帧、目标/客户端接收缓冲及缓存空闲帧；内存不足先驱逐空闲缓存。帧读取器复用长度前缀，包所有权随队列传递，在消费、拒绝、过期和退出时回收；每个尺寸最多缓存16块。上限不是整个进程RSS，TLS/bufio、队列/worker元数据和内核socket缓冲仍在其外。目标仍保留约65KB接收缓冲，但总量受进程预算约束。

客户端 relay 创建时资源不足会拒绝 association；服务端新增目标超限时丢弃相应包。读取隧道帧遇到内存不足会消费并丢弃完整帧，保持后续流对齐；预算释放后可继续处理。上述三个新字段均为本地策略，不进入连接码，0/缺省使用默认值。

会话日志保留 connection_id、transport=udp、资源与建连信息。client upload_datagrams 表示入隧道队列，download_datagrams 表示成功写入本地 UDP，udp_write_errors 记录写入失败，dropped_datagrams 包括来源、报文、队列和写入失败。server download_datagrams 为进入响应队列数量，upload_datagrams 为成功向目标写入数量。新增 queue_full_drops、queue_expired_drops 分别记录容量拒绝与年龄丢弃；request_queue_peak_bytes、response_queue_peak_bytes 记录收发队列数据峰值，server target_queue_peak_bytes 为单目标待发送队列负载峰值。client dropped_datagrams 包含年龄丢弃；server dropped_requests/dropped_responses 记录相应路径上的直接拒绝；queue_* 是队列维度统计，可与这些计数重叠，不能直接相加。统计在会话结束后输出。UDP write 成功不保证应用收到；TCP 丢包重传仍会延迟后续数据报，不宣称原生 UDP 延迟特性。

UDP 结束记录首个根因的 `stage` / `close_reason`，包括 udp_control、udp_read、udp_tunnel_read、udp_tunnel_write。正常 EOF 为 INFO closed，超时/重置/截断为 WARN failed；人为关闭其他 worker 产生的次生错误不会覆盖根因。结束记录 `udp_tunnel_write_calls/errors/timeouts` 及 `udp_tunnel_write_max_duration`（text毫秒、JSON纳秒），后者包含成功或失败的底层写调用；`queue_resource_drops` 为队列复制时的进程内存拒绝。

每30秒 stats 增加 `udp_sockets/udp_max_sockets`、`udp_buffer_bytes/udp_cached_bytes/udp_buffer_peak_bytes/udp_memory_limit_bytes`、`udp_socket_rejected/udp_memory_rejected`、`udp_sessions_closed/udp_session_errors/udp_tunnel_write_failures/udp_write_timeouts`。最后两项只累计以隧道写失败/写超时为根因结束的会话，不计人为打断产生的次生错误；会话内 write errors/timeouts 则统计写调用。拒绝数是资源申请次数，不能直接当应用丢包率。

`udp_end_eof/timeout/reset/truncated/canceled/closed/error` 按首个根终止原因互斥累计已建立会话，之和为 `udp_sessions_closed`；error归并其他原因。setup阶段拒绝不计入这些结束计数。

### 目标错误反馈兼容

服务端目标拨号失败返回 `ERR <CODE>\n`，CODE 仅允许 TIMEOUT、DNS、NETWORK、HOST、REFUSED、LIMIT、CANCELED、INTERNAL，不发送系统错误原文。新客户端仍接受旧版 `ERR\n`；旧客户端沿用非OK即拒绝的处理。AUTH 失败仍为旧ERR，PREPARE BUSY不变；不增加控制往返，也不修改UDP数据帧。

新错误在客户端日志区分 timeout、dns、unreachable、refused、limit、canceled、error，并映射到 SOCKS 回复：NETWORK=3，TIMEOUT/DNS/HOST=4，REFUSED=5，其余=1。6是TTL expired，不用于一般拨号超时。旧ERR保持原客户端CONNECT拒绝语义；未知错误码按协议错误处理。任何明确错误响应都不触发备用连接的传输回退，只有原有传输失败路径允许回退。

目标OK/ERR回复（包括预连接重取setup失败、UDP建立成功）有独立1秒写入预算，即使先前控制读取/目标拨号期限耗尽，也会尝试有界发送，并记录回复写入失败。客户端在AUTH成功后或协商ACK后重新起算目标响应等待，20秒控制预算另留1秒回复余量，仍受整体setup期限限制。

## 日志

日志使用 Go `log/slog`，写到 stderr，默认 `-log-level info -log-format text`。消息保持英文；文本采用紧凑格式，去掉重复的 `time=`、`level=`、`msg=`、`component=`。日期完整，UTC 时间精确到毫秒，启动时输出 `timezone=UTC`；`C` / `S` 分别表示客户端 / 服务端。

```text
2026-10-13 15:23:10.001 INFO C listening listen=127.0.0.1:1080 server=example.test:9001 timezone=UTC conn_max=1024 setup_max=128 idle_max=4
2026-10-13 15:23:12.057 INFO C ready github.com:443 id=8d729a10-1 peer=127.0.0.1:50200 socks=0.1ms tcp=102ms tls=104ms ctl=103ms pool=miss take=0.01ms total=309.2ms
2026-10-13 15:23:15.218 INFO C closed github.com:443 id=8d729a10-1 peer=127.0.0.1:50200 ↑12.4KiB ↓856.0KiB dur=3161ms reason=eof
2026-10-13 15:23:16.104 WARN C failed github.com:443 id=8d729a10-2 peer=127.0.0.1:50202 stage=up reason=timeout ↑0B ↓0B dur=30000ms
2026-10-13 15:23:30.001 INFO C stats active=12/1024 setup=3/128 idle=4/4 rejected=2
```

上述地址和 ID 仅为示例。日志展示目标域名或 IP 与端口，不解析 HTTPS 内容或完整 URL 路径。`peer` 是当前进程的直接连接来源，服务端看到的是客户端机器；两端的来源地址不等同。`id` 由进程随机前缀和递增编号构成，关联该进程的 ready、closed、failed、DEBUG 记录。没有通过协议传递同一个 ID，不能按 ID 直接匹配客户端和服务端。

流量统一以 SOCKS5 应用为参照：`↑` / `up` 是应用发往目标，`↓` / `down` 是目标回到应用，客户端和服务端方向一致。文本用 B/KiB/MiB/GiB 等单位展示，JSON 保留原始字节整数；text 的箭头只是 upload_bytes/download_bytes 的显示方式。`dur` 是从该进程接收连接开始的总生命周期，包含建连，以及服务端备用等待。

### 分阶段耗时

文本耗时统一带 `ms` 单位，最多保留 3 位小数；JSON 的 Duration 字段保持整数纳秒。字段如下：

| 文本短名 | JSON 字段 | 含义 |
|---|---|---|
| socks | socks_duration | 客户端本地 SOCKS5 阶段，含前端交互等待 |
| sfirst | socks_first_byte_duration | 从进入握手到收到首个 greeting 字节 |
| smethod | socks_method_duration | 首字节后读取方法列表、选择方法并返回响应 |
| sauth | socks_auth_duration | RFC 1929 凭据读取、验证及响应，未启用为 0 |
| sreq | socks_request_duration | 读取并解析 CONNECT/UDP ASSOCIATE 请求 |
| tcp | tcp_duration | 连接服务端，包含域名解析 |
| tls | tls_duration | 客户端 TLS 握手 |
| take | pool_acquire_duration | 取用备用连接 |
| ack | pool_ack_duration | 已协商预连接的命令发送到即时ACK耗时；失败时包含该阶段等待，未协商为0 |
| ctl | control_duration | 认证/CONNECT 交互，包含等待服务端拨号；回退时包含两次控制尝试 |
| auth | auth_duration | 服务端认证，包含 TLS 握手；备用连接中此阶段在后台完成 |
| wait | wait_duration | 服务端 CONNECT 命令读取和准备阶段，不包含备用闲置 |
| dial | target_dial_duration | 服务端目标拨号，包含目标域名解析 |
| reply | reply_duration | 服务端成功响应及清理控制期限 |
| idle | idle_duration | 服务端已认证备用连接的等待时间，单独列出 |
| total | setup_duration | 客户端前台总建连时间；服务端建连活动时间，排除 idle，仍包含先前的 auth |

SOCKS 子阶段均包含对端/网络等待，不能当作纯计算耗时；与总 socks 字段的边界有少量本地流程差异。失败时保留已尝试阶段的耗时，未进入的握手子阶段为 0，尚未读取请求则没有 sreq；不会输出用户名、密码或认证报文。TCP 和 UDP 共用这些计时字段，JSON 为整数纳秒。

`pool=hit/miss/fallback` 表示备用命中、普通建连或备用传输失败后普通回退。命中时文本省略已在后台完成的 tcp/tls 字段，JSON 仍保留零值；不是说这些阶段没有 CPU 或网络成本。不同阶段的中位数不能相加当作总耗时中位数，客户端与服务端的 total 也不能直接相加。

### 错误与资源状态

失败记录 `stage` 和 `reason`。阶段包括 socks、tcp、tls、auth、prepare、connect、dial、reply、control、up/down 等。`up` / `down` 指实际首先失败的转发方向，不能用被故意打断的另一方向覆盖。常见原因是 eof、reset、timeout、refused、pipe、closed、truncated、rejected、limit、error。识别到的系统错误只在 DEBUG 中保留完整 error 链；未知错误在 WARN 也保留 error，避免丢失诊断信息。正常双向 EOF 为 INFO closed；连接重置和超时仍是 WARN，不自动认定为正常结束。

每 30 秒输出一条 stats：`active` 是已接入但尚未退出的连接总数（包含建连、备用和转发），`setup` 是正在占用建连名额的数量，`idle` 是客户端备用池 / 服务端已认证备用数量，斜线后是配置上限。`rejected` 是本次服务进程启动后的准入超限累计数。快照是实时近似值；客户端后台备用连接另由 pool-size 限制，不计入本地 accepted active。超限不逐条刷日志，汇总数用于发现限额问题。stats 定时器在监听流程退出时停止。

### JSON 与调试

```sh
go run ./cmd/client -log-level debug -log-format text
go run ./cmd/server -log-level info -log-format json
```

JSON 保留标准 time/level/msg/component 和现有长字段名，例如 client_addr、target_addr、upload_bytes、download_bytes、setup_duration。新增 connection_id、stage、close_reason、wait_duration、reply_duration、idle_duration 和资源计数；时间转为 UTC，事件名缩短为 listening、ready、closed、failed、stats 等。按旧 msg 字符串匹配的采集脚本需更新；Duration 和字节数类型不变。text 短名是展示映射，不影响 JSON 长字段；ready 文本省略启动时已有的 server 和与分项重叠的 connect 耗时，JSON 仍保留 remote_addr/connect_duration。

日志严禁输出 auth_token、私钥、连接码和原始控制报文。文本字段中的空格和换行会转义，避免日志注入。目标地址和来源地址按本轮约定保留，日志文件应按自己的访问权限管理。

## 连接期限与控制报文

- 客户端 SOCKS5 协商和 CONNECT 请求读取共用 5 秒读写期限。
- 客户端连接远端 TCP/uTLS 保持 15 秒总超时；控制响应每阶段最长21秒（20秒控制+1秒回复余量），AUTH成功/ACK收到后重设，并夹住parent期限。
- 前台总setup期限为38秒（15秒远端建连+20秒控制+1秒回复+2秒池ACK），本地SOCKS5回复另留5秒，最多43秒；UDP源域名解析计入同一setup预算，不能保证每个子阶段都同时用满。
- 服务端 TLS 握手、AUTH 读取和认证响应写入共用 5 秒读写期限；认证后 CONNECT 读取和目标拨号共用20秒期限，目标拨号自身仍最长10秒，最终目标回复单独最多1秒。
- 建连成功后，客户端和服务端清除控制阶段的读写期限，不限制应用数据转发时长。
- AUTH、CONNECT 和响应的每行控制报文最多 4096 字节，包含换行；超限立即失败。发送值和接收报文拒绝内嵌控制字符，兼容行尾 CRLF。
- SOCKS5 按本地配置选择免认证或RFC1929认证；配置凭据后禁止免认证降级。不支持的命令返回 REP=07，不支持的地址类型或非法域名返回 REP=08；RSV 必须为零，目标端口不能为零。

上述超时为代码默认值，当前没有新增 JSON 配置项。AUTH/CONNECT 的顺序与成功响应保持兼容。

## 建连性能与并发控制

客户端将 AUTH 和 CONNECT 两行在一次 TLS 写入中发送，仍按顺序读取两条响应。服务端先认证，认证成功后才拨号；错误认证不会连接目标。优化客户端可连接原有服务端，原有客户端也可连接新服务端。不会提前发送应用负载。

两个程序新增 `-max-setup` 参数，默认 128，必须为正数。它限制同时进行 SOCKS5 协商、TLS 握手、认证和目标拨号的建连请求；进入转发后立即释放额度，错误或超时也会释放。超过限制的新连接立即关闭，不创建无限队列；超限次数进入每 30 秒的 stats 汇总，不逐条刷日志。此项不是已建立隧道总数限制。不可恢复的 Accept 错误使程序退出，临时错误采用最长 1 秒退避。

客户端成功建连日志包含 `socks_duration`、`tcp_duration`（包括远端域名解析）、`tls_duration`、`control_duration`（包含服务端目标建连等待）及 `setup_duration`。服务端记录 `auth_duration`（包括 TLS 握手）、`target_dial_duration`（包括目标域名解析）、`connect_duration` 和 `setup_duration`。日志不包含令牌或控制报文。没有启用 TLS 会话恢复，指纹验证和半关闭语义保持原有行为。

## 预连接池

客户端默认 `-pool-size 4 -pool-max 16`，按需在 4～16 条备用容量间调整；pool-size 范围 0～32；设为 0 使用原来的 TCP/TLS + AUTH/CONNECT 流水建连。后台完成 TLS 和 AUTH 后协商PREPARE，连接只用于一次后续CONNECT或UDP；不会复用已转发过数据的连接，也没有多路复用。备用连接用完就补充，池为空时立即走普通建连，不等待补充。

新客户端先发送 `AUTH → PREPARE ACK`；支持的新服务端回复 `OK → READY ACK`，交接后收到CONNECT/UDP即先回复ACK，再继续目标拨号或UDP建立，最后回复原OK/ERR。命令发送与即时ACK共用独立2秒期限；ACK后恢复目标响应等待，正常慢目标不会因2秒期限被提前回退。服务端发送ACK后直接继续处理，不等待客户端确认，不强制增加一次控制往返。

只有本次连接明确协商READY ACK才启用2秒期限。旧客户端仍用PREPARE/READY且不会收到ACK；旧服务端在AUTH成功后对新探测返回EOF/ERR时，新客户端最多换一条连接重试旧PREPARE。仅有效旧READY会缓存旧能力，缓存按池隔离5分钟后可重新探测；并行首次填充可能各探测一次。AUTH失败、BUSY、超时、取消或畸形协商响应不触发旧协议重试。未协商旧连接保留原控制等待行为，不能承诺其静默失效也在2秒内恢复。

备用连接最长闲置 45 秒，后台被动读取以发现 EOF/失效，取用前停止后台读取并交接同一个缓冲读取器。失败按 0.5～30 秒指数退避并增加随机抖动；不支持 PREPARE 的旧服务端可正常走普通流程，后台以较长退避周期重新探测。仅在未发送任何应用负载的备用连接发生传输错误时，允许一次普通建连回退；明确的目标拨号失败不自动重试。请求总建连期限保持有界。

服务端 `-max-idle 64` 限制全服务的已认证备用连接，0 禁用 PREPARE；备用连接最长等待 CONNECT 60 秒，超时释放。闲置期间释放建连名额，收到 CONNECT 后重新申请，防止无限目标拨号；备用容量满返回 BUSY。未认证连接仍受 5 秒期限约束，普通 CONNECT 阶段仍为 20 秒。

两端新增 `-max-connections 1024`，必须为正数，限制接受的连接总数（服务端包括备用和转发连接）；它独立于 `-max-setup`。客户端后台备用连接另由 pool-size 约束。以上都是命令行参数，没有新增 JSON 字段。

客户端日志的 `pool_hit` 表示使用了有效备用连接，`pool_fallback` 表示备用传输失败后普通建连回退，`pool_acquire_duration` 记录取用耗时。命中时 TCP/TLS 阶段为零，表示它们已经在后台完成，不表示没有消耗 CPU 或网络。服务端 `pool_connection` 表示此连接通过 PREPARE 进入。 服务端 `setup_duration` 已排除备用等待时间，单独记录为 `idle_duration`；其中认证仍是在备用阶段完成的。`connect_duration` 仅表示当前 CONNECT 阶段，不应直接与客户端总时间比较。

新客户端兼容旧服务端；旧客户端也兼容新服务端。首次启动、池未填满、突发请求超出池大小以及网络故障时，仍可能进行完整握手；预连接主要将工作提前，并不保证所有请求都有固定耗时。

## TLS 握手配置

客户端使用 uTLS `HelloChrome_133` 基线，每条连接独立生成模板；实际 ALPN 仅提供 `http/1.1`，移除模板中仅适用于 h2 的 ALPS 扩展。此前 `HelloChrome_Auto` 在当前依赖版本也对应 Chrome 133，但模板自带的 h2/ALPS 不会仅因 Config.NextProtos 而移除。此修改验证实际线上 ClientHello，避免服务端选择客户端未实现的 h2。调整后的模板不是完整 Chrome 指纹，也不宣称模拟当前最新 Chrome。

服务端继续使用 Go 标准 TLS，明确最低 TLS 1.2，TLS 1.2 仅允许 ECDHE + AES-GCM/ChaCha20-Poly1305；TLS 1.3 密码套件及密钥交换保留 Go 默认配置。此为一致性与安全整改，不是 nginx/OpenSSL 服务端指纹模仿。自定义 AUTH/CONNECT 仍不是 HTTP，即使协商 http/1.1 也不表示支持网页。TCP、预连接、半关闭及证书指纹验证保持原有机制；不引入 WSS，不增加握手往返。旧客户端仍可连接新服务端，TLS 1.0/1.1 和仅支持旧 TLS 1.2 套件的外部客户端不再支持。

## 自适应预连接与拨号测量

客户端 `-pool-size 4 -pool-max 16`：size 是备用容量下限，max 是自适应上限（均不含已经转发的连接）。当请求取用时就绪数不超过 1，目标容量增加 1，最多达到 max；取用、失效立即触发补充。连续 30 秒无取用后，每 30 秒目标容量减 1，最低回到 size。已有多余空闲连接自然到期释放，不中断正在使用的连接。此为需求耗尽驱动的保守自适应，不是基于 QPS/补充时长的预测算法。后台补充与 ready 总量受目标限制；收缩后已经启动的补充可能短暂超过新目标，但不超过 max。`-pool-max 0` 或等于 size 使用固定容量；`-pool-size 0` 禁用池。非零 max 必须不小于 size，最大 32；例如 size=32 时须同时指定 max=32。服务端 `-max-idle` 为所有客户端共享，扩容仍可能被 BUSY 拒绝，沿用有界退避。

每 30 秒 stats 新增：JSON `pool_hits/pool_misses/pool_fallbacks/pool_hit_rate/pool_target/pool_filling`，文本 `hit/miss/fallbacks/hit_pct/pool_target/filling`。hit/miss 统计启动以来的 Take 调用结果；命中指有效备用连接成功交接，不代表目标拨号成功；命中后传输错误转普通建连时同时增加 fallback。百分比为 100*hit/(hit+miss)，无请求为 0；禁用池时这些计数为 0，不将普通连接计为 miss。计数快照加锁，不改变流量和重试语义。

服务端 ready 与拨号失败日志增加 `dns_duration`（text: dns）、`target_tcp_duration`（text: target_tcp）及 `dns_retry_count`（text: dns_retry）；`target_dial_duration`（dial）继续表示 DNS+TCP 总拨号墙钟耗时。通过标准库 httptrace 观察 net.Dialer，不自行解析再顺序拨 IP，保留系统解析器、IPv4/IPv6 并行回退和原连接期限。临时 DNS 错误或 DNS 超时最多重试一次，等待100ms，且必须受同一连接 deadline 约束；NXDOMAIN 不重试。DNS 失败日志区分 `dns_not_found`、`dns_timeout`、`dns_temporary` 和其他 `dns`。各次尝试的 DNS/TCP 时间累加；IP 字面量 dns=0。TCP 时间覆盖拨号地址尝试及双栈回退，不把并发尝试分别相加。DNS 时间包括系统解析器处理，不代表纯公网 DNS RTT；分项之和与总时间可能有调度开销差异。不引入 DNS 缓存。

## 大流量吞吐基准

构建：`go build -o bench ./cmd/bench`。在服务端机器开启独立的本地回声目标：

```bash
./bench -echo 127.0.0.1:18081
```

在客户端机器经本地 SOCKS5 测试（目标地址从隧道服务端视角解释）：

```bash
./bench -socks 127.0.0.1:1080 -target 127.0.0.1:18081 -mib 32 -streams 1
./bench -socks 127.0.0.1:1080 -target 127.0.0.1:18081 -mib 32 -streams 4
```

每流上传指定 MiB 并完整回传，发送与接收并发，使用 64 KiB 数据块，不缓存整份文件；校验字节数及 SHA-256，并验证上传半关闭后下载可排空。每流总期限 5 分钟。JSON 输出 seconds（包含 SOCKS/隧道建连）、payload_mib_per_second（单份有效载荷/总时间）、bidirectional_mib_per_second（上传+回传字节/总时间）、failures。非零失败退出码为 1，失败样本的速率不可用于比较。MiB/s 乘 8.388608 为 Mbps；这是双向回声基准，不是独立的单向下载带宽测量。建议相同机器、流量与时段预热后重复 3 次报告中位数；结合 CPU、内存、GC、丢包判断瓶颈，不能以一次基准承诺优化百分比。测试后停止 echo 进程，不在公网开放无认证回声服务。

2026-10-14 UTC 工作树基准（各一轮，非优化前后对比）：

| 路径 | 并发 × 每流负载 | 有效载荷 MiB/s | 上传+回传 MiB/s | 校验失败 |
|---|---|---:|---:|---:|
| ARM64 本机回环，经完整 TLS 隧道 | 1 × 32 MiB | 242.883 | 485.766 | 0 |
| ARM64 本机回环，经完整 TLS 隧道 | 4 × 32 MiB | 329.339 | 658.678 | 0 |
| x86_64 客户端到 ARM64 服务端，公网直连 | 1 × 32 MiB | 0.316 | 0.632 | 0 |
| x86_64 客户端到 ARM64 服务端，公网直连 | 4 × 8 MiB | 0.412 | 0.824 | 0 |

公网四流各 32 MiB 的较大样本因长尾主动停止，不计作通过，改用四流各 8 MiB 完成并发测量。TCP 状态观察到重传及乱序，不能仅凭这些确定唯一瓶颈。并发样本 4/4 命中备用连接，无回退；池目标从 4 增到 5，空闲后回到 4。测试使用独立端口，结束后停止测试进程，未替换线上服务。

### 自适应池交替对照（2026-10-14 UTC）

同一 x86_64 客户端与 ARM64 服务端，公网直连，同一二进制和服务端本地回声目标；固定池（size=4,max=4）与自适应池（size=4,max=16）按 A/B/B/A 顺序运行。每轮先预热 3 秒，再发 4 批、每批 12 路同步请求，批间等待 1 秒；每种模式共 96 次请求。计时从客户端连接本地 SOCKS 到 CONNECT 成功响应，逐请求校验回声及半关闭。

| 指标 | 固定池 | 自适应池 |
|---|---:|---:|
| 命中率 | 32/96（33.3%） | 80/96（83.3%） |
| 建连 P50 | 196.868 ms | 68.275 ms |
| 建连 P95 | 1146.359 ms | 346.099 ms |
| 每批完成耗时中位数 | 969.165 ms | 414.789 ms |
| 请求失败/备用传输回退 | 0/0 | 0/0 |

此样本中 P50 减少 65.32%，P95 减少 69.81%；两轮自适应均优于两轮固定池。自适应每次启动的首批仍只有 4 条备用连接，主要收益发生在后续突发请求。该实验只支持突发建连耗时改善，不代表下载带宽提升，也不是长期网络保证；百分位采用排序后 round((n-1)*p) 索引。

## 客户端 SOCKS5 入口认证

可选配置（占位值，不是部署凭据）：

```json
"socks_auth": {"username": "proxy-user", "password": "replace-with-a-separate-password"}
```

配置后仅选择 SOCKS5 方法 0x02，执行 RFC 1929 认证；即使应用同时提供免认证方法也不得降级。无此项或为 null 时保留免认证。用户名、密码均必须为 1～255 字节，缺失或超长拒绝启动。认证与 SOCKS 请求沿用现有共用 5 秒期限，失败在读取 CONNECT/取用预连接/拨号远端之前返回；日志不得出现用户名、密码或认证原始报文。启动仅记录 socks_auth=true/false。凭据比较使用固定长度 SHA-256 摘要及常量时间比较，不记录摘要。

SOCKS 认证仅属于客户端本地配置，不导出到 mygotunnel 连接码，也不改变服务端 token/指纹/隧道协议。配置文件应为 0600。RFC 1929 不加密用户名密码，应结合现有局域网或虚拟内网及防火墙使用；无需修改监听地址或访问规则。测试必须覆盖分段读取、正确/错误凭据、无认证降级拒绝、畸形/截断报文和配置校验。

## 预连接稳定性与新版基准工具

备用连接 TTL 随机取配置上限的 80%～100%（默认 36～45 秒），在到期前另外 20% TTL（默认 9 秒）开始逐条替换。每批最多提前替换一条；有容量余量时保留旧连接，准备成功后再关旧连接，失败保留原连接直至其自身到期。已被请求取走的旧连接不属于池，替换任务不得关闭它。ready+filling 始终不超过 pool-max；满容量且 ready>1 时可先退役一条腾出位置，不保证任何时刻都满池。只有一条且达到硬上限时不提前撤掉最后一条，等待其自然到期。到期分散和提前补充减少集中失效，不保证严重断网时池永不为空。

补充按空缺独立调度，ready+filling 受目标容量和硬上限约束，不等待已有慢 worker 结束；每次 factory 仍有 35 秒上限。提前替换保持单任务串行，避免重复替换同一旧连接。失败立即建立共享指数退避窗口，同一窗口内并行失败不反复放大退避；不支持 PREPARE 可升级到最大退避。窗口到期后即使仍有慢 worker，也可补充剩余空缺；部分成功不清除失败窗口，后续无失败且所有 worker 完成时恢复基础状态。池空时前台继续直接建连。Close 取消并等待补充/守护任务，不关闭已交接连接。pool_retry（text retry）表示退避基础值而非剩余等待时间。

基准工具现在支持：

```bash
# 服务端机器：仅监听回环的上传/下载目标
./bench -serve 127.0.0.1:18082
# 客户端机器：auth-file 是独立 0600 JSON 文件，内容仅 username/password
./bench -socks 127.0.0.1:1080 -target 127.0.0.1:18082 -mode download -mib 32 -streams 4 -auth-file /private/socks-auth.json
./bench -socks 127.0.0.1:1080 -target 127.0.0.1:18082 -mode upload -mib 32 -streams 1 -auth-file /private/socks-auth.json
```

无 auth-file 时仅提供免认证；有凭据时仅提供用户名密码，不接受降级，错误不包含凭据。原 -echo 目标和默认 -mode echo 继续配套使用。新 -serve 目标使用仅供测试的 MGB1 长度/方向头，不是隧道协议修改，也不是通用代理。目标最多处理 32 个并发连接，负载限制 4 GiB，每连接 deadline 默认 5 分钟，-timeout 可调整。切勿将测试目标长期开放到公网。

上传：发送数据并半关闭，目标收到精确长度和 EOF 后返回 SHA-256；下载：发送有界长度请求并半关闭，接收数据后检查长度、确定性负载 SHA-256 及 EOF。回声：并发发送和接收，任一方向失败关闭 socket 并等待发送任务退出；超量数据立即失败，避免无限读取。工具使用固定大小块，不缓存完整文件。payload_mbps 是有效载荷 MiB/s×8.388608；bidirectional_mib_per_second 在 echo 为两倍，在单向模式只计一次有效载荷（不计少量控制/摘要/TLS 开销）。失败时只计算完成流的负载并返回非零退出码，不能将失败样本用于性能比较。计时包括建连、校验和调度，不是网卡线速。

新增测试覆盖错峰期限、提前替换、替换失败保留旧连接、取用与替换并发、容量上限、替换中 Close、批次部分失败/成功恢复，以及认证三种传输模式、降级拒绝和损坏负载拒绝。

本轮验证：完整 race 测试、vet、构建通过；连接池与基准测试重复运行。双机使用独立端口和临时认证配置，回声、上传、下载均校验通过；默认周期内观察到 renewed=4，替换后请求正常。独立服务端重启后首次请求约 2.319 秒内完成（含 1 MiB 传输），客户端无需手动重启。此为短时恢复/正确性验证，不是长期稳定性或带宽提速承诺；正式服务未替换。

错峰替换性能对照：上一版 8798e3f 与本轮代码在同一双机真实 TCP/TLS 链路按 A/B/B/A 运行；两边均使用 3 秒 TTL 加速到期场景，每次池就绪后空闲 3.020 秒再发 4 路请求，各 24 个样本、无失败。池命中率 33.3%→83.3%，建连 P50 201.958→68.438 ms、P95 616.640→279.137 ms。计时不含本地 SOCKS 协商，目标是服务端本地回声；不是默认 45 秒配置的全场景收益，也不代表大文件带宽提升。小样本且网络有波动，不作长期保证。受控 1 秒 TTL/100ms 准备实验中，完全空池时间约 198ms→0，但未满池累计时间约 201ms→313ms；提前替换也可能增加后台握手，需一起评估成本。

## 同路径裸 TCP 对照与运行时诊断

基准新增 `-direct`：直接连接 `-target`，跳过本地 SOCKS，使用同一负载、校验及半关闭协议，对照原始 TCP 和隧道。echo 仍对应 -echo 目标，upload/download 对应 -serve 目标；direct 不接受 SOCKS auth-file。

`-interval 1s`（默认）在 stderr 每秒输出 progress JSON，记录实际上传/下载负载字节和该间隔 Mbps；0 禁用。stdout 保留最终汇总 JSON，新增 transport、uploaded_bytes/downloaded_bytes、CPU 秒、alloc_bytes、mallocs、GC 次数及末次 RSS。CPU 和 RSS 有 available 标记，非 Linux 不宣称已获得相应指标。汇总中的 CPU/分配属于 bench 进程，不等于代理进程；控制报文、测试密钥和摘要不计作负载字节，失败流可能已有部分实际传输。进度字节按应用 Write/Read 成功量计数，上传可能尚在内核发送队列，不能当作网卡实时线速；最终完成样本需远端摘要/EOF 确认。

客户端、服务端和 bench 均可选 `-runtime-metrics /private/run.jsonl`，默认关闭；开启时以 0600 独占创建文件，已有文件拒绝启动，避免覆盖。输出初始及每秒进程快照：UTC 时间、Linux 用户+系统 CPU 累计秒、RSS、Go HeapAlloc、TotalAlloc、Mallocs、NumGC。两次累计值差除采样时间得到 CPU 占用或分配速率；CPU 100% 表示一核，RSS 不是 Go 堆大小。显式 stop 会等待写入任务结束；客户端和服务端正常处理 SIGTERM 后会写最终快照，bench 或 SIGKILL 等强制退出可能没有最终快照。只记录资源数据，不含配置和凭据。采样本身也有少量分配及开销，不宜用微秒级样本推断收益。

测试目标可使用 `-target-key-file /private/target.key`，文件必须是独立随机生成的 32 个原始字节，测试发起端也指定同一密钥文件。目标在接收测试头之前检查前缀，错误/截断拒绝；不得复用 SOCKS 密码或服务端 token。此为临时测试访问控制，不加密裸 TCP，不是通用对外认证服务。默认仍应监听回环；仅为同 IP/同端口 A/B 临时对照时才开放，受并发和期限限制，结束立即停止。

```bash
# 目标端（通常仅监听回环）
./bench -serve 127.0.0.1:18082 -target-key-file /private/target.key -runtime-metrics /private/target-run.jsonl
# 原始 TCP 样本：target 需为测试端实际可达地址
./bench -direct -target test-host:18082 -mode upload -mib 8 -streams 1 -target-key-file /private/target.key
# 隧道样本：target 从服务端视角解释，可按需加 SOCKS auth-file
./bench -socks 127.0.0.1:1080 -target 127.0.0.1:18082 -mode upload -mib 8 -streams 1 -target-key-file /private/target.key
```

可靠对照应保持目标 IP/端口、负载和并发一致，交替 A/B/B/A，避免基准复制、额外测速抢占带宽。结合两端进程 CPU/堆指标和 TCP 重传、RTT、窗口快照；快照是采样，不能累加同一 socket 的累计重传计数来当成总丢包率。未测实际代理 CPU 或原始 TCP 时，不得将上传慢直接归因为 TLS 或缓冲区。

2026-10-14 同路径对照：同一 x86_64→ARM64 公网 IP/18443，按裸 TCP/TLS/TLS/裸 TCP 交替运行。每轮单流上传 8 MiB、四流各下载 16 MiB，8 项均校验通过。上传裸 TCP 4.187/4.235 Mbps、隧道 4.263/4.132 Mbps，中位数差约 0.32%；绕过隧道后约 4.2 Mbps 的上传限制仍存在。下载两版都波动大，小样本不足判断 TLS 吞吐损耗。代理客户端 CPU 平均约单核 0.96～1.49%，服务端约 0.84～1.02%，均未触发 GC；采样观察到上传重传。当前证据不支持 TLS 计算或 Go 分配/GC 为主要上传瓶颈，但不能据此定位具体网络节点或限速原因。本轮未调整转发缓冲、密码套件、内核参数或正式服务。

四路上传补测（同 IP/18443，TCP/TLS/TLS/TCP 顺序，各两次）：每流 8 MiB，单流总 8 MiB、四流总 32 MiB，8 项/20 条流均校验通过。裸 TCP 单流中位数 4.123 Mbps、四流合计 3.899 Mbps；TLS 隧道单流 4.049 Mbps、四流合计 3.888 Mbps。该路径增加并发未接近 40 Mbps，当前限制不主要是连接数不足；不能仅凭这些样本定位具体限速节点，亦不能把较低四流数值推广为并发必然变慢。正式服务及内核参数未变更。


## 独立补充、错误清理与优雅退出

客户端与服务端处理 SIGINT/SIGTERM：关闭监听，客户端停止并等待备用池补充；已进入转发的连接继续排空。`-shutdown-timeout 15s` 控制连接排空期限，0 表示立即关闭，负值拒绝启动；到期关闭剩余连接并等待 handler 退出。TLS 连接强制关闭底层 TCP，避免逐条等待关闭通知。上游 systemd 的 TimeoutStopSec 应大于排空期限及清理余量。未完成的拨号使用进程 context 取消，认证/控制读取仍有原有期限，并由到期强制关闭兜底；不承诺无限保留长连接。运行时诊断在正常退出时停止并写最终快照。

转发正常 EOF 仍发送半关闭并等待反向数据排空；复制失败时跳过该方向 CloseWrite，立即向协调方报告根错误并中断双向读写，再等待两个复制任务退出。保持原错误方向、字节计数及既有 bufio.Reader。正常运行期间没有新增通用空闲超时或半关闭排空超时。

验证覆盖慢握手期间继续补充、慢 worker 与失败窗口并存时恢复、共享退避、错误路径跳过关闭通知、取消后继续传输与自然排空、期限到达后强制关闭并回收 handler/计数。历史双机性能数据属于此前版本，本轮不得据此宣称吞吐提升。

### 发布与运维（Linux/systemd）

两端支持 `-version` 输出版本、完整提交、构建时间和平台 JSON，不读取配置。
`-config /etc/mygotunnel/client.json -check-config` 离线校验配置；服务端还校验证书/私钥与有效期。
诊断只输出固定错误码，不输出配置解析原文或凭据；配置权限过宽会给出警告。
`-health` 客户端检查经证书验证和认证的远端预连接通道；服务端检查本地监听可达。
健康检查不等同于任意目标 TCP/UDP 可达，服务端监听探测会产生一次预期握手关闭日志。

在已提交的版本上运行 `scripts/release.sh v0.1.0 /private/release`，从 Git archive 构建
Linux ARM64/AMD64 两端及带 SHA-256 的 manifest。版本标签必须指向 manifest 的 commit。
安装脚本为 `/usr/local/sbin/mygotunnelctl` 后：

```bash
sudo mygotunnelctl status --role client
sudo mygotunnelctl diagnose --role client
sudo mygotunnelctl health --role client
sudo mygotunnelctl upgrade --role client --bundle /private/release
sudo mygotunnelctl rollback --role client
```

服务端用 `--role server`。工具使用现有 `/etc/mygotunnel/{client,server}.json` 和同名
systemd 服务，保留配置、凭据与启动参数。升级校验哈希、版本、提交、配置，原子替换二进制，
重启后检查健康、实际运行文件哈希；失败自动恢复上一二进制并重启。
回滚同样检查健康，成功后可再次 rollback 撤销本次回滚。
备份保存在 root 私有的 `/var/lib/mygotunnel/releases`，保留供人工审计清理，不自动删除。
仅安装可信本地 bundle；manifest 哈希验证传输完整性，不提供发行者签名验证。

`scripts/observe.py --role client --output /var/lib/mygotunnel/observation/UNIQUE --hours 72`
每 30 秒被动读取 journal、systemd 和 /proc，输出私有 samples.jsonl / summary.json；
建议通过独立 systemd 服务运行。最多 72 小时，不生成业务探测流量，不保存目标地址或凭据。
记录 RSS、FD、TCP 连接数、重启次数、stats 中活跃连接/UDP 资源、建连失败率与建连 P95/P99。
分位数来自成功 ready 的 setup_duration，含 SOCKS 前端等待，按 1ms 向上取整，超过 60s
记录为 60001；不是应用 RTT。失败率以首次 ready/failed 的连接 ID 去重，转发中错误单列；
预连接后台错误无连接 ID 不计入。去重表限制 10 万项，超长连接被逐出后可能重复分类。
单次最多读取 2 万条 journal，达到上限会标记数据可能不完整。保留基线/峰值/末值辅助判断增长，
需要完整观察窗口与负载背景才能认定泄漏；低流量时分位数不代表高负载体验。

回滚到尚无运维标志的历史版本时，版本显示为 legacy/unknown，健康门禁降为服务状态、
本地监听与运行文件哈希检查；原配置始终保留。新版本间回滚使用完整健康门禁。

### 认证失败保护、凭据过渡与签名升级

客户端和服务端对 RFC 1929 密码或隧道 token 的**实际不匹配**计数；超时、断包和畸形握手分开记录，
不消耗错误密码额度。每个来源 IP 默认 60 秒内允许 5 次错误，第 5 次后封 60 秒；成功认证清除该来源记录。
记录最多 4096 项，到上限时先清理过期项，仍满则暂时拒绝未记录的新来源，避免攻击者用大量源地址耗尽内存。
这会影响同一公网出口共享 IP 的用户，因此生产应观察 `auth_rate_limited` 和认证失败日志；当前限制按 IP，不能区分同一 NAT 后的用户。
TLS 握手在 AUTH 前完成，来源限速无法避免所有握手 CPU 消耗，仍由连接/并发上限控制资源。

隧道 token 轮换时，先在服务端把新值设为 `auth_token`，把旧值放入限时过渡列表，再更新客户端并重启客户端；确认客户端不再用旧值后删除列表项。最多允许一个旧 token：

```json
{"auth_token":"NEW_TOKEN","previous_auth_tokens":[{"token":"OLD_TOKEN","expires_at":"2026-11-01T00:00:00Z"}]}
```

时间必须是 RFC3339；过期项自动停止授权。新客户端 SOCKS 凭据在 `socks_auth`，可把一个带 `expires_at` 的旧账号放进 `previous_socks_auth`，方便应用逐步切换。旧格式 `socks_username` / `socks_password` 仍可用。
两端当前通过受控 systemd 重启加载配置；服务端配置先接受新旧 token，重启客户端切换后再撤旧 token。SOCKS 旧凭据只在过渡期有效。配置权限设为 0600，凭据不写日志。

版本包清单由 Ed25519 私钥签名，升级器从 `/etc/mygotunnel/release-keys/<key-id>.pub.pem` 的 root 管理信任目录选择公钥，并在停服务前验证签名、平台二进制哈希、构建版本和提交。发布私钥用 `scripts/generate-release-key.sh` 生成，离线保存；`scripts/release.sh VERSION OUTPUT PRIVATE_KEY.pem` 要求私钥 mode 0600，生成已签名 bundle。公钥需经可信渠道预装到两台机器的 root 信任目录；不能从待验证 bundle 自动建立信任。加入新公钥后先用新钥发布并验证，再移除旧公钥。签名只验证发布者和文件完整性，不替代 root 权限保护、配置权限或回滚备份保护。
