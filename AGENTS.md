# AGENTS.md

本文件适用于仓库根目录及其所有子目录，用于指导在本项目中工作的自动化代理。若用户的明确要求与本文冲突，以用户要求为准；更深层目录中的 `AGENTS.md` 可为其作用域补充或覆盖规则。

## 项目概览

MyGoTunnel 是一个小型 Go TCP/UDP 隧道项目，模块名为 `mygotunnel`。LA 专用分支 `feat/la-quic-udp` 引入 quic-go v0.64.1，`go.mod` 声明最低 Go 1.26；原功能分支的工具链要求不因此改变。

数据链路如下：

```text
SOCKS5 应用
    -> cmd/client（本地 SOCKS5 入口）
    -> internal/utlsconn（uTLS 客户端连接）
    -> cmd/server（标准 TLS 服务端）
    -> 目标 TCP 服务
```

客户端和服务端在 TLS 连接内使用简单的逐行文本控制协议；认证及建连成功后，连接切换为透明的双向字节转发。

LA 分支另有可选的 UDP over QUIC DATAGRAM：可靠控制流认证，业务数据报使用 DATAGRAM；普通 TCP 保留上面的 TLS/TCP 路径。配置缺省仍使用原 TLS/TCP UDP 隧道，不自动按线路、地区或节点切换。

## 目录职责

- `cmd/client`：加载客户端配置、接受本地 SOCKS5 连接、建立远端 uTLS 连接并组织隧道流程。
- `cmd/server`：加载服务端配置和证书、校验认证信息、连接目标地址并组织转发。
- `internal/config`：客户端和服务端 JSON 配置结构、默认值及必填项校验。
- `internal/logging`：基于 `log/slog` 的紧凑英文文本、结构化 JSON、连接 ID、失败分类与周期资源汇总。
- `internal/socks5`：SOCKS5 可选用户名密码握手、支持 TCP `CONNECT` 和 UDP `ASSOCIATE` 的请求解析、数据报及响应。
- `internal/tunnel`：`AUTH`、`CONNECT`、`OK`、`ERR` 控制消息的读写。
- `internal/utlsconn`：使用 Chrome ClientHello 指纹建立 uTLS 客户端连接。
- `internal/quicudp`：LA 可选 QUIC UDP 传输、证书信任、内部有界分片重组与数据报生命周期。
- `internal/relay`：保留缓冲数据并执行带半关闭语义的双向复制。
- `configs`：本地 JSON 配置；实际配置被 `.gitignore` 忽略。
- `certs`：本地 PEM 证书和私钥；实际证书文件被 `.gitignore` 忽略。

## 协议与行为不变量

修改网络流程前，先完整跟踪客户端和服务端两侧。当前控制协议顺序为：

1. 客户端一次写入 `AUTH <token>\nCONNECT <host:port>\n`；兼容旧客户端分两次发送。
2. 服务端认证后返回 `OK\n` 或 `ERR\n`；失败时不得拨号目标。
3. 客户端按顺序读取认证和 CONNECT 两条响应，服务端认证成功后读取 CONNECT。
4. 服务端完成目标连接后返回 `OK\n`，目标失败时返回固定白名单的 `ERR <CODE>\n`；客户端仍兼容旧 `ERR\n`，不增加控制往返。
5. 成功后双方不再解析行协议，直接转发原始字节流。

必须保持以下行为：

- 改动控制消息、响应含义或握手顺序时，同步修改客户端、服务端及相关测试；不要只改单侧。
- 从控制协议切换到转发时，继续使用既有的 `bufio.Reader`。其中可能已经预读了应用数据，改回直接读取底层连接会丢数据。
- 服务端认证比较使用常量时间比较；不要记录、回显或以普通字符串比较替代认证令牌。
- 认证读取的 deadline 必须在结束后清除，避免影响后续连接阶段。
- SOCKS5 支持版本 5、可选 RFC 1929 用户名密码认证、TCP `CONNECT` 和 UDP `ASSOCIATE`，地址支持 IPv4、域名及 IPv6。UDP 默认 strict 来源使用 ASSOCIATE 声明的具体地址/端口约束，全零地址回退到 TCP 对端 IP；显式 nat 模式仅允许 TCP 对端 IP，忽略声明并从合法首包学习映射端口。两种模式均先校验来源与报文再绑定，绑定后不可切换端点。
- uTLS 客户端使用固定 `HelloChrome_133` 基线并适配 ALPN，客户端与服务端均协商 `http/1.1` ALPN。相关值属于连接兼容性的一部分。
- 有导入指纹时，`InsecureSkipVerify` 仅用于替代公共 CA 验证，必须同时通过 `VerifyConnection`（包含恢复握手）校验固定证书指纹；没有指纹时使用系统 CA 和主机名验证。修改时同步说明证书信任、SNI 和部署迁移。
- 旧预连接协议为AUTH → OK → PREPARE → READY → CONNECT（或UDP）→ OK；新连接可协商PREPARE ACK / READY ACK，命令后先ACK再原OK/ERR。只有本连接成功协商才启用ACK，旧流程不发送额外ACK。原有普通流程继续兼容。备用连接有独立数量/闲置限制，取用后不得回池；后台读取必须在交接前停止。
- `-max-connections` 限制接受连接总数；备用等待时释放 setup permit，CONNECT 前必须重新申请。
- `-max-setup` 限制正在建连的请求，成功进入转发前释放，失败返回也必须释放；不要让长连接占用建连额度。
- 保留 `relay.CopyBidirectional` 的半关闭语义：正常 EOF 后等待反向数据排空；复制或半关闭失败时解除另一方向的阻塞，并在两个复制 goroutine 都退出后返回。修改转发退出策略时要考虑一侧 EOF、仍在返回的数据、阻塞 goroutine、字节统计和连接释放。
- 生产 relay 使用 `CopyBidirectionalContext` 与 `Permit.AbortContext()`：该独立 context 只在 shutdown grace 耗尽时取消，同时关闭两端底层传输并 join；不能直接传进程 context 而破坏宽限期排空。UDP 的 TCP 控制监测从来源解析开始，FIN/硬错误均取消 UDP setup，建立后继续由同一 reader 监测并 join，不能误套 TCP CONNECT 的 FIN 保留规则。
- setupwatch 仅在 TCP setup 期间独占同一个 bufio.Reader，预读至其既有容量；非 EOF 硬读错误取消子 context，FIN 保留半关闭。交接前必须 Stop 并等待退出，检查/恢复读期限，提前负载不得丢弃；缓冲满则停止监测，不能无限缓存或承诺覆盖该边界之后的 RST。

## 配置约定

客户端实际读取的字段只有：

- `local_addr`：可选，默认 `127.0.0.1:1080`。
- `socks_auth`：可选，包含本地 SOCKS5 的 `username` 和 `password`；启用后禁止免认证降级，凭据不进入连接码。
- `remote_addr`：必填，远端服务端的 `host:port`。
- `auth_token`：必填。
- `sni`：可选；为空时从 `remote_addr` 推导主机名。
- `certificate_fingerprint`：可选，服务端叶证书 DER 的 SHA-256 十六进制指纹；存在时使用固定指纹验证，否则使用系统 CA 和主机名验证。
- `trust_mode`：可选 ca/pin；省略按有无指纹推导，显式模式必须与指纹一致。ca 连接码用 v2，pin 默认保持 v1。
- `tls_session_cache`：可选布尔，缺省 false；控制普通和后台预连接的有界 TLS 会话缓存，不进入连接码。
- 客户端和服务端均支持 `udp_queue_max_bytes`、`udp_queue_max_age_ms`；0/缺省为 1 MiB、250ms，非零范围分别 65000～67108864、1～60000。属于本地策略，不进入连接码。
- 两端还支持 `udp_write_timeout_ms`（默认5000，非零1～600000）、`udp_max_sockets`（默认1024，非零1～65536）、`udp_memory_limit_bytes`（默认64MiB，非零262144～1073741824）；0/缺省取默认值，均不进入连接码。生产每个run创建一个共享Resources，不能给每个关联独立创建而绕过进程预算。
- 客户端独有 `udp_source_policy`（缺省 strict，可选 nat）及 `udp_relay_port_min/max`（同为0用系统端口，否则1～65535闭区间，最多1024端口）；不进入连接码，不自动修改防火墙。NAT 模式仅支持 TCP/UDP 共用出口 IP，不能开放任意来源。
- LA 分支客户端独有 `udp_transport`（空值/缺省 tcp，可选 quic）与 `udp_quic_remote_addr`（空值/缺省使用 remote_addr，经 UDP 连接；显式远端仍需主机与1～65535数字端口），均不进入连接码。初版无自动回退；证书/认证错误不得降级绕过，不能跨节点重放已有业务数据。

服务端实际读取的字段只有：

- `listen_addr`：可选，默认 `:9001`。
- `auth_token`：必填，必须与客户端一致。
- `cert_file`：可选，默认 `certs/cert.pem`。
- `key_file`：可选，默认 `certs/key.pem`。
- `https_entry`：可选同端口 HTTPS 网页回退，缺省关闭。启用时增加认证前单 IP 并发/速率与 HTTP 容量保护；字段、默认值和边界见 README 与 `docs/https-entry-design.md`。
- LA 分支 `udp_quic_listen_addr`：可选独立 UDP 监听，空值/缺省关闭，沿用监听地址离线校验；程序不自动修改防火墙。

JSON 中的未知字段目前会被忽略，不能仅凭某个本地配置中存在额外字段就认为功能已经实现。新增或重命名配置项时，应同步更新结构体、JSON 标签、默认值/校验、示例或说明，以及配置加载测试。

严禁提交真实认证令牌、私钥、生产地址或其他敏感配置。日志中也不得输出 `auth_token`。需要示例时使用明显的占位值。

## 常用命令

从仓库根目录运行：

```powershell
# 编译检查两个命令入口，不在仓库留下可执行文件
go build ./cmd/...

# 运行全部单元测试和本地协议/连接测试
go test ./...

# 静态检查
go vet ./...

# 启动客户端或服务端；日志默认输出到 stderr，格式为 text，级别为 info
go run ./cmd/client -config configs/client.json
go run ./cmd/server -config configs/server.json

# 调试日志或适合日志采集器处理的 JSON 日志
go run ./cmd/client -config configs/client.json -log-level debug -log-format json
```

依赖由 Go modules 管理。只有确实修改依赖时才运行 `go mod tidy`，并同时检查 `go.mod` 与 `go.sum` 的差异。不要提交 `main.exe`、其他生成的可执行文件、真实配置或证书。

## 编码与改动规范

- 遵循标准 Go 风格，保持包职责单一；可复用的协议逻辑放在 `internal` 对应包中，不要复制到两个 `main` 包。
- 对所有网络读写、拨号、握手和配置加载错误进行处理。需要补充上下文时使用 `%w` 包装底层错误。
- 明确连接所有权；新建连接后应在正确层级关闭，并注意 TLS、缓冲读取器及半关闭行为。
- 新增可能阻塞的网络操作时设置合理的 context 或 deadline，并避免 goroutine 泄漏。
- 使用标准库 `log/slog` 和 `internal/logging`，不要混用 `fmt.Print*` 或标准库旧 `log` 包输出运行日志。使用 `component=client` 或 `component=server` 区分进程，错误放在 `error` 字段，地址分别使用 `listen_addr`、`remote_addr`、`client_addr`、`target_addr`。不得记录密钥、认证令牌或未经约束的原始协议内容。
- 不做与任务无关的重构、重命名、格式化或依赖升级，保留用户已有的未提交改动。
- 只对本次修改过的 Go 文件运行 `gofmt`。当前 Windows 检出受 CRLF 影响，`gofmt -l cmd internal` 会列出全部现有 Go 文件；不要因此批量重写无关文件或制造纯换行差异。
- `README.md` 当前内容很少。若改动用户可见的启动方式、配置格式或协议能力，应在任务范围允许时同步补充文档。

## 测试要求

LA QUIC UDP 需保留来源 strict/nat、SOCKS TCP 控制关闭即结束关联、CA/指纹验证、认证轮换与限速及进程资源预算；不用应用0-RTT，不在认证前转发。QUIC TLS 不等于 uTLS Chrome 或 HTTP/3 伪装。初版每个关联一条 QUIC 连接，TCP 与 QUIC 通过合并 listener 共享 admission 总连接/setup 限制；任一子 listener 致命失败必须终止合并入口，关闭时回收尚未交付的连接并 join 接受 worker。

QUIC客户端独立固定备用池 `-quic-pool-size` 默认2、0关闭、最大32，只在QUIC配置启用；既有TCP池参数不控制该池。后台完整TLS/证书/AUTH并协商PREPARE ACK/READY ACK，服务端共用TCP idleSlots与60秒期限，等待释放setup，UDP命令前重取setup。池guard/TTL/退避/所有权复用preconnect.Pool；DATA仅在UDP最终OK后启用，前台取用后同一Reader且未消费业务才允许一次同端QUIC传输故障回退。明确LIMIT、认证拒绝、协议错误和取消不重试、不降级TCP。旧服务端不支持PREPARE则后台退避，前台普通QUIC保留。QUIC LIMIT行未送达时用独立应用关闭码0x104映射ErrLimit，factory归ErrBusy，前台归TargetError LIMIT；不得变成正常EOF引发重试。前台命中handshake=0，后台Debug记录真实QUICDuration，stats独立quic_pool_idle/max/filling/hits/misses/fallbacks/hit_rate/renewed/retry，原pool_* stats继续只指TCP。测试覆盖真实QUIC池guard交接、关闭已交接所有权、完整认证/错误pin、同端fallback与明确错误不重试、共享idle/setup/socket限制及退出回收。

有效QUIC备用容量不超过udp_max_sockets-1；后台socket用Resources原子AcquireSocketWithReserve(1)为本地relay留一名额，前台正常申请仍可使用该余量。仅后台使用DialOptions.SocketReserve，不进JSON/连接码；低预算2名额时必须能取一条备用并成功建立本地relay。回退计时ControlDuration累加旧ACK等待与新控制阶段，不能覆盖导致小于AckDuration。

QUIC 传输层先用源地址 Retry 验证，连接数受 max-connections、同时握手数受 max-setup（不超过总连接数）限制；每 IP 握手 guard 为并发8、每秒4次、突发16次。握手后共享 TCP 的应用 admission 和 authlimit。控制 ERR 未送达时，认证拒绝/超时仍可通过 QUIC 应用关闭原因跨端反馈，不能泛化成普通 EOF 或丢失认证拒绝分类。

客户端可复用进程有界的地址验证 NEW_TOKEN：最多16个端点/信任范围，每范围4枚、Pop后单次提交，按remote/SNI/系统CA或具体pin隔离，非标准自定义根池不隐式共用系统信任缓存。不持久化、不进日志/连接码，不增加部署配置。有效令牌只减少后续新关联的重复Retry；不等同TLS恢复，不启0RTT，不省证书验证或AUTH。首次、过期、出口IP变化、服务端重启失效后仍需Retry。测试须验证新UDP socket下减少Retry、每连接完整AUTH、缓存有效时错误pin仍拒绝、过期恢复Retry及缓存容量/单次取用/并发隔离。

QUIC 内部分片每个 DATAGRAM 应用数据最多1100字节（12字节头+1088字节负载），完整 SOCKS UDP 帧最多65000字节/60片；每关联最多16个未完成重组、64个去重ID、16项接收队列。缓冲从共享 datagram.Resources 借用，丢弃/关闭必须归还。重组使用独立固定2秒期限，不能直接套用默认250ms队列期限；完成时的 Packet.At 为完整重组时刻，本地队列年龄从此起算。应用 SOCKS FRAG 仍拒绝。测试覆盖乱序/重复/缺片/大包、认证拒绝、控制取消、跨关联预算和关闭回收。UDP 日志保留 transport=udp，并以 udp_tunnel_transport=tcp/quic 标识载体；不把成功包分位数当作完整丢包/体验指标。

v2 通过 ALPN mygotunnel-udp/2 协商（双方同时支持），保留旧 ALPN /1 和原 v1 分片。v2 整包 P/2+完整SOCKS帧最多1415字节，受SendDatagram尺寸验证约束；DatagramTooLargeError表示未入队才允许回退v1，每秒最多一次重探较大整包；其余错误仍原期限/关闭语义，不重发已入队业务。开启库内PMTUD，初始1200，不承诺1400负载一定合包，不启0RTT。整包接收也必须先认证并计共享Resources，旧ALPN不得接收整包。测试覆盖双向整包、老服务端/老客户端、MTU不够的无重复回退、大包v1、畸形整包及资源释放。

Conn 内嵌1415字节发送 scratch 不计 Resources，按关联连接数有界；QUIC 库/加密/协议元数据/内核缓冲亦在 managed payload 预算外，不得宣称全部应用内存或 RSS 均被 udp_memory_limit_bytes 限制。udp_quic_handshake_duration 记录完整 QUIC 拨号握手时间，tcp_duration/tls_duration 保留 TCP 阶段含义，QUIC 中为0。quic_* drops 为本地拒绝/到期事件计数，分片/完整报文维度可能不同，不能当作线路丢包率或直接相加；quic_enqueued_fragments 仅表示本地发送队列接收，不证明送达。

新增测试放在被测包旁的 `*_test.go` 文件中，优先使用表驱动测试。单元测试应可离线、可重复，不依赖公网地址、真实证书或固定端口；协议和连接测试优先使用 `net.Pipe`、本地临时 listener、临时目录及测试证书。

按改动范围重点覆盖：

- SOCKS5：分段读取、短包、错误版本、非 `CONNECT` 命令、IPv4、域名、IPv6 和不支持的地址类型。
- 隧道协议：正确换行、错误命令、认证失败、建连失败，以及握手后缓冲区中已有负载的情况。
- 配置：默认值、必填项缺失、无效 JSON、文件读取错误和新增字段。
- 转发：单侧 EOF、半关闭、反向剩余数据和无 goroutine 泄漏的退出。
- uTLS/TLS：尽量使用本地服务端验证 SNI、ALPN、超时和握手失败，不访问真实外部节点。

## 完成前检查

交付代码改动前至少执行：

```powershell
go test ./...
go vet ./...
go build ./cmd/...
```

同时检查：

- 修改过的 Go 文件已用 `gofmt` 格式化，且没有无关的全仓换行变更。
- `git diff` 中只有任务相关内容，没有令牌、证书、私钥、配置文件或构建产物。
- 协议或配置改动已经同步到所有调用方、测试和用户可见文档。
- 若某项验证无法运行，在交付说明中明确列出未运行的命令及原因。

## 日志契约

- 30秒stats默认补充RSS/Go堆（alloc/inuse/idle/released）/累计分配/GC/goroutine/FD/CPU；Linux RSS/FD/CPU各有availability，其他平台不能宣称得到不可用指标。FD分批读取且排除自身目录描述符，计数允许并发近似；不启动逐连接或逐包采样，停止仍须join。
- TCP根故障字段error_operation/error_endpoint/error_errno/error_local_addr/error_remote_addr（text op/endpoint/errno/error_local/error_remote）仅基于既有错误链及端点匹配；readfrom外层不能替代内层读错误，歧义/不明为unknown。只在失败路径收集，不包裹io.Copy端点，不改变根错误、排空、错误级别和字节计数。
- UDP来源日志每会话仅保留首个拒绝端点及原因，ready允许IP摘要最多8项并输出完整数量；不截断实际filter。first_datagram仍为收到包，first_accepted_datagram为通过来源/格式校验，不表示送达；nat_candidate仅为诊断提示，不放宽strict/nat边界。UDP控制终止与数据故障用udp_termination_scope及udp_control_errors/data_errors细分，原session_errors与互斥终止计数不变；观察器保留relay_failed并补充子计数。

- 默认 text 必须紧凑英文，不重复 time=/level=/msg=/component=；使用 UTC 完整日期时间 `YYYY-MM-DD HH:MM:SS.mmm`，启动输出 timezone=UTC，C/S 区分两端。JSON 继续使用标准字段和现有长字段名，Duration 为纳秒整数，字节数为原始整数；时间统一 UTC。事件名使用 listening/ready/closed/failed/stats 等短英文。
- 目标域名/IP:端口和 peer 保留；不解密 HTTPS、不记录 URL 路径、token、私钥、连接码或原始控制报文。文本属性中的控制字符必须转义，写入一次完整记录，并在 With/WithGroup 派生处理器间共享写锁。
- connection_id/id 只在进程内关联，包含进程前缀和原子递增编号，不通过协议传递ID，不宣称两端 ID 一致。
- 上传/下载统一以 SOCKS5 应用为参照：↑/upload_bytes 向目标，↓/download_bytes 回到应用；保留 relay 的根失败方向 up/down，不被故意中断的反向超时覆盖。
- text 阶段短名为 socks/sfirst/smethod/sauth/sreq/tcp/tls/take/ctl/auth/wait/dial/reply/idle/total，展示毫秒，最多 3 位小数。SOCKS 子阶段分别为首字节、方法协商、RFC 1929、请求读取，均含前端等待；JSON 对应 socks_first_byte_duration、socks_method_duration、socks_auth_duration、socks_request_duration，失败时未进入的握手子阶段为 0，尚未读取请求则无 sreq，不记录凭据。JSON 长字段定义见 README。服务端 total 排除 idle，但仍包含准备阶段 auth；连接生命周期 duration/dur 包含 idle。已预热池命中时 text 可省略零值 tcp/tls，JSON 保留。
- failed 必须包含 stage 与 close_reason/reason；常见系统错误完整链进入 DEBUG，未知错误在 WARN 保留诊断信息。只有真正正常 EOF 才作为 INFO closed，不能把所有 reset/timeout 静默吞掉。
- 转发失败 failure_phase（text phase）区分 copy 与 half_close，保留根方向；ENOTCONN 分类 closed 仍为 WARN failed，不吞错或更改正常排空语义。
- SOCKS RFC1929 错误以 auth_rejected/auth_limited/auth_protocol 分类，观察器据固定原因识别认证，不能把所有 stage=socks 都排除。用户名密码、摘要和原始握手仍不得写日志。
- 资源状态每 30 秒一条 stats，active 统计 accepted 总数，setup 统计 permit 占用，idle 统计备用，rejected 是准入拒绝累计；计数使用原子操作，Permit Release/TryAcquire 同步更新，监听流程退出时停止并等待定时器。不要用日志计数改变任何连接、认证、超时、重试或半关闭行为。
- 修改日志需覆盖毫秒与时区、短字段、英文事件、双向字节、ID 关联、根失败方向、分组属性、并发写入、错误详略、资源计数与定时器停止，并同步 README 和本文件。
- pool_ack_duration（text ack）为协商后命令发送至即时ACK的Duration，JSON纳秒/text毫秒；不含ACK后的目标等待，未协商为0，失败时保留已等待值。它属于control_duration子阶段，不能再与control相加。

## TLS 握手配置

客户端使用 uTLS `HelloChrome_133` 基线，每条连接独立生成模板；实际 ALPN 仅提供 `http/1.1`，移除模板中仅适用于 h2 的 ALPS 扩展。此前 `HelloChrome_Auto` 在当前依赖版本也对应 Chrome 133，但模板自带的 h2/ALPS 不会仅因 Config.NextProtos 而移除。此修改验证实际线上 ClientHello，避免服务端选择客户端未实现的 h2。调整后的模板不是完整 Chrome 指纹，也不宣称模拟当前最新 Chrome。

服务端继续使用 Go 标准 TLS，明确最低 TLS 1.2，TLS 1.2 仅允许 ECDHE + AES-GCM/ChaCha20-Poly1305；TLS 1.3 密码套件及密钥交换保留 Go 默认配置。此为一致性与安全整改，不是 nginx/OpenSSL 服务端指纹模仿。自定义 AUTH/CONNECT 仍不是 HTTP，即使协商 http/1.1 也不表示支持网页。TCP、预连接、半关闭及证书指纹验证保持原有机制；不引入 WSS，不增加握手往返。旧客户端仍可连接新服务端，TLS 1.0/1.1 和仅支持旧 TLS 1.2 套件的外部客户端不再支持。

启用可选 https_entry 后，认证失败与非 AUTH 输入转入同一个标准 HTTP 服务，不先写 ERR；成功 AUTH 与认证后 wire 不变。分类最多保留4096字节原始前缀，回放必须原样连接原 Reader，不能重建或丢失预读。TLS/分类/首请求共享从 admission 准入起的5秒绝对期限，HTTP setter不得延长或清除；HTTP首个Handler才解除此约束。HTTP分支不再进入认证，不拨号任意Host/URL/CONNECT后端。HTTP名额与总连接计数覆盖至实际关闭；setup与单IP并发在成功AUTH/首HTTP请求头后按职责释放。AUTH关键字保留，凭据失败仍原子判定且常量时间比较。HTTP与TLS失败聚合在ingress_*，不能混入代理failed/ready和P95/P99，禁止原样记录标准库HTTP错误文本。新增入口测试覆盖失败回放、期限、body清理、配额、退出及真实uTLS/TLS的TCP/UDP/预连接/半关闭。

## 自适应预连接与拨号测量

可选-pool-idle-size（默认0关闭，启用为1..pool-size）与-pool-idle-after（默认2分钟）允许长期无需求后每30秒向更低空闲容量缩减；默认保持原floor。启动记录pool_idle_size；取用立即恢复正常size，交接连接不归池、不因收缩关闭；超出目标的备用自然到期。默认自适应及显式idle收缩都须保护一条fresh keeper：所有就绪都进入续期窗口时允许串行准备一条，完成时即使仍有surplus也可保留新连接；已有fresh keeper则不续建其他surplus，仍受hard max/共享退避约束。Take优先最近入池连接，旧连接继续guard/TTL，失效仍有ACK与fallback兜底；未使用TLS关闭走NetConn避免close_notify阻塞。测试覆盖默认/非法配置、空闲门槛与节奏、首个就绪连接、恢复与交接所有权、受控续期工作量对照；不以实验次数变化承诺线上P95提升。

客户端 `-pool-size 4 -pool-max 16`：size 是备用容量下限，max 是自适应上限（均不含已经转发的连接）。当请求取用时就绪数不超过 1，目标容量增加 1，最多达到 max；取用、失效立即触发补充。连续 30 秒无取用后，每 30 秒目标容量减 1，最低回到 size。已有多余空闲连接自然到期释放，不中断正在使用的连接。此为需求耗尽驱动的保守自适应，不是基于 QPS/补充时长的预测算法。后台补充与 ready 总量受目标限制；收缩后已经启动的补充可能短暂超过新目标，但不超过 max。`-pool-max 0` 或等于 size 使用固定容量；`-pool-size 0` 禁用池。非零 max 必须不小于 size，最大 32；例如 size=32 时须同时指定 max=32。服务端 `-max-idle` 为所有客户端共享，扩容仍可能被 BUSY 拒绝，沿用有界退避。

每 30 秒 stats 新增：JSON `pool_hits/pool_misses/pool_fallbacks/pool_hit_rate/pool_target/pool_filling`，文本 `hit/miss/fallbacks/hit_pct/pool_target/filling`。hit/miss 统计启动以来的 Take 调用结果；命中指有效备用连接成功交接，不代表目标拨号成功；命中后传输错误转普通建连时同时增加 fallback。百分比为 100*hit/(hit+miss)，无请求为 0；禁用池时这些计数为 0，不将普通连接计为 miss。计数快照加锁，不改变流量和重试语义。

服务端 ready 与拨号失败日志包含 `dns_duration`（text: dns）、`target_tcp_duration`（text: target_tcp）、`dns_retry_count`（text: dns_retry）及 `target_dial_duration`（dial，DNS+TCP总墙钟耗时）。通过标准库 httptrace 观察 net.Dialer，不自行解析再顺序拨 IP，保留系统解析器和IPv4/IPv6并行回退。临时 DNS 错误或 DNS 超时最多重试一次，等待100ms并受原连接 deadline 约束；NXDOMAIN 不重试。日志 close_reason 对 DNS 区分 dns_not_found、dns_timeout、dns_temporary 和其他 dns。各次尝试的 DNS/TCP 时间累加；IP字面量dns=0。TCP从首次地址尝试到拨号返回，包含双栈回退等待，不能把并发尝试分别相加。DNS时间包含系统解析器处理，不能当作纯公网DNS RTT；两个子阶段之和与总耗时可有调度开销差异。不引入DNS缓存。

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

客户端与服务端处理 SIGINT/SIGTERM：关闭监听，客户端停止并等待备用池补充；已进入转发的连接继续排空。`-shutdown-timeout 15s` 控制连接排空期限，0 表示立即关闭，负值拒绝启动；到期通过独立 AbortContext 同时关闭每条 TCP relay 两端底层传输并等待 handler/复制任务退出，覆盖一侧已 FIN 的情况。TLS 及未使用备用连接直接关闭底层 TCP，避免逐条等待关闭通知。上游 systemd 的 TimeoutStopSec 应大于排空期限及清理余量。未完成的拨号使用进程 context 取消，认证/控制读取仍有原有期限，并由到期强制关闭兜底；不承诺无限保留长连接。运行时诊断在正常退出时停止并写最终快照。

转发正常 EOF 仍发送半关闭并等待反向数据排空；复制失败时跳过该方向 CloseWrite，立即向协调方报告根错误并中断双向读写，再等待两个复制任务退出。保持原错误方向、字节计数及既有 bufio.Reader。正常运行期间没有新增通用空闲超时或半关闭排空超时。

验证覆盖慢握手期间继续补充、慢 worker 与失败窗口并存时恢复、共享退避、错误路径跳过关闭通知、取消后继续传输与自然排空、期限到达后强制关闭并回收 handler/计数。历史双机性能数据属于此前版本，本轮不得据此宣称吞吐提升。

## UDP 整合约定

UDP 普通流程为一次写入 AUTH 与 UDP 两条命令，并依次读取两个 OK；预连接只发 UDP 并读取一个 OK。协议控制行继续遵守 4096 字节上限和控制阶段期限，保留预读 Reader。UDP 也必须验证服务端证书、消耗总连接名额，成功转发前释放 setup permit；预连接先释放 idle 并重取 setup。进程取消后已建立 UDP 会话在 grace 内可继续转发，到期由 admission 关闭 TCP 隧道并等待全部 UDP worker 退出。目标 DNS/拨号取消与会话退出联动，每次 UDP 目标拨号和写入最长 5 秒。

每 UDP 帧包含 SOCKS 头且最多 65000 字节，读写上限一致；每次最多刷新 32 个已排队报文，不等待凑批，bufio 路径复用缓冲而非整帧临时拷贝。客户端出队列 256、回包队列 128，服务端各 256；另有配置的字节及年龄上限，入队/出队淘汰过期报文，普通队列满时拒绝。服务端响应使用共享256节点的FairQueue按目标轮转，低积压目标可淘汰最大积压目标报文争取准入；不降低单流原容量，flow环/heap仅保留非空流且总数不超过节点数，inflight批次不可抢占。每会话最多 256 个目标 worker（退出中也占名额），独立拨号和发送，DNS 初始化并发最多 16，IP 绕过 DNS 名额；同目标初始化去重，待发送最多 32 包/64 KiB 负载，各目标共享配置的负载字节预算。分发时保留年龄，慢 DNS 等待也计入；元数据、读缓冲、帧头、在途包不计入负载预算。空闲 2 分钟回收，15 秒扫描；失效目标下次发包在100/200/400/800/1000ms有界短退避后重建，期间丢弃且不拨号，成功回包清历史。失败记录最多256个、保留1分钟，取消/资源错误不记失败。每worker递增generation，成功/失败更新在表锁内确认ctx和代次；旧worker不能清除/覆盖新失败，同代failureRecorded优先于并发首响应。每关联单个最早到期timer主动清理pending及响应队列，不依赖新帧或负载预算耗尽；保留原年龄，清理不取消慢DNS。已建立会话终止时取消阻塞并等待所有 worker，再输出统计。client upload 为入队数，download 为成功 UDP 写入数，udp_write_errors 为写入失败；server upload 为成功目标写入，download 为响应入队。queue_full_drops/queue_expired_drops 分别为容量/年龄丢弃，request_queue_peak_bytes/response_queue_peak_bytes 为收发队列峰值，target_queue_peak_bytes 为单目标负载队列峰值；full 与直接拒绝计数有重叠，不能相加。UDP write 成功不承诺应用收到。年龄只限制应用排队，不承诺传输 RTT 或清除内核积压。协议不消除 TCP 队头阻塞，不能称为原生 UDP。

旧 socks_username/socks_password 字段保留读取，嵌套 socks_auth 优先，认证仍使用功能分支的固定 SHA-256 摘要常量时间比较；真实 SOCKS 凭据不进入连接码。测试需覆盖池命中/回退/显式拒绝、证书指纹、UDP 来源和失败恢复、setup/idle 名额释放及 grace 到期清理。

UDP TLS写期限独立于队列年龄，默认每次底层Write最多5秒，空闲不超时且不设置读期限。写错误/超时必须终止整个关联并关闭底层连接，不能在部分帧后继续写；等待全部worker退出后输出首个终止stage/reason，正常EOF为closed，其他为failed。不得覆盖TCP CONNECT的半关闭语义。日志补udp_tunnel_write_calls/errors/timeouts/max_duration；max_duration为Duration（JSON纳秒，text毫秒）。进程stats补udp_sockets/max_sockets、buffer_bytes/cached_bytes/buffer_peak_bytes/memory_limit_bytes、socket_rejected/memory_rejected、sessions_closed/session_errors/tunnel_write_failures/write_timeouts（均以udp_为前缀）。进程写失败/超时只累计根终止会话，会话写调用统计可包含次生错误。

UDP池化Packet为单所有者：Push成功转交所有权，失败仍由调用者Release；出队消费后、队列过期/关闭时必须Release，不能保留已释放Data切片。进程预算包含512～65536分级缓冲容量、空闲缓存、在途帧和65KB接收缓冲，缓存每级最多64块，预算紧张先驱逐空闲缓存；不宣称限制RSS或覆盖TLS/内核/元数据。Socket预算覆盖初始化与退出中的目标。帧读取资源拒绝时先丢弃完整帧保持流对齐，后续仍可恢复。queue_resource_drops统计最终未能复制入队的资源拒绝；资源级memory_rejected可能包含公平队列回收后重试成功的Borrow拒绝尝试。response_fair_evictions也计入queue_full_drops/dropped_responses，response_peak_flows为非空flow峰值；target_backoff_drops/entries为短退避拒绝/剩余记录，target_queue_expiry_sweeps为主动到期清理次数，不能混同真实DNS请求次数。测试需覆盖并发预算、缓存驱逐、最大65000帧、零热路径读取分配、拒绝后帧对齐、跨关联共享限制和关闭后归还。

常驻接收 scratch 必须用 BorrowResident，活跃常驻容量最多 limit−2×65536，不能绕过进程总预算或把普通缓存永久算常驻。Release 时撤销常驻占用后可进入普通缓存，关闭和复用仍保持单所有者。资源日志补 udp_resident_bytes/resident_limit_bytes/transient_reserve_bytes/resident_rejected；resident_rejected 为 memory_rejected 子集。预留只防止常驻占满，不承诺所有瞬态并发都成功。

服务端 pendingBudget 压力下先有界清理各目标过期队列再尝试入队，不能只清理当前队列使慢 DNS 旧包一直占共享预算；不能每包创建 timer 或无条件全表扫描，保留原年龄、负载预算和 packet 所有权。

进程终止原因计数udp_end_eof/timeout/reset/truncated/canceled/closed/error互斥，之和为udp_sessions_closed，只统计已经进入UDP转发的会话；不得把setup拒绝或次生错误重复计入。

目标错误仅发送ERR白名单TIMEOUT/DNS/NETWORK/HOST/REFUSED/LIMIT/CANCELED/INTERNAL，不能传原始错误文本。新客户端兼容旧ERR，旧客户端非OK处理兼容新ERR；AUTH与PREPARE BUSY保持原响应。目标错误日志优先保留具体分类，SOCKS NETWORK=3，TIMEOUT/DNS/HOST=4，REFUSED=5，其余=1，不能把普通超时映射TTL expired=6。显式错误（含未知码的协议错误）不能触发备用传输回退。修改需覆盖普通/池命中、TCP/UDP的错误解析和SOCKS回复、新旧响应兼容。

满256项目标表时先回收其他failed/idle项再拒绝新目标；targetSlots仍覆盖退出中的worker，不能因删除map就提前释放slot。长度头完整后的body读取/丢弃EOF均为ErrUnexpectedEOF，只有帧边界EOF正常；同时覆盖池化与旧ReadDatagram及实际日志统计。

strict 模式 ASSOCIATE 源域名在成功前有界解析一次（5秒，计入setup总预算），允许解析结果 IP，不要求包含 TCP peer；具体 IP 按声明，全零回退 TCP peer。非零声明端口须匹配，零端口由合法首包绑定。nat 模式不解析来源域名，忽略声明，只允许 TCP peer IP 并从合法首包学习实际端口；固定端点包含 IPv6 zone。域名无可用 IP 返回 REP2，解析失败 REP4；拒绝先于 socket/远端拨号。TCP/UDP 共享域名语义校验；UDP 目标空域名、控制/空白字符、分隔符、port0 在绑定源端口前拒绝，ASSOCIATE 源 port0 及零 UDP 负载保持。

UDPHeader 借用报文中的域名切片，不能跨 Packet.Release 保存；有效头解析和已存在目标查找不分配。服务端仅新建目标时构造 Host/拨号地址并复制目标键，排队负载继续持有 Packet。客户端使用 AddrPort I/O，来源过滤先比较 IP/声明端口，再验证报文并绑定。结束日志记录 received_datagrams、source_ip/port/binding_drops、invalid/oversized_datagrams、first_datagram_seen/duration；服务端记录 target_dial/dns/write/read_failures，DNS 是拨号失败子集，主动取消/清理不重复算故障。

NewPreparer按pool探测ACK，仅AUTH OK后的纯EOF/ERR可在新连接重试一次legacy，成功旧READY才缓存5分钟；AUTH/BUSY/timeout/cancel/畸形/截断响应不降级。ACK命令发送+读取共2秒，ACK后独立等待目标20秒+1秒回复，夹parent期限；ACK前OK或未知/过长/控制字符响应均协议失败不可回退。父deadline已到即使ctx.Err尚未发布也不可重试。前台总setup38秒，本地SOCKS回复另留5秒；UDP解析共享此总预算。旧未协商连接不施加ACK期限。

预连接 setup 任意阶段被 context 取消而关闭 socket 时，返回 context 根错误，不能把关闭产生的 net.ErrClosed 误归为普通传输错误或协商降级。

目标OK/ERR（含重取setup拒绝、UDP成功）用SendTargetResult独立1秒写期限，不能继承已耗尽控制/旧idle写期限，发送失败要记录；成功进入转发前清除全部期限。客户端AUTH OK/ACK后重新起算目标等待，给回复留余量。ACK发送后服务端不等待客户端确认，认证、指纹、预读Reader、半关闭与转发不变量保留。

## 发布与运维入口

两端 `-version` 在读取配置前输出 buildinfo JSON；`-check-config` 只离线检查，
`-health` 为显式有界探测。诊断不得输出原始解析错误（可能含凭据）。
LA 客户端配置 quic 后，health 在 TCP 控制检查成功后补 QUIC AUTH/UDP 两 OK 探测；服务端启用 QUIC 后，在 TCP 监听检查成功后用配置证书 SHA-256 pin 和当前 token 探测本机入口。每次 QUIC 探测最多3秒且受父 context 约束，使用独立小资源预算，取消须关闭并等待回收，不发送业务 UDP/拨号目标。失败仅输出 REMOTE_UDP_QUIC_UNHEALTHY 或 UDP_QUIC_LISTENER_UNHEALTHY；通配监听需转同地址族回环，IPv6 :: 必须使用 ::1。不能仅凭 TCP 健康就声称配置的 QUIC 入口健康，也不能把控制探测成功当作目标 UDP 可达。
发布用 scripts/release.sh 从已提交 Git archive 构建，通过 ldflags 写入 version/commit/built。
运维升级仅使用可信本地 bundle，校验 manifest、版本与运行文件，保留原配置和 unit；失败自动回滚。
scripts/observe.py 被动采集最多72小时，指标为成功建连耗时分位数而非应用RTT；
采集上限/异常须显式标记，不得把监测启动当作72小时稳定验证已完成。
观察支持 --unit 对应具体 systemd 实例，所有采集使用相同 unit；活跃/完成表分开有界保留。setup/relay/half_close 与 auth 分别统计，proxy_failure_rate 只排除 auth，不等同真实用户失败率。journal_batches_limited、collection_errors、tracking_gaps 任一累计后 data_complete 永久为 false；finished 只表示计划时间结束，complete 还须覆盖完整。


## 认证限速与发布签名

证书部署脚本 scripts/sync_certificate.py 只使用 ACME 导出的快照，不直接读 account 凭据或执行签发。证书/私钥匹配、CA链、SNI域名及有效期通过后，以不可变配对目录发布并原子更新配置；与二进制升级共用 server 锁。prepared恢复旧配置，committed仅校验/清理，外部保护项变化则停止；通过 -capabilities 确认 sighup 能力的新 Unix 服务端采用热加载并检查 PID/实际叶证书；旧版保留受控重启，未变化不重启，不向旧二进制盲发 HUP。客户端须先迁移到系统CA+域名验证，不能在自动续期后继续固定旧叶证书指纹；SOCKS认证和其他配置保留。

监听与远端地址统一离线校验host:port及纯数字端口，监听允许通配host/port0，remote仍1..65535；不做DNS或bind探测。升级/回滚替换前须持久prepared intent，旧binary恢复副本预留在binary同一文件系统、旧state快照保留；state提交必须在事务回滚保护内，文件和目录均fsync。ENOSPC恢复优先rename预留文件，不得先建stage阻止无分配recover。committed只清理并验证/重启同一已提交版本，不得退版；prepared恢复旧binary/state并验证running hash/health。外部config/unit变化或校验失败保留intent且fail-safe。recover或upgrade/rollback的恢复阶段返回recovery_only，不继续第二次变更；status显示recovery_pending。set-id/filecap binary在停服务前拒绝，不悄悄丢元数据。测试覆盖写盘/目录fsync失败、各阶段子进程强制退出、恢复幂等和预检，保留签名/私有快照不变量。

认证错误按peer IP有界计数；只计真实凭据不匹配，不把超时/截断算密码错误。锁表上限必须明确采用fail-closed策略，日志不可包含凭据。凭据过渡最多保留一个到期时间明确的旧项，constant-time比较，过期后新建会话不得授权；不要改动旧AUTH wire format。发布bundle由Ed25519签名，升级先验证root本地信任公钥、签名、平台和哈希，再停服务；不信任bundle自带公钥。

previous_socks_auth 非空时必须有有效当前 SOCKS 凭据，漏主项配置必须 fail-closed，仍兼容显式无认证和旧字段。两端认证在完整读凭据后，用同一次 authlimit 原子操作完成当前许可判定及成功/失败更新，不能读前快照或让并发 Allow/Failure 分离绕过封禁。

bench CONNECT 根据字面量使用 IPv4/IPv6 ATYP，域名仍为 domain ATYP；IPv6 zone 无法在线上 SOCKS 地址表示，应明确拒绝，不能编码成含冒号的域名。测试应通过实际 SOCKS 请求解析、回声和半关闭验证 IPv6 目标，不能只比对构造字节。

SOCKS 凭据 provider 在方法选择和完整读取凭据后的实际比较前分别取值，过期旧项不能因等待握手被继续接受。DNS 重试的总预算在 Dial 入口固定，父 context、Dialer.Timeout、Dialer.Deadline 取最早期限；退避与所有尝试共享，DNSRetries 只计实际开始的重试。

升级和回滚须先将普通候选文件复制到 root 管理目录中的0700暂存目录，再验证副本哈希、执行和安装同一副本；拒绝 symlink/特殊文件及大于256MiB的文件，不能验证后执行原 bundle 路径。操作结束清理暂存；禁止更改配置、unit、信任公钥保护或实际运行哈希检查。

连接码 pin 保留 v1，ca 显式 v2 trust_mode，无指纹；旧版缺指纹及新版模式/指纹冲突必须 fail-closed。ca 导出验证系统链及公网主机名；客户端配置可显式 ca/pin，省略兼容推导。tls_session_cache 缺省关闭，不进入连接码；进程最多64项 LRU，按 remote/SNI/信任隔离；恢复握手仍验指纹或 CA 链/域名/有效期，不启用应用0-RTT、不省 AUTH。tls_resumed 布尔 JSON/text resumed，pool hit 前台无新握手，后台 DEBUG pool prepared 单独记录。服务端热加载仅替换证书快照，拒绝其他已识别配置变化，坏证书保留旧快照；新快照票据密钥独立并保留 Go 自动轮换，旧连接排空/半关闭语义不变。
