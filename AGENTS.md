# AGENTS.md

本文件适用于仓库根目录及其所有子目录，用于指导在本项目中工作的自动化代理。若用户的明确要求与本文冲突，以用户要求为准；更深层目录中的 `AGENTS.md` 可为其作用域补充或覆盖规则。

## 项目概览

MyGoTunnel 是一个小型 Go TCP 隧道项目，模块名为 `mygotunnel`，`go.mod` 声明 Go 1.24。

数据链路如下：

```text
SOCKS5 应用
    -> cmd/client（本地 SOCKS5 入口）
    -> internal/utlsconn（uTLS 客户端连接）
    -> cmd/server（标准 TLS 服务端）
    -> 目标 TCP 服务
```

客户端和服务端在 TLS 连接内使用简单的逐行文本控制协议；认证及建连成功后，连接切换为透明的双向字节转发。

## 目录职责

- `cmd/client`：加载客户端配置、接受本地 SOCKS5 连接、建立远端 uTLS 连接并组织隧道流程。
- `cmd/server`：加载服务端配置和证书、校验认证信息、连接目标地址并组织转发。
- `internal/config`：客户端和服务端 JSON 配置结构、默认值及必填项校验。
- `internal/logging`：基于 `log/slog` 的紧凑英文文本、结构化 JSON、连接 ID、失败分类与周期资源汇总。
- `internal/socks5`：SOCKS5 可选用户名密码握手、仅支持 TCP `CONNECT` 的请求解析和响应。
- `internal/tunnel`：`AUTH`、`CONNECT`、`OK`、`ERR` 控制消息的读写。
- `internal/utlsconn`：使用 Chrome ClientHello 指纹建立 uTLS 客户端连接。
- `internal/relay`：保留缓冲数据并执行带半关闭语义的双向复制。
- `configs`：本地 JSON 配置；实际配置被 `.gitignore` 忽略。
- `certs`：本地 PEM 证书和私钥；实际证书文件被 `.gitignore` 忽略。

## 协议与行为不变量

修改网络流程前，先完整跟踪客户端和服务端两侧。当前控制协议顺序为：

1. 客户端一次写入 `AUTH <token>\nCONNECT <host:port>\n`；兼容旧客户端分两次发送。
2. 服务端认证后返回 `OK\n` 或 `ERR\n`；失败时不得拨号目标。
3. 客户端按顺序读取认证和 CONNECT 两条响应，服务端认证成功后读取 CONNECT。
4. 服务端完成目标连接后返回 `OK\n`，失败时返回 `ERR\n`。
5. 成功后双方不再解析行协议，直接转发原始字节流。

必须保持以下行为：

- 改动控制消息、响应含义或握手顺序时，同步修改客户端、服务端及相关测试；不要只改单侧。
- 从控制协议切换到转发时，继续使用既有的 `bufio.Reader`。其中可能已经预读了应用数据，改回直接读取底层连接会丢数据。
- 服务端认证比较使用常量时间比较；不要记录、回显或以普通字符串比较替代认证令牌。
- 认证读取的 deadline 必须在结束后清除，避免影响后续连接阶段。
- SOCKS5 当前支持版本 5、可选 RFC 1929 用户名密码认证和 TCP `CONNECT`，地址支持 IPv4、域名及 IPv6。不要在未同步协议、响应和测试的情况下宣称支持 UDP 或其他认证方式。
- uTLS 客户端使用固定 `HelloChrome_133` 基线并适配 ALPN，客户端与服务端均协商 `http/1.1` ALPN。相关值属于连接兼容性的一部分。
- 有导入指纹时，`InsecureSkipVerify` 仅用于替代公共 CA 验证，必须同时通过 `VerifyPeerCertificate` 校验固定证书指纹；没有指纹时使用系统 CA 和主机名验证。修改时同步说明证书信任、SNI 和部署迁移。
- 预连接协议是 AUTH → OK → PREPARE → READY → CONNECT → OK；原有普通流程继续兼容。备用连接有独立数量/闲置限制，取用后不得回池；后台读取必须在交接前停止。
- `-max-connections` 限制接受连接总数；备用等待时释放 setup permit，CONNECT 前必须重新申请。
- `-max-setup` 限制正在建连的请求，成功进入转发前释放，失败返回也必须释放；不要让长连接占用建连额度。
- 保留 `relay.CopyBidirectional` 的半关闭语义：正常 EOF 后等待反向数据排空；复制或半关闭失败时解除另一方向的阻塞，并在两个复制 goroutine 都退出后返回。修改转发退出策略时要考虑一侧 EOF、仍在返回的数据、阻塞 goroutine、字节统计和连接释放。

## 配置约定

客户端实际读取的字段只有：

- `local_addr`：可选，默认 `127.0.0.1:1080`。
- `socks_auth`：可选，包含本地 SOCKS5 的 `username` 和 `password`；启用后禁止免认证降级，凭据不进入连接码。
- `remote_addr`：必填，远端服务端的 `host:port`。
- `auth_token`：必填。
- `sni`：可选；为空时从 `remote_addr` 推导主机名。
- `certificate_fingerprint`：可选，服务端叶证书 DER 的 SHA-256 十六进制指纹；存在时使用固定指纹验证，否则使用系统 CA 和主机名验证。

服务端实际读取的字段只有：

- `listen_addr`：可选，默认 `:9001`。
- `auth_token`：必填，必须与客户端一致。
- `cert_file`：可选，默认 `certs/cert.pem`。
- `key_file`：可选，默认 `certs/key.pem`。

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

- 默认 text 必须紧凑英文，不重复 time=/level=/msg=/component=；使用 UTC 完整日期时间 `YYYY-MM-DD HH:MM:SS.mmm`，启动输出 timezone=UTC，C/S 区分两端。JSON 继续使用标准字段和现有长字段名，Duration 为纳秒整数，字节数为原始整数；时间统一 UTC。事件名使用 listening/ready/closed/failed/stats 等短英文。
- 目标域名/IP:端口和 peer 保留；不解密 HTTPS、不记录 URL 路径、token、私钥、连接码或原始控制报文。文本属性中的控制字符必须转义，写入一次完整记录，并在 With/WithGroup 派生处理器间共享写锁。
- connection_id/id 只在进程内关联，包含进程前缀和原子递增编号。本轮不改变协议，不宣称两端 ID 一致。
- 上传/下载统一以 SOCKS5 应用为参照：↑/upload_bytes 向目标，↓/download_bytes 回到应用；保留 relay 的根失败方向 up/down，不被故意中断的反向超时覆盖。
- text 阶段短名为 socks/tcp/tls/take/ctl/auth/wait/dial/reply/idle/total，展示毫秒，最多 3 位小数。JSON 长字段定义见 README。服务端 total 排除 idle，但仍包含准备阶段 auth；连接生命周期 duration/dur 包含 idle。已预热池命中时 text 可省略零值 tcp/tls，JSON 保留。
- failed 必须包含 stage 与 close_reason/reason；常见系统错误完整链进入 DEBUG，未知错误在 WARN 保留诊断信息。只有真正正常 EOF 才作为 INFO closed，不能把所有 reset/timeout 静默吞掉。
- 资源状态每 30 秒一条 stats，active 统计 accepted 总数，setup 统计 permit 占用，idle 统计备用，rejected 是准入拒绝累计；计数使用原子操作，Permit Release/TryAcquire 同步更新，监听流程退出时停止并等待定时器。不要用日志计数改变任何连接、认证、超时、重试或半关闭行为。
- 修改日志需覆盖毫秒与时区、短字段、英文事件、双向字节、ID 关联、根失败方向、分组属性、并发写入、错误详略、资源计数与定时器停止，并同步 README 和本文件。

## TLS 握手配置

客户端使用 uTLS `HelloChrome_133` 基线，每条连接独立生成模板；实际 ALPN 仅提供 `http/1.1`，移除模板中仅适用于 h2 的 ALPS 扩展。此前 `HelloChrome_Auto` 在当前依赖版本也对应 Chrome 133，但模板自带的 h2/ALPS 不会仅因 Config.NextProtos 而移除。此修改验证实际线上 ClientHello，避免服务端选择客户端未实现的 h2。调整后的模板不是完整 Chrome 指纹，也不宣称模拟当前最新 Chrome。

服务端继续使用 Go 标准 TLS，明确最低 TLS 1.2，TLS 1.2 仅允许 ECDHE + AES-GCM/ChaCha20-Poly1305；TLS 1.3 密码套件及密钥交换保留 Go 默认配置。此为一致性与安全整改，不是 nginx/OpenSSL 服务端指纹模仿。自定义 AUTH/CONNECT 仍不是 HTTP，即使协商 http/1.1 也不表示支持网页。TCP、预连接、半关闭及证书指纹验证保持原有机制；不引入 WSS，不增加握手往返。旧客户端仍可连接新服务端，TLS 1.0/1.1 和仅支持旧 TLS 1.2 套件的外部客户端不再支持。

## 自适应预连接与拨号测量

客户端 `-pool-size 4 -pool-max 16`：size 是备用容量下限，max 是自适应上限（均不含已经转发的连接）。当请求取用时就绪数不超过 1，目标容量增加 1，最多达到 max；取用、失效立即触发补充。连续 30 秒无取用后，每 30 秒目标容量减 1，最低回到 size。已有多余空闲连接自然到期释放，不中断正在使用的连接。此为需求耗尽驱动的保守自适应，不是基于 QPS/补充时长的预测算法。后台补充与 ready 总量受目标限制；收缩后已经启动的补充可能短暂超过新目标，但不超过 max。`-pool-max 0` 或等于 size 使用固定容量；`-pool-size 0` 禁用池。非零 max 必须不小于 size，最大 32；例如 size=32 时须同时指定 max=32。服务端 `-max-idle` 为所有客户端共享，扩容仍可能被 BUSY 拒绝，沿用有界退避。

每 30 秒 stats 新增：JSON `pool_hits/pool_misses/pool_fallbacks/pool_hit_rate/pool_target/pool_filling`，文本 `hit/miss/fallbacks/hit_pct/pool_target/filling`。hit/miss 统计启动以来的 Take 调用结果；命中指有效备用连接成功交接，不代表目标拨号成功；命中后传输错误转普通建连时同时增加 fallback。百分比为 100*hit/(hit+miss)，无请求为 0；禁用池时这些计数为 0，不将普通连接计为 miss。计数快照加锁，不改变流量和重试语义。

服务端 ready 与拨号失败日志增加 `dns_duration`（text: dns）及 `target_tcp_duration`（text: target_tcp），原 `target_dial_duration`（dial）继续表示 DNS+TCP 总拨号墙钟耗时。通过标准库 httptrace 的网络事件观察 net.Dialer，不自行解析再顺序拨 IP，保留标准解析器、IPv4/IPv6 并行回退及原 deadline。IP 字面量 dns=0；TCP 从首次地址尝试到拨号返回，包含双栈回退等待，不能把并发尝试分别相加。DNS 时间包含系统解析器处理，不能当作纯公网 DNS RTT；两个子阶段之和与总耗时可有调度开销差异。不引入 DNS 缓存或修改双栈策略。

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
