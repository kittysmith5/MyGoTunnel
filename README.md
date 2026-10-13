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
| socks | socks_duration | 客户端本地 SOCKS5 阶段 |
| tcp | tcp_duration | 连接服务端，包含域名解析 |
| tls | tls_duration | 客户端 TLS 握手 |
| take | pool_acquire_duration | 取用备用连接 |
| ctl | control_duration | 认证/CONNECT 交互，包含等待服务端拨号；回退时包含两次控制尝试 |
| auth | auth_duration | 服务端认证，包含 TLS 握手；备用连接中此阶段在后台完成 |
| wait | wait_duration | 服务端 CONNECT 命令读取和准备阶段，不包含备用闲置 |
| dial | target_dial_duration | 服务端目标拨号，包含目标域名解析 |
| reply | reply_duration | 服务端成功响应及清理控制期限 |
| idle | idle_duration | 服务端已认证备用连接的等待时间，单独列出 |
| total | setup_duration | 客户端前台总建连时间；服务端建连活动时间，排除 idle，仍包含先前的 auth |

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
- 客户端连接远端 TCP/uTLS 保持 15 秒总超时；随后 AUTH 和 CONNECT 交互共用 20 秒读写期限。
- 本地 SOCKS5 建连响应另受 40 秒期限约束，覆盖远端拨号、控制交互和响应写入。
- 服务端 TLS 握手、AUTH 读取和认证响应写入共用 5 秒读写期限；认证后 CONNECT 读取、目标拨号和响应写入共用 20 秒期限。目标拨号仍为 10 秒超时。
- 建连成功后，客户端和服务端清除控制阶段的读写期限，不限制应用数据转发时长。
- AUTH、CONNECT 和响应的每行控制报文最多 4096 字节，包含换行；超限立即失败。发送值和接收报文拒绝内嵌控制字符，兼容行尾 CRLF。
- SOCKS5 仅接受客户端提供的无认证方法，否则返回 05 FF 并关闭连接。不支持的命令返回 REP=07，不支持的地址类型或非法域名返回 REP=08；RSV 必须为零，目标端口不能为零。

上述超时为代码默认值，当前没有新增 JSON 配置项。AUTH/CONNECT 的顺序与成功响应保持兼容。

## 建连性能与并发控制

客户端将 AUTH 和 CONNECT 两行在一次 TLS 写入中发送，仍按顺序读取两条响应。服务端先认证，认证成功后才拨号；错误认证不会连接目标。优化客户端可连接原有服务端，原有客户端也可连接新服务端。不会提前发送应用负载。

两个程序新增 `-max-setup` 参数，默认 128，必须为正数。它限制同时进行 SOCKS5 协商、TLS 握手、认证和目标拨号的建连请求；进入转发后立即释放额度，错误或超时也会释放。超过限制的新连接立即关闭，不创建无限队列；超限次数进入每 30 秒的 stats 汇总，不逐条刷日志。此项不是已建立隧道总数限制。不可恢复的 Accept 错误使程序退出，临时错误采用最长 1 秒退避。

客户端成功建连日志包含 `socks_duration`、`tcp_duration`（包括远端域名解析）、`tls_duration`、`control_duration`（包含服务端目标建连等待）及 `setup_duration`。服务端记录 `auth_duration`（包括 TLS 握手）、`target_dial_duration`（包括目标域名解析）、`connect_duration` 和 `setup_duration`。日志不包含令牌或控制报文。没有启用 TLS 会话恢复，指纹验证和半关闭语义保持原有行为。

## 预连接池

客户端默认 `-pool-size 4`，范围 0～32；设为 0 使用原来的 TCP/TLS + AUTH/CONNECT 流水建连。后台完成 TLS 和 AUTH 后发送 PREPARE，服务端回复 READY，连接只用于一次后续 CONNECT；不会复用已转发过数据的连接，也没有多路复用。备用连接用完就补充，池为空时立即走普通建连，不等待补充。

备用连接最长闲置 45 秒，后台被动读取以发现 EOF/失效，取用前停止后台读取并交接同一个缓冲读取器。失败按 0.5～30 秒指数退避并增加随机抖动；不支持 PREPARE 的旧服务端可正常走普通流程，后台以较长退避周期重新探测。仅在未发送任何应用负载的备用连接发生传输错误时，允许一次普通建连回退；明确的目标拨号失败不自动重试。请求总建连期限保持有界。

服务端 `-max-idle 64` 限制全服务的已认证备用连接，0 禁用 PREPARE；备用连接最长等待 CONNECT 60 秒，超时释放。闲置期间释放建连名额，收到 CONNECT 后重新申请，防止无限目标拨号；备用容量满返回 BUSY。未认证连接仍受 5 秒期限约束，普通 CONNECT 阶段仍为 20 秒。

两端新增 `-max-connections 1024`，必须为正数，限制接受的连接总数（服务端包括备用和转发连接）；它独立于 `-max-setup`。客户端后台备用连接另由 pool-size 约束。以上都是命令行参数，没有新增 JSON 字段。

客户端日志的 `pool_hit` 表示使用了有效备用连接，`pool_fallback` 表示备用传输失败后普通建连回退，`pool_acquire_duration` 记录取用耗时。命中时 TCP/TLS 阶段为零，表示它们已经在后台完成，不表示没有消耗 CPU 或网络。服务端 `pool_connection` 表示此连接通过 PREPARE 进入。 服务端 `setup_duration` 已排除备用等待时间，单独记录为 `idle_duration`；其中认证仍是在备用阶段完成的。`connect_duration` 仅表示当前 CONNECT 阶段，不应直接与客户端总时间比较。

新客户端兼容旧服务端；旧客户端也兼容新服务端。首次启动、池未填满、突发请求超出池大小以及网络故障时，仍可能进行完整握手；预连接主要将工作提前，并不保证所有请求都有固定耗时。
