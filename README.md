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

两个程序新增 `-max-setup` 参数，默认 128，必须为正数。它限制同时进行 SOCKS5 协商、TLS 握手、认证和目标拨号的建连请求；进入转发后立即释放额度，错误或超时也会释放。超过限制的新连接立即关闭，不创建无限队列；超限事件只记录 debug 日志。此项不是已建立隧道总数限制。不可恢复的 Accept 错误使程序退出，临时错误采用最长 1 秒退避。

客户端成功建连日志包含 `socks_duration`、`tcp_duration`（包括远端域名解析）、`tls_duration`、`control_duration`（包含服务端目标建连等待）及 `setup_duration`。服务端记录 `auth_duration`（包括 TLS 握手）、`target_dial_duration`（包括目标域名解析）、`connect_duration` 和 `setup_duration`。日志不包含令牌或控制报文。没有启用 TLS 会话恢复，指纹验证和半关闭语义保持原有行为。

## 预连接池

客户端默认 `-pool-size 4`，范围 0～32；设为 0 使用原来的 TCP/TLS + AUTH/CONNECT 流水建连。后台完成 TLS 和 AUTH 后发送 PREPARE，服务端回复 READY，连接只用于一次后续 CONNECT；不会复用已转发过数据的连接，也没有多路复用。备用连接用完就补充，池为空时立即走普通建连，不等待补充。

备用连接最长闲置 45 秒，后台被动读取以发现 EOF/失效，取用前停止后台读取并交接同一个缓冲读取器。失败按 0.5～30 秒指数退避并增加随机抖动；不支持 PREPARE 的旧服务端可正常走普通流程，后台以较长退避周期重新探测。仅在未发送任何应用负载的备用连接发生传输错误时，允许一次普通建连回退；明确的目标拨号失败不自动重试。请求总建连期限保持有界。

服务端 `-max-idle 64` 限制全服务的已认证备用连接，0 禁用 PREPARE；备用连接最长等待 CONNECT 60 秒，超时释放。闲置期间释放建连名额，收到 CONNECT 后重新申请，防止无限目标拨号；备用容量满返回 BUSY。未认证连接仍受 5 秒期限约束，普通 CONNECT 阶段仍为 20 秒。

两端新增 `-max-connections 1024`，必须为正数，限制接受的连接总数（服务端包括备用和转发连接）；它独立于 `-max-setup`。客户端后台备用连接另由 pool-size 约束。以上都是命令行参数，没有新增 JSON 字段。

客户端日志的 `pool_hit` 表示使用了有效备用连接，`pool_fallback` 表示备用传输失败后普通建连回退，`pool_acquire_duration` 记录取用耗时。命中时 TCP/TLS 阶段为零，表示它们已经在后台完成，不表示没有消耗 CPU 或网络。服务端 `pool_connection` 表示此连接通过 PREPARE 进入。 此时服务端 `setup_duration` 包含备用等待时间；用 `connect_duration` 查看取用后的目标建连阶段，不要直接与客户端前台 `setup_duration` 比较。

新客户端兼容旧服务端；旧客户端也兼容新服务端。首次启动、池未填满、突发请求超出池大小以及网络故障时，仍可能进行完整握手；预连接主要将工作提前，并不保证所有请求都有固定耗时。
