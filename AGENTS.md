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
- `internal/logging`：基于标准库 `log/slog` 创建统一的分级、结构化日志记录器。
- `internal/socks5`：SOCKS5 无认证握手、仅支持 TCP `CONNECT` 的请求解析和响应。
- `internal/tunnel`：`AUTH`、`CONNECT`、`OK`、`ERR` 控制消息的读写。
- `internal/utlsconn`：使用 Chrome ClientHello 指纹建立 uTLS 客户端连接。
- `internal/relay`：保留缓冲数据并执行带半关闭语义的双向复制。
- `configs`：本地 JSON 配置；实际配置被 `.gitignore` 忽略。
- `certs`：本地 PEM 证书和私钥；实际证书文件被 `.gitignore` 忽略。

## 协议与行为不变量

修改网络流程前，先完整跟踪客户端和服务端两侧。当前控制协议顺序为：

1. 客户端发送 `AUTH <token>\n`。
2. 服务端返回 `OK\n` 或 `ERR\n`。
3. 客户端发送 `CONNECT <host:port>\n`。
4. 服务端完成目标连接后返回 `OK\n`，失败时返回 `ERR\n`。
5. 成功后双方不再解析行协议，直接转发原始字节流。

必须保持以下行为：

- 改动控制消息、响应含义或握手顺序时，同步修改客户端、服务端及相关测试；不要只改单侧。
- 从控制协议切换到转发时，继续使用既有的 `bufio.Reader`。其中可能已经预读了应用数据，改回直接读取底层连接会丢数据。
- 服务端认证比较使用常量时间比较；不要记录、回显或以普通字符串比较替代认证令牌。
- 认证读取的 deadline 必须在结束后清除，避免影响后续连接阶段。
- SOCKS5 当前仅支持版本 5、无认证方式和 TCP `CONNECT`，地址支持 IPv4、域名及 IPv6。不要在未同步协议、响应和测试的情况下宣称支持 UDP 或其他认证方式。
- uTLS 客户端使用 `HelloChrome_Auto`，客户端与服务端均协商 `http/1.1` ALPN。相关值属于连接兼容性的一部分。
- `InsecureSkipVerify` 是当前实现的一部分，也是明确的安全敏感点。除非任务要求，不要顺手改变；若改变，需同时说明证书信任、SNI 和部署配置的迁移方式。
- 保留 `relay.CopyBidirectional` 的半关闭语义：正常 EOF 后等待反向数据排空；复制或半关闭失败时解除另一方向的阻塞，并在两个复制 goroutine 都退出后返回。修改转发退出策略时要考虑一侧 EOF、仍在返回的数据、阻塞 goroutine、字节统计和连接释放。

## 配置约定

客户端实际读取的字段只有：

- `local_addr`：可选，默认 `127.0.0.1:1080`。
- `remote_addr`：必填，远端服务端的 `host:port`。
- `auth_token`：必填。
- `sni`：可选；为空时从 `remote_addr` 推导主机名。

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

# 运行全部测试；当前尚无 *_test.go，因此这同时是全包编译检查
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
