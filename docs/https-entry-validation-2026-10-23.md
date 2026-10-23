# HTTPS 入口实现验证

分支：`feat/alpha-utls-connection-code`；修改基线：`ee976148582bdedfe7bd14258c4e331088bbd0f5`。Linux ARM64、Go 1.27.0，2026-10-23。本报告记录提交前验证；尚未部署，未改线上配置、证书、SOCKS 认证或服务。

## 已实现

- 可选同端口 HTTPS 回退；认证判定不写拒绝响应，失败时原样回放前缀与原 Reader，由标准 HTTP 服务器处理。成功 AUTH/CONNECT、PREPARE/ACK、UDP wire 保持兼容。
- 本地静态首页、GET/HEAD/404/405、有界 keep-alive 与 body 清理；关闭标准库 OPTIONS `*` 特殊旁路，确保它同样经过请求计数、setup 释放和方法规则。
- 握手前的单 IP 并发/速率保护、有界状态表、独立 HTTP 容量；全局连接与 setup 名额继续覆盖入口连接，所有交接与释放有明确所有者。
- TLS、认证、分类、首个 HTTP 请求头共享 5 秒期限；HTTP 适配层不能延长此期限。正确认证后解除原期限；原 Reader 继续承载预读命令及业务数据。
- 配置默认关闭；检查非法限额、公开 HTML 大小/类型/符号链接并在启动时载入快照。新增入口 stats 自动进入观察器资源字段，不混入代理失败率或成功 setup 分位数。

## 功能与故障验证

使用独立回环监听、临时测试证书与测试 token，不探测生产错误认证或耗尽生产资源。

| 项目 | 已验证结果 |
| --- | --- |
| 真实 TLS/uTLS | TLS 1.2/1.3、h1/无 ALPN、不同 SNI 的站点行为正常；仅 h2 握手失败；真实 uTLS 校验证书 pin 后接入 |
| TCP 兼容 | 普通连接、legacy PREPARE 和 ACK PREPARE 都能连接目标；AUTH+CONNECT+应用数据单次写入不丢字节；上传 FIN 后反向响应完整排空 |
| UDP 兼容 | 普通连接及两种预连接均正确回包；UDP 命令与首帧一起写入，Reader 预读交接完整 |
| 公开 HTTP | GET/HEAD、404、405、OPTIONS `*`、HEAD 无 body、8 次 keep-alive 上限；超长请求头 431、冲突 Content-Length 400 |
| 认证拒绝 | 网页访问不消耗密码额度；错误凭据触发原封禁，封禁中的正确 token 不能接入；HTTP 拒绝不会触发 ACK 兼容降级 |
| 输入与回放 | 非 AUTH、前导空格、Unicode 空格、CRLF、嵌入控制字符、4096 边界及长 HTTP 行原样回放；非法 AUTH 拼接 CONNECT/正确 AUTH/UDP 均不拨号 |
| 有界读取 | 失败 AUTH 转入 HTTP、半条 HTTP 请求头和半条 AUTH 都不能重启入口 5 秒；不读取 OK 的客户端也受原期限约束 |
| body 与关闭 | 大 Content-Length 且不发 body 时仍及时完成响应/退出；不提前发送 100 Continue；HTTP 半请求退出及 keep-alive 关闭无阻塞 |
| 准入公平性 | 同源静默连接达到单 IP 上限后拒绝，仍只占一个指定 setup；另一回环源可完成 TLS；速率补充、表满 fail-closed、活跃项不被回收、并发幂等释放通过 |
| HTTP 容量 | HTTP 满额仍允许正确 AUTH 进入原隧道；HTTP 空闲连接不占 setup；连接结束后 HTTP、认证前、setup 和总连接计数归零 |
| 日志与观察 | 不出现测试 token、原始 HTTP Host 或拒绝报文；公开失败不生成代理 failed/ready；text/JSON stats 不污染代理失败率和延迟样本 |

完整 Go 测试与 race 通过；最终 HTTP/准入改动再对受影响场景做 3 次 race 回归。没有引入新第三方依赖。

```sh
go test ./... -count=1 -timeout=120s
go test -race ./... -count=1 -timeout=150s
go test -race ./internal/ingress ./cmd/server ./internal/admission -run 'TestHTTP|TestClassification|TestFallback|TestGuard|TestBlockedAuth|TestServe|TestPermit|TestResourceCounters|TestGraceful' -count=3 -timeout=60s
go vet ./...
go build ./cmd/...
GOOS=linux GOARCH=amd64 go build ./cmd/...
python3 -B -m unittest scripts/test_operations.py
git diff --check
```

Python 共34项，33通过、1项真实 file-capability 测试因环境不能设置该属性而跳过；无特权拒绝逻辑仍有现有模拟覆盖。ARM64 原生与 Linux AMD64 交叉构建通过。Go 1.24 未安装，本轮未单独在其标准库上运行；本轮没有提高 go.mod 的 Go 版本或使用仅 Go 1.27 提供的接口。

## 本地时延与分配对照

其他 Go 测试和 race 完成后串行执行 A/B/B/A，每轮1000次。两边使用相同真实 uTLS 客户端、Go TLS 服务端、证书及回环 TCP 目标，仅切换 HTTPS 入口；每轮全部 setup 成功。测试显式提高连接速率额度以测处理成本，不代表默认限速下的高 QPS 容量。

| 轮次 | 入口 | 平均总耗时 ns/op | setup P50 ms | P95 ms | P99 ms | B/op | allocs/op |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | 原入口 | 6511617 | 6.425 | 6.945 | 7.192 | 224277 | 1189 |
| B1 | HTTPS 回退启用 | 6533758 | 6.446 | 6.967 | 7.184 | 224676 | 1201 |
| B2 | HTTPS 回退启用 | 6555315 | 6.461 | 7.021 | 7.425 | 224480 | 1201 |
| A2 | 原入口 | 6555021 | 6.442 | 7.004 | 7.634 | 224370 | 1189 |

两轮 P95 的均值约 6.975ms 对 6.994ms，差约 0.020ms；平均耗时差约 0.17%，本机样本未见明显时延回归。B/op 均值增加约255字节、allocs/op 增加12；统计包括同进程客户端、服务端及异步回收，不是孤立的服务端分配。实现中已移除重复 4KiB Reader 分配；分类借用原 Reader 前缀，回放先消费此前缀再继续读取，成功路径不额外复制 AUTH 原始行。

成功路径没有新增应用层握手往返。以上是本机冷建连处理成本，不代表公网 RTT/P95、吞吐、抗识别能力或长期稳定性；没有据此声称性能提升。

复现：

```sh
for entry_case in legacy https https legacy; do
  go test ./cmd/server -run '^$' -bench "^BenchmarkHTTPSEntryColdSetup/${entry_case}$" -benchtime=1000x -count=1 || exit 1
done
```

## 尚未验证及部署边界

本轮未执行双机公网对照、完整 TCP 大流/UDP 多目标混合压力矩阵、长时间共享 NAT 负载、浏览器大样本/DPI 分类或长期稳定观察。默认配额仍需结合合法突发校准。现有 TLS/证书及认证后自定义隧道的可观察边界保留，不把 HTTPS 回退描述为完整 HTTP 承载。

启用前需构建包含本轮源码的版本并确认启动 `https_entry=true`。旧二进制忽略未知字段，仅写配置不能生效；线上切换和证书身份迁移不在本次操作中。
