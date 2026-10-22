# 2026-10-22 稳定性修复与受控对照

分支：`feat/alpha-utls-connection-code`；修复前基线：`f2cdc84df3b39bdee58252226d5fd748b70a264c`。
在 Linux ARM64 本机运行本地 TCP/TLS、net.Pipe、故障注入和内存基准，不依赖公网节点。正式服务没有替换；以下结果不代表双机公网 RTT、带宽或长期 P95/P99。

## 五项修复

| 问题 | 修复与回归验证 |
| --- | --- |
| 半关闭后 shutdown 卡住 | admission 独立强制退出 context 只在 grace 耗尽时触发；同时关闭 relay 两端底层连接并等待两个复制任务。客户端与真实 uTLS→TLS→TCP 服务端覆盖上传 FIN 后反向阻塞；grace 内回复仍完整排空。admission/relay/pool 完整 race 重复3次，服务端 drain/force 集成 race 重复10次。 |
| 过期 UDP pending 占满进程缓冲 | 每关联一个最早到期 timer 主动清理 pending 和响应队列，不依赖新帧到达。262144字节预算、三个慢 DNS 的测试中，过期帧在 DNS 仍阻塞时归还，活跃缓冲从262144回到65536字节；健康目标继续回包，未出现内存拒绝。缓存仍计入预算，归还不等于 RSS 立即下降。 |
| UDP setup 忽略应用断开 | 单个控制 reader 从来源解析持续到关联结束；FIN/RST/关闭均取消 setup。来源 DNS、TLS、AUTH、UDP 响应等待四阶段分别覆盖断开。旧版 close/FIN 共8用例等待1秒仍未结束；新版12用例（含RST）及时退出，socket/resident 全归还；建立后的控制 FIN 也结束关联。 |
| 收缩跳过最后备用的续建 | 默认 adaptive 与可选 idle 策略都保留一条新鲜备用；其他 surplus 不无谓续建。150ms准备、旧连接400/440ms到期的受控测试跨越旧到期窗口仍有就绪备用，只续建一条，并验证容量/交接所有权。未使用TLS连接直接关闭底层，避免 close_notify 等待。 |
| 升级事务与配置预检不完整 | intent 在替换前持久化；旧 binary/state 提前预留，state 提交也在回滚保护内，文件与目录均 fsync。磁盘满、替换/重启/提交各阶段子进程退出均可恢复，已提交版本不误退；外部配置/unit变动时保留事务并停止。地址校验拒绝70000等非法端口，加载配置时监听port0保留，初始化非法配置不产生凭据文件。 |

## 三项优化对照

| 场景 | 修复前 | 修复后 |
| --- | --- | --- |
| 大流600个回包后，另一目标发一个交互回包，隧道暂不读取 | 同一正向用例重复3次，交互回包都被满FIFO拒绝 | 重复3次均送达，第34帧出现：已有最多32帧不可抢占批次，再进入下一轮公平调度。总队列仍256包，字节/年龄上限不变。 |
| 同一失败目标20包、约1ms节奏 | 20次目标dial调用 | 1次dial，19包在短退避中丢弃；随后重试与同关联恢复通过。这里统计dial调用，不等于真实DNS网络包数。退避100/200/400/800/1000ms，成功回包清历史，失败记录最多256条。 |
| 较旧备用静默、较新备用健康 | 同一协议回归先选旧备用，150ms测试预算耗尽；默认ACK预算的独立旧版复现等待约2秒 | 先用新备用完成ACK/OK，150ms预算内成功；旧备用仍受自身ACK期限保护。net.Pipe时延不用于推算公网节省。 |

退避另覆盖旧 worker 迟到成功/失败不能改写新代记录，以及同代首次回包与写失败的并发。公平队列覆盖 packet/byte/进程缓冲压力、并发所有权、空 flow/heap 回收，以及不能抢占其他关联的缓冲。

## 分配与调度成本

同机 A/B/B/A、`GOMAXPROCS=3`，仅改变每尺寸缓存上限16/64；使用相同基准，1400字节、每轮同时借用并归还64包：

| 缓存上限 | ns/轮 | B/轮 | allocs/轮 |
| --- | --- | --- | --- |
| 16 | 26936～27658 | 100608 | 96 |
| 64 | 3210～3226 | 0 | 0 |

2048字节尺寸类多缓存48块最多增加96KiB缓存，仍全计入进程预算，压力下可驱逐；其他尺寸类同样受总预算限制。采用64缓存时，单独比较FIFO与公平调度，32包批次的公平调度额外成本约单流1.2µs、四流2µs；公平性并非零CPU成本。这些是内存/调度微基准，不是网络吞吐。

## 完整检查

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
GOOS=linux GOARCH=amd64 go build ./cmd/...
python3 -B -m unittest scripts/test_operations.py
git diff --check
```

Go全量测试、race、vet及Linux ARM64原生/AMD64交叉构建通过。Python共33项；主验环境32通过、1项真实file-capability测试因权限跳过，独立无特权模拟已验证拒绝逻辑，set-id已实测。并行验证环境33项全部通过（含真实capability保留验证）。事务测试使用临时文件和模拟systemd，子进程直接退出模拟控制器中断，未对正式服务做故障注入或物理断电实验。

可重复运行的专项及微基准：

```sh
go test -race ./cmd/client -run 'TestUDPSetupControlDisconnectCancelsEveryStage|TestUDPAssociationControlFINStopsEstablishedSession|TestHandleClientForceAbortAfterUploadFIN|TestPreparedFreshChannelAvoidsSilentOlderACKWait' -count=3
go test -race ./cmd/server -run 'TestUDPActiveExpiry|TestUDPFairResponses|TestUDPRetry|TestServerHalfClosedRelay' -count=3
go test -race ./internal/datagram ./internal/preconnect ./internal/admission ./internal/relay -count=3
go test ./internal/datagram -run '^$' -bench 'Benchmark(PoolBurst64|FairQueueNoisyInteractive|FairQueueSteadyBatch32)' -benchmem -benchtime=300ms
```

缓存16/64的对照需在独立源码副本中修改 `cachePerClass`，运行相同基准后丢弃该副本；不要为复现修改正式部署。协议、证书验证、SOCKS认证、strict/nat来源约束及进程资源上限保持原约定。
