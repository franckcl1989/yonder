# 需求追踪矩阵

| ID | 当前产品需求 | 责任边界 | 协议/状态 | 必须产生的证据 |
| --- | --- | --- | --- | --- |
| R-001 | `yon` 同时提供 host/connect，`yon-relay` 独立 | workspace、Clap binaries | product CLI | CLI unit + 真进程 E2E + 六 target 两产物 |
| R-002 | 单二进制跨 macOS/Linux/Windows | release workflow | 无 | 链接检查、空目录 smoke、单文件归档、checksum、SBOM/provenance |
| R-003 | 第一方全 safe Rust | workspace lints | 无 | `unsafe_code=forbid`、源码扫描、Miri/sanitizer |
| R-004 | 不造网络/密码/PTY/CLI/限速轮子 | dependency adapters | 全部协议 | 依赖锁、trait 边界测试、依赖审计 |
| R-005 | 三角色复用统一 libp2p 基础栈 | `yonder-net` transport builder | endpoint Identify/DCUtR/UPnP/relay client；relay AutoNAT/relay server | behaviour 组合 unit + 三角色互操作 E2E |
| R-006 | QUIC/TCP/WS/WSS 自适应 | path candidate actor | 路径选择状态 | transport E2E、阻断/降级 namespace 测试 |
| R-007 | 可用直连优先、同类质量排序并自动 relay | controller-only `QualityPathPolicy` + 单次 Swarm 重建 fallback | relay 10s；无候选 30s；DCUtR 最长 3s；1.5s 最小采样；晚到直连 750ms；host 跟随唯一连接 | 直连不被低 RTT relay 覆盖回归、最终 Direct/Relayed+transport 真实断言、10 轮直连稳定性、故障入口与真实 relay-only E2E、分阶段时延、benchmark |
| R-008 | 子流绑定唯一物理连接 | roster + `ApplicationStreams` | 唯一连接屏障 | 双连接可行性回归、迟到连接全状态测试 |
| R-009 | 专业短连接码且 relay 不知 secret | `ConnectionCode`/`Locator`/`PakeSecret` | 20+60 bit Crockford | golden/property/fuzz、日志脱敏测试 |
| R-010 | 一次性认证、失败不消费 | target session actor | Advertised..Spent | 全转换 unit/property、断点 E2E |
| R-011 | 标准 PAKE，不自研密码学 | core `Pake` trait + `yon` opaque adapter | `/yonder/auth/1.0.0` | RFC/golden lengths、正反认证、context 绑定 |
| R-012 | relay 不可信且只能转发密文 | endpoint transport + OPAQUE | circuit 内 Noise/QUIC | 恶意 relay E2E、抓包无明文/secret |
| R-013 | registry 纯内存、有界、宽限恢复 | relay registry owner | Registry Active/Suspended | 确定时钟集成、restart/reclaim/conflict E2E |
| R-014 | 查询枚举和资源受控 | relay limiter owner | Resolve/Retry/Unavailable | governor unit/property、4096 容量压力 |
| R-015 | 当前用户 shell/权限/环境 | `PtyBackend` | Terminal Hello/Ready | PTY E2E、cwd/env/权限/exit/resize |
| R-016 | 终端像本地、控制序列逐字节透传且可本地脱离；Unix/重定向输出字节透明，Windows 原生控制台为 UTF-8 文本边界 | `TerminalFrontend` + fixed-capacity escape state + bridges | data/control streams；交互 `Ctrl+] .`；TerminalComplete 半关闭 | ANSI/Esc/方向键/Ctrl+C/跨块脱离 E2E、Windows 非 UTF-8 替换后续传、EOF/Exit/确认乱序、非交互透明、backpressure、吞吐/延迟 |
| R-017 | 线程安全、取消、无数据竞争 | single-owner actors | 所有状态；Closing 保留唯一文件 owner 到确定结果 | TSan、10k stress、fault injection、task leak、提交期间取消/关闭后无后台落盘 |
| R-018 | 零分配/低资源优先；社区 runtime 内部开销必须有界且如实测量 | fixed duplex/buffers/newtypes + Tokio fs | 热路径 | allocation profile、RSS/CPU/handle/FD/binary/三平台 criterion gates、10 次真实会话相对本地 PTY 吞吐中位数、审计+PTY blocking 预算 |
| R-019 | 输入/错误类型安全且不泄密 | core parsers/errors | 所有 decoder | 100% unit、fuzz、snapshot 脱敏、invalid input E2E |
| R-020 | 全面测试和风险分级覆盖 | CI/release | 全部 | 五原生 target 独立 llvm-cov JSON 阈值、fuzz corpus、Linux/Windows/macOS 性能与平台报告 |
| R-021 | 依赖最新、feature 最小且受审 | workspace dependencies | 无 | metadata/feature tree、audit/deny、MSRV builds |
| R-022 | 无公共默认 relay，必须自建 | CLI validation | relay PeerId pin | 缺省参数失败、身份生成和自建 E2E |
| R-023 | 0.1.x 实际体验可感知、终端零污染 | `OperationProgress<Stage>` + CLI renderer + file diagnostics | 配置先校验；首反馈同步；心跳 <=1s；动态单行宽度；Active tracing 隔离；路径可诊断 | renderer/unit、Unix PTY + Windows ConPTY 原生清行 E2E、`--log-file`、strict fallback、真实 namespace 时延门禁、错误/恢复回归 |
| R-024 | relay 秘密文件在受支持平台 fail-closed | `SecretFilePolicy` + `IdentityStore` | Unix 0600、可信且不可被 group/other 写入的直接父目录；Windows protected DACL/可信 owner | Unix mode/父目录/普通文件、Windows ACL 正反测试、原生 config check、空目录 identity smoke |
| R-025 | relay 可生产托管且可低噪声观测 | relay root task + aggregate observations | 跨平台停止信号；2s shutdown；60s 低基数汇总 | Unix/Windows 原生信号 E2E、聚合计数、拓扑配置拒绝、停止期限 |
| R-026 | 配置与公开身份可在网络启动前自检 | endpoint/relay Clap + layered loader | 两个二进制 config check/sources；identity show | CLI 集成、秘密值负断言、无 listener 副作用、错误链 |
| R-027 | relay 普通/企业模式互斥且企业模式只提供 Enterprise Resolve；两端以 `access_mode` 固定本地期望并禁止降级 | yon-relay service + endpoint typed config | `/yonder/enterprise-resolve/2.0.0`；`access_mode`/`YON_ACCESS_MODE` | 缺省 standard、文件/环境覆盖、非法值、namespace 隔离、两端/relay 模式错配、旧 connect 拒绝、旧 host 注册、普通与企业进程 E2E |
| R-028 | 企业事务内存单次、与子流绑定、断连/超时/重启失效 | yon-relay enterprise owner | Created..Completed/失败态 | 全转换、重放、重复回调、容量、假时钟、EOF 清理 |
| R-029 | 企业微信/飞书只放行可确认的有效内部成员 | `EnterpriseProvider` adapters | 官方授权 URL + OAuth callback + typed HTTPS exchange；用户拒绝/不可见与配置/平台故障本地分类、wire 统一拒绝 | 完整授权 URL 参数、双平台官方错误码 fixture、真实 HTTPS/TLS callback 与故障矩阵；真实自建应用的权限/范围/IP/tenant 正反验收是首次生产启用门槛，不计入 0.2.0 发布证据 |
| R-030 | 企业回调只开放两个 HTTPS GET 路径且无敏感日志 | yon-relay callback | 固定 path/state/code | TLS loopback、404/400/405、no-store、泄露负断言 |
| R-031 | 企业 secret 和审计文件跨平台强制保护 | `SecretFilePolicy` + audit store | Unix 0700/0600；Windows protected DACL | Unix mode/owner/symlink、Windows owner/ACE 正反原生测试 |
| R-032 | controller 提示/选择 provider、先显示 URL、浏览器打开失败可继续 | yon enterprise UI | Providers/Select/Authenticate | 单/双 provider、非 TTY、open 失败、心跳与零污染测试 |
| R-033 | 活动交互会话原生单文件上传/下载 | yon file actor | `/yonder/file-transfer/2.0.0` | 上传/下载 E2E、错误/取消不结束终端、终态后有界顺序交接、真实并发 Busy、新旧互操作 |
| R-034 | 文件流式 64 KiB、打开句柄权威、Tokio 异步 backend、SHA-256、安全临时文件和 no-replace | `FileTransferBackend` | Open/Data/Finish/Committed；CommittedUnconfirmed/CommitStatusUnknown 仅本地；Closing 结算 | 多块/空文件、symlink 最终普通文件、路径重绑定、源变化、目标竞态、提交歧义、owner 取消/关闭、磁盘/权限故障、生产 backend 基准；Unix FIFO probe/open TOCTOU 保留显式风险 |
| R-035 | 本地控制命名空间跨平台一致且非交互字节透明 | terminal frontend | `Ctrl+] u/d/?/./Ctrl+]` | 跨块状态属性测试、PTY/ConPTY 原生 E2E、未知选择器 |
| R-036 | 仅企业会话强制双端审计，普通会话零审计副作用；审计 v3/format 3 完整保留跨平台 `u32` 退出码，旧格式明确报告不支持 | yon audit/session | `/yonder/audit/3.0.0` | 普通回归、企业握手/旧端拒绝、目录缺失/不可写失败关闭、255/256/Windows 高位/u32::MAX、v2 Unsupported |
| R-037 | 原始输入不落盘，双端以会话私有 HMAC 承诺一致 | audit observer/crypto | Input shared chain | 内容边界、承诺一致、无 key 离线猜测不可验证测试 |
| R-038 | 输出/控制/文件事实链、周期检查点、共同清单和双签名；失败通知固定为 `AuditError -> CloseNotice`，同时就绪时审计失败不得被终端 EOF/I/O 覆盖 | audit session/wire + controller/host event pump | Hello..LedgerCommit；文件路径仅本地精确 UTF-8；提交歧义 fixed payload/角色方向状态；文件边界立即 checkpoint due | wire golden/property/fuzz、跨子流晚到、双方向序号/确认、关闭屏障、文件四角色路径与歧义拒绝矩阵、重复/mismatch、writer 真故障 fail-closed、完整/中断 E2E、双端结构化审计失败与终端关闭竞态回归 |
| R-039 | 持久身份和串行连续账本抵抗本地静默改写/分叉 | audit identity/ledger | identity + ledger + record container | 竞争、崩溃恢复、回滚/fork 检测、签名/链篡改矩阵 |
| R-040 | 离线 verify 六状态和 vt100 安全 replay | yon audit CLI | `.yonaudit` format 2 | 退出码、截断/逐字节篡改、OSC52/DCS/查询过滤、原生 smoke |
| R-041 | 0.2.0 产物与历史只建立在 v0.1.1 和本基线上 | release workflow | v0.1.1 -> v0.2.0 | commit provenance、六 target 资产、撤回 release/tag/run 清理审计 |

实现任务只有同时关联至少一个需求 ID、一个责任 package 和一个验证项才能进入开发。该矩阵是可追踪的当前基线，不是凌驾于产品目标之上的不可变规则；真实实现、网络或运维证据证明现有条目不合理时，应同时修订需求、设计、实现和验证，而不是为保持旧文本牺牲远程终端的正确性与可用性。发现需求没有可执行证据时视为设计缺口，不能用人工目测关闭。
