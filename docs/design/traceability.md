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
| R-016 | 终端像本地、控制序列逐字节透传且可本地脱离；Unix/重定向输出字节透明，Windows 原生控制台为 UTF-8 文本边界 | `TerminalFrontend` + fixed-capacity escape state + bridges | data/control streams；交互 `Ctrl+] .` | ANSI/Esc/方向键/Ctrl+C/跨块脱离 E2E、Windows 非 UTF-8 替换后续传、非交互透明、backpressure、吞吐/延迟 |
| R-017 | 线程安全、取消、无数据竞争 | single-owner actors | 所有状态 | TSan、10k stress、fault injection、task leak test |
| R-018 | 零分配/低资源优先 | fixed duplex/buffers/newtypes | 热路径 | allocation profile、RSS/CPU/handle/FD/binary/criterion gates、10 次真实会话相对本地 PTY 吞吐中位数 |
| R-019 | 输入/错误类型安全且不泄密 | core parsers/errors | 所有 decoder | 100% unit、fuzz、snapshot 脱敏、invalid input E2E |
| R-020 | 全面测试和风险分级覆盖 | CI/release | 全部 | 五原生 target 独立 llvm-cov JSON 阈值、fuzz corpus、平台与性能报告 |
| R-021 | 依赖最新、feature 最小且受审 | workspace dependencies | 无 | metadata/feature tree、audit/deny、MSRV builds |
| R-022 | 无公共默认 relay，必须自建 | CLI validation | relay PeerId pin | 缺省参数失败、身份生成和自建 E2E |
| R-023 | 0.1.0 实际体验可感知、终端零污染 | `OperationProgress<Stage>` + CLI renderer + file diagnostics | 配置先校验；首反馈同步；心跳 <=1s；动态单行宽度；Active tracing 隔离；路径可诊断 | renderer/unit、Unix PTY + Windows ConPTY E2E、`--log-file`、strict fallback、真实 namespace 时延门禁、错误/恢复回归 |
| R-024 | relay 秘密文件在受支持平台 fail-closed | `SecretFilePolicy` + `IdentityStore` | Unix 0600、可信且不可被 group/other 写入的直接父目录；Windows protected DACL/可信 owner | Unix mode/父目录/普通文件、Windows ACL 正反测试、原生 config check、空目录 identity smoke |
| R-025 | relay 可生产托管且可低噪声观测 | relay root task + aggregate observations | 跨平台停止信号；2s shutdown；60s 低基数汇总 | Unix/Windows 原生信号 E2E、聚合计数、拓扑配置拒绝、停止期限 |
| R-026 | 配置与公开身份可在网络启动前自检 | endpoint/relay Clap + layered loader | 两个二进制 config check/sources；identity show | CLI 集成、秘密值负断言、无 listener 副作用、错误链 |

实现任务只有同时关联至少一个需求 ID、一个责任 package 和一个验证项才能进入开发。该矩阵是可追踪的当前基线，不是凌驾于产品目标之上的不可变规则；真实实现、网络或运维证据证明现有条目不合理时，应同时修订需求、设计、实现和验证，而不是为保持旧文本牺牲远程终端的正确性与可用性。发现需求没有可执行证据时视为设计缺口，不能用人工目测关闭。
