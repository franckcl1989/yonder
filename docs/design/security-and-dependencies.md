# 安全与依赖基线

## 威胁模型

relay 永远按恶意基础设施处理，即使由用户自己部署。它可以观察双方 IP、PeerId、时间、持续时间、转发字节数和连接关系，也可以拒绝、延迟、丢弃或重放外层流量；v1 不隐藏这些元数据，也不能强迫恶意 relay 可用。

endpoint 之间在 relay circuit 内仍建立经过 PeerId 身份认证的 Noise 或 QUIC/TLS 连接。OPAQUE 再用连接码完成相互认证和 key confirmation，并绑定 locator、双方 PeerId 与双方 nonce。relay 不得到 60 bit secret、OPAQUE context/session key、终端内容、按键或控制消息，不能修改受保护内容后仍通过端点认证。

以下不在 v1 防护范围：已入侵任一 endpoint、拥有被控当前用户权限的本地攻击者、读取进程内存/调试器/core dump/swap/休眠镜像的攻击者、恶意 shell 或终端应用、流量分析和大规模分布式 DoS。Yonder 不提权，因此攻陷会话等价于被控端当前用户权限，不等价于 root/Administrator。

## 安全不变量

- 全部第一方 crate 在 workspace 和 package 层设置 `unsafe_code = "forbid"`，源码、测试、example、bench、fuzz 辅助和 build script 都不得出现第一方 unsafe 或 FFI。
- 并发共享状态由单一 owner、所有权转移和有界 channel 表达，不手写 `Send`/`Sync`，不使用第一方共享可变全局变量或 `Arc<Mutex<_>>`。
- 连接码 secret、OPAQUE 临时状态和 session key 使用 `zeroize` 管理可控的小型缓冲区生命周期；不会进入 `Debug`、`Display`、日志、panic 或指标。
- 所有远端长度、数量、并发、时间和内存都先校验硬上限。无界输入不产生按输入比例的分配、任务、重试或日志。
- 认证失败不降级协议、不恢复弱随机、不回退明文、不复用旧授权。Active 前失败不消费 code，Active 后失败不复活 code。
- WSS 的 TLS 验证和 Multiaddr PeerId 验证都必须成功；任何一层失败都拒绝该入口。

Safe Rust 能消除第一方未定义行为和数据竞争类别，但第三方 crate 内部允许包含经过审查的 unsafe。锁文件安全审计、Miri、sanitizer、跨平台压力和上游 soundness 监控共同构成交付证据，不能用“使用 Rust”替代验证。

## 随机与秘密

第一方 `SecureRandom` 生产实现只调用 `rand 0.8.7` `OsRng::try_fill_bytes`，失败向上传播，不回退。连接码、身份密钥字节、locator 起点和显式 nonce 都走该接口且填充调用方缓冲区，不分配。

`opaque-ke 4.0.1` 的公开 API 接收 Rand 0.8 `CryptoRng + RngCore`，Pake 适配层必须把同一 `OsRng` 直接交给它，不能用第一方 `SecureRandom` trait 伪装一个 infallible `RngCore`。`opaque-ke` 内部会直接调用 `fill_bytes`；操作系统熵源灾难性失败时可能 panic，无法由第一方向上传播。这里接受仅限该第三方 API 的残余风险：不包装 catch/unwind，不提供弱随机 fallback；`panic=abort` 会终止进程。上游提供 fallible RNG API 后必须重新评估。AGENTS 中“只允许 try_fill_bytes”严格约束第一方直接随机操作，不虚假覆盖第三方内部。

`opaque-ke` 的 Argon2 工作区约 19 MiB，释放前不保证全部清除。小型原始 secret 和最终 key 仍清除；大型工作区残留只影响已经具备本地进程内存读取能力的攻击者。系统无法保证秘密不进入 swap、core dump 或休眠镜像，部署方需要用操作系统策略控制这些介质。

## 依赖声明规则

- 版本为 2026-07-16 核实的稳定版；Cargo 使用精确版本和受审 `Cargo.lock`。只有 `libp2p-stream` 是已批准的 alpha 例外。
- 每个直接依赖都写 `default-features = false`，只打开下表 feature。兼容性例外 `rand 0.8.7` 和 `sha2 0.10.9` 由 `opaque-ke` 的公开 trait 主版本决定。
- Rust 项目 MSRV 固定为 `1.88`。直接依赖最高声明 1.86，但锁定树中的 `time 0.3.53` 要求 1.88；CI 必须用 1.88 和当前 stable 分别构建。
- 所有生产依赖是 Rust crate 或系统 API wrapper，不要求用户安装 OpenSSL、C runtime、动态网络库或其他第三方运行时。

## 生产直接依赖

| crate | 精确版本与 feature | 放置/用途 | 选择与影响 |
| --- | --- | --- | --- |
| `backon` | `1.6.0`; `std,tokio-sleep` | `yonder-net`; 重连退避 | Apache-2.0，维护活跃；替代手写退避。冷路径，小型 fastrand jitter，无原生库 |
| `clap` | `4.6.2`; `color,derive,error-context,help,std,suggestions,usage` | 两个 binary；CLI | MIT/Apache-2.0，事实标准；替代手写解析。主要增加启动/体积，不在数据热路径 |
| `config` | `0.15.25`; `toml` | `yonder-config`；严格分层配置 | MIT/Apache-2.0，成熟；替代手写 TOML、环境变量嵌套与合并。只在启动冷路径，禁用 async/json/yaml 等未使用能力 |
| `crossterm` | `0.29.0`; `windows` | `yon`; raw mode、尺寸 | MIT，成熟跨平台；替代平台终端 FFI。只在 controller 链接 |
| `data-encoding` | `2.11.0`; `std` | `yonder-core`; Crockford Base32 | MIT，成熟、零拷贝 API；替代手写编码表。影响极小 |
| `futures` | `0.3.33`; `async-await,std` | `yonder-net`; libp2p stream I/O | MIT/Apache-2.0，Rust 异步基础库；不引入 executor |
| `governor` | `0.10.4`; `std` | `yonder-core`; relay/query/auth GCRA | MIT，成熟；替代手写令牌桶。只用 direct limiter，不用 keyed store/等待队列；已测 direct limiter 40 B、调用约 30 ns |
| `libp2p` | `0.56.0`; `autonat,dcutr,dns,ed25519,identify,macros,memory-connection-limits,noise,ping,quic,relay,tcp,tokio,upnp,websocket,yamux` | `yonder-net`; 完整网络栈 | MIT，官方 rust-libp2p；替代自研传输、NAT、加密、relay。是主要体积/编译成本，纯单二进制可分发 |
| `libp2p-stream` | `0.4.0-alpha`; 无 feature | `yonder-net`; 应用子流 | MIT，rust-libp2p 官方 alpha；替代手写 ConnectionHandler/multistream。API 被 trait 隔离，存在受限预发布例外 |
| `opaque-ke` | `4.0.1`; `argon2,ristretto255` | `yon`; RFC 9807 PAKE adapter | MIT/Apache-2.0，RustCrypto/Meta 实现；替代自研密码协议。认证冷路径约 19 MiB 临时内存，不让 relay 编译该依赖 |
| `portable-pty` | `0.9.0`; 无 feature | `yon`; PTY 和 child | MIT，WezTerm 使用的跨平台实现；替代 Unix/ConPTY FFI。第三方含平台 unsafe，只在 `yon` 链接 |
| `rand` | `0.8.7`; `getrandom` | `yonder-core`; OPAQUE 兼容 CSPRNG | MIT/Apache-2.0；0.8 最新修复补丁，因 opaque-ke Rand 0.8 约束不能用全局 0.10。系统熵路径无额外运行时 |
| `rpassword` | `7.5.4`; 无 feature | `yon`; 隐藏 code 输入 | Apache-2.0，成熟跨平台；替代平台 console 手写。仅启动冷路径 |
| `rustls-pki-types` | `1.15.0`; `alloc` | `yonder-net`; DER key/cert 边界校验 | MIT/Apache-2.0，rustls 官方类型；先校验再调用 libp2p websocket 避免无效 key 触发其 panic API |
| `serde` | `1.0.229`; `derive,std` | 两个 binary；类型安全配置 schema | MIT/Apache-2.0，事实标准；只为启动配置反序列化启用 derive/std，不进入终端数据热路径 |
| `sha2` | `0.10.9`; 无 feature | `yon`; OPAQUE SHA-512 | MIT/Apache-2.0；因 opaque-ke Digest 0.10 公开约束使用兼容主版本最新补丁，不让 relay 编译该依赖 |
| `tempfile` | `3.27.0`; `getrandom` | `yon-relay` 身份原子写入、`yon` CLI 集成测试 | MIT/Apache-2.0，成熟；替代跨平台临时文件/rename 竞态手写。只在 init 冷路径或测试构建 |
| `thiserror` | `2.0.19`; `std` | 所有 package；结构化错误 | MIT/Apache-2.0，成熟 derive；替代重复 Display/Error 样板，无运行时分配要求 |
| `tokio` | `1.53.0`; `io-std,io-util,macros,rt,signal,sync,time` | 网络库和 binaries；runtime/I/O | MIT，成熟；current-thread runtime，避免手写 reactor。阻塞池上限 4 |
| `tokio-util` | `0.7.18`; `compat,io-util,rt` | `yonder-net`/`yon`; I/O 适配、取消、任务跟踪 | MIT，Tokio 官方；替代手写 bridge/cancellation。duplex 固定容量一次分配 |
| `tracing` | `0.1.44`; `std` | 所有 package；结构化诊断 | MIT，生态标准；字段白名单确保秘密和终端数据不记录 |
| `tracing-subscriber` | `0.3.23`; `ansi,fmt` | 两个 binary；文本日志 | MIT，官方 subscriber；只在进程边界，默认简洁 stderr |
| `zeroize` | `1.9.0`; `alloc,derive` | `yonder-core`; 小型秘密清除 | MIT/Apache-2.0，RustCrypto；`alloc` 用于立即包裹 rpassword/Clap 交出的 code String，避免手写 volatile 清除。不承诺 swap/core dump 清除 |

`governor` 同时用于 relay 查询和被控端认证启动限速。此前“只允许链接 relay”的约束被本冻结替换：不用它就只能手写 auth 限速，违反不造轮子目标。`yon` 增加的已测最小静态体积约 13.5 KiB，收益大于该成本。

## 测试直接依赖与工具

| 名称 | 精确版本与 feature | 用途/边界 |
| --- | --- | --- |
| `criterion` | `0.8.2`; `cargo_bench_support` | benchmark harness；Apache-2.0/MIT，MSRV 1.86，不进入产物 |
| `proptest` | `1.11.0`; `std` | parser、allocator、状态机、排序性质；MIT/Apache-2.0 |
| `libp2p-swarm-test` | `0.6.0`; `tokio` | 官方内存 transport 和多 Swarm 集成测试；MIT，plaintext 仅测试可达 |
| `libfuzzer-sys` | `0.4.13`; `link_libfuzzer` | fuzz targets；MIT/Apache-2.0/NCSA，仅 nightly fuzz 构建 |
| `cargo-fuzz` | `0.13.2` | 固定安装的 fuzz runner |
| `cargo-audit` | `0.22.2` | RustSec 锁文件审计 |
| `cargo-deny` | `0.20.2` | 许可证、重复版本、source 和 advisory 策略 |
| `cargo-llvm-cov` | `0.8.7` | 五个可工作原生 target 的独立风险分级 line/function/region/per-file line/branch 门禁 |
| `cargo-cyclonedx` | `0.5.9` | 可复现 CycloneDX 1.5 JSON SBOM；Apache-2.0，MSRV 1.85，仅 CI/release 工具 |
| `cargo-about` | `0.9.1`; `cli` | 生成独立第三方许可证清单；MIT/Apache-2.0，MSRV 1.88，仅发布候选工具，不进入二进制 |
| `actionlint` | `1.7.12` | GitHub Actions 语法和语义检查；MIT，仅 CI/release 工具，官方资产校验 SHA-256 |

标准库、rustdoc compile-fail、Miri、LLVM sanitizer、系统链接检查和操作系统网络 namespace 足以完成其余门禁，不为这些能力新增库。

## 许可证策略

允许锁文件中经逐项解析的 MIT、Apache-2.0、BSD-2-Clause、BSD-3-Clause、ISC、Zlib、Unicode-3.0、Unlicense、CDLA-Permissive-2.0、MPL-2.0 和 NCSA。`attohttpc` 的 MPL-2.0 是文件级弱 copyleft 且只经 UPnP 传递，不要求 Yonder 整体改许可证；`webpki-roots` 的 CDLA-Permissive-2.0 允许分发。`r-efi` 的 LGPL 是 `OR` 备选，构建选择 MIT/Apache-2.0 许可。任何仅有 GPL/AGPL/LGPL、未知、非商业或不可再分发许可证的新路径一律失败并重新审批。

## 受限上游例外

### Hickory DNS

锁定路径必须是 `libp2p 0.56.0 -> libp2p-dns 0.44.0 -> hickory-resolver 0.25.2 -> hickory-proto 0.25.2`。临时忽略且只忽略：

- `RUSTSEC-2026-0118`：DNSSEC 路径 DoS；当前 feature graph 不含 Hickory DNSSEC/TLS/HTTPS/QUIC/H3，故不可达。
- `RUSTSEC-2026-0119`：DNS encoder DoS；Yonder 只解析本机操作员提供的有界 `/dns4`、`/dns6`，不提供 DNS server/递归/代理，不接受远端 DNS 记录，禁止 `/dnsaddr`。

`libp2p-dns 0.44.0` 自身把单次 transport dial 尝试硬限制为 `16`、DNS lookup 硬限制为 `32`；Yonder 再把操作员 relay 地址限制为 8、endpoint 同目标已建立候选限制为 8、每 transport 在途限制为 2。实现复用这些上游界限，不手写 DNS parser/resolver；每次升级必须核对上游常量仍存在且语义未放宽。

版本、路径、feature 或公告语义任一变化即使例外失效。rust-libp2p 发布兼容修复后立即提升级方案。

### `paste` 停止维护

Linux transport 路径为 `libp2p -> libp2p-{quic,tcp} -> if-watch 3.2.2 -> netlink-packet-core 0.8.1 -> paste 1.0.15`，命中 `RUSTSEC-2024-0436`。`paste` 是构建期 proc macro，不存在于运行时调用图，该公告是停止维护而非漏洞或 soundness 缺陷；当前 libp2p 稳定版没有可替换路径。允许 CI 精确忽略此编号，继续监控 `netlink-packet-core`/`if-watch` 升级；禁止扩大为通用维护警告豁免。

### `libp2p-stream` alpha

只允许精确 `0.4.0-alpha`，API 不越过 `ApplicationStreams` 适配层。正式集成测试锁定背压、唯一连接屏障和取消语义。可用稳定版发布后必须优先评审并退出例外。

## 持续审计

每次依赖变更必须重新执行版本/feature、RustSec、许可证、source、重复主版本、MSRV、unsafe/soundness、静态链接、六 target、体积、RSS、分配和基准审查。CI 的 advisory ignore 必须逐个写出三个精确编号，不能忽略 crate、严重级别或全部 warning。
