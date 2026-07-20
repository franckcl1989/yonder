# 验证与交付门禁

## 编译基线

- Edition 2024，MSRV Rust `1.88.0`，同时验证当前 stable。MSRV 必须在六个原生 runner 上对生产 workspace 执行 all-target/all-feature build/link；fuzz workspace 额外执行 check，不能用 metadata 或单平台 check 替代链接证据。
- `dev`：`opt-level=0`、debug/overflow checks 开、incremental 开、codegen units 256。
- `test`：`opt-level=0`、debug/overflow checks 开；CI 关闭 incremental 以保证可复现覆盖率。
- `release`：`opt-level=3`、fat LTO、codegen units 1、incremental 关、strip symbols、`panic=abort`。
- 全 workspace、all targets、all features 实际不存在未批准 feature；Clippy 使用 `-D warnings`。第一方 package 均 `unsafe_code=forbid`。

任何门禁失败都不能发布，也不能声称功能完成。所有测试使用真实协议实现；mock 只允许在 trait 边界替代外部时钟、随机、终端或 transport，生产路径不得选择 mock。

## 测试分层

### 单元测试

- 每个 newtype 的全部合法边界、非法边界、Display/Debug 脱敏和转换。
- 连接码规范化、别名、分组、全零/全一、错误字符和固定 golden vectors。
- registry/resolve/auth/control 每个 tag、长度、保留位、上下限、截断和尾随状态。
- 状态机每个合法转换和每个非法事件；失败、超时、取消和重复事件幂等。
- locator 环形分配 0/1/128/满表、wrap、冲突、RNG 失败。
- direct governor 配额、确定性时钟、边界瞬间和来源表准入/回收。
- 路径排序全部 tie-break、失败样本、迟到候选和确定性。
- shell 选择、环境校验、exit code 映射和错误脱敏。

### 属性测试

- 任意 80 bit 值连接码 encode/decode round-trip；规范输出唯一。
- 任意输入 parser 不 panic，成功结果永远满足领域不变量。
- 任意容量不超过 128 的 locator 集合，未满时最多 `n+1` 次找到空值且不重复。
- 任意时间/事件序列，code 最多提交一次、Active 不回退、未认证连接永不进入 StartingTerminal。
- 任意候选排列得到相同 winner；排序满足全序和稳定 tie-break。
- 任意限速事件流不超过 burst/恢复上界，来源表永不超过 4096。

### 集成测试

- 使用 `libp2p-swarm-test` 建立同 PeerId 两连接，关闭指定 loser，双方观察关闭后子流只能走唯一连接。
- 额外连接分别在 Authenticating、AwaitingTerminal、StartingTerminal、Active 到达，验证撤销/终止语义。
- OPAQUE 正确 secret、错误 secret、错误 PeerId/context/nonce、并发、Retry、超时、断流和 golden 长度。
- registry reservation/连接两个条件的笛卡尔组合、续租、Suspend/恢复、Release、中继重启和 locator 冲突。
- `libp2p-stream` 接收循环饱和、endpoint 单入口、relay `16/64` permit、慢消费者、取消、关闭、重复协议流和 unsupported protocol。
- 两个 `duplex` bridge 的背压、半关闭、大输出、慢 stdout、child 先退、最后输出排空、data/Exit 乱序、网络先断和清理期限。
- DER cert/key/CA 合法与各种非法输入，确认边界返回错误而不是进入上游 panic API。

### 端到端测试

- 真进程 `yon-relay + yon host + yon connect`，用伪终端执行交互 shell、ANSI、Ctrl+C、resize、退出码、工作目录和环境继承。
- 直连 QUIC、TCP、WS；仅 relay；UDP 被阻断自动落 TCP；普通 TCP 被代理限制时走 WS/WSS。
- Linux network namespace 覆盖公网、单 NAT、双 NAT、端口受限/对称 NAT、IPv4-only、IPv6-only、双栈、丢包、延迟、抖动、乱序和 relay 中断。
- relay 恶意丢弃/延迟/截断协议，错误必须有界且 endpoint 不死锁、不泄漏 secret。
- 连接码位置参数、TTY 隐藏输入和 pipe 输入三条 CLI 路径。
- 六个发布 target 都运行原生 smoke；不能只交叉编译通过。

### 模糊测试

独立 fuzz target 覆盖：连接码 parser、registry request/response、resolve request/response、auth 状态 decoder、terminal control decoder、PeerId/context builder、目标状态事件序列。每次 PR 每 target 至少 `60s` 固定 corpus；nightly 每 target `30min`；发布候选每 target累计 `24h` 且零 crash、hang、OOM、超限分配和不变量失败。发现缺陷后最小化样本进入永久 regression corpus。

### 性能测试

Criterion 覆盖 code encode/decode、wire decoder、locator allocation、governor check、path ranking 和固定 buffer copy。进程 benchmark 覆盖启动、OPAQUE、直接/relay 建连、交互延迟、吞吐、RSS、CPU、文件描述符和二进制体积。

基准结果保存原始 JSON/环境信息。相对已批准基线：吞吐、启动、RSS、体积回归不得超过 `5%`，p99 延迟不得超过 `10%`；噪声超过阈值时在同一 runner 重复至少 10 次取中位数，不能直接放宽门槛。

## 覆盖率与缺陷强度

- `cargo-llvm-cov 0.8.7` 在五个可可靠产出 profraw 的原生目标分别运行 target-specific 测试并保留 JSON 报告；每个目标独立满足全部阈值，不用跨平台合并掩盖平台缺口。
- 每个可工作的原生目标独立满足聚合 line `>=95%`、function `>=95%`、region `>=90%`、每文件 line `>=75%`、可测 branch `>=75%`；不使用跨平台合并掩盖单目标缺口。门槛只允许基于稳定证据提高，降低必须重新审批。
- derive/macro 展开、第三方源码以及无法映射到第一方源行的编译器分支不计入分母；任何新的排除必须逐项审批。
- nightly coverage 专用构建允许用 `#[coverage(off)]` 排除 `#[cfg(test)]` 单元测试模块；integration test、example 与 benchmark harness 使用 `cargo-llvm-cov 0.8.7` 的官方默认路径排除，fuzz harness 不进入生产 workspace coverage。不得排除任何生产模块或生产分支；stable、MSRV、Miri、sanitizer 和 release 构建不启用该专用 cfg。
- 覆盖率不足必须保留报告和逐项分类，不算发布门禁通过；不得为了数字执行本应不可达的失败夹具或伪造违反生产不变量的状态。超过门槛也不替代安全、认证、协议、状态机、资源边界和并发故障路径的定向测试。
- rustdoc 示例和 compile-fail 类型不变量测试必须运行。
- 缺陷修复先加入能失败的回归测试。达到覆盖率门槛后仍需属性、fuzz、并发压力和端到端测试，不能把行覆盖率当正确性证明。
- `aarch64-pc-windows-msvc` 因 Rust 上游 issue `#150123` 暂不运行 coverage；该例外不影响其原生 Clippy、测试、release 构建、PE import/static CRT 和空目录 smoke。上游修复后立即加入第六个独立风险分级 coverage gate。

## 内存、并发与故障验证

- Miri 运行 `yonder-core` 全部单元/属性缩减集；Linux nightly 分别运行 ASan 和 TSan 集成测试。
- 重复至少 10,000 次连接/取消/resize/child-exit 竞态，验证无死锁、任务泄漏、双提交和超时漂移。
- 外部 profiler 验证终端稳定转发循环每个方向第一方逐块堆分配为 `0`；所有一次性 buffer 的数量、容量和生命周期与架构一致。
- 故障注入覆盖 RNG 失败、时钟推进、channel/semaphore 满、连接数/内存限制、内存统计失败、DNS 超时/超量地址、reservation 到期、relay restart、磁盘满、权限失败、stdout 关闭和 child kill 失败。
- 首根错误必须保持，secondary cleanup error 可观测但不覆盖；每个取消点都有有界完成时间。

## 性能与资源验收值

| 指标 | v1 上限/下限 |
| --- | --- |
| stripped `yon` | 每 target `<= 20 MiB` |
| stripped `yon-relay` | 每 target `<= 16 MiB` |
| `yon host` Advertised 稳态 RSS | `<= 32 MiB`，OPAQUE Argon2 临时峰值另允许 `25 MiB` |
| relay 128 reservation/registration RSS | `<= 48 MiB` |
| relay idle CPU | 128 endpoint 下 `< 1%` 单核参考容量 |
| 终端稳态第一方分配 | 每个复制方向逐块 `0`，仅启动时固定 buffer |
| loopback 终端吞吐 | 不低于同机原始 async pipe 的 `90%` |
| 1 KiB 交互应用层额外延迟 | p99 `<= 1ms`，不含网络 RTT |
| resize 传播 | 无网络阻塞时 p99 `<= 500ms` |
| OPAQUE 单次认证峰值 | `<= 25 MiB` 附加 RSS，且不会并发两次 |

参考 runner 固定 CPU 型号、内存、OS 镜像、电源模式和工具链并记录在基准产物。绝对上限与相对回归门槛同时生效；首次完整实现建立基线，但不能用基线覆盖上述绝对值。

## 供应链与许可证门禁

- `cargo audit` 只精确忽略 `RUSTSEC-2026-0118`、`RUSTSEC-2026-0119`、`RUSTSEC-2024-0436`，其他 vulnerability、unsound、unmaintained warning 均失败。
- `cargo deny` 检查 advisory、license、source、bans；只允许 crates.io registry，不允许 Git/path 生产依赖，不允许 wildcard version。
- 验证 `curve25519-dalek >=4.1.3,<5`、`quinn-proto >=0.11.13`，并断言 Hickory 和 paste 精确路径。
- 重复主版本逐项审核。Rand、thiserror 等由不同上游主版本造成的重复必须记录，不因整洁而强行统一不兼容生态。
- `cargo-cyclonedx 0.5.9` 使用 tag commit 时间作为 `SOURCE_DATE_EPOCH`，为 `yon` 和 `yon-relay` 分别生成 CycloneDX 1.5 JSON SBOM；发布同时包含 `Cargo.lock`、全资产 SHA-256 和构建 provenance，tag 构建必须 `--locked`。
- 仓库必须包含项目的 `LICENSE-MIT` 与 `LICENSE-APACHE`。`cargo-about 0.9.1` 以已审查 allowlist 生成 `THIRD-PARTY-LICENSES.html`；三个许可证文件作为独立 release 资产纳入 SHA-256 与 provenance，不改变“每个二进制归档恰好一个文件”的约束。
- `actionlint 1.7.12` 的官方 Linux x64 资产必须校验固定 SHA-256 后执行；所有 GitHub Actions 必须固定完整 commit SHA。

## 静态链接与平台门禁

- Linux 对两个 ELF 运行 `file`、`readelf -d`、`ldd`；不得有动态 interpreter 或 `NEEDED`。
- Windows 对两个 EXE 检查 PE imports；允许 Windows 系统 DLL，禁止动态 CRT 和第三方 DLL。运行目标架构原生 smoke。
- macOS `otool -L` 只允许 `/usr/lib`、`/System/Library` 的系统库/框架；禁止 Homebrew、MacPorts 或打包外 dylib。
- 每个平台从空目录只复制单个 binary 和参数启动，不依赖当前仓库、资源文件或预装运行时。
- Unix 每个二进制分别打包为只含一个规范名称可执行文件的 `.tar.gz`；Windows 分别打包为只含一个 `.exe` 的 `.zip`，工作流必须断言归档条目数恰好为一。

## 发布完成定义

格式、Clippy、MSRV/current stable build、全部测试、逐目标风险分级覆盖率、doc、fuzz 时长、Miri/sanitizer、audit/deny、性能、资源、静态链接、六 target 原生 smoke、SBOM、许可证、校验和全部通过，才允许创建 release。tag workflow 可以生成并证明 release candidate，但在上述完整证据全部接入前不得自动创建正式 GitHub Release。任何未真实运行的项必须明确标为未完成，不能用设计评审结果替代交付验证。
