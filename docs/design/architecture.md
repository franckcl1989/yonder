# 架构与资源模型

## Workspace

| package | 类型 | 职责 |
| --- | --- | --- |
| `yonder-core` | library | 连接码与领域 newtype、固定 wire 类型、PAKE trait、限速配置、状态机、结构化错误、时间和安全随机抽象 |
| `yonder-config` | library | 严格的系统文件、当前目录文件和环境变量分层加载，schema 反序列化及路径来源解析 |
| `yonder-net` | library | 共享 libp2p transport/behaviour、应用子流适配、路径候选与选择、relay client、连接名册和唯一连接屏障 |
| `yon` | binary | `host`/`connect` CLI、`opaque-ke` PAKE 适配、本地终端、PTY/shell 生命周期和用户可见错误 |
| `yon-relay` | binary | 持久身份 CLI、Circuit Relay v2、AutoNAT v2 server、临时注册表、查询和滥用控制 |

依赖方向固定为二进制依赖共享库、`yonder-net` 依赖 `yonder-core`，`yonder-config` 独立于领域和网络层，`yonder-core` 不依赖网络或 CLI。协议类型由 core 定义，网络库只负责在子流上精确读写。CLI 和 relay 不互相依赖。

## 类型与 trait 边界

领域值使用私有字段 newtype 或枚举建模，包括 `ConnectionCode`、`Locator`、`PakeSecret`、`RelayPeerId`、`TerminalSize`、`RetryAfter`、`ReservationLimit`、`CircuitLimit`、`AuthBudget`、`ConnectionRoster` 和各状态枚举。构造函数完成范围、长度、字符集和组合校验；内部代码不能持有未验证的等价裸值。

只在真实替换点建立最小 trait：

| trait | 能力 | 分发与理由 |
| --- | --- | --- |
| `SecureRandom` | 尝试填充调用方缓冲区 | 泛型静态分发；生产为 `OsRng`，测试为确定实现 |
| `MonotonicClock` | 返回单调时刻 | 泛型静态分发；状态过期和确定性测试需要替换 |
| `Pake` | 注册、客户端开始/完成、服务端开始/完成 | 泛型静态分发；隔离 `opaque-ke` 与密码套件 |
| `ApplicationStreams` | 注册协议、打开子流、持续接收子流 | 单一网络 actor 持有；隔离 alpha `libp2p-stream` |
| `PathPolicy` | 从有界候选与样本选择唯一连接 | 纯静态策略；便于性质和回归测试 |
| `PtyBackend` | 创建 PTY、spawn shell、resize、kill、wait | 冷路径允许适配 `portable-pty` 的第三方 trait object |
| `TerminalFrontend` | raw mode guard、尺寸、stdin/stdout | 隔离 `crossterm` 和平台 I/O，支持伪终端集成测试 |
| `IdentityStore` | 原子创建和读取中继身份 | relay 冷路径；生产使用 `tempfile` 原子持久化 |
| `SecretFilePolicy` | 创建前收紧并读取前验证 identity/WSS 私钥及直接父目录权限 | 平台冷路径；Unix mode/owner 与 Windows ACL 实现可独立验证 |

固定格式解析、newtype 方法、状态转换纯函数和包内辅助函数不包装成 trait。第一方热路径不使用 `dyn`；`portable-pty` API 自身返回的第三方 trait object 只被封装在终端适配层。

## 共享 libp2p 栈

所有角色使用相同 transport builder 和基础 behaviour 组合：

- IPv4、IPv6、普通 `/dns4` 与 `/dns6` Multiaddr；v1 拒绝 `/dnsaddr`。
- QUIC v1 over UDP，使用 QUIC/TLS 1.3 的 libp2p 身份认证。
- TCP + Noise + Yamux。
- WS + Noise + Yamux；WSS 在 WS 外增加 TLS，之后仍执行 Noise。
- Ed25519 PeerId、Identify、Ping、DCUtR、Circuit Relay v2、memory connection limits。
- endpoint 启用 UPnP，不启用未被产品消费且会产生额外 relay 回拨连接的 AutoNAT v2 client；Identify observed address 直接为 DCUtR 提供外部地址候选。relay 启用 AutoNAT v2 server 和 Circuit Relay v2 server，不启用 UPnP client。

endpoint 默认分别监听 IPv4/IPv6 的 `udp/0/quic-v1`、`tcp/0`、`tcp/0/ws`，TCP 启用 `nodelay`；端口由操作系统分配。未指定 IP、环回或不可拨号地址不向对端发布，Identify observed address 和成功 UPnP 映射进入直接候选。relay 只监听操作员显式配置的地址。

WSS 主要用于 endpoint 到 relay 的受限网络入口。临时 endpoint 没有域名和受信证书，因此 endpoint 间直接候选只包括 QUIC、TCP 和 WS；共享代码仍能拨号 WSS relay。WSS transport 必须包在 DNS(TCP) 外侧以保留主机名和 SNI。

endpoint 会并发拨号已配置的同一 relay 入口，使用相同的 Ping 样本排序并只保留一条基础连接，之后才申请 reservation 或执行 resolve。relay 为每个 endpoint PeerId 维护连接名册；registry/resolve 只在名册恰好一条时接受，并从该唯一 `ConnectedPoint` 取得来源 IP 前缀。迟到入口造成临时第二条连接时应用请求返回 Retry，额外连接结束后恢复。这样无需手写 ConnectionHandler 也不会把一个子流错误归因到另一个来源地址。

libp2p 提供 transport 握手、加密、复用、地址、NAT 探测、UPnP、打洞、relay circuit、Ping 和子流协商。Yonder 只负责枚举/约束候选、并发触发这些能力、按策略选择、关闭败选连接以及驱动业务状态机；rust-libp2p 不会替应用自动完成跨 transport 的质量选择。

## 路径建立与选择

1. 两个 endpoint 先通过配置的 relay 建立 circuit，保证存在保底候选。
2. Identify、UPnP 和 DCUtR 提供直接候选；QUIC、TCP、WS 地址并发拨号，单个地址只允许一个在途拨号。
3. relay 入口建立继续使用绝对 `10s` 期限；尚无任何 endpoint-to-endpoint 候选时，全能力建立保留 `30s` 总期限。第一条 relay 候选建立后质量窗口固定为 `1.5s`，DCUtR 另有 `3s` 优先窗口；底层 transport 的单次 `8s` timeout 仍约束独立拨号，但不可达直连不再串行占满三轮 timeout 后才使用已经可用的 relay。
4. Ping 在每条连接建立后立即开始，单次超时 `750ms`；endpoint 后续间隔 `1s`，relay 后续间隔 `15s`，避免 128 个空闲 endpoint 对 relay 形成高频永久轮询。第一条候选后的 `1.5s` 是最小选择采样窗；尚无直连时继续驱动最长 `3s` 的 DCUtR 优先窗口。直连已建立但尚无样本时最多再等待 `750ms`，每条候选最多保存前三个成功结果。零样本的已建立候选仍保留为连通性 fallback，Ping 失败不等价于 transport 断开。
5. 路由类别先于质量排序：只要窗口内存在已认证直连，controller 就排除全部 relay 候选，只在直连集合中排序；没有直连时才允许 relay fallback。同类候选排序键固定为：有成功样本优先于无样本、RTT 中位数升序；只有双方均有至少两个样本时才比较 RTT 极差，之后依次为 QUIC 优先于 TCP、TCP 优先于 WS/WSS、建立顺序升序。样本数量本身不参与排序。没有主动带宽探测，避免额外流量、延迟和攻击面。
6. `libp2p-dcutr` 成功事件中的 `ConnectionId` 只对应本端发起的连接；对称同时拨号或单 NAT 入站成功时，两端可能报告不同 ID，甚至只有一侧报告成功。controller 是唯一选路者：它从本地已建立直连候选中选出 winner，按本地 `ConnectionId` 关闭全部 loser，并等待 `ConnectionClosed`；host 不独立排序，而是在收到 auth 子流后等待名册收敛，验证剩余唯一连接的路由类别并绑定它。两端都在 OPAQUE 前满足唯一名册。
7. 没有直连候选且 DCUtR 明确失败、首条 relay 候选后的 `3s` 优先窗口截止、无候选时 `30s` 总期限截止，或全能力连接在 OPAQUE 认证及两条 terminal 子流打开的预提交阶段丢失唯一绑定时，controller 销毁整个全能力 Swarm，生成新临时 PeerId，以 `Toggle<dcutr::Behaviour>` 禁用 DCUtR 构建新 Swarm，经同一 relay 重新查询并建立 relay-only circuit。额外同 PeerId 连接仍先触发 fail-closed 并关闭相关连接，旧 Swarm drop 是取消残余拨号的所有权边界；fallback 恰好一次，不循环，OPAQUE、协议和业务错误不触发降级。
8. v1 不热迁移。relay-only 尝试或 terminal 预提交准备完成后出现任何迟到的同 PeerId 额外连接仍按唯一连接屏障终止当前操作，而不是成为备用路径。

该规则先保证已有连通路径不被 Ping 缺失误杀，再以“可用直连优先、否则 relay”确定路由类别，最后才用可比较的 RTT、抖动和 transport 偏好对同类候选排序。它避免两端依据各自 RTT 独立选择不同物理连接，也避免更低的 relay RTT 覆盖产品要求的点对点优先。

## 唯一连接屏障

`libp2p-stream 0.4.0-alpha` 的出站 API 只接收 PeerId，并会在同 PeerId 的多条连接中选择一条；入站只返回 `(PeerId, Stream)`。它不向应用暴露子流对应的 `ConnectionId`。因此 v1 采用以下唯一且已验证的绑定语义：

- Swarm actor 根据 `ConnectionEstablished`/`ConnectionClosed` 为每个 PeerId 维护有硬上限的本地 `ConnectionRoster`。
- 主控端只有在本地 roster 恰好一条、所有 loser 已观察为关闭时才打开认证子流。
- 被控端只在该主控 PeerId 的 roster 恰好一条时接受认证；否则返回 `Retry`。接受时把 roster 中唯一 `ConnectionId` 记录为授权连接。
- host 的 OPAQUE `ServerFinish` 不直接写 `Authenticated`。网络 owner 在认证 future 返回并重验 binding 后先同步提交 `Authenticating -> AwaitingTerminal`，再在一个组合阶段并发 flush 确认、驱动连接事件并有界收集两条终端子流，消除 controller 收到确认后立即开流时的丢流窗口。
- 从 `Authenticating` 开始到 `StartingTerminal` 结束，出现第二条同 PeerId 连接会撤销认证、关闭该 PeerId 全部连接并返回 `Advertised`，连接码不消耗。
- `Active` 后出现第二条同 PeerId 连接会立即关闭全部该 PeerId 连接、终止 shell 并结束会话；连接码保持已消费。这样额外连接无法利用仅有 PeerId 的入站子流 API 继承授权。
- 控制和数据子流只有在本地 roster 仍为记录的唯一连接时才进入状态机。连接关闭立即撤销未提交授权；Active 后选中连接关闭不建立新授权或路径迁移，只允许既有 control/data 子流在同一个绝对 `2s` 截止内交付已经排队的 EOF 与 Exit，随后会话进入 Spent。
- endpoint 到 relay 的 registry/resolve 使用同一名册原则，但不建立授权状态：名册不唯一时返回 Retry；每 PeerId 同时最多一个相应请求，代替无法实现的“按物理连接并发”表述。
- host 的 reservation lease 只要求精确选中的 relay `ConnectionId` 仍存在且对应 listener 已 ready；同 relay PeerId 的短暂额外连接不会把 reservation 或注册映射误判为失效，也不会触发完整重连。registry/resolve 调用期间 relay 侧名册若暂时不唯一仍按上一条返回 Retry，并由既有有界退避等待临时连接收敛；这与注册映射 Active 所要求的“reservation 有效且至少一条连接仍存在”一致。

2026-07-16 的独立可行性测试使用 `libp2p-swarm-test 0.6.0` 真实建立两条连接、关闭指定 loser、等待双方关闭事件，再通过 `libp2p-stream` 成功打开并收发子流。该回归必须进入正式集成测试。

## 并发与所有权

- 每个进程使用 Tokio current-thread runtime；业务状态机、Swarm 和协议编解码在一个异步线程中按事件驱动，不增加无收益的线程竞争。
- `SwarmTask` 独占 `Swarm`、连接 roster 和 `libp2p-stream::Control`；命令通道容量 `32`，业务事件通道容量 `64`。
- 每个入站协议接收循环必须持续 poll。endpoint 的 auth、terminal-control、terminal-data 各只有容量 `1` 的会话入口；入口占用时立即关闭多余子流，不建立等待队列。relay 用 `tokio::sync::Semaphore::try_acquire` 限制 registry reader 最多 `16`、resolve reader 最多 `64`，每个 reader 受消息超时约束；无 permit 时立即关闭新子流。结构校验后的请求分别进入容量 `16`/`64` 的 actor channel，由单 owner 修改状态并通过 oneshot 返回响应。
- relay 的 reservation 视图、注册表、前缀状态和 direct governor limiter 由同一个 actor 独占，不使用第一方 `Arc<Mutex<_>>`、CAS 状态机或跨任务共享可变映射。`Arc<Semaphore>` 只表达不可绕过的任务准入计数，不承载业务状态。
- `yon` 的会话状态由一个 `SessionTask` 独占。PTY 同步 API 最多使用三个 `spawn_blocking` 任务：PTY 读、PTY 写和 child supervisor；supervisor 是真实 `portable_pty::Child` 的唯一所有者，以有界间隔调用 `try_wait`，收到取消后直接调用该 `Child::kill`。runtime 的 `max_blocking_threads` 固定为 `4`。
- `TaskTracker` 收集任务，`CancellationToken` 单向广播关闭；每次 spawn 同时保留有界清理所需的 `AbortHandle`，并及时裁剪已经完成的句柄。首个根错误触发取消；其他任务只回报清理错误，不能覆盖根因。全部异步任务共享一个绝对 `2s` 协作截止时间，截止后 abort 仍存活的任务并等待 tracker 确认归零。

所有 channel、map、候选集、协议消息和复制缓冲区均有硬上限。生产代码不得调用 `tokio::spawn` 后丢弃 handle，也不得依赖任务退出顺序碰巧正确。

## 终端数据与背压

- 终端数据使用独立全双工子流，控制消息使用独立低流量子流，防止大量输出阻塞 resize/exit。
- libp2p futures I/O 通过 `tokio-util::compat` 适配；不手写 AsyncRead/AsyncWrite 协议桥。
- PTY 同步两端与异步网络之间使用两个 `tokio::io::duplex(64 KiB)` 和 `SyncIoBridge`。每个复制方向使用一次创建的 `16 KiB` 缓冲区；稳定转发循环不得逐块分配。
- 网络写入慢时，固定 duplex 容量自然反压 PTY/标准输入；不丢终端字节、不无限缓存。控制消息入口容量 `8`，重复 resize 在入队前合并为最新尺寸。
- controller 为避免跨平台线程栈承载完整 libp2p 预提交 async 状态，只在启动阶段把该 future 固定到堆上；每次全能力或 relay-only 尝试各分配一次，严格最多两次，并在进入终端数据热路径前释放。
- controller 的交互输入使用固定容量状态机识别 `Ctrl+] .` 本地脱离和双 `Ctrl+]` 字面发送；跨读取块保持状态，不在终端热路径分配。非交互输入绕过该状态机。
- Crossterm 只负责 raw mode、终端尺寸和显示恢复；Windows 额外通过 safe 的 `crossterm_winapi` 打开 `ENABLE_VIRTUAL_TERMINAL_INPUT`。按键数据刻意不使用 Crossterm `EventStream`、termwiz 或其他会先解析再重编码的高层事件模型，而是保持终端产生的 raw bytes，使 Esc、方向键、Ctrl 组合、bracketed paste 和应用自定义序列无需第一方翻译即可进入远端 PTY。该取舍复用社区的平台状态抽象，同时避免重写或损坏终端协议。
- 主控端每 `250ms` 用 `crossterm::terminal::size()` 检查尺寸，只在变化时发送，避免同时读取按键事件再手写终端按键编码。
- 本地 stdin/stdout 使用 Tokio `io-std`。stdin 的底层阻塞读取不能被所有平台可靠强制取消；raw mode guard 必须先恢复，随后 runtime 最多等待 `1s` 关闭并退出进程。这是进程边界内的有界清理，不允许形成常驻后台任务。

## 取消、关闭与故障传播

正常顺序固定为：停止接受新子流和拨号、取消会话、关闭网络写半部、关闭 PTY master、由 supervisor kill 尚存 child、在同一绝对截止内等待 child 与三个 PTY 阻塞任务、等待受控异步任务 `2s` 并在截止后 abort、恢复本地 raw mode、runtime `shutdown_timeout(1s)`。达到期限时记录结构化清理错误并退出，不无限等待。若平台 `Child::kill` 本身失败且已移动的底层 PTY 读写句柄仍阻塞，`portable-pty` 的 safe 公共 API 无法强制关闭这些句柄；实现必须报告该残余失败，禁止声称进程内绝对零泄漏。

被控端在 `Active` 前的任何可恢复失败都回到 `Advertised`；`Active` 后网络失败终止 shell 和进程。主控端在 Active 连接关闭时仅为已经建立的终端子流保留绝对 `2s` 收尾窗口：data EOF 与 Exit 都完成才正常返回远端退出码，否则报告连接/收尾错误；额外同 PeerId 连接仍立即违反精确绑定。任何错误都先恢复本地终端再显示。relay 某条连接或协议失败只影响对应 PeerId，不得 panic 或停止 accept loop。

host 在认证前最多用 `3s` 让目标 PeerId 名册收敛，并在此期间持续 poll Swarm、关闭额外 auth/control/data 子流；OPAQUE 每条消息的 `10s` 上限保持独立。relay 在 Unix 统一处理 SIGINT/SIGTERM/SIGHUP，在 Windows 统一处理 Ctrl+C/Break/Close/Logoff/Shutdown，并在既有 `2s` 绝对截止内协作关闭。进程必须先同步安装平台信号监听，再构造 libp2p 网络；生命周期只输出低基数 debug 事件 `relay_signal_handlers_installed` 及 `relay_starting`、`relay_ready`、`relay_shutdown_requested`、`relay_stopped`，协议拒绝和失败按固定类别累加到每 `60s` 一次的 `relay_activity_summary`，不在公开 relay 上逐请求记录 PeerId 或错误。

## 重连与资源默认值

- relay 入口重连复用 `backon` 指数退避：最小 `250ms`、倍率 `2`、builder 最大 `5s`，开启 crate 自带 jitter（在当前 delay 上增加 `0..delay`），因此实际硬上限小于 `10s`；host 在取消前无限重试，connect 受总连接期限控制。
- 每个底层 transport 拨号/握手的内部 timeout 固定为 `8s`，一次 relay 连接 API 使用入口创建的绝对 `10s` 总截止。第一批同时竞速全部已配置 transport；失败地址只允许在起始后的 `1.5s` 内按有界退避重试，之后不再发起新拨号，并预留 `500ms` 收敛/排空，因此 `1.5s + 8s + 500ms = 10s`。rust-libp2p 的 safe 公共 API 不能取消尚未建立的 outbound connection，API 必须持续消费拨号终态、关闭败选连接并在 pending 集清空后返回；不会为了等待不可取消的旧拨号把用户可见总预算扩展到 `18.5s`。
- endpoint 每个目标 PeerId 最多 `8` 条正在选择的连接、每种 transport 最多 `2` 条；达到上限拒绝新候选。
- endpoint 复用 `libp2p::connection_limits`：pending inbound/outbound 各 `16`、established inbound/outbound 各 `16`、established total `24`、per PeerId `8`；memory connection limit 为进程 RSS `96 MiB`。
- relay 复用同一官方 behaviour：pending inbound `128`、pending outbound `64`、established inbound `320`、outbound `64`、total `320`、per PeerId `8`；该上限允许同一 endpoint 竞速最多 8 个入口及短暂 AutoNAT 连接，应用协议仍要求收敛到名册唯一。relay memory connection limit 为进程 RSS `64 MiB`。
- relay 的产品语义固定为默认 `max_reservations=128`、每 PeerId 最多 `1` 个 reservation、reservation `1h`，并且每 PeerId 最多 `1` 条 circuit。锁定的 `libp2p-relay 0.21.1` 对两个 per-peer 字段使用 `current > configured` 判断，因此适配层把对应上游字段设为 `0` 才能得到有效上限 `1`；升级上游时必须用真实双连接 reservation 回归重新核对，不能机械保留该兼容值。
- relay 默认 `max_circuits=128`、`max_circuits_per_peer=1`、单 circuit 最长 `24h`、双向合计最多 `8 GiB`。配置可以收紧或调整，但必须通过组合 newtype 校验且不能超过平台文件描述符和内存预算。
- memory connection limits 触发时拒绝新连接，不驱逐 Active 会话。上游平台内存统计暂时失败时可能沿用最近值，因此 connection count limits 始终作为独立硬边界，不能被关闭。ASan/TSan 插桩会让空载进程 RSS 超过生产阈值，因此只有显式启用 `yonder_sanitizer` cfg 的 sanitizer 验证构建把 endpoint 与 relay 阈值提高到 `512 MiB`；普通 dev/test/release 仍固定为上述 `96 MiB`/`64 MiB`，连接数与其他资源边界也不变。
