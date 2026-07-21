# 产品契约

## 目标

Yonder 让两台都只有公网出口、网络拓扑未知的设备建立一次性远程终端会话。被控端运行 `yon host` 后显示连接码，主控端运行 `yon connect` 后得到与直接打开被控端当前用户终端等价的交互体验。系统优先选择质量最好的可用端到端路径，并在直连不可用时自动使用同一自建中继转发密文。

`yon` 同时承载主控端和被控端角色；`yon-relay` 是独立、自建、无默认公共实例的中继。三种角色复用同一个网络栈，差异只在启用的行为和业务状态机。

## CLI

```text
yon [--log-level <LEVEL>] [--log-file <PATH>] host
yon [--log-level <LEVEL>] [--log-file <PATH>] connect [CODE]
yon config check
yon config sources
yon-relay [--log-level <LEVEL>] identity init --output <PATH>
yon-relay [--log-level <LEVEL>] identity show --input <PATH>
yon-relay [--log-level <LEVEL>] config check
yon-relay [--log-level <LEVEL>] serve
```

- relay、TLS 和资源设置只通过分层配置读取。优先级从高到低固定为环境变量、当前目录文件、系统文件；`yon` 使用 `yon.toml`/`YON_`，relay 使用 `yon-relay.toml`/`YON_RELAY_`。Linux 系统目录是 `/etc/yonder`，macOS 是 `/Library/Application Support/Yonder`，Windows 是 `%PROGRAMDATA%\Yonder`。Windows 必须能取得非空绝对路径形式的 `PROGRAMDATA` 才能安全定位系统层；该系统环境异常时启动失败，即使更高层已完整配置也不猜测或静默改用其他目录。嵌套环境键使用 `__`，列表使用逗号。
- `yon.toml` 必须提供 `relays`，可选 `wss_ca_der`。`relays` 接受 `1..=8` 个、文本长度各不超过 `512` 字节的中继地址；只允许 `/ip4`、`/ip6`、`/dns4`、`/dns6` 加 QUIC v1、TCP、WS 或 canonical `/tls/ws`，禁止 `/dnsaddr`、未指定 IP 和端口 `0`。所有地址必须以同一个 `/p2p/<PeerId>` 结尾，因此它们只是同一中继的不同入口，不是多个独立中继。
- `CODE` 可作为位置参数传入。省略时，TTY 使用隐藏输入；非 TTY 从标准输入读取一行后再把标准输入交给终端会话。三条输入路径得到的 `String` 都必须立即移入 `Zeroizing<String>` 并在解析后尽快销毁；位置参数的内容校验在应用边界完成，错误信息只报告“连接码无效”，Clap 和应用日志均不得回显原值。位置参数仍会暴露在 shell history 和短暂的进程参数列表中，交互使用默认采用省略参数的隐藏输入。
- 连接码、PAKE 秘密和终端字节不属于配置 schema，也不允许通过环境变量配置。`LEVEL` 是 `off/error/warn/info/debug/trace` 枚举，`yon` 默认 `error`、`yon-relay` 默认 `info`；日志级别和 `--log-file` 仍是显式 CLI 操作项。当 `connect` 的 stdout 与 stderr 同为终端且未提供日志文件时，tracing 必须关闭，应用错误仍在进度行清理后由结构化错误链显示；显式 `warn/info/debug/trace` 必须指定 `--log-file` 或重定向 stderr，避免诊断事件破坏远端终端，未分离时在网络活动前拒绝并给出命令提示。日志文件以追加模式打开，打开失败必须在网络活动前报告。
- `yon config check` 在不启动网络的情况下加载并验证有效 endpoint 配置；`yon config sources` 只展示固定系统/当前目录路径、文件状态、优先级和环境变量前缀，不输出配置值。`yon connect` 必须先完成配置校验，再向交互用户请求隐藏连接码，避免用户输入秘密后才发现本地配置错误。`yon-relay config check` 必须验证配置、identity、地址、资源组合及 TLS 材料，但不绑定 listener；`identity show` 只从受保护的 identity 文件导出公开 PeerId。
- `wss_ca_der` 向系统信任根之外增加一个 DER 编码 CA，仅用于 WSS。中继地址中的 PeerId 仍必须与完成 libp2p 身份认证后的 PeerId 一致。
- `yon-relay.toml` 必须提供 `identity`、`1..=8` 个 `listen` 和 `1..=8` 个 `external`，可提供 WSS DER 路径及 `[registry]`、`[resolve]`、`[circuit]` 资源覆盖。Circuit Relay v2 reservation 必须携带至少一个可拨号的 relay 地址，因此程序不从 wildcard、私网或 NAT 后的 listen 地址猜测公网入口，缺失 `external` 时必须在启动边界失败。地址各不超过 `512` 字节；listen 只允许可绑定的 `/ip4`/`/ip6` transport 地址且不带 `/p2p`，并允许 wildcard/端口 `0`；external 允许 IP/DNS transport 地址且不带 `/p2p`，但拒绝未指定 IP 和端口 `0`。listen 和 external 内部都拒绝重复项，每个 external transport 必须至少有一个同类型 listen；IP 和端口允许由 NAT 改写。程序展示拨号地址时追加持久 relay PeerId。
- 配置文件最大 `64 KiB`，严格拒绝未知字段、非法 TOML、非 UTF-8、目录冒充文件和无效领域值。相对路径按字段来源解析：文件字段相对于该文件目录，环境字段相对于当前目录。缺失的低优先级文件可忽略，已存在但无效的高低任一层都必须失败。
- 只有 WSS 需要运维侧 TLS 证书。relay 的服务端证书和私钥必须同时提供且是 DER；普通 WS、TCP 和 QUIC 不使用这组证书。每个 WSS external 的 DNS 名或 IP 必须分别匹配证书中的 DNS SAN 或 IP SAN，`CN` 不参与匹配；任意 WSS listen 或 external 存在而未提供证书对时必须在启动边界失败。
- 自签证书和私有 CA 均受支持。单证书自签部署中，relay 使用带 `CA:FALSE`、`serverAuth` 和正确 SAN 的自签叶证书，两个 endpoint 将同一证书配置为 `wss_ca_der`；私有 CA 部署中，relay 使用该 CA 直接签发的叶证书，endpoint 的 `wss_ca_der` 指向 CA 证书。启动边界负责有界读取、DER/密钥编码解析及 WSS external 的 DNS/IP SAN 匹配；有效期、`CA`/`serverAuth` 用途、证书链、信任关系及证书与私钥的密码学匹配由真实客户端 TLS 握手最终验证，失败时关闭连接且不降级到明文。当前服务端只发送一个叶证书 DER，不支持需要发送 intermediate chain 的部署。
- WSS 是 endpoint 直接连接 relay TCP/TLS listener 的 transport，不实现 HTTP `CONNECT`、PAC、系统代理或带凭据的显式企业代理；浏览器能访问 HTTPS 不构成 Yonder 可达性证据。
- `identity init` 使用 Ed25519 生成持久中继身份，在目标目录内原子写入且拒绝覆盖。Unix 在秘密写入前把临时文件设为 `0600`，读取 identity 和 WSS 私钥时也必须精确验证 `0600`，任何 group/other 位都拒绝。Windows 在秘密写入前通过系统 Windows PowerShell 5.1/.NET ACL API 设置受保护 DACL，并在创建和读取时验证文件、父目录、可信 owner 及允许主体；只有当前服务账户、SYSTEM 和 Administrators 可获准访问。无法执行或可靠验证平台权限时必须失败，不能以运维提示替代强制边界；精简掉 Windows PowerShell 的镜像不属于 `0.1.0` relay 支持范围。
- Clap 负责帮助、用法、参数冲突、数量和非秘密类型校验。连接码是唯一例外：Clap 只接收并立即包裹原始参数，领域解析必须在不会回显秘密的应用边界完成。

完整的默认配置形状如下；relay `identity`、`listen`、`external` 和 endpoint `relays` 没有默认值：

```toml
# yon.toml
relays = ["/dns4/relay.example/tcp/4001/p2p/12D3KooW..."]
wss_ca_der = "private-ca.der" # 可选
```

```toml
# yon-relay.toml
identity = "relay.key"
listen = ["/ip4/0.0.0.0/tcp/4001"]
external = ["/dns4/relay.example/tcp/4001"]
wss_certificate_der = "relay-cert.der" # 与私钥同时提供或同时省略
wss_private_key_der = "relay-key.der"

[registry]
capacity = 128
per_source = 32
reservation_duration_seconds = 3600

[resolve]
concurrency = 64
global_rate_per_second = 4
global_burst = 128
source_rate_per_second = 1
source_burst = 32
source_limiter_capacity = 4096
source_limiter_idle_seconds = 600
retry_milliseconds = 250

[circuit]
capacity = 128
duration_seconds = 86400
bytes = 8589934592
```

## 被控端生命周期

1. 创建进程级临时 Ed25519 身份和 OPAQUE 注册状态。
2. 并发连接同一中继的已配置入口，按质量只保留一条基础连接，再取得 Circuit Relay v2 reservation；终端运行时用单行进度显示连接、reservation 和有界重试状态。
3. 注册定位码前显示注册状态，输出连接码前先清除进度行；随后显示等待主控端。中继失效时显示重连状态，恢复后回到等待状态。定位码冲突导致换码时再次先清行，在 stderr 明确声明旧码已失效，再把完整新码写入 stdout；即使提示通道写入失败，已成功分配的新码仍必须输出，不能因此丢失可用会话。
4. 解析候选端到端连接、完成唯一连接屏障、OPAQUE 认证和终端建立。
5. `TerminalReady` 成功刷新时消耗连接码；向中继尽力发送注销，但注销成功不是会话提交条件。
6. 当前用户 shell 退出或会话不可恢复地断开后，清理 PTY、恢复状态并退出 `yon host`。v1 每个进程只提供一个成功会话。

中继短暂断开时，host 按既定的有界退避策略重连；`120s` 内恢复同一 PeerId、reservation 和定位映射时连接码保持不变。中继重启导致映射丢失时，host 先以同一 PeerId `Reclaim` 原定位码：定位码仍空闲则完整连接码保持不变；只有定位码已被其他 PeerId 占用并返回 `Conflict` 时，才重新生成 locator、PAKE secret 和 OPAQUE 注册状态，明确输出一枚全新的完整连接码，并让旧码立即本地失效。

## 主控端生命周期

1. 在边界解析并规范化连接码，并发连接配置的同一中继入口后只保留一条基础连接。
2. 只把 20 bit 定位码发送给中继，解析目标 PeerId。
3. 建立 relay circuit，同时尝试 DCUtR、UPnP 已发布地址和已发现的直接地址；尚无任何端到端候选时保留 `30s` 总连通期限。首条候选出现后至少等待 `1.5s` 采样；尚未形成直连时，DCUtR 最多获得固定 `3s` 优先窗口。直连恰在采样窗末尾建立且尚无样本时，最多再给 `750ms` 取得一个样本。无 Ping 样本的已建立连接仍是可用 fallback，Ping 只能改善同类候选排序，不能否决已经建立的路径。
4. 优先窗口内出现已完成 libp2p 传输身份认证的直连候选时，controller 只在直连集合内部选出一条连接并完成唯一连接屏障，relay 的较低本地 RTT 不能覆盖可用直连。同类候选排序先区分有样本与无样本，再按 RTT 中位数；只有双方都有至少两个样本时才比较抖动极差，最后依次使用 QUIC 优于 TCP 优于 WS/WSS、建立顺序作为确定性 tie-break，不以样本数量或连接年龄冒充质量。DCUtR 事件的 `ConnectionId` 仅是本端标识，不能假定双方成功事件指向同一物理连接；controller 是唯一选路者，host 跟随 loser 关闭并绑定剩余的唯一认证连接。若没有直连且 DCUtR 明确失败或 `3s` 内没有形成直连，销毁整个 Swarm 以取消所有在途拨号，生成新的临时 endpoint 身份，并仅执行一次禁用 DCUtR 的 relay-only 重连、重新查询和认证；不循环重建。最终选中的 route 与 transport 进入诊断日志而不污染终端画面。
5. 完成 OPAQUE 并打开终端控制流和数据流后，先取得本地 raw mode guard，再发送 `TerminalHello` 触发远端 PTY 创建；收到 `TerminalReady` 后开始转发字节。
6. 当 stdout 与 stderr 同为终端时，网络准备期间由类型安全的进度边界在 stderr 同一行显示当前阶段；首次反馈必须早于网络 future，任一阶段持续超过 `1s` 时用 ASCII spinner 心跳，每次刷新重新取得终端宽度，且提示最多占当前宽度减一列，不能自动换行。这不依赖 stdin 是否为 TTY，因此连接码或后续输入来自管道时仍能解释当前等待。收到 `TerminalReady` 后必须先清除该行，再显示远端输出、转发本地输入和窗口变化。远端 shell 退出后恢复本地终端并退出；stdout 非终端、stderr 已重定向、`TERM=dumb` 或无法取得可靠终端尺寸时不显示进度行。

raw mode 只在网络、认证和两条终端子流都已成功后启用，但必须早于会触发远端 PTY 创建及连接码消费的 `TerminalHello`。进入 raw mode 失败时不会发送 hello，远端保持未提交状态；后续握手失败时 guard 负责恢复。所有受控退出路径必须先恢复 raw mode；panic、进程被强制终止、断电或内核终止不在可恢复保证内，文档和实现不得宣称这些情况下绝对恢复。

## Shell 语义

- Unix 使用被控进程环境中的 `SHELL`，它必须是无 NUL 的绝对路径，指向现存且至少具有一个执行位的普通文件；无效或缺失时使用 `/bin/sh`。
- Windows 使用 `COMSPEC`，它必须是指向现存普通文件的绝对路径；无效或缺失时使用 `cmd.exe`。Windows 没有统一 API 能读取终端应用中选定的 PowerShell、CMD 或其他 profile，因此这里的“当前用户 shell”严格指操作系统命令解释器环境，而不是终端应用 profile。
- shell 在 PTY 中启动，不拼接命令字符串，不提升权限，不切换用户。它继承被控 `yon` 的当前工作目录、环境和权限，只用主控端提供且已校验的 `TERM`、`COLORTERM` 覆盖同名变量。
- Ctrl+C、Ctrl+Z 和应用终端字节原样送入 PTY。交互主控端只保留一个本地脱离前缀：`Ctrl+]` 后跟 `.` 会在本地结束会话，`Ctrl+]` 后再跟 `Ctrl+]` 会向远端发送一个字面 `Ctrl+]`；状态机跨读取块保持语义一致且不分配。非交互输入不解释该前缀，所有字节原样转发。
- Unix PTY 可以在已排队输入写完后把 controller 的输入半关闭映射为 shell EOF。ConPTY 关闭输入 writer 会同时拆除伪控制台，无法可靠表达不截断输出的通用 EOF；因此 Windows 非交互脚本必须在转发内容末尾显式发送适合当前 shell 的退出命令（默认 `cmd.exe` 为 `exit`）。交互会话和显式退出不受此限制，Yonder 不伪造可能丢失尾部输出的 EOF。

## 支持平台与分发

| 系统 | Rust target | 产物属性 |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-musl` | 完全静态 ELF |
| Linux arm64 | `aarch64-unknown-linux-musl` | 完全静态 ELF |
| Windows x86_64 | `x86_64-pc-windows-msvc` | 单 EXE、静态 CRT，只依赖系统 DLL |
| Windows arm64 | `aarch64-pc-windows-msvc` | 单 EXE、静态 CRT，只依赖系统 DLL |
| macOS Intel | `x86_64-apple-darwin` | 单 Mach-O，只动态链接系统 `libSystem`/系统框架 |
| macOS Apple Silicon | `aarch64-apple-darwin` | 单 Mach-O，只动态链接系统 `libSystem`/系统框架 |

每个 target 同时发布 `yon` 和 `yon-relay`，不附带运行时、配置模板、CA、资源文件或第三方动态库。macOS 不支持把系统库完全静态链接进普通应用，“单二进制分发”不等于静态嵌入 `libSystem`。

## 错误与退出

- 错误使用按领域划分的枚举并在 CLI 边界渲染；跨模块错误不得是裸 `String`。
- 网络响应不会区分连接码不存在、过期或已消费；CLI 对查询和认证失败统一精确显示 `connection code is invalid or expired`。认证错误不显示密码、OPAQUE 内部状态、PeerId、locator 或可用于探测的细节。
- Clap 参数错误使用退出码 `2`；会话建立前的配置、网络、认证、协议或终端错误使用退出码 `1`。
- 成功进入 Active 后，主控端返回远端 shell 的 `0..=255` 退出码；更大的平台退出值映射为 `1` 并在结束期警告中记录原值，不依赖 tracing 级别。被信号结束时使用 `portable-pty` 给出的可移植退出码。Active 后的应用错误、退出码警告和本地 raw mode 恢复失败必须在共享终端上先另起一行再显示；raw mode 正常恢复和会话根错误同时失败时结构化错误必须保留两者。
- `host` 在等待阶段收到 Ctrl+C 时有界清理并安静返回 `130`；controller 在 Active 前收到本地终止信号同样返回 `130`。Active 中的 Ctrl+C 是远端终端字节，本地脱离使用 `Ctrl+] .`。被控端收到会话关闭后终止 shell、关闭 PTY 并退出失败。已经主动脱离该 PTY/session 的后台进程不保证被终止，这与本地 shell 的脱离语义一致。

## v1 非目标

- SSH 协议、OpenSSH 配置、SSH agent、SFTP 或 SSH 端口转发兼容。
- 文件传输、剪贴板同步、图形界面、浏览器端、多人会话和会话恢复。
- 公共中继发现、中继联盟、跨中继复制、多个不同中继间故障转移或中继持久化连接码数据库。
- 隐藏流量元数据、抵抗已入侵端点、抵抗拥有当前用户权限的本地攻击者。
- Active 会话的路径热迁移。当前连接失败即结束会话，不恢复已经消费的连接码。
