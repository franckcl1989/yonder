# Protocol v1

## 通用规则

所有整数使用网络字节序。每个应用协议由 multistream-select 的完整 ID 版本化，消息体不再重复版本。解析器使用固定数组或有上限的栈/单次缓冲区，禁止按远端声明的无界长度分配。未知 tag、保留位非零、截断、超长、非法枚举或尾随状态数据都关闭该子流并产生结构化协议错误。

协议 ID 固定为：

```text
/yonder/registry/1.0.0
/yonder/resolve/1.0.0
/yonder/auth/1.0.0
/yonder/terminal/1.0.0
/yonder/terminal-control/1.0.0
```

每个 registry/resolve 子流只处理一个请求和一个响应；请求方发送固定请求后关闭写半部，接收方必须在精确长度后读到 EOF 才处理，因此尾随字节会被可靠拒绝。未来不兼容格式使用新的协议 ID；只在协商明确不支持当前版本时才能选择另一个已批准版本，认证或解析失败后禁止自动降级。

## 连接码

- 字符表：`0123456789ABCDEFGHJKMNPQRSTVWXYZ`。
- 规范形式：`XXXX-XXXX-XXXX-XXXX`，前 4 字符是 20 bit `Locator`，后 12 字符是 60 bit `PakeSecret`。
- 输出总是大写并带三个连字符。输入接受大写/小写、规范分组或无连字符紧凑形式；`O/o` 归一为 `0`，`I/i/L/l` 归一为 `1`。`U/u`、空白、其他分隔符、错误组长和错误总长拒绝。
- 20 bit 和 60 bit 空间的全部值均合法，包括全零。编码和解码由 `data-encoding` 的自定义 Specification 完成，第一方只负责分组和领域校验。
- secret 和认证 nonce 由被控端 CSPRNG 均匀生成；locator 由 relay 以 CSPRNG 随机起点加环形扫描分配。

连接码只在被控进程内存和主控输入边界出现。relay、日志、指标和错误中永远不能出现后三组。

## Registry

`/yonder/registry/1.0.0` 只允许在 endpoint 与其配置并完成身份认证的 relay 之间使用。请求恰好 4 字节：

| tag | 名称 | 后 3 字节 |
| --- | --- | --- |
| `0x01` | `Allocate` | 必须全零 |
| `0x02` | `Reclaim` | locator，最高 4 bit 必须为零 |
| `0x03` | `Release` | locator，最高 4 bit 必须为零 |

响应恰好 5 字节：`tag || value:u32`。

| tag | 名称 | value |
| --- | --- | --- |
| `0x80` | `Acquired` | locator，最高 12 bit 为零 |
| `0x81` | `Released` | `0` |
| `0x82` | `Retry` | `100..=5000` 毫秒 |
| `0x83` | `Conflict` | `0` |
| `0x84` | `Capacity` | `0` |
| `0x85` | `ReservationRequired` | `0` |

owner PeerId 和来源地址取自 relay 本地该 PeerId 名册中的唯一 libp2p 连接，wire 不携带；名册不是恰好一条时返回 Retry。`Allocate` 对已有映射的同一 PeerId 幂等返回原 locator。`Reclaim` 对同一 PeerId 的 Active/Suspended 映射幂等；无原映射且 locator 空闲时创建，已被其他 PeerId 占用时返回 `Conflict`。`Release` 只删除调用 PeerId 自己的匹配映射；已不存在也幂等返回 `Released`。

只有“该 PeerId 存在有效 relay reservation”且“至少一条该 PeerId 到 relay 的连接仍存在”时映射为 Active。任一条件失效即进入 Suspended；即使控制连接仍在，reservation 到期也必须 Suspended。Suspended 查询返回 Retry，`120s` 后删除。正常 Release 立即删除。

新建映射总数默认 `128`，每 PeerId `1`，每来源 IPv4 `/32` 或 IPv6 `/64` 默认 `32`。映射记录首次创建时的来源前缀并在该映射生命周期内保持不变；同 PeerId 从其他网络恢复不会转移计数，也不会被当作新建。总数和来源配额都只统计仍存活的 Active/Suspended 映射，Release 或宽限到期删除时同步递减，绝不能变成 relay 重启前的累计终身计数。分配从随机 20 bit 起点环形递增；表未满时最多检查 `129` 个值。容量满时不驱逐。

## Resolve

`/yonder/resolve/1.0.0` 请求恰好 3 字节 locator，最高 4 bit 必须为零。响应为以下一种：

| 首字节 | 格式 | 语义 |
| --- | --- | --- |
| `0x80` | `tag || peer_len:u8 || peer_id[peer_len]` | `Resolved`；`peer_len=1..=64` |
| `0x81` | `tag || retry_ms:u32` | `Retry`；`100..=5000` |
| `0x82` | 只有 tag | `Unavailable` |

PeerId 使用 `PeerId::to_bytes()`/`from_bytes()`。只有 Active 映射返回 Resolved；Suspended 或限速返回 Retry；不存在、过期和已消费统一 Unavailable。查询不锁定、不消费、不改变连接码。

每个查询 PeerId 同时只处理一个查询，并且其 relay 本地连接名册必须恰好一条，来源前缀从该连接取得；无法由 `libp2p-stream` 可靠观察的“每物理连接”不作为协议不变量。处理顺序为固定长度校验、名册/并发校验、全局 governor、来源 governor、注册表。全局默认 burst `128`、恢复 `4/s`；来源默认 burst `32`、恢复 `1/s`。完整但 locator 编码非法的请求消耗全局额度；截断和超长直接关闭。来源状态 `10min` 空闲回收，硬上限 `4096`；满时新来源返回 Retry，不驱逐活跃项。

## OPAQUE 注册与认证

被控端在本地同时扮演一次性 OPAQUE 注册客户端和服务端，生成仅驻留内存的 `ServerSetup` 与 password file；网络认证时主控端是 client、被控端是 server。密码套件固定为 RFC 9807 OPAQUE、Ristretto255、TripleDH、SHA-512、Argon2id `v=0x13,m=19456 KiB,t=2,p=1`。`credential_identifier` 和 server identifier 都使用被控端 PeerId bytes，client identifier 为空；注册 finish、client login finish 和 server login 必须显式传入完全相同的 identifiers，不能依赖 crate 默认值。

认证 context 精确连接以下字段，不加外层长度：

```text
ASCII "/yonder/auth/1.0.0"
locator[3]
controller_peer_len:u8 || controller_peer_id
target_peer_len:u8 || target_peer_id
controller_nonce[32]
target_nonce[32]
```

两个 PeerId 长度均为 `1..=64` 且来自已经完成 transport 身份认证的唯一 libp2p 连接。context 最大 256 字节，使用一次有界缓冲区构造。路径类型、transport 和本地 `ConnectionId` 不进入共享 context；物理连接绑定由唯一连接屏障保证。

`opaque-ke 4.0.1` 在冻结套件下实测序列化长度为 KE1 `96`、KE2 `320`、KE3 `64` 字节，并由编译期类型与 golden test 锁定。认证状态流为：

1. client 发送 `controller_nonce[32] || KE1[96]`，恰好 `128` 字节。
2. server 可发送 `0x02 || retry_ms:u32` 后关闭；否则发送 `0x01 || target_nonce[32] || KE2[320]`，恰好 `353` 字节。
3. client 发送 KE3，恰好 `64` 字节。
4. server 完成 `ServerFinish` 后先由单一 owner 重验唯一连接、记录授权并同步提交 `Authenticating -> AwaitingTerminal`，随后发送并 flush 单字节 `0x03` (`Authenticated`)。发送确认的同一阶段必须继续驱动 Swarm，并用既有有界 `PendingPair` 接收 control/data 每类第一条，不能在确认写入或认证子流关闭尚未收敛时丢弃合法终端流。

单条消息等待上限 `10s`，完整交换总上限 `20s`。被控端每个 code 同时最多一个交换；认证启动 governor burst `4`、恢复 `1/s`，只在收到结构合法的完整首消息后消耗。并发占用、唯一连接尚未收敛或额度不足使用 Retry；所有 OPAQUE/密码/上下文失败直接关闭且不区分原因。失败不消费连接码。

## Terminal Control

主控端收到 `Authenticated` 后 `10s` 内依次打开 control 和 data 子流。被控端以 `Authenticated` 成功 flush 作为本地 `10s` 绝对截止起点；每类只接受目标 PeerId 的第一条，重复或异 PeerId 流关闭，两条都到达才创建 PTY。确认 flush 自身仍受认证阶段剩余的有界截止约束，不能无限等待。

control 第一条消息必须是：

```text
0x01
cols:u16
rows:u16
term_len:u8 || term[term_len]
colorterm_len:u8 || colorterm[colorterm_len]
```

`cols`、`rows` 为 `1..=65535`。两个字符串长度分别 `0..=64`，只允许 ASCII 字母、数字、`.`、`_`、`+`、`-`；空值表示不覆盖。之后主控端可发送任意个 resize：`0x02 || cols:u16 || rows:u16`。被控端 shell 结束后发送 `0x80 || exit_code:u32`，随后关闭 control。

方向错误的 tag、非法尺寸/字符串或任何未知消息关闭会话。control 只传终端元数据，不传按键或输出。

## Terminal Data 与提交点

`/yonder/terminal/1.0.0` 在握手阶段由主控端先取得本地 raw mode guard，再通过 control 子流发送 `TerminalHello`；进入 raw mode 失败时禁止发送 hello。被控端成功创建 PTY/shell 后通过 data 子流写单字节 `0x01` (`TerminalReady`) 并 flush，此次 flush 是连接码消费提交点。主控端收到并校验 `TerminalReady` 前不得转发 stdin，被控端不得把 PTY 输出作为已建立会话发送；任一握手失败都必须恢复主控端 raw mode，提交点前还必须撤销被控端授权并清理 PTY。

被控端状态固定为：

```text
Advertised -> Authenticating -> AwaitingTerminal -> StartingTerminal -> Active -> Spent
```

- 认证失败、超时、唯一连接失效：`Authenticating -> Advertised`。
- OPAQUE 成功：`Authenticating -> AwaitingTerminal`；两条终端流须在 `10s` 内到齐。
- 两条流合法：`AwaitingTerminal -> StartingTerminal`。PTY、shell、bridge 或 Ready 失败会 kill child、清理并回到 Advertised。
- PTY/shell 成功且 Ready 已 flush：原子转换 `StartingTerminal -> Active`。这是连接码唯一权威消费点。
- Active 后断线或 shell 退出：`Active -> Spent`，不得恢复连接码；host 清理后退出。

Ready 后 data 子流全部字节都是不解释、不分帧的原始终端数据，双向传输直到 EOF。flush 成功不能证明主控应用已经读取 Ready；提交瞬间断网可能使 code 已消费但主控未显示终端，这是已接受的分布式提交窗口。

child exit 后，被控端停止接受新输入，最多等待 `2s` 把 PTY reader 排空到 data 写半部并关闭，再发送 Exit；data EOF 与 Exit 的到达顺序不构成协议错误。主控端必须同时观察 data EOF 和 Exit 才按远端退出码正常结束。排空、Exit 或关闭在期限内失败属于 Active 会话错误，不能静默报告正常退出。

## Relay 信道与中继限制

controller 与 target 通过 Circuit Relay v2 建立的连接仍由两个 endpoint 完成 Noise 或 QUIC/TLS 身份认证与加密；relay 只转发密文。relay 默认 reservation 和 circuit 参数见 architecture。超过 `24h`、`8 GiB` 或连接资源限制时 circuit 关闭，Active 会话结束。

target 在提交后尽力发送 Registry Release。Release 丢失不会回滚 Active；relay 最终根据 reservation/连接消失进入 Suspended 并在 `120s` 后清除。
