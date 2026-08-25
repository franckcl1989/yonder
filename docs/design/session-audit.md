# 企业会话可验证审计

## 启用边界

审计只对通过 Enterprise Resolve 建立的会话自动、强制、双端启用；普通 relay 会话完全禁用。企业 controller 和 host 必须在 OPAQUE 成功、唯一连接确定之后，Terminal Active、终端输入和文件传输之前完成 `/yonder/audit/3.0.0` 握手。任一端不支持、身份/存储不可用或握手不一致都在 PTY 创建前失败关闭，不存在单端记录或无审计降级。

relay 不理解、不保存、不验证审计。两端分别保存本地 `.yonaudit` 文件，通过持久 Ed25519 身份、每会话临时签名密钥、共享事实哈希链、周期双端检查点、最终共同清单、记录封印和本地连续账本证明记录来源、完整性和双端一致前缀。

审计对象是字节级会话事实，不解析 shell 命令。记录完整网络终端输出和 controller 实际提交显示的字节；原始键盘输入永不落盘，只记录长度和使用未持久化会话私钥计算的 HMAC-SHA-256 承诺。文件内容、连接码、OPAQUE 状态、会话秘密和临时私钥不记录。

## 本地身份与存储

审计根目录固定为：

| 平台 | 路径 |
| --- | --- |
| Linux | `$XDG_STATE_HOME/yonder/audit`；未设置时 `~/.local/state/yonder/audit` |
| macOS | `~/Library/Application Support/Yonder/Audit` |
| Windows | `%LOCALAPPDATA%\Yonder\Audit` |

显式环境路径必须是非空绝对路径，异常时失败关闭。目录结构：

```text
Audit/
|-- identity.ed25519
|-- ledger.state
|-- ledger.lock
`-- records/
    `-- <session-id>.<controller|host>.yonaudit
```

首次企业会话自动生成持久 Ed25519 审计身份；已有历史/账本但身份缺失或损坏时禁止生成新身份掩盖断链。Unix 目录创建即 `0700`，文件创建即 `0600`，拒绝 symlink 和不可信 owner/父目录。Windows 必须复用 `SecretFilePolicy` 的 PowerShell 5.1/.NET ACL 适配：受保护 DACL 只允许当前用户、SYSTEM、Administrators，并在创建/打开时复核 owner 和 ACE；适配不可用或验证失败即拒绝企业会话。第一方不写 unsafe/FFI。

身份、账本和记录排他/原子创建。账本通过 `fs4` 的同步文件锁把读取、验证、推进和替换串行化，锁只存在于短临界区且在 Tokio runtime 外执行。审计记录不自动轮转、删除或静默丢弃；空间不足必须在可观察效果前失败关闭。保留/归档由企业运维策略负责。

## 密码学模型

- 持久身份和会话签名使用 `ed25519-dalek 3.0.0`；持久身份签署本次临时公钥、连接绑定与账本快照，临时密钥签署检查点和最终清单。
- 两端各生成 32 字节秘密贡献并先在 `AuditHello` 中提交 SHA-256 commitment，再交换原值；贡献验证后按 controller/host 固定顺序用 HKDF-SHA-256 派生输入承诺键，原始贡献和派生键在会话结束时清除。
- 输入承诺为 `HMAC-SHA-256(key, domain || direction || sequence || length || bytes)`；记录只含 sequence、length 和 MAC。没有未持久化 key 的审计文件不能成为离线猜测输入的验证器。
- 共享事实按 Input、Output、Control、FileTransfer 四条 SHA-256 链分别累计；本端独有显示适配、路径和 I/O 结果进入本地观察链。时间只进入本地时间线，不进入跨端一致性链。
- 所有本版会话内容哈希、签名、HKDF 和 HMAC 使用版本化、互不相同的域分离标签 `yonder-audit-*-v3`。连接绑定包含已认证 controller/host PeerId、OPAQUE 会话绑定、双方随机数和本次唯一连接的本地授权事实摘要，不包含 relay 可声明身份。持久账本的 genesis 标签仍固定为 `yonder-audit-ledger-genesis-v2`，以保持已经存在的 `ledger.state` 连续谱系；它不是本版 wire/container 内容域，禁止随格式升级重置。

## Wire

每条消息为 `tag:u8 || payload_length:u32(be) || payload`，payload 上限 `1024`，完整帧上限 `1029`。接收方必须先按 tag 验证精确或有界长度再读取；未知 tag、非法枚举、保留值、截断、超长和尾随字节关闭子流。文件容器版本与协议版本独立，本版 `format_version=3`。

| Tag | 消息 | Payload 长度 | 作用 |
| --- | --- | --- | --- |
| `0x01` | `AuditHello` | 267 | 角色、持久/会话公钥、nonce、账本快照、连接绑定、format、贡献 commitment、持久签名 |
| `0x02` | `SecretContribution` | 32 | 原始秘密贡献，只在线且立即清除 |
| `0x03` | `AuditReady` | 130 | session ID、对端 hello 摘要、format、会话签名 |
| `0x04` | `Checkpoint` | 328 | 序号、四条共享链快照、本地链/账本摘要、会话签名 |
| `0x05` | `CheckpointAck` | 296 | checkpoint 摘要、相同共享快照、会话签名 |
| `0x06` | `JointManifest` | 400 | 双方身份/会话键/绑定、terminal 摘要、最终链、结束原因 |
| `0x07` | `ManifestSignature` | 64 | 对共同清单的会话签名 |
| `0x08` | `LocalRecordSeal` | 329 | 本地链、共享链、清单和 sealed prefix 的本端封印 |
| `0x09` | `LedgerCommit` | 233 | 前一根、session、record 摘要、对端身份、结果和持久签名 |
| `0x0A` | `CloseNotice` | 1 | 正常退出、detach、中断、连接丢失、审计失败 |
| `0x0B` | `AuditError` | 2 | 固定结构化失败码 |

逐字段布局固定如下；数组均为原始字节，所有整数大端：

- `AuditHello`：`role:u8 || persistent_key[32] || session_key[32] || nonce[32] || ledger_sequence:u64 || ledger_root[32] || connection_binding[32] || format_version:u16 || input_commitment[32] || signature[64]`。
- `SecretContribution`：`contribution[32]`，其 SHA-256 必须等于对端已签名 hello 中的 commitment。
- `AuditReady`：`session_id[32] || peer_hello_digest[32] || format_version:u16 || signature[64]`。
- `Checkpoint`：`session_id[32] || sequence:u64 || snapshot[160] || local_chain_head[32] || ledger_snapshot_digest[32] || signature[64]`。
- `CheckpointAck`：`session_id[32] || sequence:u64 || checkpoint_digest[32] || snapshot[160] || signature[64]`。
- `JointManifest`：`format_version:u16 || session_id[32] || controller_fingerprint[32] || host_fingerprint[32] || controller_session_key[32] || host_session_key[32] || connection_binding[32] || terminal_hello_digest[32] || final_snapshot[160] || ending_tag:u8 || ending_value:u32 || ended_normally:u8 || final_checkpoint_sequence:u64`。
- `LocalRecordSeal`：`session_id[32] || role:u8 || final_local_root[32] || local_count:u64 || final_shared_roots[128] || manifest_digest[32] || sealed_prefix_digest[32] || signature[64]`。
- `LedgerCommit`：`sequence:u64 || previous_root[32] || session_id[32] || manifest_digest[32] || sealed_record_digest[32] || peer_fingerprint[32] || result:u8 || signature[64]`。

`snapshot` 按 Input、Output、Control、FileTransfer 固定顺序各包含 `count:u64 || head[32]`。角色只有 `1 Controller/2 Host`；ledger result 只有 `1 Normal/2 Interrupted/3 AuditFailed`；`ended_normally` 只有 `0/1`。结束类型为 `1 ShellExit` 或 `2 CloseReason`：`ShellExit` 的 `ending_value` 保留终端协议完整 `u32` 退出码，`CloseReason` 只允许低八位的 `1 NormalShellExit/2 ControllerDetach/3 LocalInterrupt/4 ConnectionLost/5 AuditFailure`，高 24 位必须为零。共享 `TerminalExit` 控制事件也携带相同的四字节大端 `u32`。签名覆盖对应 payload 除 signature 外的全部字段，并分别加 `yonder-audit-<message>-v3` 域前缀。实现必须在 `yonder-core::wire::audit` 用公开常量逐字段定义，并用 compile-time/golden/property/fuzz 锁住总长度；文档与代码任何不一致都视为发布阻塞缺陷。

审计 v3 是 0.2.0 发布前对未被接受的 v2 草案的受控替换：0.1.1 没有企业审计，端点不协商或降级到 `/yonder/audit/2.0.0`，离线验证器把具有 Yonder magic 但 `format_version != 3` 的容器报告为“不支持的审计格式”，不得报告为 `TAMPERED`。本次破坏性升级保留上述账本 genesis 谱系。

双方签名容器头中的 `AuthMode::Enterprise` 表达本次会话经双方配置的企业 relay 和 Enterprise Resolve 建立，并不构成 endpoint 对成员身份的独立密码学证明。成员身份只在作为准入可信决策点的 relay 内用于判断，验证后立即清除；Enterprise Resolve 不向端点传播该身份，因此共同清单不得包含成员标识、提供商用户 ID 或由其派生的稳定值。离线验证能够证明双方共同记录了 Enterprise 模式，不能在 relay 已被攻陷的威胁模型下反向证明 OAuth 成员检查确实执行。

握手固定为双方发送 `AuditHello` 和 `SecretContribution`，验证承诺与持久签名，按角色顺序计算相同 session ID/输入承诺键，安全创建并同步本地 header，交换并验证 `AuditReady`。只有双方 ready 成功，host 才能创建 PTY 并发送 TerminalReady。每个独立 wire 读写继续受绝对 `10s` 上限约束；包含身份/账本打开、排他创建记录、header 持久同步和全部握手消息的整个审计建立阶段使用独立绝对 `30s` 总预算，避免正常安全存储初始化挤占单条对端消息预算。两层截止都必须失败关闭，不能超时后降级为无审计会话。

检查点在距上次检查点 `1s`、新增规范共享数据达到 `1 MiB`、文件操作边界或关闭边界任一条件满足时触发。快照永远描述生成它之前的链头，避免自引用。运行期检查点是发送方对其当时四条共享链的会话密钥签名观察，Ack 是接收方对该检查点摘要及原快照的会话密钥签名回执；由于 terminal、file 与 audit 使用独立 libp2p 子流，接收时不得假定本地链恰好停在同一快照，也不得用跨子流到达顺序制造伪不一致。发送记录必须与发送方本地链位置一致，接收记录由签名、严格递增的方向内序号、Ack 原快照绑定及双文件交叉验证证明。关闭屏障后的最终双边检查点仍要求双方四条链的 count/head 精确相同，随后构造的 `JointManifest` 必须逐字节一致。检查点发送不能阻塞每个终端块，但延迟达到硬上限时施加背压，不能静默跳过。

正常结束顺序固定为：`CloseNotice -> 记录共同关闭事实并封闭 input/output 规范化方向 -> 结清在途运行期 Checkpoint/Ack -> 交换快照精确一致的最终 Checkpoint/Ack -> JointManifest -> controller ManifestSignature -> host ManifestSignature -> LocalRecordSeal -> LedgerCommit -> record sync_all -> ledger 原子推进`。关闭事实和最后部分块提交后共享快照才稳定；禁止把跨越关闭边界晚到的运行期观察误当最终检查点。任一步失败都报告审计失败，不能只返回 shell 退出码。连接异常时不伪造共同清单，只封存本地可验证记录；双文件离线验证按发送/接收两个独立方向交叉匹配已签名 Checkpoint 与 Ack，并以第二次有界流式遍历证明所选快照确为双方共享链前缀，不在内存中保留无界链头历史。

`AuditError` 固定码：`1 IdentityMissing`、`2 IdentityInvalid`、`3 IdentityPermissions`、`4 LedgerInvalid`、`5 LedgerConflict`、`6 DirectoryUnavailable`、`7 RecordCreateFailed`、`8 RecordWriteFailed`、`9 RecordSyncFailed`、`10 ProtocolUnsupported`、`11 HandshakeInvalid`、`12 SessionBindingMismatch`、`13 CheckpointMismatch`、`14 PeerSignatureInvalid`、`15 FinalManifestMismatch`、`16 LedgerCommitFailed`、`17 ReplayUnsafe`、`18 ContainerInvalid`。对端自由文本不得进入 CLI。

## 记录与并发

`AuditObserver` 是终端/文件与审计的唯一窄边界，提供输入发送前、PTY 写入前、输出发送前、显示写入前、resize、文件事件、关闭和最终化方法。需要 append-before-effect 的方法把有界 record batch 交给专用 writer 并等待确认后才允许外部效果；状态推进或 writer append 任一失败都进入同一 fail-closed 路径，立即停止新效果、终止 PTY/文件、恢复本地终端，并尽力按 `AuditError -> CloseNotice(AuditFailure)` 通知对端。失败记录与这两个通知共用 writer 的绝对 `2s` 失败关闭窗口，通知不得再各自串联普通 `10s` wire 超时；对端停止读取审计子流时仍须按时恢复本地终端。writer 错误不能只毒化后台任务而让会话继续。

文件传输开始和终态记录同样必须传播 writer 结果，禁止在返回传输结果前丢弃错误。开始记录失败必须返回类型安全的 `AuditFailedBeforeCommit`，不创建最终目标，并显示 `upload/download aborted: audit recording failed; session closing`。若原 wire 结果为 `Committed` 而终态记录失败，传输层返回 `AuditFailed { bytes }`，controller 显示 `upload/download committed: <bytes> bytes; audit recording failed; session closing`；receiver 的原子文件已经存在，不能谎称失败、取消或回滚。若原结果已经是 `Failed`、`Cancelled`、`CommittedUnconfirmed` 或 `CommitStatusUnknown`，UI 必须先保留该更具体的主结果，再追加 `audit recording failed; session closing`。controller 与 host 都必须让该权威 observer 失败唤醒会话所有者并终止企业会话，不能依赖对端合作关闭。该本地 outcome 不新增或改变文件 wire 消息。

所有本地 effect outcome 的 `0x01/0x02` 统一解释为 `Confirmed/Unconfirmed`，而不是“成功/绝对未发生”：`Confirmed` 只表示对应的完整写入及 flush 在所有者截止前返回成功；`Unconfirmed` 表示截止前未取得这一确认，操作可能完全未发生、部分发生，或在不可取消的操作系统阻塞写已经派发后延迟完成。关闭路径取消 Tokio stdout、PTY 或网络写时必须记录 `Unconfirmed`，不得声称目标端一定没有收到字节；这项本地不确定性不允许推进任何共享事实，也不得绕过会话失败关闭。

企业会话的活动期事件泵必须确定性地先处理连接取消/生命周期与审计帧，再处理同时就绪的终端 EOF、终端 I/O 和文件事件。这样，对端已经发送的强制审计失败不会因独立终端子流恰好同时关闭而被随机降格为普通 I/O 断开；该优先级只决定同时就绪事件的根因归类，不允许审计处理长期饿死终端或绕过现有背压与超时。

活动期检查点轮询使用跨事件持续存在的 `250ms` 周期计时器，controller 与 host 语义完全一致。终端尺寸、PTY、文件、Swarm 或审计帧事件只能让该计时器继续前进或按 `Skip` 策略跳过积压 tick，禁止在每轮事件选择时重新创建相对 timeout；否则同周期的 resize 或网络事件可能无限重置检查点并破坏双向收敛。检查点发送、接收和帧处理仍各自由一个持久 future 独占，任何写盘或子流背压都不得停止其他网络分支被 poll。

本地审计失败的尽力通知顺序固定为 `AuditError(code) -> CloseNotice(AuditFailure)`；前者保留结构化失败类别，后者驱动统一关闭。接收任一帧都必须立即失败关闭，不得等待另一帧或因随后出现的终端 EOF 改写根因。

writer 使用容量固定的有界队列，并运行在命名的独立 `std::thread` 上；该线程拥有私有 current-thread Tokio runtime、记录句柄和哈希状态，不占 `yon` 上限为 `4` 的 Tokio blocking pool。PTY 最多三个长生命周期 blocking job 因而不会与审计 writer 一起耗尽文件系统所需的第四个 worker。不共享 `File`、不无界缓存、不每事件 `fsync`。规范块最大 `16 KiB`，每方向最多一个未检查点部分块；队列容量和峰值内存必须通过压力/分配测量固定。账本锁与记录 writer 不交叉持有。排队和 writer 回执共用单个 `2s` 绝对截止；超时后句柄永久 poisoned，后续请求不得越过可能仍卡在内核或文件系统中的旧写入。调用会话必须在截止内恢复终端并失败关闭。底层内核/FUSE 写已开始后无法由 safe Rust 强制中止，writer 线程可能存活到进程退出，因此生产审计根必须使用可靠的本地文件系统，禁止放在 FUSE、网络盘或可由外部服务无限阻塞的挂载上。

文件共享记录的 kind 只允许 `1 Start/2 Success/3 Cancelled/4 Failed`，固定关联方向、`transfer_id`、声明/最终大小、摘要、协议远端路径、文件名和错误码；两种提交不确定性不得进入共享链。本地路径记录的 kind 和 `transfer_id` 必须与最近一条共享文件事件完全一致，`related_shared_event_hash` 必须指向该事件，每条共享事件最多记录一次本地路径。路径是本端实际解析的 controller 上传源、host 上传目标、controller 下载目标或 host 下载源；仅精确 UTF-8 表示可记录，非 UTF-8 路径省略，不进行 lossy 转换。其 kind-specific payload 为 `shared_kind:u8 || transfer_id:u64 || local_path_len:u16 || local_path`。

提交歧义只允许两种本地 kind：`5 CommittedUnconfirmed` 表示 receiver 已提交但确认未送达，`6 CommitStatusUnknown` 表示 sender 已送出 `Finish` 但不知道 receiver 是否提交。它必须紧跟同一未终结 START 的事实关系，transfer ID 精确匹配，每次传输最多一次，并由本端角色与方向唯一决定：upload 的 controller/download 的 host 只能记录 `CommitStatusUnknown`，upload 的 host/download 的 controller 只能记录 `CommittedUnconfirmed`。固定 kind-specific payload 为 `local_kind:u8 || transfer_id:u64 || final_size:u64 || sha256[32] || local_path_len:u16(0)`，总长 `51` 字节；本地路径若尚未记录，先作为独立 START 路径记录追加，歧义载荷自身始终零路径。错误 ID、错误角色/方向、共享终态后的歧义、重复路径、重复歧义及二者互相替代都由在线状态机和离线 verifier 拒绝。

每个共享文件 START、Success/Cancelled/Failed 终态和每个本地提交歧义在记录成功后都立即设置 checkpoint due；长度、路径和状态验证必须在改变共享/本地链头之前完成，失败不得留下半推进链。

## 容器、验证与安全重放

`.yonaudit` 是有 magic/version/header、长度有界 record frames、可选 footer 的二进制容器。footer 依次包含共同清单、双方签名、本地封印、账本 commit 和最终容器摘要；摘要只引用已经完成的前缀，不形成循环。未知 critical record、非法长度、截断、尾随数据、链/签名不符都拒绝。

CLI：

```text
yon audit verify <LOCAL_FILE> [PEER_FILE]
yon audit replay <CONTROLLER_FILE> [PEER_FILE]
```

验证状态固定为 `VERIFIED_COMPLETE`、`CONSISTENT_COMPLETE_UNANCHORED`、`MATCHED_INTERRUPTED_PREFIX`、`INTACT_UNPAIRED`、`MISMATCH`、`TAMPERED`；退出码依次为成功完整 `0`、I/O/格式 `1`、三种可验证但非完整锚定状态 `2`、不一致 `3`、篡改 `4`。

重放先验证文件，完整双端状态才允许完整重放，单文件明确显示 unpaired，篡改拒绝。使用 `vt100 0.16.2` 的成熟虚拟屏幕解析器消费记录的 controller display bytes，只渲染虚拟屏幕可见文本/光标状态；绝不把原始 escape、OSC 52、DCS、设备查询、标题或终端控制响应重新写入用户终端。`Ctrl+C` 只退出本地重放。

## 验收

必须覆盖身份/权限/账本竞争和恢复、全部 wire 帧及签名输入、贡献重放、连接绑定、输入承诺、输出/Windows 显示差异、检查点乱序/重复/停顿、文件事件、磁盘满/只读/崩溃/掉电前缀、容器截断与逐字节篡改、六验证状态、VT 危险序列过滤、旧端点失败关闭和三平台原生企业会话。性能门禁分别测量普通会话零审计回归、企业会话交互延迟、writer 队列、RSS、磁盘吞吐和关闭最终化延迟。
