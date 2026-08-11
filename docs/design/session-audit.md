# 企业会话可验证审计

## 启用边界

审计只对通过 Enterprise Resolve 建立的会话自动、强制、双端启用；普通 relay 会话完全禁用。企业 controller 和 host 必须在 OPAQUE 成功、唯一连接确定之后，Terminal Active、终端输入和文件传输之前完成 `/yonder/audit/2.0.0` 握手。任一端不支持、身份/存储不可用或握手不一致都在 PTY 创建前失败关闭，不存在单端记录或无审计降级。

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
- 所有哈希、签名、HKDF 和 HMAC 使用版本化、互不相同的域分离标签 `yonder-audit-*-v2`。连接绑定包含已认证 controller/host PeerId、OPAQUE 会话绑定、双方随机数和本次唯一连接的本地授权事实摘要，不包含 relay 可声明身份。

## Wire

每条消息为 `tag:u8 || payload_length:u32(be) || payload`，payload 上限 `1024`，完整帧上限 `1029`。接收方必须先按 tag 验证精确或有界长度再读取；未知 tag、非法枚举、保留值、截断、超长和尾随字节关闭子流。文件容器版本与协议版本独立，本版 `format_version=2`。

| Tag | 消息 | Payload 长度 | 作用 |
| --- | --- | --- | --- |
| `0x01` | `AuditHello` | 267 | 角色、持久/会话公钥、nonce、账本快照、连接绑定、format、贡献 commitment、持久签名 |
| `0x02` | `SecretContribution` | 32 | 原始秘密贡献，只在线且立即清除 |
| `0x03` | `AuditReady` | 130 | session ID、对端 hello 摘要、format、会话签名 |
| `0x04` | `Checkpoint` | 328 | 序号、四条共享链快照、本地链/账本摘要、会话签名 |
| `0x05` | `CheckpointAck` | 296 | checkpoint 摘要、相同共享快照、会话签名 |
| `0x06` | `JointManifest` | 399..=911 | 双方身份/会话键/绑定、企业标识、terminal 摘要、最终链、结束原因 |
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
- `JointManifest`：`format_version:u16 || session_id[32] || controller_fingerprint[32] || host_fingerprint[32] || controller_session_key[32] || host_session_key[32] || connection_binding[32] || enterprise_len:u16 || enterprise[0..=512] || terminal_hello_digest[32] || final_snapshot[160] || ending_tag:u8 || ending_value:u8 || ended_normally:u8 || final_checkpoint_sequence:u64`。
- `LocalRecordSeal`：`session_id[32] || role:u8 || final_local_root[32] || local_count:u64 || final_shared_roots[128] || manifest_digest[32] || sealed_prefix_digest[32] || signature[64]`。
- `LedgerCommit`：`sequence:u64 || previous_root[32] || session_id[32] || manifest_digest[32] || sealed_record_digest[32] || peer_fingerprint[32] || result:u8 || signature[64]`。

`snapshot` 按 Input、Output、Control、FileTransfer 固定顺序各包含 `count:u64 || head[32]`。角色只有 `1 Controller/2 Host`；ledger result 只有 `1 Normal/2 Interrupted/3 AuditFailed`；`ended_normally` 只有 `0/1`。结束类型为 `1 ShellExit` 或 `2 CloseReason`，关闭原因只有 `1 NormalShellExit/2 ControllerDetach/3 LocalInterrupt/4 ConnectionLost/5 AuditFailure`。签名覆盖对应 payload 除 signature 外的全部字段，并分别加 `yonder-audit-<message>-v2` 域前缀。实现必须在 `yonder-core::wire::audit` 用公开常量逐字段定义，并用 compile-time/golden/property/fuzz 锁住总长度；文档与代码任何不一致都视为发布阻塞缺陷。

握手固定为双方发送 `AuditHello` 和 `SecretContribution`，验证承诺与持久签名，按角色顺序计算相同 session ID/输入承诺键，安全创建并同步本地 header，交换并验证 `AuditReady`。只有双方 ready 成功，host 才能创建 PTY 并发送 TerminalReady。

检查点在距上次检查点 `1s`、新增规范共享数据达到 `1 MiB`、文件操作边界或关闭边界任一条件满足时触发。快照永远描述生成它之前的链头，避免自引用；收到 Ack 且双方四条链的 count/head 完全相同后才成为共同确认前缀。检查点发送不能阻塞每个终端块，但延迟达到硬上限时施加背压，不能静默跳过。

正常结束顺序固定为：最终 `Checkpoint/CheckpointAck -> JointManifest -> controller ManifestSignature -> host ManifestSignature -> LocalRecordSeal -> LedgerCommit -> record sync_all -> ledger 原子推进`。任一步失败都报告审计失败，不能只返回 shell 退出码。连接异常时不伪造共同清单，只封存本地可验证前缀和最后共同检查点。

`AuditError` 固定码：`1 IdentityMissing`、`2 IdentityInvalid`、`3 IdentityPermissions`、`4 LedgerInvalid`、`5 LedgerConflict`、`6 DirectoryUnavailable`、`7 RecordCreateFailed`、`8 RecordWriteFailed`、`9 RecordSyncFailed`、`10 ProtocolUnsupported`、`11 HandshakeInvalid`、`12 SessionBindingMismatch`、`13 CheckpointMismatch`、`14 PeerSignatureInvalid`、`15 FinalManifestMismatch`、`16 LedgerCommitFailed`、`17 ReplayUnsafe`、`18 ContainerInvalid`。对端自由文本不得进入 CLI。

## 记录与并发

`AuditObserver` 是终端/文件与审计的唯一窄边界，提供输入发送前、PTY 写入前、输出发送前、显示写入前、resize、文件事件、关闭和最终化方法。需要 append-before-effect 的方法把有界 record batch 交给专用同步 writer 并等待确认后才允许外部效果；写入失败立即停止新效果、终止 PTY/文件、恢复本地终端并保留中断记录。

writer 使用容量固定的有界队列，在 Tokio runtime 之外独占记录句柄和哈希状态；不共享 `File`、不无界缓存、不每事件 `fsync`。规范块最大 `16 KiB`，每方向最多一个未检查点部分块；队列容量和峰值内存必须通过压力/分配测量固定。账本锁与记录 writer 不交叉持有，所有等待有绝对截止并可取消，避免磁盘停顿造成死锁。

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
