# 原生单文件传输

## 用户契约

文件传输只依附已经 Active 的交互式终端，由 controller 本地控制前缀触发：

```text
Ctrl+] u   上传一个文件
Ctrl+] d   下载一个文件
Ctrl+] ?   显示本地控制帮助
Ctrl+] .   结束会话（既有语义）
Ctrl+] Ctrl+]  发送字面 Ctrl+]（既有语义）
```

非交互 stdin 不解释这些快捷键，所有字节继续原样发往 PTY。每次仅一个活动文件操作；终端 I/O 在路径提示和传输期间继续工作。普通文件错误、取消和不支持只结束该文件操作，不结束终端。`Ctrl+] .` 会取消文件并结束整个会话。

传输不调用 shell，不注入命令，不使用 ZMODEM/SCP/SFTP/rsync，不解析 shell 当前目录。相对路径分别基于 controller 启动 cwd 和 host shell 启动 cwd；不进行 `~`、环境变量、glob 或 shell 展开。两端都以运行 `yon` 的当前身份和权限访问文件，不继承 shell 内部通过 `sudo`/`su` 获得的身份。

只接受普通文件。源路径可以直接指向普通文件，也可以经过 symlink 最终解析到普通文件；Windows 的普通 UNC 共享路径按普通文件处理，`\\.\`、`\\?\` 设备或扩展命名空间仍在系统调用前拒绝。打开成功后，已打开句柄是本次传输的权威对象，目录、FIFO、socket、设备等特殊文件仍拒绝。目标必须不存在，已有普通文件、目录、symlink 或其他对象都视为已存在；父目录必须已存在且是目录。最终文件名在同步与异步 no-replace 提交边界使用同一接收平台验证器再次校验，不能依赖不同文件系统、Windows 版本或 Rust 标准库对非法名称返回相同 OS 错误类别。接收端写入同一父目录内的安全临时文件，校验实际大小和 SHA-256 后用成熟 no-replace 提交；任何失败删除临时文件，不覆盖既有目标，不留下部分目标。

## 协议

协议 ID 固定为 `/yonder/file-transfer/2.0.0`，复用选中的唯一认证连接上的独立双向有序子流。首次快捷键触发时探测能力；协商不支持只把本连接缓存为 `Unsupported`，显示固定错误并返回终端。relay 不理解文件协议。

每条消息为 `tag:u8 || payload_length:u32(be) || payload`。接收方必须在分配前按 tag 验证长度；未知 tag、尾随字节和错误状态只关闭当前文件子流。

| Tag | 消息 | Payload |
| --- | --- | --- |
| `0x01` | `UploadOpen` | `destination_len:u16 || destination || file_name_len:u16 || file_name || declared_size:u64` |
| `0x02` | `DownloadOpen` | `source_len:u16 || source` |
| `0x03` | `DownloadOffer` | `file_name_len:u16 || file_name || declared_size:u64` |
| `0x04` | `Ready` | empty |
| `0x05` | `Data` | `1..=65536` file bytes |
| `0x06` | `Finish` | `actual_size:u64 || sha256[32]` |
| `0x07` | `Committed` | empty; only success terminal state |
| `0x08` | `Cancel` | empty |
| `0x09` | `Error` | `error_code:u16` |

路径最大 `4096` UTF-8 字节，基本文件名最大 `1024` UTF-8 字节。上传目标路径可为空以使用远端启动 cwd 和源基本名；其他路径/文件名非空。空文件不发送 `Data`，仍执行 `Finish` 和 `Committed`。不得按 `declared_size` 分配内存。

错误码固定为：`1 Busy`、`2 InvalidRequest`、`3 InvalidPathEncoding`、`4 InvalidFileName`、`5 PathTooLong`、`6 SourceNotFound`、`7 SourceNotRegularFile`、`8 DestinationExists`、`9 DestinationParentNotFound`、`10 DestinationNotDirectory`、`11 PermissionDenied`、`12 NoSpace`、`13 FileTooLargeForPlatform`、`14 ReadFailed`、`15 WriteFailed`、`16 SizeMismatch`、`17 DigestMismatch`、`18 SourceChanged`、`19 CommitFailed`、`20 Cancelled`、`21 SessionClosing`、`22 Unsupported`。`0` 或未知值是协议错误；对端不能提供 CLI 文案。

上传顺序：`UploadOpen -> Ready -> Data* -> Finish -> Committed`。下载顺序：`DownloadOpen -> DownloadOffer -> Ready -> Data* -> Finish -> Committed`。首帧只能是方向对应的 `UploadOpen` 或 `DownloadOpen`；首帧 `Error` 与其他消息统一视为 `InvalidRequest`，不能冒充一个已开始传输的远端失败。打开帧建立方向状态后，主控可在非终态发送 `Cancel`，任一方可在其方向表允许的开放阶段发送 `Error`。EOF 只能出现在帧边界；真正传输在首帧前 EOF 是失败，单独能力探测流的首帧前正常 EOF 无副作用。

## I/O、所有权和提交

`FileTransferBackend` 抽象源句柄、目标解析、流式 reader 和 no-replace receiver，关联类型与 future 在生产数据路径静态分发。生产实现 `TokioFileTransferBackend` 使用 Tokio 异步文件 API 完成块读写、flush、sync 和句柄元数据复核；可能阻塞的路径探测、私有临时文件创建及 `persist_noclobber` 提交进入 Tokio 有界 blocking pool。接收器使用 `tempfile 3.27.0` 在目标父目录创建临时文件并提交，不得先 `exists()` 后 rename 形成 TOCTOU，也不得自行拼接随机临时名。

每个会话一个 `FileTransferActor` 独占状态，状态为 `Idle/Negotiating/Sending/Receiving/Finishing`，不能用多布尔值表达。第一方显式文件数据块固定为 `64 KiB`，最多一个发送块和一个接收块在途；不得按文件大小分配。Tokio 的文件适配和 blocking 调度可在实现内部产生额外的有界分配或复制，因此这里只保证第一方块数、容量和生命周期有界，不宣称整个 Tokio 栈“恰好一次分配”或逐层零复制。文件读取/写入不得阻塞网络 owner；文件流、终端流和审计流都有界调度，终端控制优先，文件数据每块后让出调度。

`yon` current-thread runtime 的 blocking pool 上限固定为 `4`。PTY 输入、输出和 child wait 最多占用三个长生命周期 blocking job；审计 writer 使用独立命名 `std::thread` 和该线程私有的 current-thread Tokio runtime，不占第四个 blocking worker。短生命周期的文件路径/临时文件/提交操作因此保留至少一个 Tokio blocking worker；该预算必须由审计启用且三个 PTY bridge 同时存活的回归测试锁定。

`Busy` 只表示前一笔文件操作仍在执行线协议。对端收到 `Committed`、`Error` 或流关闭后可以立即开始下一笔；若 host 此时仅剩前一笔本地审计结束记录尚未追加完成，文件协调器必须把下一条子流保存在唯一的容量 `1` 交接槽中，待前一笔审计有序完成后再启动，不能误报 `Busy`。该槽不改变“最多一个活动文件操作”，不增加协议消息，也不允许无界排队；真实并发的额外子流仍按既有 `Busy`/关闭规则处理。会话入口关闭后必须停止轮询已关闭通道，完成现有活动、Busy 回复和交接槽后退出，禁止空转。

源文件以打开后的句柄为权威：普通文件类型、初始长度和修改身份都从句柄读取，完成发送前再复核同一句柄。路径在打开后被重绑定、改名或替换不会切换本次传输内容，也不会仅因路径名变化返回 `SourceChanged`；同一打开对象可检测到的缩短、增长或修改身份变化才返回 `SourceChanged`。保留长度和修改身份的原位修改并非所有文件系统都可检测，接收端仍以实际传输字节的 SHA-256 保证落盘内容一致。

Unix 上为避免用 safe `std` 阻塞打开 FIFO，生产实现在 `open` 前先用跟随 symlink 的 `metadata` 排除非普通文件。`metadata -> open` 之间仍存在同一用户或拥有该路径写权限的本地攻击者把普通文件替换成 FIFO 的 TOCTOU 窗口；safe `std` 没有可用的 `O_NONBLOCK`/`O_NOFOLLOW` 句柄打开接口，当前不为此引入平台 FFI 或新依赖。该风险可使一个文件 blocking worker 卡在本地打开，不破坏内存/线程安全，也不让攻击者越过运行 `yon` 的现有文件权限；在提供成熟 safe 跨平台打开能力后必须重新评估。

接收方只有完整读取、flush、sync、大小/摘要一致且 no-replace 成功后发送 `Committed`。receiver 已提交目标但 `Committed` 未成功送达时，本地结果是 `CommittedUnconfirmed`；sender 一旦开始发送 `Finish` 的任意字节或 flush，就进入提交不确定窗口，后续取消、超时或 I/O 失败均返回 `CommitStatusUnknown`；只有 `Finish` 尚未发送任何字节时才可报告普通失败或取消。两者都不能伪装为双方确认的共享成功。所有正常协议帧写入和 flush 都必须同时受取消信号与既有预算约束：控制帧的完整 frame+flush 共用绝对 `control_timeout`，数据帧每次成功写进度刷新 `data_progress_timeout`，禁止让停读对端无限占有 transfer owner。会话进入 Closing 后先停止接收新文件操作并请求取消，但 controller 和 host 必须继续持有唯一在途 transfer owner，直至其得到确定本地结果；已经开始的 blocking no-replace 提交不能靠 drop/取消撤回，且不得在会话返回后才悄悄生成目标文件。提交前的断线、会话结束、取消、摘要错误和写入错误都关闭句柄并由 guard 清理临时文件。

企业会话必须把传输方向、双方共享路径、声明/实际大小、SHA-256 和双方可确认的最终结果写入审计共享事实；文件内容和本端独有路径不进入共享事实。controller 上传源、host 上传目标、controller 下载目标和 host 下载源的本地解析路径只进入各自本地审计链；只有路径能精确表示为 UTF-8 时才记录，禁止 lossy 转换。`CommittedUnconfirmed` 与 `CommitStatusUnknown` 只记录为与匹配 transfer ID、方向、角色及最近共享 START 绑定的本地固定载荷，不进入共享文件链。任一强制审计记录失败都必须在保留提交事实或原主结果后终止企业会话；开始记录失败发生在文件 effect 之前，不得映射为用户/对端取消。普通会话不因文件传输创建审计。

## 验收

测试覆盖五个快捷键跨读取块状态、交互/非交互、所有 tag/长度/顺序/错误码、零字节与多块文件、目标竞态、symlink 最终普通文件、目录/特殊文件、打开后路径重绑定、源变化、磁盘满、权限、取消/断线、摘要错误、两种提交不确定结果、Closing 持有唯一 owner、`Committed` 后且 EOF 前的连续传输交接、真实并发 `Busy`、入口关闭收尾、终端公平性、新旧端互操作，以及 Windows/Linux/macOS 原生文件语义。基准必须记录终端延迟回归、生产异步 backend 的打开/读写/哈希/同步/no-replace 提交、传输吞吐、峰值内存和有界分配；不能用回环 mock 代替至少一组跨平台真实会话。release performance workflow 在 Linux、Windows、macOS 三类原生 runner 上执行相同 Criterion 门禁和平台资源采样，运行结果只能写入验证记录，不能由本设计预先宣称通过。
