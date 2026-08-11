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

只接受普通文件。源不得是目录、symlink 或特殊文件；目标必须不存在，父目录必须已存在且是目录。接收端写入同一父目录内的安全临时文件，校验实际大小和 SHA-256 后用成熟 no-replace 提交；任何失败删除临时文件，不覆盖既有目标，不留下部分目标。

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

上传顺序：`UploadOpen -> Ready -> Data* -> Finish -> Committed`。下载顺序：`DownloadOpen -> DownloadOffer -> Ready -> Data* -> Finish -> Committed`。主控可在非终态发送 `Cancel`，任一方可发送 `Error`。EOF 只能出现在帧边界；真正传输在首帧前 EOF 是失败，单独能力探测流的首帧前正常 EOF 无副作用。

## I/O、所有权和提交

`FileTransferBackend` 抽象普通文件元数据、流式 reader 和 no-replace receiver；生产接收器使用 `tempfile 3.27.0` 在目标父目录创建临时文件并用 `persist_noclobber` 或等价成熟 API 提交。实现不得先 `exists()` 后 rename 形成 TOCTOU，也不得自行拼接随机临时名。

每个会话一个 `FileTransferActor` 独占状态，状态为 `Idle/Negotiating/Sending/Receiving/Finishing`，不能用多布尔值表达。数据缓冲固定 `64 KiB`，最多一个发送块和一个接收块在途；文件读取/写入不得阻塞网络 owner。文件流、终端流和审计流都有界调度，终端控制优先，文件数据每块后让出调度。

源文件在打开前和完成后校验普通文件属性、长度及稳定身份；中途缩短、增长或被替换返回 `SourceChanged`。接收方只有完整读取、flush、按需要持久化、大小/摘要一致且 no-replace 成功后发送 `Committed`。断线、会话结束、取消、摘要错误、写入错误都关闭句柄并删除临时文件。

企业会话必须把传输方向、双方共享路径、声明/实际大小、SHA-256 和最终结果写入审计共享事实；文件内容和本端独有路径不进入共享事实。普通会话不因文件传输创建审计。

## 验收

测试覆盖五个快捷键跨读取块状态、交互/非交互、所有 tag/长度/顺序/错误码、零字节与多块文件、目标竞态、symlink/目录/特殊文件、磁盘满、权限、源变化、取消/断线、摘要错误、终端公平性、新旧端互操作，以及 Windows/Linux/macOS 原生文件语义。基准必须记录终端延迟回归、传输吞吐、峰值内存和每块分配；不能用回环 mock 代替至少一组跨平台真实会话。
