# yonder

Yonder 是一个跨平台、一次授权的点对点远程终端。项目发布两个单文件可执行程序：

- `yon`：同时提供被控端 `host` 和主控端 `connect`。
- `yon-relay`：需要用户自行部署的协调与 Circuit Relay v2 节点；项目不提供默认公共中继。

双方只需能够访问同一个 relay。Yonder 会同时尝试 QUIC、TCP、WebSocket 和安全 WebSocket，在 relay circuit 建立后继续通过 DCUtR 尝试直连，并根据连通性、延迟、抖动和路径类型选出最终连接；无法直连时继续使用端到端加密的 relay circuit。

交互式终端会话内可以直接原生传输单个文件：主控端按 `Ctrl+] u` 上传、按 `Ctrl+] d` 下载，两端只需同一个 `yon` 二进制，不依赖 `rz`/`sz`、ZMODEM、SFTP/SCP、Shell 命令或任何额外软件。

完整的生产部署、全字段配置、证书、服务托管、升级回滚与故障排查说明见 [Yonder 0.1.3 运维与使用手册](docs/operations-manual.md)。

## 快速开始

先在有公网入口的机器上创建 relay 身份：

```console
yon-relay identity init --output relay.key
```

创建 `yon-relay.toml`，声明身份、监听地址和客户端可访问的公网地址：

```toml
identity = "relay.key"
listen = [
  "/ip4/0.0.0.0/tcp/4001",
  "/ip4/0.0.0.0/udp/4001/quic-v1",
]
external = [
  "/dns4/relay.example/tcp/4001",
  "/dns4/relay.example/udp/4001/quic-v1",
]
```

```console
yon-relay serve
```

relay 会输出带固定 PeerId 的完整地址，例如：

```text
/dns4/relay.example/tcp/4001/p2p/12D3KooW...
```

stdout 只列出 `external` 对应的可复制地址；wildcard、私网或动态端口形式的实际 listen 地址只进入诊断日志，不会混入 endpoint 配置。

在两个 endpoint 的当前目录放置相同的 `yon.toml`：

```toml
relays = [
  "/dns4/relay.example/tcp/4001/p2p/12D3KooW...",
  "/dns4/relay.example/udp/4001/quic-v1/p2p/12D3KooW...",
]
```

在被控端启动一次性终端：

```console
yon host
```

被控端会显示 `XXXX-XXXX-XXXX-XXXX` 形式的连接码。主控端连接：

```console
yon connect XXXX-XXXX-XXXX-XXXX
```

省略位置参数时，TTY 会隐藏输入连接码：

```console
yon connect
```

非交互环境从标准输入首行读取连接码，后续内容继续转发给远端 shell：

```console
printf 'XXXX-XXXX-XXXX-XXXX\necho hello\nexit\n' | \
  yon connect
```

Windows ConPTY 不能在保留尾部输出的同时可靠地把管道关闭映射为 shell EOF，因此 Windows 非交互内容必须像上例一样显式包含 `exit`；Unix 会额外把输入半关闭传递为 PTY EOF。

配置优先级固定为环境变量、当前目录配置文件、系统配置文件。Linux 系统目录是 `/etc/yonder`，macOS 是 `/Library/Application Support/Yonder`，Windows 是 `%PROGRAMDATA%\Yonder`；文件名分别为 `yon.toml` 和 `yon-relay.toml`。Windows 的 `PROGRAMDATA` 必须存在且是非空绝对路径，否则无法安全定位系统层并会直接启动失败。`yon` 使用 `YON_` 前缀，relay 使用 `YON_RELAY_`；嵌套字段用 `__`，列表用逗号，例如 `YON_RELAYS`、`YON_RELAY_REGISTRY__CAPACITY`。相对路径相对于提供该字段的配置文件目录解析，环境变量中的相对路径相对于当前目录解析。

endpoint 可配置一到八个属于同一 PeerId 的 relay 传输地址；`yon-relay` 的 `listen` 与可被客户端拨号的 `external` 也都必须各提供一到八个地址。WSS 地址使用 `/tcp/<PORT>/tls/ws`；endpoint 配置 `wss_ca`，relay 配置 `wss_certificate` 和 `wss_private_key`。证书、信任锚和私钥可使用 DER 或 PEM；证书链与轮换期信任锚可使用有序列表。`*_der` 旧键在 `0.1.x` 继续兼容，高优先级的新键可覆盖低优先级旧键，同一层同时提供新旧键则拒绝启动。未知字段、非法文件、非 UTF-8、超过 64 KiB 的配置或无效组合都会使启动失败，不会静默降级。

只有 WSS 需要这组运维侧证书。自签证书可以使用：relay 配置带 `CA:FALSE`、`serverAuth` 和正确 SAN 的自签叶证书及私钥，两个 endpoint 把同一证书配置为 `wss_ca`。使用私有 CA 时，endpoint 改为信任该 CA。通过 IP 连接必须有对应 `IP SAN`，通过域名连接必须有对应 `DNS SAN`；只设置 `CN` 无效。relay 会在监听前使用 rustls 官方类型解析并实际构造 TLS 配置，校验证书/私钥匹配和每个 WSS external 的 SAN；有效期、用途、证书链与信任关系由真实客户端 TLS 握手最终验证，失败时关闭连接且绝不降级为明文。服务端支持叶证书优先的完整证书链，endpoint 最多同时加载八个信任锚用于证书轮换。

## 交互会话中的本地控制与文件传输

会话建立后，`Ctrl+]` 是主控端的本地控制前缀。`0.1.3` 的完整快捷键集合：

| 操作 | 快捷键 | 语义 |
| --- | --- | --- |
| 结束当前会话 | `Ctrl+]` 后按 `.` | 保持既有语义 |
| 发送字面 `Ctrl+]` | `Ctrl+]` 后再按 `Ctrl+]` | 保持既有语义 |
| 上传一个文件 | `Ctrl+]` 后按 `u` | 主控端文件传到被控端 |
| 下载一个文件 | `Ctrl+]` 后按 `d` | 被控端文件传到主控端 |
| 显示本地控制帮助 | `Ctrl+]` 后按 `?` | 显示当前版本定义的全部本地快捷键 |

选择器固定为小写 ASCII；`?` 以状态行输出帮助后立即返回终端，不进入分页器、不启动外部程序。

上传：按 `Ctrl+] u` 后依次输入 `local source:`（必填）与 `remote destination [remote session start directory]:`（留空 = 远端会话起始目录，即被控端启动 Shell 时的工作目录）。下载：按 `Ctrl+] d` 后依次输入 `remote source:`（必填）与 `local destination [local connect start directory]:`（留空 = 主控端启动 `yon connect` 时的工作目录）。相对路径分别相对各自的会话起始目录，远端绝对路径由被控端操作系统解释；路径按字面解释，不做 Shell 展开、不自动创建父目录，目标已存在一律拒绝。

- 只支持单文件、普通文件（空文件可以）；同一会话同一时刻最多一个文件操作。
- 目标文件绝不覆盖：接收方先在目标同目录写入安全临时文件，完整接收并验证大小与 SHA-256 后才以 no-replace 方式提交。
- 文件字节不经过远端终端/Shell，走独立子流；relay 不存储、不理解文件内容。
- 只在主控端标准输入为交互式终端时可用；管道/脚本输入下快捷键不生效，所有字节原样转发。
- 传输期间终端输入暂停（本地提示会说明），`Ctrl+C` 取消当前文件操作，`Ctrl+] .` 取消并结束会话；普通文件错误只结束本次操作，终端会话继续工作。
- 旧版本对端不支持文件协议时显示固定错误，终端会话不受影响。
- 六个正式发布目标行为一致，跨系统（如 Linux 主控 ↔ Windows 被控）也可互传；文件名规则按接收端系统校验。
- 日志与诊断不包含路径、文件名或文件摘要。
- 明确非目标：一次多文件、目录/递归传输、断点续传、压缩、删除/重命名/权限管理、Shell 通配符/`~` 展开、脚本化传输 CLI、`rz/sz`/ZMODEM/SFTP/SCP 兼容。`0.1.3` 不增加配置项。

完整的上传/下载流程、语义、限制与故障行为见 [运维与使用手册 9.6 节](docs/operations-manual.md)。

## 安全模型

relay 始终被视为不可信基础设施。它可以观察双方地址、PeerId、时序和流量大小，也可以拒绝或中断服务；终端内容和控制消息则由两个 `yon` 端点之间的 libp2p 身份认证与 OPAQUE 连接码认证共同保护。

连接码每次 `yon host` 启动重新生成，只允许一个成功建立的终端会话消费。Yonder 不提权，远端 shell 使用被控端当前用户、当前权限、工作目录和环境。

完整威胁模型、协议和依赖例外见 [设计规范](docs/design/README.md)。

## 开发验证

```console
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo deny -L error --locked check
```

模糊测试位于独立的 `fuzz` workspace：

```console
cargo +nightly fuzz run connection_code
cargo +nightly fuzz run wire_protocol
cargo +nightly fuzz run session_state
cargo +nightly fuzz run network_address --features network-address
```

## 发布目标

| 系统 | Rust target | 产物链接约束 |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-musl` | 完全静态 ELF |
| Linux arm64 | `aarch64-unknown-linux-musl` | 完全静态 ELF |
| Windows x86_64 | `x86_64-pc-windows-msvc` | 静态 CRT，无第三方 DLL |
| Windows arm64 | `aarch64-pc-windows-msvc` | 静态 CRT，无第三方 DLL |
| macOS Intel | `x86_64-apple-darwin` | 单 Mach-O，仅链接系统 `libSystem`/framework |
| macOS Apple Silicon | `aarch64-apple-darwin` | 单 Mach-O，仅链接系统 `libSystem`/framework |

macOS 不支持把 Apple 系统库静态链接进第三方程序，因此其产物是无需附带额外文件的单二进制，但不是字面意义上的全静态 Mach-O。推送 `vMAJOR.MINOR.PATCH` 形式的 tag 会在六个原生 runner 上构建并验证 release candidate，同时等待四个 fuzz target 各 `30min` 的并行门禁、风险驱动的真实网络/故障矩阵、Windows/Linux 原生性能与资源证据、覆盖率和安全门禁，最后汇总 `yon`、`yon-relay`、SBOM、项目双许可证、第三方许可证清单、SHA-256、锁文件和构建来源证明。任一门禁失败都不会创建正式 GitHub Release。
