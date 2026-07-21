# yonder

Yonder 是一个跨平台、一次授权的点对点远程终端。项目发布两个单文件可执行程序：

- `yon`：同时提供被控端 `host` 和主控端 `connect`。
- `yon-relay`：需要用户自行部署的协调与 Circuit Relay v2 节点；项目不提供默认公共中继。

双方只需能够访问同一个 relay。Yonder 会同时尝试 QUIC、TCP、WebSocket 和安全 WebSocket，在 relay circuit 建立后继续通过 DCUtR 尝试直连，并根据连通性、延迟、抖动和路径类型选出最终连接；无法直连时继续使用端到端加密的 relay circuit。

完整的生产部署、全字段配置、证书、服务托管、升级回滚与故障排查说明见 [Yonder 0.1.0 运维与使用手册](docs/operations-manual.md)。

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

endpoint 可配置一到八个属于同一 PeerId 的 relay 传输地址；`yon-relay` 的 `listen` 与可被客户端拨号的 `external` 也都必须各提供一到八个地址。WSS 地址使用 `/tcp/<PORT>/tls/ws`；endpoint 配置 `wss_ca`，relay 配置 `wss_certificate` 和 `wss_private_key`。证书、信任锚和私钥可使用 DER 或 PEM；证书链与轮换期信任锚可使用有序列表。`*_der` 旧键在 `0.1.0` 继续兼容，高优先级的新键可覆盖低优先级旧键，同一层同时提供新旧键则拒绝启动。未知字段、非法文件、非 UTF-8、超过 64 KiB 的配置或无效组合都会使启动失败，不会静默降级。

只有 WSS 需要这组运维侧证书。自签证书可以使用：relay 配置带 `CA:FALSE`、`serverAuth` 和正确 SAN 的自签叶证书及私钥，两个 endpoint 把同一证书配置为 `wss_ca`。使用私有 CA 时，endpoint 改为信任该 CA。通过 IP 连接必须有对应 `IP SAN`，通过域名连接必须有对应 `DNS SAN`；只设置 `CN` 无效。relay 会在监听前使用 rustls 官方类型解析并实际构造 TLS 配置，校验证书/私钥匹配和每个 WSS external 的 SAN；有效期、用途、证书链与信任关系由真实客户端 TLS 握手最终验证，失败时关闭连接且绝不降级为明文。服务端支持叶证书优先的完整证书链，endpoint 最多同时加载八个信任锚用于证书轮换。

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

macOS 不支持把 Apple 系统库静态链接进第三方程序，因此其产物是无需附带额外文件的单二进制，但不是字面意义上的全静态 Mach-O。推送 `v0.1.0` 形式的 tag 会在六个原生 runner 上构建并验证 release candidate，汇总 `yon`、`yon-relay`、SBOM、项目双许可证、第三方许可证清单、SHA-256、锁文件和构建来源证明。完整压力、网络和固定 runner 性能证据尚未接入自动门禁前，workflow 不会自动创建正式 GitHub Release。
