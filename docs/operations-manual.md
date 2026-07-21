# Yonder 0.1.0 运维与使用手册

本文档面向需要部署、维护和使用 Yonder 的系统管理员、网络管理员与终端用户。文中的命令、配置字段和行为均对应 Yonder `0.1.0`。

## 目录

1. [产品与组件](#1-产品与组件)
2. [平台与发布文件](#2-平台与发布文件)
3. [网络规划](#3-网络规划)
4. [配置加载规则](#4-配置加载规则)
5. [部署 relay](#5-部署-relay)
6. [配置 endpoint](#6-配置-endpoint)
7. [WSS 证书部署](#7-wss-证书部署)
8. [托管 relay 进程](#8-托管-relay-进程)
9. [使用远程终端](#9-使用远程终端)
10. [生命周期、重启与升级](#10-生命周期重启与升级)
11. [安全运维要求](#11-安全运维要求)
12. [监控与日常巡检](#12-监控与日常巡检)
13. [故障排查](#13-故障排查)
14. [上线验收清单](#14-上线验收清单)
15. [命令速查](#15-命令速查)

## 1. 产品与组件

Yonder 是一个跨平台、一次授权的远程终端工具。它不实现 SSH 协议，也不要求目标机器安装 SSH Server。远端终端直接继承被控端启动 `yon host` 的当前用户、权限、工作目录和环境。

Yonder 发布两个单文件程序：

| 程序 | 角色 | 说明 |
| --- | --- | --- |
| `yon` | 被控端和主控端 | `yon host` 发布一次性终端；`yon connect` 连接终端 |
| `yon-relay` | 自建中继 | 提供端点发现、临时注册、NAT 协调和 Circuit Relay v2 密文转发 |

项目不提供默认公共 relay。主控端和被控端必须预先配置同一个自建 relay。relay 需要可被双方访问的固定入口；两个 endpoint 只需具备到 relay 的公网出口，不要求固定公网 IP。

### 1.1 连接过程

1. `yon host` 连接已配置 relay，取得 reservation，并发布临时定位信息。
2. 被控端显示 `XXXX-XXXX-XXXX-XXXX` 格式的一次性连接码。
3. `yon connect` 仅把连接码的公开定位部分发送给 relay，查询被控端临时 PeerId。
4. 两个 endpoint 先建立可用的 relay circuit，再通过 DCUtR 尝试直连升级。
5. Yonder 优先保留可用直连，并在直连候选内部根据延迟、抖动和 transport 选择；只有直连不可用时才使用 relay circuit。
6. 两个 endpoint 使用 OPAQUE 验证完整连接码，并把授权绑定到当前已认证的端到端连接。
7. 终端创建并确认成功后连接码立即消费，不能再次使用。

relay 不掌握连接码中的认证秘密，也不能读取终端内容。relay 可以看到连接双方的网络地址、PeerId、连接时间、持续时间和流量大小，并可以拒绝、中断、延迟或丢弃服务。

### 1.2 当前功能边界

Yonder `0.1.0` 提供一次性远程交互终端、终端尺寸同步、ANSI 字节传输、Ctrl+C、远端退出码传播和 TCP/QUIC/WS/WSS 自适应连接。它不提供 SSH/SFTP 兼容、文件同步、端口转发、常驻多会话账户体系或官方公共 relay。

## 2. 平台与发布文件

从项目的 [GitHub Releases](https://github.com/franckcl1989/yonder/releases) 下载与系统匹配的归档。

| 平台 | `yon` | `yon-relay` |
| --- | --- | --- |
| Linux x86_64 | `yon-linux-x86_64.tar.gz` | `yon-relay-linux-x86_64.tar.gz` |
| Linux arm64 | `yon-linux-aarch64.tar.gz` | `yon-relay-linux-aarch64.tar.gz` |
| Windows x86_64 | `yon-windows-x86_64.zip` | `yon-relay-windows-x86_64.zip` |
| Windows arm64 | `yon-windows-aarch64.zip` | `yon-relay-windows-aarch64.zip` |
| macOS Intel | `yon-macos-x86_64.tar.gz` | `yon-relay-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `yon-macos-aarch64.tar.gz` | `yon-relay-macos-aarch64.tar.gz` |

每个归档恰好包含一个规范名称的可执行文件。Linux 产物是完全静态 ELF；Windows 产物静态链接 CRT，不依赖第三方 DLL；macOS 产物只依赖 Apple 系统 `libSystem`/framework。macOS 不允许普通第三方程序把系统库静态嵌入 Mach-O，因此 macOS 的“单文件分发”不等于字面意义上的全静态链接。

`0.1.0` 发布流程提供 SHA-256 和 GitHub 构建来源证明，但当前不包含 Windows Authenticode 签名或 Apple notarization。Windows SmartScreen、macOS Gatekeeper 或企业终端防护可能因此要求管理员批准。应先验证 SHA-256 与 provenance，再通过组织的软件分发、MDM 或应用白名单流程授权；不要为了运行 Yonder 全局关闭系统安全机制。

`0.1.0` 的生产支持基线如下。低于基线的系统可能仍能启动，但不属于发布验收范围：

| 平台 | 最低生产基线 | 说明 |
| --- | --- | --- |
| Linux x86_64/arm64 | Linux kernel `4.18`，64 位 | musl 完全静态产物；不依赖目标机 glibc。实际门禁覆盖 Rocky Linux 8 系列内核。 |
| Windows x86_64/arm64 | Windows 10 `1809` 或 Windows Server 2019 | 交互终端依赖 ConPTY；不支持 Windows Nano Server，也不依赖 WSL。 |
| macOS Intel/Apple Silicon | macOS 12 | 只依赖 Apple 系统库；不同架构必须使用对应归档。 |

Windows PowerShell `5.1` 是 relay identity 与 WSS 私钥 ACL 校验所用的系统组件；它随上述受支持的常规 Windows 客户端和 Server/Core 安装提供。精简掉 Windows PowerShell 的自定义镜像不属于 `0.1.0` 支持范围。Linux 与 macOS 不调用 PowerShell。

### 2.1 校验下载文件

正式 Release 附带 `SHA256SUMS`。Linux 可以执行：

```console
sha256sum -c SHA256SUMS --ignore-missing
```

macOS 可以执行：

```console
shasum -a 256 yon-macos-aarch64.tar.gz
grep 'yon-macos-aarch64.tar.gz' SHA256SUMS
```

Windows PowerShell 可以执行：

```powershell
Get-FileHash .\yon-windows-x86_64.zip -Algorithm SHA256
Select-String -Path .\SHA256SUMS -Pattern 'yon-windows-x86_64.zip'
```

使用 GitHub CLI 时，还可以验证 Release 附带的构建来源证明：

```console
gh attestation verify yon-linux-x86_64.tar.gz --repo franckcl1989/yonder
```

### 2.2 安装二进制

Linux：

```console
tar -xzf yon-linux-x86_64.tar.gz
sudo install -o root -g root -m 0755 yon /usr/local/bin/yon

tar -xzf yon-relay-linux-x86_64.tar.gz
sudo install -o root -g root -m 0755 yon-relay /usr/local/bin/yon-relay
```

macOS：

```console
tar -xzf yon-macos-aarch64.tar.gz
sudo install -o root -g wheel -m 0755 yon /usr/local/bin/yon

tar -xzf yon-relay-macos-aarch64.tar.gz
sudo install -o root -g wheel -m 0755 yon-relay /usr/local/bin/yon-relay
```

Windows PowerShell：

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\Yonder' | Out-Null
Expand-Archive .\yon-windows-x86_64.zip -DestinationPath 'C:\Program Files\Yonder' -Force
Expand-Archive .\yon-relay-windows-x86_64.zip -DestinationPath 'C:\Program Files\Yonder' -Force
& 'C:\Program Files\Yonder\yon.exe' --version
& 'C:\Program Files\Yonder\yon-relay.exe' --version
```

将安装目录加入 `PATH` 后即可直接使用 `yon` 和 `yon-relay`。也可以始终使用绝对路径运行。

## 3. 网络规划

### 3.1 relay 入口与传输

Yonder 支持以下 relay 入口：

| 传输 | Multiaddr 示例 | 底层网络 | 常见用途 |
| --- | --- | --- | --- |
| TCP | `/dns4/relay.example.com/tcp/4001` | TCP | 通用基础入口 |
| QUIC | `/dns4/relay.example.com/udp/4001/quic-v1` | UDP | 低延迟、弱网恢复 |
| WebSocket | `/dns4/relay.example.com/tcp/4002/ws` | TCP | 只允许 WebSocket 的网络 |
| Secure WebSocket | `/dns4/relay.example.com/tcp/443/tls/ws` | TCP + TLS | 允许直连 TLS/443 的网络 |

推荐至少同时提供 TCP 和 QUIC。网络只允许客户端直接连接指定 TLS/443 目的地址时，可以增加 WSS。WS 是明文 WebSocket 承载，但其中的 libp2p Noise 会继续保护端到端链路；WSS 在此基础上增加运维侧 TLS。

WSS **不实现** HTTP `CONNECT`、PAC、系统代理或需要用户名/密码的显式企业代理。浏览器能通过组织代理访问 HTTPS，不代表 `yon` 能访问 `/tls/ws`；只有 endpoint 可以直接建立到 relay TCP/443 的连接时该入口才可用。需要显式代理的网络必须由组织提供允许直连的出口、透明代理或 VPN，不能把当前 WSS 能力描述为“支持企业 HTTP 代理”。

同一个数字端口可以分别用于 TCP 和 UDP，例如 TCP `4001` 与 QUIC UDP `4001`。原始 TCP、WS 和 WSS 都占用 TCP listener，部署时应为它们使用不同的 TCP 端口，避免监听冲突。

### 3.2 防火墙与安全组

relay 所在主机及云安全组必须允许所有已配置 `listen` 端口入站。以上述四入口为例：

| 端口 | 协议 | 用途 |
| --- | --- | --- |
| 4001 | TCP | 原始 TCP |
| 4001 | UDP | QUIC v1 |
| 4002 | TCP | WebSocket |
| 443 | TCP | Secure WebSocket |

firewalld 示例：

```console
sudo firewall-cmd --permanent --add-port=4001/tcp
sudo firewall-cmd --permanent --add-port=4001/udp
sudo firewall-cmd --permanent --add-port=4002/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

UFW 示例：

```console
sudo ufw allow 4001/tcp
sudo ufw allow 4001/udp
sudo ufw allow 4002/tcp
sudo ufw allow 443/tcp
```

endpoint 通常不需要固定入站规则，但必须允许出站 DNS 解析以及到 relay 所有 TCP/UDP 端口的访问。DCUtR 直连成功率还取决于 NAT、防火墙和本机临时端口策略；直连失败不会影响 relay fallback。

Windows 首次运行 `yon` 时可能出现 Defender Firewall 网络访问提示，因为 endpoint 会监听由系统分配的临时 TCP/UDP 端口参与直连。允许与实际使用网络配置文件相符的入站访问可提高 DCUtR 成功率；拒绝不会泄露终端内容，通常只是让会话继续走 relay。受管环境应由管理员按二进制路径/签名和允许的网络配置文件预置规则，不要要求用户一律开放所有 Public 网络。

如果 relay 位于 NAT 后，必须把每个公网端口转发到对应 listener，并在 `external` 中填写外部可达地址和外部端口，不能填写容器地址、私网地址或 wildcard 地址。

### 3.3 DNS 与 IPv6

- `/dns4/...` 应解析为可达 IPv4 地址。
- `/dns6/...` 应解析为可达 IPv6 地址。
- `/ip4/...` 和 `/ip6/...` 直接使用固定 IP。
- `external` 可以使用 DNS 或明确 IP；`listen` 必须使用 IP。
- IPv6 listener 示例为 `/ip6/::/tcp/4001` 和 `/ip6/::/udp/4001/quic-v1`。
- DNS 变更生效前应保留旧地址，并在 endpoint 的 `relays` 列表中短期同时配置新旧入口。所有入口必须属于同一个 relay PeerId。

同一 PeerId 下的多个地址仅表示**同一个 relay 进程的多个传输入口**，不是独立高可用节点。relay 的定位注册表只在本进程内存中；不要把同一 identity 同时复制给多个进程，不要在这些进程前使用 DNS 轮询或无会话一致性的四层负载均衡，否则 host 注册与 controller 查询可能落到不同内存注册表。`0.1.0` 不提供多 relay 一致性或活动会话迁移；生产可用性应通过单实例进程监督、稳定存储 identity、快速重启和多传输入口保障。

## 4. 配置加载规则

`yon` 和 `yon-relay` 使用独立 TOML 配置。两者都按以下优先级合并：

1. 环境变量，优先级最高。
2. 当前运行目录中的配置文件。
3. 系统配置文件，优先级最低。

| 平台 | 系统目录 | endpoint 文件 | relay 文件 |
| --- | --- | --- | --- |
| Linux | `/etc/yonder` | `/etc/yonder/yon.toml` | `/etc/yonder/yon-relay.toml` |
| macOS | `/Library/Application Support/Yonder` | `yon.toml` | `yon-relay.toml` |
| Windows | `%PROGRAMDATA%\Yonder` | `yon.toml` | `yon-relay.toml` |

Windows 的 `PROGRAMDATA` 必须存在，并且是非空绝对路径。系统环境异常时程序会直接报错，不会猜测其他目录。

配置层具有以下语义：

- 标量和嵌套字段按层覆盖。
- 列表字段按层整体替换，不做拼接。
- 未知字段会导致启动失败。
- 配置文件必须是普通文件、UTF-8 编码且不超过 `64 KiB`。
- 文件中的相对路径以提供该字段的配置文件目录为基准。
- 环境变量中的相对路径以进程当前目录为基准。
- 空路径、目录路径、缺失文件、非法组合和超范围数值都会在启动阶段失败。

上线前使用只读检查命令验证最终合并结果。它会加载所有配置层、解析地址和资源限制，并验证 identity、WSS 证书及私钥，但不会绑定 listener：

```console
yon config check
yon-relay config check
```

环境变量前缀：

- endpoint 使用 `YON_`。
- relay 使用 `YON_RELAY_`。
- 嵌套字段使用双下划线 `__`。
- 列表使用逗号分隔。

例如：

```console
YON_RELAYS=/dns4/relay.example.com/tcp/4001/p2p/12D3KooW...
YON_RELAY_REGISTRY__CAPACITY=128
```

## 5. 部署 relay

### 5.1 创建持久身份

relay 身份决定其固定 PeerId。首次部署只生成一次：

```console
yon-relay identity init --output relay.key
```

命令会拒绝覆盖已存在文件，并输出：

```text
Relay PeerId: 12D3KooW...
```

身份文件包含私钥，应满足以下要求：

- 只允许 relay 运行账户读取。
- 不要提交到 Git、镜像层、工单或普通日志。
- 使用组织现有的加密备份机制离线备份。
- 不要手工修改文件。
- 丢失身份文件会改变 PeerId，所有 endpoint 配置都必须更新。

Linux 权限示例：

```console
sudo install -d -o yonder -g yonder -m 0750 /var/lib/yonder
sudo -u yonder yon-relay identity init --output /var/lib/yonder/relay.key
sudo chmod 0600 /var/lib/yonder/relay.key
```

Unix 上 relay 会在读取 identity 时拒绝任何 group/other 权限，`0640` 也会失败；文件必须由运行账户持有并使用 `0600`。直接父目录不得由 group/other 写入，且必须由 `root` 或密钥文件所有者持有，否则创建和读取都会安全失败。Windows 上 `identity init` 会在写入私钥字节前设置受保护 ACL，只允许当前运行账户、`SYSTEM` 和 `Administrators`；读取 identity 时会再次验证文件 ACL、所有者以及父目录替换权限。应以最终运行 relay 的服务账户创建 identity，不要先用普通管理员账户创建后再只复制文件。

Windows 生产目录应先建立明确 ACL。以下命令中的 `DOMAIN\YonderSvc` 必须替换为实际服务账户：

```powershell
New-Item -ItemType Directory -Force 'C:\ProgramData\Yonder' | Out-Null
icacls 'C:\ProgramData\Yonder' /inheritance:r /grant:r `
  'DOMAIN\YonderSvc:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
```

如果目录允许其他主体修改或替换文件，`identity init` 和后续读取会安全失败。不要通过关闭 ACL 检查绕过该错误。

### 5.2 最小生产配置

创建 `/etc/yonder/yon-relay.toml`：

```toml
identity = "/var/lib/yonder/relay.key"

listen = [
  "/ip4/0.0.0.0/tcp/4001",
  "/ip4/0.0.0.0/udp/4001/quic-v1",
]

external = [
  "/dns4/relay.example.com/tcp/4001",
  "/dns4/relay.example.com/udp/4001/quic-v1",
]
```

启动：

```console
yon-relay --log-level info serve
```

启动成功后，stdout 会输出可直接复制到 endpoint 的完整地址：

```text
/dns4/relay.example.com/tcp/4001/p2p/12D3KooW...
/dns4/relay.example.com/udp/4001/quic-v1/p2p/12D3KooW...
Relay PeerId: 12D3KooW...
```

stdout 只用于可复制的公开地址和 PeerId；诊断日志写入 stderr。wildcard、私网或动态监听地址不会混入 endpoint 配置输出。

### 5.3 四传输配置

```toml
identity = "/var/lib/yonder/relay.key"

listen = [
  "/ip4/0.0.0.0/tcp/4001",
  "/ip4/0.0.0.0/udp/4001/quic-v1",
  "/ip4/0.0.0.0/tcp/4002/ws",
  "/ip4/0.0.0.0/tcp/443/tls/ws",
]

external = [
  "/dns4/relay.example.com/tcp/4001",
  "/dns4/relay.example.com/udp/4001/quic-v1",
  "/dns4/relay.example.com/tcp/4002/ws",
  "/dns4/relay.example.com/tcp/443/tls/ws",
]

wss_certificate_der = "/etc/yonder/tls/relay-cert.der"
wss_private_key_der = "/etc/yonder/tls/relay-key.der"
```

`listen` 与 `external` 都必须包含 `1..=8` 个地址，每个地址最长 `512` 字节。`listen` 不带 `/p2p`，允许 wildcard；`external` 不带 `/p2p`，必须是客户端真实可达且端口非零的 IP/DNS 地址。

使用固定 IP 部署时，把 `external` 中的 `/dns4/<域名>` 换成
`/ip4/<客户端可达的 IP>`。例如 relay 的公网 IP 是 `203.0.113.10`：

```toml
identity = "/var/lib/yonder/relay.key"

listen = [
  "/ip4/0.0.0.0/tcp/4001",
  "/ip4/0.0.0.0/udp/4001/quic-v1",
  "/ip4/0.0.0.0/tcp/4002/ws",
  "/ip4/0.0.0.0/tcp/443/tls/ws",
]

external = [
  "/ip4/203.0.113.10/tcp/4001",
  "/ip4/203.0.113.10/udp/4001/quic-v1",
  "/ip4/203.0.113.10/tcp/4002/ws",
  "/ip4/203.0.113.10/tcp/443/tls/ws",
]

wss_certificate_der = "/etc/yonder/tls/relay-cert.der"
wss_private_key_der = "/etc/yonder/tls/relay-key.der"
```

relay 启动后会在 stdout 输出已经追加真实 PeerId 的四条地址。把这些地址原样放到主控端和被控端的 `yon.toml`，并在使用自签证书时配置信任锚：

```toml
relays = [
  "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooW...",
  "/ip4/203.0.113.10/udp/4001/quic-v1/p2p/12D3KooW...",
  "/ip4/203.0.113.10/tcp/4002/ws/p2p/12D3KooW...",
  "/ip4/203.0.113.10/tcp/443/tls/ws/p2p/12D3KooW...",
]

wss_ca_der = "/etc/yonder/relay-cert.der"
```

`203.0.113.10` 只是文档保留地址，部署时必须替换。服务器直接持有公网 IP 时，`listen` 继续使用 `0.0.0.0` 即可；服务器位于云 NAT、端口转发或 DNAT 后面时，`external` 写转换后的客户端可达 IP，并把 `4001/TCP`、`4001/UDP`、`4002/TCP` 和 `443/TCP` 分别转发到上述监听端口。若不启用某种传输，应同时从 `listen`、`external` 和 endpoint `relays` 中删除对应地址。

IP 形式的 WSS 地址要求叶证书的 SAN 包含精确的 `IP:203.0.113.10`；仅把 IP 写入 Common Name 不会通过验证。自签叶证书本身配置为 endpoint 的 `wss_ca_der`，私钥只能留在 relay。完整生成命令见 7.3 节。

### 5.4 relay 全量资源配置

以下示例显式写出全部默认值。没有明确容量测量需求时，建议保留默认值：

```toml
identity = "/var/lib/yonder/relay.key"
listen = ["/ip4/0.0.0.0/tcp/4001"]
external = ["/dns4/relay.example.com/tcp/4001"]

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

字段含义与范围：

| 字段 | 默认值 | 合法范围/约束 | 说明 |
| --- | ---: | --- | --- |
| `registry.capacity` | 128 | `1..=320` | Active 与断线宽限映射总数 |
| `registry.per_source` | 32 | `1..=320` 且不大于总容量 | 每个来源 IPv4 `/32` 或 IPv6 `/64` 的注册数 |
| `registry.reservation_duration_seconds` | 3600 | `60..=86400` | Circuit Relay reservation 有效期 |
| `resolve.concurrency` | 64 | `1..=320` | 同时处理的定位查询数 |
| `resolve.global_rate_per_second` | 4 | `1..=10000` | 全局查询持续速率 |
| `resolve.global_burst` | 128 | `1..=65536` | 全局查询突发量 |
| `resolve.source_rate_per_second` | 1 | `1..=10000` 且不大于全局值 | 单来源持续速率 |
| `resolve.source_burst` | 32 | `1..=65536` 且不大于全局值 | 单来源突发量 |
| `resolve.source_limiter_capacity` | 4096 | `1..=65536`，并满足下述公式 | 来源限速状态表容量 |
| `resolve.source_limiter_idle_seconds` | 600 | `1..=86400` | 来源限速状态空闲回收时间 |
| `resolve.retry_milliseconds` | 250 | `100..=5000` | 返回给客户端的有界重试提示 |
| `circuit.capacity` | 128 | `1..=320` | 同时转发的 circuit 总数 |
| `circuit.duration_seconds` | 86400 | `60..=604800` | 单 circuit 最长持续时间 |
| `circuit.bytes` | 8589934592 | `1048576..=1099511627776` | 单 circuit 最大转发字节数 |

`source_limiter_capacity` 还必须满足：

```text
source_limiter_capacity >=
  global_rate_per_second * source_limiter_idle_seconds + global_burst
```

提高注册容量时，应同步提高 `circuit.capacity`，并重新评估文件描述符、带宽、内存和来源配额。容量满时 relay 不会驱逐现有会话，而是拒绝新注册。

### 5.5 relay 环境变量清单

| TOML 字段 | 环境变量 |
| --- | --- |
| `identity` | `YON_RELAY_IDENTITY` |
| `listen` | `YON_RELAY_LISTEN` |
| `external` | `YON_RELAY_EXTERNAL` |
| `wss_certificate_der` | `YON_RELAY_WSS_CERTIFICATE_DER` |
| `wss_private_key_der` | `YON_RELAY_WSS_PRIVATE_KEY_DER` |
| `registry.capacity` | `YON_RELAY_REGISTRY__CAPACITY` |
| `registry.per_source` | `YON_RELAY_REGISTRY__PER_SOURCE` |
| `registry.reservation_duration_seconds` | `YON_RELAY_REGISTRY__RESERVATION_DURATION_SECONDS` |
| `resolve.concurrency` | `YON_RELAY_RESOLVE__CONCURRENCY` |
| `resolve.global_rate_per_second` | `YON_RELAY_RESOLVE__GLOBAL_RATE_PER_SECOND` |
| `resolve.global_burst` | `YON_RELAY_RESOLVE__GLOBAL_BURST` |
| `resolve.source_rate_per_second` | `YON_RELAY_RESOLVE__SOURCE_RATE_PER_SECOND` |
| `resolve.source_burst` | `YON_RELAY_RESOLVE__SOURCE_BURST` |
| `resolve.source_limiter_capacity` | `YON_RELAY_RESOLVE__SOURCE_LIMITER_CAPACITY` |
| `resolve.source_limiter_idle_seconds` | `YON_RELAY_RESOLVE__SOURCE_LIMITER_IDLE_SECONDS` |
| `resolve.retry_milliseconds` | `YON_RELAY_RESOLVE__RETRY_MILLISECONDS` |
| `circuit.capacity` | `YON_RELAY_CIRCUIT__CAPACITY` |
| `circuit.duration_seconds` | `YON_RELAY_CIRCUIT__DURATION_SECONDS` |
| `circuit.bytes` | `YON_RELAY_CIRCUIT__BYTES` |

列表环境变量用逗号分隔：

```console
export YON_RELAY_LISTEN='/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic-v1'
export YON_RELAY_EXTERNAL='/dns4/relay.example.com/tcp/4001,/dns4/relay.example.com/udp/4001/quic-v1'
```

## 6. 配置 endpoint

主控端和被控端使用相同的 `yon.toml`。把 relay 启动时输出的完整地址原样填入 `relays`：

```toml
relays = [
  "/dns4/relay.example.com/tcp/4001/p2p/12D3KooW...",
  "/dns4/relay.example.com/udp/4001/quic-v1/p2p/12D3KooW...",
  "/dns4/relay.example.com/tcp/4002/ws/p2p/12D3KooW...",
  "/dns4/relay.example.com/tcp/443/tls/ws/p2p/12D3KooW...",
]

wss_ca_der = "/etc/yonder/relay-ca.der"
```

规则：

- `relays` 必填，必须包含 `1..=8` 个地址。
- 每个地址最长 `512` 字节。
- 每个地址必须以 `/p2p/<relay PeerId>` 结尾。
- 列表中所有地址必须固定同一个 relay PeerId。
- 只有使用私有 CA 或自签 WSS 时才需要 `wss_ca_der`。
- `wss_ca_der` 最大 `1 MiB`。

环境变量：

```console
export YON_RELAYS='/dns4/relay.example.com/tcp/4001/p2p/12D3KooW...,/dns4/relay.example.com/udp/4001/quic-v1/p2p/12D3KooW...'
export YON_WSS_CA_DER='/etc/yonder/relay-ca.der'
```

在 Windows PowerShell 中：

```powershell
$env:YON_RELAYS = '/dns4/relay.example.com/tcp/4001/p2p/12D3KooW...'
$env:YON_WSS_CA_DER = 'C:\ProgramData\Yonder\relay-ca.der'
```

## 7. WSS 证书部署

### 7.1 什么时候需要证书

只有 `/tls/ws` 即 WSS 使用运维证书：

- TCP 和 WS 使用 libp2p Noise，不读取 WSS 证书。
- QUIC 使用 libp2p QUIC/TLS 1.3 身份认证，不读取这组运维证书。
- WSS 同时具有外层 TLS 和内层 libp2p 身份认证。

WSS 不会替代 relay PeerId 固定。证书正确但 PeerId 不匹配时，endpoint 仍会拒绝连接。

### 7.2 证书要求

- 文件格式必须是 DER，不是 PEM。
- relay 必须同时配置证书和私钥。
- 通过 IP 连接时，证书必须包含对应 `IP SAN`。
- 通过域名连接时，证书必须包含对应 `DNS SAN`。
- 只设置 Common Name (`CN`) 不够。
- 叶证书应为 `CA:FALSE`，并允许 `serverAuth`。
- 私钥必须与证书匹配，且使用客户端 TLS 实现支持的 DER 私钥编码。
- 证书 DER 最大 `1 MiB`，私钥 DER 最大 `64 KiB`。
- 当前 relay 只发送一个叶证书 DER，不支持需要发送 intermediate chain 的证书链。
- 可使用公有 CA 直接签发的叶证书、私有根 CA 直接签发的叶证书，或自签叶证书。

relay 会在监听前解析 DER 和私钥编码，并逐项验证所有 WSS `external` 地址的 DNS/IP SAN。有效期、用途、信任关系、证书链和密钥匹配最终由真实 TLS 握手验证。TLS 失败时不会降级为明文 WS。

在 Linux/macOS 上，WSS 私钥必须由 relay 运行账户持有并使用 `0600`；其直接父目录同样必须禁止 group/other 写入，并由 `root` 或私钥所有者持有。证书是公钥材料，可以使用 `0644`。例如：

```console
sudo install -d -o root -g yonder -m 0750 /etc/yonder/tls
sudo install -o root -g root -m 0644 relay-cert.der /etc/yonder/tls/relay-cert.der
sudo install -o yonder -g yonder -m 0600 relay-key.der /etc/yonder/tls/relay-key.der
```

Windows 对 WSS 私钥执行与 identity 相同的 ACL/父目录校验。使用 `icacls` 将私钥限制为服务账户、`SYSTEM` 和 `Administrators`；WSS 证书不含私钥，不需要同等读取限制。

### 7.3 生成自签 IP 叶证书

下面示例为 IP `203.0.113.10` 生成自签叶证书。应替换为真实 relay IP：

```console
umask 077

cat > yonder-openssl.cnf <<'EOF'
[req]
prompt = no
distinguished_name = subject
x509_extensions = server

[subject]
CN = yonder-relay

[server]
subjectAltName = IP:203.0.113.10
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -config yonder-openssl.cnf \
  -keyout relay-key.pem \
  -out relay-cert.pem

openssl x509 -in relay-cert.pem -outform DER -out relay-cert.der
openssl pkcs8 -topk8 -nocrypt -in relay-key.pem -outform DER -out relay-key.der

openssl x509 -inform DER -in relay-cert.der -noout -text
openssl pkey -inform DER -in relay-key.der -noout -check
```

这里使用独立的最小 OpenSSL 配置，而不是在系统 `openssl.cnf` 上叠加多个 `-addext`。部分 OpenSSL 1.1.1 发行版会为 `req -x509` 从系统配置自动加入 `CA:TRUE`；继续叠加 `CA:FALSE` 会生成带两个同名 `Basic Constraints` 的畸形证书，OpenSSL 命令可能仍能读取，但 Yonder/WebPKI 会按规范拒绝。检查 `-text` 输出时，必须只有一项 `Basic Constraints: critical` 且其值为 `CA:FALSE`，SAN 也必须只有预期的精确 IP。确认 DER 后可删除临时的 `yonder-openssl.cnf`、PEM 私钥和 PEM 证书。

relay 配置：

```toml
listen = ["/ip4/0.0.0.0/tcp/443/tls/ws"]
external = ["/ip4/203.0.113.10/tcp/443/tls/ws"]
wss_certificate_der = "/etc/yonder/tls/relay-cert.der"
wss_private_key_der = "/etc/yonder/tls/relay-key.der"
```

两个 endpoint 都信任同一自签叶证书：

```toml
relays = ["/ip4/203.0.113.10/tcp/443/tls/ws/p2p/12D3KooW..."]
wss_ca_der = "/etc/yonder/relay-cert.der"
```

私钥只能部署到 relay；endpoint 只需要证书或 CA 公钥材料。

### 7.4 证书轮换

当前一个 relay 进程只加载一份 WSS 叶证书。建议轮换步骤：

1. 生成覆盖同一 DNS/IP SAN 的新证书和私钥。
2. 私有 CA 的根证书不变时，endpoint 无需改动；先用测试 endpoint 验证新叶证书。
3. 原子替换 relay DER 文件。
4. 重启 relay 并执行真实 `yon host + yon connect` WSS 会话。
5. 确认所有 endpoint 使用正常后归档或销毁旧私钥。

使用自签叶证书时，新叶证书本身就是新信任锚，而 `0.1.0` 的一个 endpoint 配置只能加载一份 `wss_ca_der`，不能同时信任旧、新两份自签叶证书。应在维护窗口协调更新双方 endpoint 和 relay，或始终保留一个已验证的 TCP/QUIC/WS 非 WSS 入口作为轮换通道。需要长期无中断轮换时，优先使用稳定的私有根 CA 签发短期叶证书。

## 8. 托管 relay 进程

### 8.1 Linux systemd

创建专用系统账户：

```console
sudo useradd --system --home-dir /var/lib/yonder --shell /usr/sbin/nologin yonder
sudo install -d -o root -g yonder -m 0750 /etc/yonder
sudo install -d -o yonder -g yonder -m 0750 /var/lib/yonder
```

创建身份并写好 `/etc/yonder/yon-relay.toml` 后，创建 `/etc/systemd/system/yon-relay.service`：

```ini
[Unit]
Description=Yonder Relay
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=simple
User=yonder
Group=yonder
WorkingDirectory=/var/lib/yonder
ExecStart=/usr/local/bin/yon-relay --log-level info serve
KillSignal=SIGTERM
TimeoutStopSec=5s
Restart=on-failure
RestartSec=3s
LimitNOFILE=4096
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/yonder /var/lib/yonder

[Install]
WantedBy=multi-user.target
```

启动和检查：

```console
sudo systemctl daemon-reload
sudo systemctl enable --now yon-relay
sudo systemctl status yon-relay
sudo journalctl -u yon-relay -f
```

如果身份、证书或配置放在其他目录，应同步调整 systemd 只读路径与文件 ACL。relay 正常不需要 root 权限。`SIGTERM`、`SIGINT` 和 `SIGHUP` 都会进入有界清理；`TimeoutStopSec=5s` 给应用内部 `2s` 清理留出余量。`StartLimit*` 防止配置错误导致无限快速重启，修复配置后可用 `systemctl reset-failed yon-relay` 清除启动限制。

推荐让 relay 监听非特权端口，再由云 NAT、防火墙或反向入口把公网 `443/TCP` 转发到本机高端口。例如：

```toml
listen = ["/ip4/0.0.0.0/tcp/8443/tls/ws"]
external = ["/dns4/relay.example.com/tcp/443/tls/ws"]
```

若必须由 `yon-relay` 直接绑定本机 `443`，只在上述 service 的 `[Service]` 增加以下两行，不要改为 root 运行：

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

### 8.2 macOS launchd

relay 应使用专用服务账户的系统 LaunchDaemon 托管。先按组织账户管理规范创建无交互登录权限的 `yonder` 账户，再准备目录：

```console
sudo install -d -o yonder -g staff -m 0700 '/Library/Application Support/Yonder'
sudo install -d -o yonder -g staff -m 0700 /var/log/yonder
sudo chmod 0600 '/Library/Application Support/Yonder/relay.key'
```

创建 `/Library/LaunchDaemons/com.yonder.relay.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.yonder.relay</string>
  <key>UserName</key><string>yonder</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/yon-relay</string>
    <string>--log-level</string><string>info</string>
    <string>serve</string>
  </array>
  <key>WorkingDirectory</key><string>/Library/Application Support/Yonder</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>/var/log/yonder/relay.out.log</string>
  <key>StandardErrorPath</key><string>/var/log/yonder/relay.err.log</string>
</dict>
</plist>
```

加载前校验属主、权限和 plist：

```console
sudo chown root:wheel /Library/LaunchDaemons/com.yonder.relay.plist
sudo chmod 0644 /Library/LaunchDaemons/com.yonder.relay.plist
plutil -lint /Library/LaunchDaemons/com.yonder.relay.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.yonder.relay.plist
sudo launchctl kickstart -k system/com.yonder.relay
sudo launchctl print system/com.yonder.relay
```

停止或卸载时使用 `sudo launchctl bootout system/com.yonder.relay`。launchd 发送的 `SIGTERM` 会触发 relay 有界清理。不要把用户级 LaunchAgent 当作生产系统服务。

### 8.3 Windows 进程托管

`yon-relay` `0.1.0` 是 console 程序，不实现 Windows SCM 的 `ServiceMain`，因此不能直接用 `sc.exe create` 注册后期待正常启动。生产环境必须使用组织已有、经过验证的进程监督或编排系统，以专用低权限服务账户运行 console 程序：

```powershell
& 'C:\Program Files\Yonder\yon-relay.exe' --log-level info serve
```

配置放在 `C:\ProgramData\Yonder\yon-relay.toml`，身份和私钥只授予服务账户读取权限。服务管理器应：

- 在网络就绪后启动。
- 捕获 stdout 和 stderr 到受控日志系统。
- 失败后进行有界重启。
- 停止时先发送可处理的控制事件，并设置终止上限。
- 不把身份、WSS 私钥或连接码写入命令行参数。

Windows 路径支持 Ctrl+C、Ctrl+Break、Close、Logoff 和 Shutdown 控制事件并执行有界清理。若所选 supervisor 只调用 `TerminateProcess`，在线注册与 circuit 会被立即中断；这不破坏端到端保密性，但不属于优雅停止。仓库和正式 release 不捆绑第三方 service wrapper，运维方必须把 supervisor 本身纳入补丁、签名和供应链管理。

## 9. 使用远程终端

### 9.1 被控端发布终端

在希望成为远端工作目录的位置运行：

```console
cd /path/to/workspace
yon host
```

成功后 stdout 显示：

```text
Connection code: ABCD-EFGH-JKMP-QRST
```

注意：

- 连接码每次进程启动重新生成。
- 不要把连接码写入公开聊天、工单、日志或 shell history。
- `yon host` 使用当前用户权限，不提权。
- Unix 优先使用绝对、存在、可执行的 `$SHELL`，否则使用 `/bin/sh`。
- Windows 使用有效的 `%COMSPEC%`，否则回退到 `cmd.exe`。
- 以 root、Administrator 或高权限服务账户启动会把同等权限暴露给成功认证的本次会话。

当 stdout 与 stderr 同为终端时，`yon host` 会在 stderr 的同一行显示 relay 连接、reservation、注册、等待主控、断线重连、认证和终端启动状态。连接码写入 stdout 前会先清除注册进度；连接码输出后继续显示等待状态。relay 暂时不可用时，host 会持续显示重连心跳，而不是无输出地等待退避计时。

### 9.2 主控端连接

默认推荐省略位置参数，通过隐藏提示输入连接码，避免进入 shell history 和进程参数列表：

```console
yon connect
```

交互 TTY 会先校验 endpoint 配置，然后显示 `Connection code:`；输入内容不会回显。直接传入连接码仅适合作为清楚了解泄漏面的临时便利方式：

```console
yon connect ABCD-EFGH-JKMP-QRST
```

连接码输入接受规范分组和无连字符形式，也接受小写；`O/o` 按 `0` 处理，`I/i/L/l` 按 `1` 处理。输入不接受空白、其他分隔符或字母 `U/u`。

当 stdout 与 stderr 同为终端时，连接会在 stderr 的同一行依次显示 relay 连接、host 查询、路径建立、端到端认证和终端启动阶段；即使连接码或后续输入来自管道，画面上仍能看到当前等待内容。直连未在优先窗口内形成可信终态时会明确显示正在切换到 relay。收到远端 `TerminalReady` 后该进度行会被清除，之后屏幕只属于远端终端。启用诊断文件后，最终选中的 Direct/Relayed 路径和 QUIC/TCP/WS/WSS transport 会记录在诊断日志中，不写入远端终端画面。

`host` 与 `connect` 的进度都会立即显示；同一阶段持续等待时，ASCII spinner 最迟每 `1s` 刷新一次。每次刷新都会重新读取终端宽度，提示限制在当前宽度减一列，不会自动换行。stdout 或 stderr 不是终端、stderr 已重定向、初始终端尺寸不可可靠取得，或 `TERM=dumb` 时不发送进度和光标控制序列；已显示进度后若终端尺寸查询失效，程序会用无 ANSI 的 CRLF 结束当前行并停用后续进度，避免 raw mode 下远端首行从旧列位置开始。

### 9.3 非交互调用

标准输入第一行可以提供连接码，剩余字节继续发给远端 shell：

```console
printf 'ABCD-EFGH-JKMP-QRST\necho hello\nexit\n' | yon connect
```

Windows ConPTY 无法在保留尾部输出的同时可靠地把管道关闭映射为 shell EOF，因此 Windows 非交互脚本必须显式发送 `exit`。Unix 会把输入半关闭传递为 PTY EOF，但显式 `exit` 仍是更清晰的跨平台做法。

### 9.4 终端行为

- 本地终端尺寸变化会同步到远端 PTY。
- ANSI 控制字节原样传输。
- 交互模式下 Ctrl+C 作为字节发送给远端前台程序。
- 按 `Ctrl+]` 后再按 `.` 会在本地主控端断开会话；连续按两次 `Ctrl+]` 会向远端发送一个原样的 `Ctrl+]`。该转义只作用于交互终端，管道输入完全原样转发。
- 远端 shell 的 `0..=255` 退出码传播给本地主控进程。
- 超出可移植范围的远端退出码会记录警告，并在本地返回 `1`。
- 会话结束、连接中断或本地终端恢复失败时，必要警告和结构化错误会在远端最后一段输出后另起一行显示，不会黏在远端提示符或被 tracing 过滤掉。
- 会话创建成功后连接码被消费，即使随后立即断线也不能复用。
- 会话结束后 `yon host` 清理 PTY 和子进程并退出。

常见进程退出码：

| 退出码 | 含义 |
| ---: | --- |
| `0` | 命令或远端 shell 成功完成 |
| `1` | 一般配置、网络、运行时或服务错误；也用于无法映射的远端退出码 |
| `2` | 连接码长度、编码或格式错误 |
| `130` | `host` 在等待阶段收到 Ctrl+C，或主控端在非 Active 阶段被中断 |
| 其他 `0..=255` | 成功建立会话后传播的远端 shell 退出码 |

### 9.5 日志级别与输出通道

两个程序都支持全局日志级别：

```console
yon --log-level error host
yon --log-level debug --log-file yon-connect-debug.log connect
yon-relay --log-level info serve
```

可选值为 `off`、`error`、`warn`、`info`、`debug`、`trace`。

- `yon` 默认 `error`。当 `connect` 的 stdout 与 stderr 同为终端时，程序关闭 tracing，应用错误仍会在进度行清理后显示，因此远端终端不会被第三方 warning 或网络诊断污染。
- `yon-relay` 默认 `info`。
- 业务输出写 stdout。
- 诊断日志写 stderr。
- `yon connect` 向终端输出远端画面时，使用 `warn`、`info`、`debug` 或 `trace` 必须指定 `--log-file` 或重定向 stderr；未分离时会在连接前直接拒绝并显示示例命令。优先使用 `--log-file`，这样进度仍留在终端，而详细诊断追加写入文件。
- 调试时可以临时使用 `debug`；`trace` 只应在受控窗口启用，避免产生大量网络事件日志。日志可能包含地址、PeerId 和时序元数据，按敏感运维材料保存。

## 10. 生命周期、重启与升级

### 10.1 连接码状态

- 注册正常且 reservation 有效时，连接码可查询。
- relay 连接或 reservation 临时失效时，映射进入最多 `120s` 的断线宽限。
- 宽限内恢复时，被控端优先取回原定位码和完整连接码。
- 正常注销会立即删除映射。
- 认证或网络失败不会消费连接码。
- 只有终端创建成功并确认后才消费连接码。
- 一个连接码同时只允许一个 OPAQUE 认证交换，额外请求收到可重试结果。

### 10.2 relay 重启

relay 注册表只存在内存中。重启会丢失临时映射，但不会丢失持久 PeerId，前提是身份文件保持不变。

被控端会重新连接并优先申请原定位码：

- 原定位码仍可用时，连接码保持不变。
- 原定位码已被其他 host 占用时，被控端生成全新的连接码并重新输出。

运维自动化不能假设 relay 重启后连接码绝对不变，应监控 `yon host` stdout 是否输出了替换码。

### 10.3 升级 relay

1. 校验新二进制 SHA-256 和 provenance。
2. 备份 relay 身份文件，并确认备份访问受控。
3. 保留旧二进制以便回滚。
4. 停止旧进程并替换单文件程序。
5. 使用 `yon-relay --version` 和 `yon-relay --help` 做离线 smoke。
6. 启动 relay，确认输出 PeerId 与升级前完全一致。
7. 从独立 endpoint 验证至少一个 TCP/QUIC 连接和真实终端会话。

回滚时恢复旧二进制，不要重新生成身份。因为注册表是内存态，升级和回滚都会使在线 host 执行重连。

### 10.4 升级 endpoint

`yon` 是单文件程序，没有本地持久身份。退出当前 host/connect 后替换二进制即可。不要在 Active 终端会话中直接覆盖正在运行的文件；先结束会话，再升级并重新生成连接码。

## 11. 安全运维要求

### 11.1 必须保护的材料

| 材料 | 存放位置 | 保护要求 |
| --- | --- | --- |
| relay identity | 仅 relay | 私钥；最小读取权限、加密备份、禁止外发 |
| WSS private key | 仅 relay | 私钥；最小读取权限、按证书制度轮换 |
| WSS certificate/CA | relay 和/或 endpoint | 公钥材料；保持完整性，避免误配 |
| 连接码 | host 与获授权用户 | 短期认证秘密；不要记录或复用 |
| 终端内容 | 两个 endpoint 内存 | relay 只能转发密文，端点仍需按主机安全基线保护 |

### 11.2 relay 信任边界

relay 按不可信基础设施设计。即使 relay 被入侵，攻击者也不应通过正常协议读取或修改终端内容、伪造按键或冒充 endpoint。但恶意 relay 仍可：

- 观察双方网络元数据和流量大小。
- 拒绝查询或 reservation。
- 延迟、丢弃、截断或中断转发。
- 通过可用性攻击迫使会话失败。

因此 relay 日志、网络流量和操作权限仍应纳入组织安全监控。不要把“不可信 relay”误解为“relay 无需加固”。

`0.1.0` 的 relay 不提供租户账户、接入 allowlist、令牌鉴权或计费。只要能访问监听端口的任意 libp2p PeerId 都可以尝试申请 reservation；内置总容量、每 PeerId/来源限制和查询限速只保证资源有界，不把公网 listener 变成私有准入系统。互联网公开部署必须结合网络层访问控制、容量监控和组织的抗 DDoS 能力；若 relay 只供固定网络使用，应在云安全组/防火墙限制来源。不要把连接码的端到端认证误当作 relay 使用权认证。

### 11.3 endpoint 主机安全

- 只在确实要授权远程终端时运行 `yon host`。
- 使用最小权限用户，不要习惯性使用 root/Administrator。
- 会话结束后确认 `yon host` 已退出。
- 连接码通过独立受控渠道传递。
- 不要在共享终端或录屏环境中直接显示连接码。
- 调试日志不应上传到公开渠道；虽然产品避免输出认证秘密，日志仍可能包含地址和 PeerId 等元数据。

## 12. 监控与日常巡检

### 12.1 relay 启动检查

```console
yon-relay --version
yon-relay config check
yon-relay --log-level info serve
```

应确认：

- 进程持续运行且没有配置错误。
- stdout 列出的所有 `external` 地址均带同一个预期 PeerId。
- DNS 解析结果和公网端口映射正确。
- TCP/UDP listener 均已建立。
- WSS 证书 SAN 与每个 WSS `external` 地址一致。
- 进程文件描述符上限高于计划连接容量。

Linux 查看监听：

```console
ss -lntup | grep -E ':(4001|4002|443)\b'
```

### 12.2 建议监控项

Yonder `0.1.0` 主要通过结构化诊断日志和操作系统指标观测。relay 会输出低基数的 `relay_starting`、`relay_ready`、`relay_shutdown_requested`、`relay_stopped` 事件，并每 `60s` 输出一次 `relay_activity_summary` 聚合计数。建议采集：

- 进程存活、重启次数和退出码。
- CPU、RSS、文件描述符数量和网络吞吐。
- 各 listener 的 TCP/UDP 可达性。
- `relay_activity_summary` 中注册容量/并发拒绝、查询重试/限速和协议失败计数。
- WSS 握手失败、证书到期时间和 DNS 变更。
- relay PeerId 是否意外变化。
- endpoint 建立直连还是使用 relay fallback 的诊断信息。

不要对 QUIC UDP 端口只做 TCP 探测；应使用真实 `yon host + yon connect` 会话作为端到端健康检查。

### 12.3 备份与恢复演练

至少定期验证：

1. 能从加密备份恢复 relay identity。
2. 恢复后启动 `yon-relay serve`，确认输出的 PeerId 与备份前相同。
3. 配置、证书和私钥路径权限正确。
4. 新主机的公网 TCP/UDP 防火墙与 NAT 映射正确。
5. 两个 endpoint 能使用现有 `yon.toml` 建立真实终端会话。

注册表和连接码映射不需要备份，也无法通过文件恢复。

## 13. 故障排查

### 13.1 配置加载失败

检查顺序：

1. 运行 `yon config sources` 查看 endpoint 实际读取的系统文件、当前目录文件及环境变量前缀；relay 使用手册列出的对应固定路径和 `YON_RELAY_` 前缀。
2. 运行 `yon config check` 或 `yon-relay config check`，在启动网络活动前完成完整配置校验；relay 检查还会读取 identity、地址、资源限制和 TLS 材料。
3. 检查 `YON_` 或 `YON_RELAY_` 环境变量是否覆盖了文件。
4. 确认 TOML 是 UTF-8、普通文件且小于等于 `64 KiB`。
5. 删除未知字段，检查嵌套字段拼写。
6. 检查相对路径是相对于提供该字段的配置层，而不是统一相对于程序目录。

可以临时使用只包含必要字段的独立目录排除当前目录覆盖：

```console
mkdir /tmp/yonder-config-check
cd /tmp/yonder-config-check
yon config sources
yon config check
```

程序仍会读取系统配置；如需完全隔离，应在测试账户或容器中使用受控系统配置。

### 13.2 relay 无法启动 listener

- 检查端口是否被其他进程占用。
- 检查同一个 TCP 端口是否同时配置了 TCP、WS 或 WSS listener。
- 检查低端口绑定权限。
- `listen` 必须使用 IP，不能使用 DNS 或带 `/p2p` 的地址。
- `external` 必须非 wildcard、端口非零且真实可达。
- 配置 WSS 时必须同时提供证书和私钥。
- 每个 `external` transport 必须存在同类型 `listen`；公网 IP 和端口可以是 NAT 改写后的值，但不能发布进程并未监听的 transport。

### 13.3 endpoint 无法连接 relay

- 确认双方 `yon.toml` 使用同一个 PeerId。
- 从 relay 最新启动输出复制完整地址，不要手工拼 PeerId。
- 检查 DNS、云安全组、本机防火墙和 NAT 端口转发。
- 分别验证 TCP 和 UDP 出站；某些网络会阻断 QUIC UDP。
- 保留多个传输入口，让 Yonder 自动选择可用路径。
- 使用 `yon --log-level debug --log-file yon-connect-debug.log connect` 查看具体候选失败，不要立即只保留一个协议。

### 13.4 WSS 握手失败

- 确认 endpoint 配置的是 CA/自签证书 DER，不是 PEM。
- 确认 relay 配置的是叶证书 DER 与匹配私钥 DER。
- 使用 IP 地址时检查 `IP SAN`；使用域名时检查 `DNS SAN`。
- 检查证书有效期、`serverAuth` 和 `CA:FALSE`。
- 当前不支持需要发送 intermediate chain 的证书。
- 系统时间错误会导致有效期校验失败。
- TLS 失败不会自动降级为 WS；如果同时配置了其他独立地址，Yonder 可以选择其他地址。

OpenSSL 检查示例：

```console
openssl x509 -inform DER -in relay-cert.der -noout -subject -issuer -dates -ext subjectAltName
openssl pkey -inform DER -in relay-key.der -noout -check
```

### 13.5 `yon host` 不显示连接码

- host 必须先取得 relay reservation 和临时注册。
- 检查 relay `external` 是否配置并可发布。
- 检查 relay 注册容量和来源配额是否已满。
- 检查双方到 relay 的所有候选地址是否均失败。
- 查看 stderr；连接码只写 stdout。
- relay 身份错误或传输被篡改时，host 会安全重试且不会发布连接码。

### 13.6 连接码无效或已失效

可能原因统一包括：

- 连接码输入错误。
- host 已退出。
- 断线宽限已超过 `120s`。
- 连接码已被一次成功会话消费。
- relay 重启后原定位码发生冲突，host 已输出替换码。

relay 和 CLI 不会向查询者进一步区分这些内部状态。向被控端索取当前 stdout 上最新连接码，不要重复使用旧码。

### 13.7 直连失败但会话可用

这是允许的正常状态。Yonder 会先建立 relay circuit，再尝试 DCUtR。严格 NAT、对称 NAT、UDP 阻断或主机防火墙可能阻止直连；会话会继续通过 relay 端到端加密转发。

有可用 relay 候选时，Yonder 至少进行 `1.5s` 质量采样；尚未出现直连时，DCUtR 最多获得 `3s` 优先窗口。窗口末尾刚建立的直连最多再等待 `750ms` 取得首个样本。可用直连不会因为 relay RTT 更低而被覆盖，Ping 没有返回也不会把已建立路径判为不可用。未形成可信直连时严格重建 relay-only 路径。没有任何端到端候选时才保留 `30s` 总连通预算。排障时应根据进度阶段观察完整预算，不要在几秒内反复终止进程。

### 13.8 终端行为异常

- 确认被控端当前用户的 shell 可执行且路径有效。
- Unix 检查 `$SHELL`；Windows 检查 `%COMSPEC%`。
- 检查被控端当前工作目录权限。
- 非交互 Windows 会话必须显式发送 `exit`。
- 如果远端程序修改了终端模式，先在普通本地 PTY 中复现。
- 使用 `yon --log-level debug --log-file yon-connect-debug.log connect` 收集诊断；不要让详细诊断与远端画面共享终端。

## 14. 上线验收清单

### 14.1 relay

- [ ] 已验证归档 SHA-256 和 provenance。
- [ ] 使用专用低权限账户运行。
- [ ] 身份文件只生成一次，权限和加密备份已验证。
- [ ] Unix identity/WSS 私钥为 `0600`，直接父目录禁止 group/other 写入且所有者为 `root` 或文件所有者；Windows 文件和父目录 ACL 只允许服务账户、SYSTEM 与 Administrators，且已通过 `yon-relay config check`。
- [ ] `listen` 与公网 `external` 一一对应。
- [ ] TCP/UDP 防火墙、安全组和 NAT 映射已开放。
- [ ] relay 启动输出的 PeerId 与 endpoint 配置一致。
- [ ] WSS DER、SAN、有效期、用途和私钥权限正确。
- [ ] 文件描述符、CPU、内存和带宽容量已评估。
- [ ] 日志进入受控系统，未把身份或连接码写入日志。
- [ ] 重启、升级和身份恢复演练已完成。

### 14.2 endpoint

- [ ] 主控端和被控端配置同一个 relay PeerId。
- [ ] 至少配置 TCP 和 QUIC 两种入口，或记录只使用单入口的网络原因。
- [ ] 私有 CA/自签 WSS 信任材料已部署到双方。
- [ ] 使用普通权限账户完成真实终端测试。
- [ ] 直连和 relay fallback 均符合预期。
- [ ] 诊断文件中的最终 Direct/Relayed 路径和 transport 与测试网络预期一致。
- [ ] 连接码通过受控渠道传递。
- [ ] 会话结束后 host 进程和远端 shell 均已退出。

### 14.3 端到端 smoke

被控端：

```console
yon host
```

主控端：

```console
yon connect
```

成功连接后至少验证：

```console
whoami
pwd
echo YONDER_SMOKE
exit
```

确认远端用户、权限和工作目录符合预期，本地主控进程返回成功，连接码不能再次使用。

## 15. 命令速查

```text
yon [--log-level <off|error|warn|info|debug|trace>] [--log-file <PATH>] host
yon [--log-level <off|error|warn|info|debug|trace>] [--log-file <PATH>] connect [CODE]
yon config check
yon config sources

yon-relay [--log-level <off|error|warn|info|debug|trace>]
  identity init --output <PATH>
yon-relay identity show --input <PATH>
yon-relay config check

yon-relay [--log-level <off|error|warn|info|debug|trace>] serve
```

查看当前二进制的权威 CLI 帮助：

```console
yon --help
yon connect --help
yon config --help
yon-relay --help
yon-relay identity init --help
yon-relay identity show --help
yon-relay config check --help
```
