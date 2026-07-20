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
5. Yonder 根据连通性、延迟、抖动和路径类型选择最终连接。直连不可用时继续使用 relay circuit。
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
| Secure WebSocket | `/dns4/relay.example.com/tcp/443/tls/ws` | TCP + TLS | 需要 WSS 或只开放 443 的网络 |

推荐至少同时提供 TCP 和 QUIC。需要穿越严格企业代理或只开放 HTTPS 风格出口时，再增加 WSS。WS 是明文 WebSocket 承载，但其中的 libp2p Noise 会继续保护端到端链路；WSS 在此基础上增加运维侧 TLS。

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

如果 relay 位于 NAT 后，必须把每个公网端口转发到对应 listener，并在 `external` 中填写外部可达地址和外部端口，不能填写容器地址、私网地址或 wildcard 地址。

### 3.3 DNS 与 IPv6

- `/dns4/...` 应解析为可达 IPv4 地址。
- `/dns6/...` 应解析为可达 IPv6 地址。
- `/ip4/...` 和 `/ip6/...` 直接使用固定 IP。
- `external` 可以使用 DNS 或明确 IP；`listen` 必须使用 IP。
- IPv6 listener 示例为 `/ip6/::/tcp/4001` 和 `/ip6/::/udp/4001/quic-v1`。
- DNS 变更生效前应保留旧地址，并在 endpoint 的 `relays` 列表中短期同时配置新旧入口。所有入口必须属于同一个 relay PeerId。

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

### 7.3 生成自签 IP 叶证书

下面示例为 IP `203.0.113.10` 生成自签叶证书。应替换为真实 relay IP：

```console
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -subj '/CN=yonder-relay' \
  -addext 'subjectAltName=IP:203.0.113.10' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout relay-key.pem \
  -out relay-cert.pem

openssl x509 -in relay-cert.pem -outform DER -out relay-cert.der
openssl pkcs8 -topk8 -nocrypt -in relay-key.pem -outform DER -out relay-key.der
```

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
2. 在两个 endpoint 的信任配置中提前部署新 CA；如果根 CA 不变则无需修改。
3. 原子替换 relay DER 文件。
4. 重启 relay 并观察 WSS 真实握手。
5. 确认所有 endpoint 使用正常后移除旧信任材料。

使用自签叶证书时，新叶证书本身就是新信任锚，必须先更新 endpoint，或在轮换窗口同时保留非 WSS 入口，避免锁死管理通道。

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

[Service]
Type=simple
User=yonder
Group=yonder
WorkingDirectory=/var/lib/yonder
ExecStart=/usr/local/bin/yon-relay --log-level info serve
KillSignal=SIGINT
Restart=on-failure
RestartSec=3s
LimitNOFILE=4096
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

如果身份、证书或配置放在其他目录，应同步调整 systemd 只读路径与文件 ACL。relay 不需要 root 权限；只有绑定低于 1024 的端口时才需要由平台安全策略授予相应绑定能力，或改用高端口加外部端口映射。

### 8.2 macOS launchd

relay 可以用专用服务账户的 LaunchDaemon 托管。以下用户级 LaunchAgent 示例适合功能验证；生产环境应按组织规范改为系统 LaunchDaemon 和受限账户。

`~/Library/LaunchAgents/com.yonder.relay.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.yonder.relay</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/yon-relay</string>
    <string>--log-level</string><string>info</string>
    <string>serve</string>
  </array>
  <key>WorkingDirectory</key><string>/Library/Application Support/Yonder</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Users/REPLACE_ME/Library/Logs/Yonder/relay.out.log</string>
  <key>StandardErrorPath</key><string>/Users/REPLACE_ME/Library/Logs/Yonder/relay.err.log</string>
</dict>
</plist>
```

加载前创建日志目录、替换用户名并校验 plist：

```console
mkdir -p ~/Library/Logs/Yonder
plutil -lint ~/Library/LaunchAgents/com.yonder.relay.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.yonder.relay.plist
launchctl print gui/$(id -u)/com.yonder.relay
```

### 8.3 Windows 进程托管

`yon-relay` 当前不包含 Windows Service 的安装/卸载子命令。生产环境应使用组织已有的 Windows 服务管理或编排系统，以专用低权限服务账户运行：

```powershell
& 'C:\Program Files\Yonder\yon-relay.exe' --log-level info serve
```

配置放在 `C:\ProgramData\Yonder\yon-relay.toml`，身份和私钥只授予服务账户读取权限。服务管理器应：

- 在网络就绪后启动。
- 捕获 stdout 和 stderr 到受控日志系统。
- 失败后进行有界重启。
- 停止时先发送可处理的控制事件，并设置终止上限。
- 不把身份、WSS 私钥或连接码写入命令行参数。

## 9. 使用远程终端

### 9.1 被控端发布终端

在希望成为远端工作目录的位置运行：

```console
cd /path/to/workspace
yon host
```

成功后 stdout 显示：

```text
ABCD-EFGH-JKMP-QRST
```

注意：

- 连接码每次进程启动重新生成。
- 不要把连接码写入公开聊天、工单、日志或 shell history。
- `yon host` 使用当前用户权限，不提权。
- Unix 优先使用绝对、存在、可执行的 `$SHELL`，否则使用 `/bin/sh`。
- Windows 使用有效的 `%COMSPEC%`，否则回退到 `cmd.exe`。
- 以 root、Administrator 或高权限服务账户启动会把同等权限暴露给成功认证的本次会话。

### 9.2 主控端连接

直接传入连接码：

```console
yon connect ABCD-EFGH-JKMP-QRST
```

不希望连接码进入 shell history 时，省略参数：

```console
yon connect
```

交互 TTY 会显示 `Connection code:`，但隐藏输入内容。

连接码输入接受规范分组和无连字符形式，也接受小写；`O/o` 按 `0` 处理，`I/i/L/l` 按 `1` 处理。输入不接受空白、其他分隔符或字母 `U/u`。

### 9.3 非交互调用

标准输入第一行可以提供连接码，剩余字节继续发给远端 shell：

```console
printf 'ABCD-EFGH-JKMP-QRST\necho hello\nexit\n' | yon connect
```

Windows ConPTY 无法在保留尾部输出的同时可靠地把管道关闭映射为 shell EOF，因此 Windows 非交互脚本必须显式发送 `exit`。Unix 会把输入半关闭传递为 PTY EOF，但显式 `exit` 仍是更清晰的跨平台做法。

### 9.4 终端行为

- 本地终端尺寸变化会同步到远端 PTY。
- ANSI 控制字节原样传输。
- 交互模式下 Ctrl+C 发送到远端前台程序；主控端自身中断会映射为退出码 `130`。
- 远端 shell 的 `0..=255` 退出码传播给本地主控进程。
- 超出可移植范围的远端退出码会记录警告，并在本地返回 `1`。
- 会话创建成功后连接码被消费，即使随后立即断线也不能复用。
- 会话结束后 `yon host` 清理 PTY 和子进程并退出。

常见进程退出码：

| 退出码 | 含义 |
| ---: | --- |
| `0` | 命令或远端 shell 成功完成 |
| `1` | 一般配置、网络、运行时或服务错误；也用于无法映射的远端退出码 |
| `2` | 连接码长度、编码或格式错误 |
| `130` | 主控端被中断 |
| 其他 `0..=255` | 成功建立会话后传播的远端 shell 退出码 |

### 9.5 日志级别与输出通道

两个程序都支持全局日志级别：

```console
yon --log-level warn host
yon --log-level debug connect
yon-relay --log-level info serve
```

可选值为 `off`、`error`、`warn`、`info`、`debug`、`trace`。

- `yon` 默认 `warn`。
- `yon-relay` 默认 `info`。
- 业务输出写 stdout。
- 诊断日志写 stderr。
- 调试时可以临时使用 `debug`；`trace` 只应在受控窗口启用，避免产生大量网络事件日志。

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
yon-relay --help
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

Yonder `0.1.0` 主要通过结构化诊断日志和操作系统指标观测。建议采集：

- 进程存活、重启次数和退出码。
- CPU、RSS、文件描述符数量和网络吞吐。
- 各 listener 的 TCP/UDP 可达性。
- reservation/注册容量拒绝和查询重试日志。
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

1. 确认程序实际运行目录。
2. 检查系统文件和当前目录文件是否同时存在。
3. 检查 `YON_` 或 `YON_RELAY_` 环境变量是否覆盖了文件。
4. 确认 TOML 是 UTF-8、普通文件且小于等于 `64 KiB`。
5. 删除未知字段，检查嵌套字段拼写。
6. 检查相对路径是相对于提供该字段的配置层，而不是统一相对于程序目录。

可以临时使用只包含必要字段的独立目录排除当前目录覆盖：

```console
mkdir /tmp/yonder-config-check
cd /tmp/yonder-config-check
yon --log-level debug host
```

程序仍会读取系统配置；如需完全隔离，应在测试账户或容器中使用受控系统配置。

### 13.2 relay 无法启动 listener

- 检查端口是否被其他进程占用。
- 检查同一个 TCP 端口是否同时配置了 TCP、WS 或 WSS listener。
- 检查低端口绑定权限。
- `listen` 必须使用 IP，不能使用 DNS 或带 `/p2p` 的地址。
- `external` 必须非 wildcard、端口非零且真实可达。
- 配置 WSS 时必须同时提供证书和私钥。

### 13.3 endpoint 无法连接 relay

- 确认双方 `yon.toml` 使用同一个 PeerId。
- 从 relay 最新启动输出复制完整地址，不要手工拼 PeerId。
- 检查 DNS、云安全组、本机防火墙和 NAT 端口转发。
- 分别验证 TCP 和 UDP 出站；某些网络会阻断 QUIC UDP。
- 保留多个传输入口，让 Yonder 自动选择可用路径。
- 使用 `--log-level debug` 查看具体候选失败，不要立即只保留一个协议。

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

直连选择和严格 fallback 可能需要数十秒。排障时应观察完整连接预算，不要在几秒内反复终止进程。

### 13.8 终端行为异常

- 确认被控端当前用户的 shell 可执行且路径有效。
- Unix 检查 `$SHELL`；Windows 检查 `%COMSPEC%`。
- 检查被控端当前工作目录权限。
- 非交互 Windows 会话必须显式发送 `exit`。
- 如果远端程序修改了终端模式，先在普通本地 PTY 中复现。
- 使用 `--log-level debug` 时，诊断在 stderr，不应出现在终端 stdout。

## 14. 上线验收清单

### 14.1 relay

- [ ] 已验证归档 SHA-256 和 provenance。
- [ ] 使用专用低权限账户运行。
- [ ] 身份文件只生成一次，权限和加密备份已验证。
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
- [ ] 连接码通过受控渠道传递。
- [ ] 会话结束后 host 进程和远端 shell 均已退出。

### 14.3 端到端 smoke

被控端：

```console
yon --log-level info host
```

主控端：

```console
yon --log-level info connect
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
yon [--log-level <off|error|warn|info|debug|trace>] host
yon [--log-level <off|error|warn|info|debug|trace>] connect [CONNECTION_CODE]

yon-relay [--log-level <off|error|warn|info|debug|trace>]
  identity init --output <PATH>

yon-relay [--log-level <off|error|warn|info|debug|trace>] serve
```

查看当前二进制的权威 CLI 帮助：

```console
yon --help
yon connect --help
yon-relay --help
yon-relay identity init --help
```
