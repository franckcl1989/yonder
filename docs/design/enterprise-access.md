# 企业成员准入

## 产品语义

一个 `yon-relay` 进程只处于一种不可热切换的模式：没有 `[enterprise_auth]` 时为普通模式，只提供既有 Resolve；存在完整配置时为企业模式，只提供 `/yonder/enterprise-resolve/2.0.0`。不得同时注册两种 resolve 协议，也不得在企业认证失败、超时或提供商不可用时回退普通 Resolve。

企业准入只证明 controller 用户在连接时是所选企业自建应用可确认的有效内部成员。它不授权具体 host、不替代 OPAQUE、不建立用户目录、RBAC 或通用 IAM。旧 host 可继续注册；只有 `0.2.0` 双端能在企业准入后满足强制审计并进入终端。

## 配置

企业配置继续使用 relay 的环境变量、当前目录文件、系统文件三层覆盖规则。完整形状为：

```toml
[enterprise_auth]
callback_listen = "0.0.0.0:8443"
callback_external_url = "https://relay.example.com:8443"
certificate = ["callback-leaf.pem", "callback-intermediate.pem"]
private_key = "callback-key.pem"
secret_wecom = "wecom.secret.toml"       # 至少配置一个提供商
secret_feishu = "feishu.secret.toml"
```

回调外部 URL 必须是无 query/fragment/userinfo 的绝对 `https` origin。监听地址必须是明确 socket 地址；证书链、私钥、SAN、权限和密码学匹配复用 WSS 已验证的解析与验证能力，但回调证书与 WSS transport 证书是两个独立配置域。公开浏览器 OAuth 回调必须使用浏览器和平台信任的证书；自签证书只在组织已把对应 CA 安全安装到浏览器信任库且平台允许该回调 URL 时有效。

每个平台一个独立 TOML 秘密文件，最大 `16 KiB`，启动时一次加载且不热更新：

```toml
# 企业微信
corp_id = "..."
agent_id = "..."
app_secret = "..."

# 飞书
app_id = "..."
app_secret = "..."
```

秘密文件必须复用 `SecretFilePolicy`：Unix 文件 `0600` 且父目录可信；Windows 使用受保护 DACL 并复核 owner/ACE。任一启用提供商配置或权限无效时 relay 拒绝启动。凭据、OAuth code、token、state 和成员身份使用 `Zeroizing`/领域秘密类型持有并在最短生命周期结束时清除。

## Wire 与状态机

子流按以下固定顺序交换；所有整数大端，locator 是既有 3 字节 20-bit 编码，PeerId 是 `to_bytes()` 且长度 `1..=64`。除授权 URL 外消息固定长度，URL 是 `1..=2048` UTF-8 字节且必须为 HTTPS。

| 方向 | Tag 与载荷 | 语义 |
| --- | --- | --- |
| client → relay | `0x01 || locator[3]` | `Start` |
| relay → client | `0x10 || provider_mask:u8` | `Providers`；`0x01` 企业微信，`0x02` 飞书 |
| relay → client | `0x11 || retry_ms:u32` | `Retry`，`100..=5000` |
| client → relay | `0x02 || provider:u8` | `Select`，只能选择 mask 中一个 bit |
| relay → client | `0x12 || url_len:u16 || url` | `Authenticate` |
| relay → client | `0x13 || peer_len:u8 || peer_id` | `Resolved` |
| relay → client | `0x14` | `Cancelled` |
| relay → client | `0x15` | `Expired` |
| relay → client | `0x16` | `Denied`，包含平台/成员/协议失败 |
| relay → client | `0x17` | `Unavailable`，目标不可用 |

未知 tag、非法长度、尾随字节、非法 provider bit 或状态外消息关闭子流，不返回可探测细节。公共 CLI 只区分暂时重试、认证未完成/被拒和连接码无效或失效。

状态机为 `Created -> ProviderSelection -> Authenticating -> Authenticated -> Resolving -> Completed`，终态另有 `Cancelled/Expired/Denied/Unavailable`。provider 选择前不生成 state；选择后不能切换。state 使用 OS CSPRNG 生成 256 bit，URL-safe Base64 无 padding，单次消费，并与当前 Enterprise Resolve 子流、provider、callback path 和随机 request ID 绑定。子流 EOF 立即取消，事务最长 `10min`，完成、超时、取消和 relay 重启都销毁；禁止恢复、转移或复用。

## 提供商与 HTTP

`EnterpriseProvider` trait 只负责构造授权 URL、用 code 换取平台 token、读取当前用户及确认内部在职状态。生产实现只使用官方当前稳定 API；端点、请求/响应字段和权限范围必须在实现提交中链接对应官方文档并由锁步 JSON fixture 固定。企业微信与飞书的“接口成功但成员状态缺失/未知”、外部身份、离职、停用、tenant/corp 不匹配全部拒绝。

HTTP 客户端使用 `reqwest 0.13.4` 的 Rustls 后端，启动时安装 workspace 已有的 ring provider。客户端强制 HTTPS、禁用自动降级，连接/首字节/完整请求使用绝对截止，响应体有硬上限，重定向仅允许同平台 HTTPS 白名单。JSON 只经 `serde` 类型反序列化；不得用字符串搜索字段。provider 错误映射为本地结构化枚举，网络响应不透传平台文案。

回调服务使用 `axum 0.8.9` 和 `axum-server 0.8.0`，只开放精确 GET 路径 `/yonder/callback/wecom` 与 `/yonder/callback/feishu`。未知路径 `404`、错误 method `405`、缺参/非法参数 `400`；结果页是无外部资源的固定文本，始终带 `Cache-Control: no-store`。每个 TLS/HTTP 连接有 `10s` 总期限、禁用 keep-alive、并发上限 `16`。

浏览器授权 URL 必须先输出并 flush，再用 `open 5.4.1` 尽力打开；打开失败不会取消事务，用户仍可手工访问已显示 URL。交互等待继续使用不污染终端的单行进度与 <=1s 心跳。

## 单一所有者和限额

企业事务表归 relay 网络 owner 独占。Axum handler 只能通过容量 `16` 的有界 `mpsc` 和 `oneshot` 提交回调，不能持有注册表锁或直接完成 resolve。事务容量 `64`；resolve 子流处理 permit `64`；准入全局与来源 limiter 均为 `1/s`、burst `4`。回调来源 limiter 表最多 `1024` 项，空闲 `10min` 回收且不驱逐活跃项。达到任一上限时拒绝新工作，不驱逐/抢占现有事务。

日志只允许 request ID、provider、阶段和脱敏结果，不记录连接码、locator、PeerId、OAuth state/code/token、用户身份和响应正文。测试必须对 tracing、错误链、HTTP 页面和 CLI 做负面泄露断言。

## 验收

正式发布必须通过状态机、wire、限流、超时、断连、重放、重复回调、真实 HTTPS/TLS listener、类型化平台响应和敏感信息泄露测试。项目所有者已确认 `0.2.0` 无法取得企业微信或飞书自建应用，因此真实平台联调不作为本版本发布硬门槛；测试服务器与 fixture 只能证明 Yonder 自身的协议和适配语义，发布说明不得把它表述为企业微信或飞书官方环境已经认证。

首次生产启用任一提供商前，部署方必须使用本组织的真实自建应用分别完成有效内部成员成功、非成员/无效状态拒绝、超时及不降级验证，并确认平台当时的回调 URL、权限范围和 API 策略仍与本文一致。该部署验收不能反向扩大 `0.2.0` 的发布证据；若平台行为不兼容，企业模式必须保持失败关闭并在后续修订中处理。
