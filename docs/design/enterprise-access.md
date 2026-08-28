# 企业成员准入

## 产品语义

一个 `yon-relay` 进程只处于一种不可热切换的模式：没有 `[enterprise_auth]` 时为普通模式，只提供既有 Resolve；存在完整配置时为企业模式，只提供 `/yonder/enterprise-resolve/2.0.0`。不得同时注册两种 resolve 协议，也不得在企业认证失败、超时或提供商不可用时回退普通 Resolve。

企业准入只证明受信任的自建企业 relay 在连接时通过所选企业自建应用确认了 controller 用户是有效内部成员。relay 是该成员准入结果的显式可信决策点；endpoint 不接收可独立验证的成员证明。它不授权具体 host、不替代 OPAQUE、不建立用户目录、RBAC 或通用 IAM。旧 host 可继续注册；只有 `0.2.0` 双端能在企业准入后满足强制审计并进入终端。

## 配置

企业配置继续使用 relay 的环境变量、当前目录文件、系统文件三层覆盖规则。relay 的完整形状为：

```toml
[enterprise_auth]
callback_listen = "0.0.0.0:8443"
callback_external_url = "https://relay.example.com:8443"
certificate = ["callback-leaf.pem", "callback-intermediate.pem"]
private_key = "callback-key.pem"
secret_wecom = "wecom.secret.toml"       # 至少配置一个提供商
secret_feishu = "feishu.secret.toml"
```

同一部署的主控端和被控端必须在各自 `yon.toml` 中显式选择企业准入：

```toml
access_mode = "enterprise"
relays = ["/dns4/relay.example.com/tcp/4001/p2p/12D3KooW..."]
```

对应环境变量是 `YON_ACCESS_MODE=enterprise`。`access_mode` 是 endpoint 自己执行的期望策略，不由 relay 发布的模式自动改写；任一端使用缺省 `standard`、两端值不同或 relay 发布的 Resolve 模式不匹配时，必须在 registry/resolve 前失败，不得降级。

企业 relay 仍不在终端内容、端点身份和会话完整性的信任边界内：连接码秘密不发送给 relay，OPAQUE 由两个 endpoint 执行，终端、文件和审计子流保持端到端加密与认证。它只在企业成员准入这一项上受信任。攻陷 relay 可以跳过 OAuth 成员检查并返回目标 PeerId，但攻击者仍需取得完整一次性连接码并通过 OPAQUE；因此企业准入是依赖 relay 完整性的附加门禁，而不是取代连接码的独立端点凭据。企业部署必须把 relay 主机、二进制、配置、回调私钥和平台 Secret 纳入授权系统同等级别的加固、变更审计和监控。

回调外部 URL 必须是无 query/fragment/userinfo 的绝对 `https` origin。监听地址必须是明确 socket 地址；证书链、私钥、SAN、权限和密码学匹配复用 WSS 已验证的解析与验证能力，但回调证书与 WSS transport 证书是两个独立配置域。公开浏览器 OAuth 回调必须使用浏览器和平台信任的证书；自签证书只在组织已把对应 CA 安全安装到浏览器信任库且平台允许该回调 URL 时有效。

每个平台一个独立 TOML 秘密文件，最大 `16 KiB`，启动时一次加载且不热更新：

```toml
# 企业微信
corp_id = "..."
agent_id = 1000002
app_secret = "..."

# 飞书
app_id = "..."
app_secret = "..."
tenant_key = "..."
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

一次 `yon connect` 最多启动一次进入浏览器的 Enterprise Resolve，无论选择企业微信还是飞书。直连准备失败后的一次性 relay-only Swarm 重建不是新的用户授权意图：controller 必须验证重连后的 relay 仍发布 Enterprise access，并复用本次已完成准入返回的目标 PeerId；不得生成第二个 OAuth state、重复打开浏览器或重复触发平台授权通知。新 Swarm 仍使用新临时 PeerId，并对复用的目标重新执行完整 OPAQUE，因此该复用不跨命令、不跨进程、不取代连接码认证。授权前的 relay admission `Retry` 尚未产生 URL，可以在原机器预算内重试；URL 已展示后的失败不自动重放，用户必须显式重新执行命令。

## 提供商与 HTTP

`EnterpriseProvider` trait 只负责构造授权 URL、用 code 换取平台 token、读取当前用户及确认内部在职状态。生产实现只使用官方当前稳定 API；端点、请求/响应字段和权限范围必须在实现提交中链接对应官方文档并由锁步 JSON fixture 固定。企业微信授权入口固定为 `https://login.work.weixin.qq.com/wwlogin/sso/login` 和 `login_type=CorpApp`；飞书 `accounts.feishu.cn` 授权入口与 OAuth v3 token JSON 统一使用 `client_id`，凭据配置中的 `app_id` 只是平台控制台字段在本地的领域名称。企业微信与飞书的“接口成功但成员状态缺失/未知”、外部身份、离职、停用、tenant/corp 不匹配全部拒绝。

### 官方契约证据（2026-08-24 核对）

| 平台步骤 | 固定接口与关键契约 | 官方依据 |
| --- | --- | --- |
| 企业微信 Web 登录 | `GET https://login.work.weixin.qq.com/wwlogin/sso/login`；`login_type=CorpApp`、`appid`、`agentid`、精确 `redirect_uri`、单次 `state` | [企业微信 Web 登录](https://developer.work.weixin.qq.com/document/path/98151) |
| 企业微信应用 token | `GET https://qyapi.weixin.qq.com/cgi-bin/gettoken`；`corpid`、`corpsecret` | [获取 access_token](https://developer.work.weixin.qq.com/document/path/91039) |
| 企业微信登录身份 | `GET https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo`；只有内部成员返回 `userid`，外部身份没有 `userid` | [获取用户登录身份](https://developer.work.weixin.qq.com/document/path/98176) |
| 企业微信成员状态 | `GET https://qyapi.weixin.qq.com/cgi-bin/user/get`；`userid`，并核对 `status == 1` | [读取成员](https://developer.work.weixin.qq.com/document/path/90196) |
| 飞书授权与 user token | `GET https://accounts.feishu.cn/open-apis/authen/v1/authorize` 与 `POST https://accounts.feishu.cn/oauth/v3/token`；统一使用 `client_id`，token 请求另含 `client_secret`、`grant_type=authorization_code`、单次 `code`、精确 `redirect_uri` | [获取 user_access_token](https://open.feishu.cn/document/server-docs/authentication-management/access-token/get-user-access-token) |
| 飞书登录身份 | `GET https://open.feishu.cn/open-apis/authen/v1/user_info`；Bearer user token，要求 `user_id` 与 `tenant_key` 均存在且租户匹配 | [获取登录用户信息](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get) |
| 飞书应用 token | `POST https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal`；`app_id`、`app_secret`，返回 `tenant_access_token` 与 `expire` | [自建应用获取 tenant_access_token](https://open.feishu.cn/document/server-docs/authentication-management/access-token/tenant_access_token_internal) |
| 飞书成员状态 | `GET https://open.feishu.cn/open-apis/contact/v3/users/:user_id?user_id_type=user_id`；Bearer tenant token；五个状态字段必须齐全并明确为有效在职 | [获取单个用户信息](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/get) |

上述所有平台 HTTP 请求禁止自动跟随重定向。对 provider 的 `3xx` 一律按平台故障失败关闭，因为把含应用 Secret、授权 code 或 Bearer token 的请求自动重放到 Location 主机会扩大凭据泄露边界；若官方未来强制迁移端点，必须核对新契约并显式升级固定 URL，不能用通用 redirect allowlist 静默吸收变化。

提供商明确的用户结果与配置/平台故障在本地类型中分离，但 wire 统一为 `Denied`，不得泄漏可探测细节。企业微信授权 code 无效/过期 `40029/42003/42022`、成员不可见/不存在 `60021/60111`，以及飞书通讯录成员不可见/无权读取 `20010` 和既有离职/停用类 code 映射为 `Rejected`；无效企业 ID、应用凭据、权限、可信 IP、平台异常和未知 code 保持 `Platform` 并失败关闭。

HTTP 客户端使用 `reqwest 0.13.4` 的 Rustls 后端，启动时安装 workspace 已有的 ring provider。客户端强制 HTTPS、禁用自动降级，连接/首字节/完整请求使用绝对截止，响应体有硬上限，任何 HTTP 重定向都按上一段规则失败关闭。JSON 只经 `serde` 类型反序列化；不得用字符串搜索字段。provider 错误映射为本地结构化枚举，网络响应不透传平台文案。

回调服务使用 `axum 0.8.9` 和 `axum-server 0.8.0`，只开放精确 GET 路径 `/yonder/callback/wecom` 与 `/yonder/callback/feishu`。未知路径 `404`、错误 method `405`、缺参/非法参数 `400`；结果页是无外部资源的固定文本，始终带 `Cache-Control: no-store`。每个 TLS/HTTP 连接有 `10s` 总期限、禁用 keep-alive、并发上限 `16`。

浏览器授权 URL 必须先输出并 flush，再用 `open 5.4.1` 尽力打开；打开失败不会取消事务，用户仍可手工访问已显示 URL。交互等待继续使用不污染终端的单行进度与 <=1s 心跳。

## 单一所有者和限额

企业事务表归 relay 网络 owner 独占。Axum handler 只能通过容量 `16` 的有界 `mpsc` 和 `oneshot` 提交回调，不能持有注册表锁或直接完成 resolve。事务容量 `64`；resolve 子流处理 permit `64`；Enterprise Resolve 准入的全局与来源 limiter 均为 `1/s`、burst `4`，来源表最多 `1024` 项、空闲 `10min` 回收且不驱逐活跃项。OAuth callback 由随机单次 state、事务容量、容量 `16` 的 handler channel 和最多 `16` 条并发 HTTPS 连接约束；回调来源 IP 不另建 limiter，避免同一企业 NAT 下合法并发互相阻断。达到任一上限时拒绝新工作，不驱逐/抢占现有事务。

日志只允许 request ID、provider、阶段和脱敏结果，不记录连接码、locator、PeerId、OAuth state/code/token、用户身份和响应正文。测试必须对 tracing、错误链、HTTP 页面和 CLI 做负面泄露断言。

## 验收

正式发布必须通过状态机、wire、限流、超时、断连、重放、重复回调、真实 HTTPS/TLS listener、类型化平台响应和敏感信息泄露测试。项目所有者已确认 `0.2.0` 无法取得企业微信或飞书自建应用，因此真实平台联调不作为本版本发布硬门槛；测试服务器与 fixture 只能证明 Yonder 自身的协议和适配语义，发布说明不得把它表述为企业微信或飞书官方环境已经认证。

首次生产启用任一提供商前，部署方必须按运维手册完成应用发布/审核、精确回调、最小 API 权限、应用可见/通讯录数据范围、relay 公网出口 IP 白名单及飞书 `tenant_key` 固定，并使用本组织的真实自建应用分别完成有效内部成员成功、非成员/不可见/无效状态拒绝、过期或重复 code、超时及不降级验证。该部署验收不能反向扩大 `0.2.0` 的发布证据；若平台行为不兼容，企业模式必须保持失败关闭并在后续修订中处理。
