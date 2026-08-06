# Yonder 0.1.2 Enterprise Authentication Design

状态：Final Design Baseline

## 1. 目标

Yonder 0.1.2 只增加企业成员认证准入能力。

目标：

> 企业部署的 yon-relay
> 可以要求发起连接的用户先证明自己仍是该企业有效成员，避免企业 relay
> 被非企业用户正常使用。

不包含：

-   企业权限系统
-   用户管理系统
-   IAM
-   审计平台
-   端到端企业授权体系
-   host 身份认证改造

## 2. 核心运行模型

一个 yon-relay 实例只能处于一种模式：

### 普通模式

没有 enterprise_auth 配置。

行为：

-   保持 0.1.1 行为；
-   只提供原 resolve 协议；
-   不启动企业认证 HTTPS；
-   不访问企业平台；
-   不读取企业 Secret。

### 企业模式

配置至少一个完整企业认证提供商。

行为：

-   只提供 Enterprise Resolve；
-   不提供普通 Resolve；
-   不允许认证失败后降级；
-   生命周期内模式不可切换。

同一个 relay 不存在普通和企业混用。

## 3. 兼容原则

保持：

-   host 协议不变；
-   OPAQUE 不变；
-   terminal 不变；
-   relay 数据面不变。

企业认证只发生在目标解析之前。

兼容：

-   旧 host 可以注册到企业 relay；
-   旧 connect 无法使用企业 relay；
-   新 connect 自动识别普通或企业 relay。

## 4. Enterprise Resolve

协议：

/yonder/enterprise-resolve/1.0.0

流程：

yon connect → Enterprise Resolve → relay 返回可用认证平台 → 用户选择平台
→ 企业认证 → 成功后内部执行 resolve → 返回 PeerId → 进入原有连接流程

## 5. 状态模型

EnterpriseResolveSession:

Created

ProviderSelection

Authenticating

Authenticated

Resolving

Completed

失败状态：

Cancelled Expired Failed Unavailable

规则：

-   provider 未选择前不创建 OAuth state；
-   provider 一旦选择不可切换；
-   state 单次有效；
-   认证成功后立即销毁用户身份数据；
-   resolving 不携带企业身份。

## 6. 企业认证

支持：

-   企业微信自建应用
-   飞书企业自建应用

规则：

-   每个平台最多一个企业应用；
-   两个平台可同时配置；
-   两个平台效力相同；
-   双平台时用户选择其一。

认证要求：

-   当前用户属于配置企业；
-   当前用户仍为有效内部成员。

拒绝：

-   外部用户；
-   其他企业用户；
-   离职；
-   停用；
-   无法确认状态。

## 7. 配置

所有配置位于：

\[enterprise_auth\]

没有 enabled 开关。

配置存在决定企业模式。

Secret：

-   独立敏感文件；
-   不允许明文配置；
-   启动时加载；
-   运行期间不热更新。

## 8. 认证事务

事务：

-   内存保存；
-   不持久化；
-   单次使用；
-   与当前 connect 子流绑定。

生命周期：

-   创建后有限时间存在；
-   断开立即失效；
-   超时立即失效；
-   relay 重启全部失效。

禁止：

-   恢复；
-   转移；
-   重用。

## 9. 浏览器回调

relay 提供独立 HTTPS 回调。

只用于：

-   企业微信回调；
-   飞书回调。

不提供：

-   首页；
-   管理页面；
-   状态查询；
-   静态资源。

结果页：

-   极简；
-   不缓存；
-   无外部资源。

## 10. 安全边界

不记录：

-   用户身份；
-   Token；
-   state；
-   locator；
-   PeerId。

日志只记录：

-   请求 ID；
-   平台；
-   阶段；
-   脱敏结果。

认证成功后：

用户身份立即销毁。

## 11. 资源保护

Enterprise Resolve 必须：

-   使用有界资源；
-   防止无限事务；
-   防止重复创建；
-   防止回调重放。

资源保护包括：

-   请求速率限制；
-   来源限制；
-   事务容量限制。

## 12. 错误原则

失败关闭。

任何失败：

-   不降级普通 Resolve；
-   不绕过认证；
-   不泄露敏感信息。

失败包括：

-   平台异常；
-   用户拒绝；
-   状态无效；
-   超时；
-   locator 无效。

## 13. 实现原则

产品设计冻结：

-   模式互斥；
-   协议边界；
-   状态机；
-   安全语义。

实现阶段决定：

-   具体依赖；
-   crate 版本；
-   HTTP 参数；
-   超时数字；
-   性能参数。

这些不属于产品语义。

## 14. 验收标准

必须通过：

-   普通 relay 回归；
-   企业 relay 模式隔离；
-   新旧客户端兼容矩阵；
-   企业微信认证；
-   飞书认证；
-   超时；
-   断连；
-   重放；
-   重复回调；
-   日志脱敏；
-   Secret 安全；
-   全平台构建。

## 五要素审计结论

哲学统一：通过。

企业认证只是连接入口准入，不改变 Yonder 产品定位。

语义一致：通过。

普通模式、企业模式、认证、Resolve、终端职责明确。

逻辑自洽：通过。

企业模式唯一入口为 Enterprise Resolve，认证成功后进入原流程。

真实有效：通过。

方案基于真实企业 OAuth 和现有 Yonder
架构，不承诺超出能力范围的安全效果。

完整可靠：通过。

生命周期、失败路径、资源边界和兼容边界均已定义。

结论：

Yonder 0.1.2 Enterprise Authentication Design 可作为实现基线。
