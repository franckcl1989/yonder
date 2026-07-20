# Yonder Design Freeze v1

- 状态：Frozen（Design Freeze v1）
- 基线日期：2026-07-16
- 适用版本：`0.1.x` 首个可交付协议版本
- 产物：`yon`、`yon-relay`

本目录是 v1 的规范性设计输入，和根目录 `AGENTS.md` 共同驱动实现、测试与交付。`AGENTS.md` 定义长期工程红线；本目录定义 v1 产品行为。两者冲突时必须停止实现并由项目所有者裁决，不能自行选择其中一份。

## 文档索引

- [product.md](product.md)：产品范围、CLI、生命周期、平台与用户可见行为。
- [architecture.md](architecture.md)：workspace、trait 边界、网络路径、并发、背压与资源所有权。
- [protocol.md](protocol.md)：连接码、协议 ID、字节格式、状态机、超时与兼容规则。
- [security-and-dependencies.md](security-and-dependencies.md)：威胁模型、依赖选择、feature、许可证与受限例外。
- [verification.md](verification.md)：测试矩阵、覆盖率、安全、性能、静态链接与发布门禁。
- [traceability.md](traceability.md)：需求到模块、协议和验收证据的追踪矩阵。
- [validation.md](validation.md)：冻结时已执行的可行性证据与尚未冒充完成的交付门禁。

## 冻结含义

冻结后，后续实现可以在不改变可观测行为和边界的前提下完成模块内部细节，但不得自行改变 CLI、wire format、协议 ID、状态转换、超时、容量、信任边界、直接依赖或质量门禁。任何此类改变都必须新增一份经项目所有者批准的 ADR，同时更新本目录、`AGENTS.md`、测试与追踪矩阵。

已列明的上游风险是被接受并持续监控的受限例外，不是留给实现阶段决定的开放项。v1 不包含任何未决设计占位符。
