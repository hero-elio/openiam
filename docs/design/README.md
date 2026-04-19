# OpenIAM 设计文档索引

本目录基于当前代码实现整理，按「总览 -> 限界上下文 -> 上下文交互」拆分。

## 文档清单

- `docs/design/00-system-overview.md`：整体领域模型、上下文地图、启动装配流程
- `docs/design/10-tenant-context.md`：Tenant 限界上下文设计
- `docs/design/20-identity-context.md`：Identity 限界上下文设计
- `docs/design/30-authz-context.md`：Authz 限界上下文设计
- `docs/design/40-authn-context.md`：Authn 限界上下文设计
- `docs/design/50-context-interactions.md`：跨上下文交互、事件编排与典型业务链路

## 阅读顺序建议

1. 先读 `00-system-overview.md` 建立全局视图
2. 再按 `tenant -> identity -> authz -> authn` 深入各上下文
3. 最后读 `50-context-interactions.md` 理解跨上下文协作细节
