# Tenant 限界上下文设计

## 1. 责任边界

Tenant 上下文负责：

- 租户创建与查询
- 应用（App）创建、查询、列表、更新
- 应用客户端凭据生成（ClientID / ClientSecretHash）
- 发布 `tenant.created`、`application.created` 领域事件

不负责认证、授权决策和用户认证资料。

## 2. 分层结构

```mermaid
flowchart TD
  REST[adapter/inbound/rest] --> APP[TenantAppService]
  APP --> TRepo[TenantRepository]
  APP --> ARepo[ApplicationRepository]
  APP --> Bus[EventBus]
  APP --> Tx[TxManager]
```

模块装配在 `internal/tenant/module.go`：

- `NewManager(db, bus, txMgr, check)`
- 若存在 `check`（Authz checker），才初始化 REST Handler

## 3. 领域模型（实体与聚合）

```mermaid
classDiagram
  class Tenant {
    +TenantID ID
    +string Name
    +string Status
    +time CreatedAt
  }
  class Application {
    +AppID ID
    +TenantID TenantID
    +string Name
    +string ClientID
    +string ClientSecretHash
    +[]string RedirectURIs
    +[]string Scopes
    +string Status
    +time CreatedAt
  }
```

聚合说明：

- `Tenant`：租户聚合根，创建时记录 `TenantCreatedEvent`
- `Application`：应用聚合根，创建时记录 `ApplicationCreatedEvent`

## 4. 应用服务用例

`TenantAppService` 提供：

- `CreateTenant`
- `GetTenant`
- `CreateApplication`
- `GetApplication`
- `ListApplications`
- `UpdateApplication`

输入约束（新增）：

- `CreateTenant`：`name` 去空白后不能为空，否则返回 `ErrInvalidInput`
- `CreateApplication`：`tenant_id` 不能为空，`name` 去空白后不能为空
- `UpdateApplication`：`app_id` 不能为空；若 `name` 字段出现，则不能是仅空白

事务边界：

- `CreateTenant`、`CreateApplication`、`UpdateApplication` 在 `TxManager.Execute` 中执行业务写入。
- `CreateTenant` / `CreateApplication` 在事务内持久化并发布聚合事件。

## 5. 关键流程

### 5.1 创建应用

```mermaid
sequenceDiagram
  participant API as Tenant Handler
  participant App as TenantAppService
  participant TRepo as TenantRepository
  participant ARepo as ApplicationRepository
  participant Bus as EventBus

  API->>App: CreateApplication(cmd)
  App->>App: 校验 tenant_id/name
  App->>App: 生成 ClientCredentials
  App->>TRepo: FindByID(tenantID)
  TRepo-->>App: Tenant
  App->>ARepo: Save(Application)
  App->>Bus: Publish(application.created) (in transaction)
  App-->>API: ApplicationDTO + ClientSecret
```

### 5.2 更新应用

```mermaid
flowchart TD
  A[校验 app_id/name 输入] --> B[加载 Application]
  B --> C{Name 非空?}
  C -- 是 --> D[更新 Name]
  C -- 否 --> E[跳过]
  D --> F{RedirectURIs != nil?}
  E --> F
  F -- 是 --> G[更新 RedirectURIs]
  F -- 否 --> H[跳过]
  G --> I{Scopes != nil?}
  H --> I
  I -- 是 --> J[更新 Scopes]
  I -- 否 --> K[跳过]
  J --> L[Save]
  K --> L
```

## 6. 发布事件

- `tenant.created`
- `application.created`（会触发 Authz 侧的角色/权限初始化）

## 7. 与其他上下文交互

- 向 Authz 提供 `application.created` 事件输入
- 自身受 Authz checker 保护（路由层）
