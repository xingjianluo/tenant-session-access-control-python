# 多租户身份会话与访问控制（Python / FastAPI）

一套**完全离线、可本地验证**的多租户会话与访问控制实现：内存存储、无外部身份服务、
无真实凭据、无网络依赖。登录、续期、撤销与权限判定在并发与异常情况下给出
稳定且可解释的结果。

## 结构

| 文件 | 职责 |
|---|---|
| `app/models.py` | 领域模型：`User` / `Session` / `Role` / `Permission` / `FailureReason` |
| `app/store.py` | 线程安全内存存储，所有"检查-修改"在同一把锁内原子完成 |
| `app/auth.py` | 会话生命周期：登录、续期（令牌轮换）、注销、撤销、校验 |
| `app/access.py` | 租户 + 角色访问判定，请求级稳定快照 |
| `main.py` | FastAPI 端点（`/` 原有行为保持不变） |
| `tests/` | 离线可重复的 pytest 测试，日志打印关键输入与判定依据 |

## 会话生命周期

```
login ──> 有效会话(token, expires_at)
            │  refresh(old_token)          logout / revoke_user_sessions
            ▼                                ▼
     原地轮换：新 token 生效，           会话 revoked，
     旧 token 立即失效（保留映射）       所有入口统一拒绝
            │
            ▼
     expires_at <= now 时过期
```

- **登录**：密码错误/用户不存在 → `bad_credentials`；账号禁用 → `account_disabled`。
- **续期（令牌轮换）**：成功后会话原地轮换新 token 并重置有效期；旧 token 的映射被保留，
  因此重放旧凭据得到的是可解释的 `token_replayed`，而不是"不存在"，也不会生成新会话或延长有效期。
- **注销/撤销**：`logout` 撤销单个会话；`revoke_user_sessions` 撤销某用户全部已建立会话，
  撤销立即生效，后续 `validate`/`refresh` 均返回 `session_revoked`。
- **过期**：`expires_at <= now` 时返回 `session_expired`。时间通过可注入的 `clock` 获取，
  测试用 `FakeClock` 精确推进，无需真实等待。

## 授权边界

- 角色 → 权限：`ADMIN` = read/write/manage_users，`MEMBER` = read/write，`VIEWER` = read。
- 判定顺序：未知权限（`unknown_permission`）→ 跨租户（`cross_tenant`）→ 权限不足
  （`permission_denied`）。跨租户访问即使拥有该权限也一律拒绝。
- **稳定视图**：每次请求开始时 `begin_request(user_id)` 捕获租户与角色的不可变快照
  （`RequestContext`）。请求处理期间角色或租户归属被修改，同一请求内的后续判定仍基于快照，
  不会得到相互矛盾的结论；下一个请求才看到新状态。

## 并发与撤销语义

- 续期的"校验旧令牌 + 轮换"在存储锁内原子完成：同一旧 token 的 N 个并发续期中
  **恰好一个成功**，其余全部得到 `token_replayed`，系统中只存在一个可继续使用的后继凭据。
- 重放旧凭据是**显式拒绝**而非静默处理：不生成会话、不延长有效期，且拒绝原因可区分。
- 撤销作用于会话本身，已建立的会话立即失效，与是否过期、是否轮换无关。

## 可观察的失败原因

`FailureReason`（HTTP 层以 `detail` 字段返回）：

| 原因 | 含义 |
|---|---|
| `bad_credentials` | 用户不存在或密码错误 |
| `account_disabled` | 账号已禁用 |
| `session_not_found` | token 从未存在 |
| `session_expired` | 会话已过期 |
| `session_revoked` | 会话已注销/撤销 |
| `token_replayed` | 旧凭据重放（令牌已轮换） |
| `cross_tenant` | 跨租户访问 |
| `permission_denied` | 角色不拥有该权限 |
| `unknown_permission` | 未定义的权限名 |

## 本地验证

```bash
# 全部离线运行，可重复；日志打印关键输入、状态变化与判定依据
python3 -m pytest tests -q

# 手动体验 HTTP 层（演示账号 alice/bob/carol/dave，密码 pw-<name>）
python3 main.py   # 或 uvicorn main:app
curl -X POST localhost:8000/login -H 'content-type: application/json' \
     -d '{"user_id":"bob","password":"pw-bob"}'
```

测试覆盖：正常登录/续期/注销流程、并发续期（8 线程竞争同一旧 token）、
旧凭据重放（拒绝且不延长有效期）、会话撤销（单个与按用户）、会话过期、
跨租户访问、未知权限、请求中途角色/租户变化时的快照一致性，以及原有
`GET /` 行为不变的回归断言。
