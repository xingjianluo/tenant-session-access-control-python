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
| `app/access.py` | 租户 + 角色访问判定，请求级稳定快照，凭据校验+判定原子授权 |
| `main.py` | FastAPI 端点：登录/续期/注销/判定 + 后台封禁/解封（`/` 行为不变） |
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

## 账号封禁 / 解封

后台通过 `AuthService.ban_user(user_id)` / `unban_user(user_id)`（HTTP 为
`POST /admin/ban`、`POST /admin/unban`）管控账号。封禁**即时生效**，作用范围如下：

- **已有会话全部立即不可用**：封禁在同一把存储锁内撤销该账号名下所有会话。
  此后无论持凭据做什么——继续用旧凭据、续期换新凭据、注销、访问判定——
  统一返回 `account_disabled`，与 `bad_credentials`（密码错误）、
  `session_expired`（过期）、`session_revoked`（注销）明确可区分。
  判定优先级为：账号封禁 > 会话撤销 > 过期 > 旧凭据重放。
- **封禁期间不允许新登录**：登录直接得到 `account_disabled`。
- **解封不复活老会话**：解封只翻转账号封禁标记，**不清除**封禁时打下的撤销标记。
  封禁前的老凭据在解封后得到的是 `session_revoked`，必须重新登录。
- **封禁幂等**：重复封禁仍成功，返回值中的 `revoked_sessions` 只统计本次新撤销数。
- **用户不存在**：封禁/解封未知用户返回 `user_not_found`（HTTP 404）。

### 封禁与并发的线性化保证

封禁、续期、注销、授权判定全部在 `store.lock` 内完成"检查-修改"，因此这些操作
彼此线性化，只存在两种合法顺序，且两种顺序下封禁都站得住：

1. **续期/判定先于封禁**：这一次操作成功；封禁提交后，刚轮换出来的新凭据
   立即被 `account_disabled` 拦截，不会存活。
2. **封禁先于续期/判定**：续期连换凭据的机会都没有，判定直接拒绝。

不会出现"封禁已经生效、却仍然换到了新凭据"，也不会出现"封禁已经生效、这次判定
仍然放行"。访问判定请走原子入口 `AccessControl.authorize(auth, token, tenant, perm)`
——它把"令牌校验 → 建快照 → 权限判定"收在同一次加锁内（`/check` 端点即如此实现）；
若自行分开调用 `validate()` 与 `begin_request()/check()`，两步之间可能被封禁插入。

## 多设备会话

同一账号多次登录得到**各自独立的会话**（不同 `session_id` 与凭据），设备之间互不干扰：

- 某台设备续期是**原地轮换自己那条会话**：只有它手里的旧凭据作废、新凭据生效，
  同账号其它设备的凭据照旧可用。
- 某台设备 `logout` 只撤销它自己的会话，不会把同账号其它设备一起踢下线。
- 封禁是唯一的"连坐"：它按账号撤销该账号**所有**设备的会话。

## 失效凭据的处理约定

对已经失效的旧凭据（轮换前的旧令牌、已注销、已过期、账号已封），任何操作都是
**只读拒绝、绝不改动现状**：

- 拒绝原因可区分：轮换旧凭据 → `token_replayed`，已注销 → `session_revoked`，
  已过期 → `session_expired`，账号封禁 → `account_disabled`，从未存在 →
  `session_not_found`。
- 不生成新会话、不延长有效期，尤其**不会**因为持旧凭据注销而把当前真正在用的
  有效会话连带撤销。

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
- 封禁/解封与续期、注销、授权判定共用同一把锁并彼此线性化，原子授权
  （`authorize`）保证封禁生效后不存在"仍换到新凭据"或"判定仍放行"的窗口；
  详见上文「账号封禁 / 解封」一节。

## 可观察的失败原因

`FailureReason`（HTTP 层以 `detail` 字段返回）：

| 原因 | 含义 |
|---|---|
| `bad_credentials` | 用户不存在或密码错误 |
| `account_disabled` | 账号已封禁（对一切凭据操作即时生效） |
| `user_not_found` | 封禁/解封的目标用户不存在 |
| `session_not_found` | token 从未存在 |
| `session_expired` | 会话已过期 |
| `session_revoked` | 会话已注销/撤销（含封禁后解封的老会话） |
| `token_replayed` | 旧凭据重放（令牌已轮换） |
| `cross_tenant` | 跨租户访问 |
| `permission_denied` | 角色不拥有该权限 |
| `unknown_permission` | 未定义的权限名 |

## 本地验证

```bash
# 全部离线运行，可重复；日志打印关键输入、状态变化与判定依据
python3 -m pytest tests -q

# 只跑账号安全场景（封禁/解封、多设备、失效凭据、并发）
python3 -m pytest tests/test_account_security.py -v

# 手动体验 HTTP 层（演示账号 alice/bob/carol/dave，密码 pw-<name>）
python3 main.py   # 或 uvicorn main:app
curl -X POST localhost:8000/login -H 'content-type: application/json' \
     -d '{"user_id":"bob","password":"pw-bob"}'

# 后台封禁/解封（本地演示未加管理端鉴权；生产应置于管理权限之后）
curl -X POST localhost:8000/admin/ban   -H 'content-type: application/json' \
     -d '{"user_id":"bob"}'
curl -X POST localhost:8000/admin/unban -H 'content-type: application/json' \
     -d '{"user_id":"bob"}'
```

测试日志会逐条打印 `>>>> 场景用例开始: <用例名>`、关键输入/状态变化/判定原因，
以及 `<<<< 场景用例结果: <用例名> -> PASSED/FAILED`，可直接据此核对场景覆盖与结果。

`tests/test_account_security.py` 覆盖：

- **封禁即时生效**：旧凭据续期/校验、注销、原子访问判定全部以 `account_disabled`
  拒绝；封禁原因与密码错误、过期可区分；封禁一次撤销全部已有会话；封禁幂等、
  封禁未知用户返回 `user_not_found`。
- **解封不复活**：解封后老凭据得到 `session_revoked`，重新登录才恢复。
- **多设备隔离**：三设备独立轮换互不影响；单设备下线不踢同账号其它设备。
- **失效凭据只读拒绝**：持轮换旧令牌/已注销/已过期凭据注销或续期被明确拒绝，
  且当前有效会话不受连累；未知 token 操作不改变任何状态。
- **封禁并发**：封禁 vs 5 路续期、封禁 vs 5 路判定各 100 轮随机交错，断言
  "封禁后不存在可用新凭据""封禁后判定零放行"；另有确定性交错用例固定两种
  线性化顺序。

此外保留并全部通过原有覆盖：正常登录/续期/注销流程、并发续期（8 线程竞争同一
旧 token）、旧凭据重放（拒绝且不延长有效期）、会话撤销（单个与按用户）、会话过期、
跨租户访问、未知权限、请求中途角色/租户变化时的快照一致性，以及原有 `GET /`
行为不变、封禁/解封 HTTP 全生命周期的回归断言。
