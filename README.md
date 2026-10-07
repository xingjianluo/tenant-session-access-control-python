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

- **登录**：密码错误/用户不存在 → `bad_credentials`；账号禁用 → `account_disabled`；
  账号被封 → `account_banned`（三种原因可区分）。
- **续期（令牌轮换）**：成功后会话原地轮换新 token 并重置有效期；旧 token 的映射被保留，
  因此重放旧凭据得到的是可解释的 `token_replayed`，而不是"不存在"，也不会生成新会话或延长有效期。
- **注销/撤销**：`logout` 撤销单个会话；`revoke_user_sessions` 撤销某用户全部已建立会话，
  撤销立即生效，后续 `validate`/`refresh` 均返回 `session_revoked`。
- **过期**：`expires_at <= now` 时返回 `session_expired`。时间通过可注入的 `clock` 获取，
  测试用 `FakeClock` 精确推进，无需真实等待。

## 账号封禁与解封（后台管控）

后台通过 `AuthService.ban_account(user_id)` / `unban_account(user_id)`
（HTTP 层为 `POST /admin/ban` / `POST /admin/unban`）管控账号。

**封禁的生效范围**（封禁动作 = 置封禁标记 + 撤销该用户全部会话，两步在同一把锁内原子完成）：

- **立即、全量生效**：封禁完成的那一刻，该账号所有已登录会话（全部设备、无论新旧凭据）
  立刻不可用。之后无论是继续用旧凭据、用轮换后的新凭据、发起注销、还是做权限判定，
  一律返回 `account_banned`。
- **原因可区分**：`account_banned` 独立于 `bad_credentials`（密码错误）、
  `session_expired`（过期）、`session_revoked`（已注销）。判定顺序上封禁优先。
- **并发站得住**：封禁与续期、判定共用同一把锁。不可能出现"封禁已生效、却仍换到新凭据"，
  也不可能出现"封禁已生效、本次判定仍放行"。若某续期恰好在封禁前完成，它拿到的后继凭据
  在封禁完成后同样立即失效；HTTP `/check` 把令牌校验与授权判定包在同一临界区内，
  封禁无法插入两者之间。
- **解封不救活老会话**：`unban_account` 只清除封禁标记，封禁前的会话保持"已撤销"状态
  （再用时返回 `session_revoked`），用户必须重新登录。封禁/解封对不存在用户返回 `False`
  （HTTP 404 `user_not_found`），重复封禁是幂等的。

## 多设备会话

- 同一账号每次登录产生一条**独立会话**（独立 `session_id`/token/有效期）。多台设备各自
  登录、各自续期，彼此互不干扰：
  - 设备 A 续期只轮换 A 自己那条会话的 token；设备 B、C 手里的凭据照旧有效，
    不会被连带轮换或失效。
  - 设备 A 注销/下线只撤销 A 的会话；同账号其它设备不受影响，仍可继续续期。
  - 封禁是例外：封禁命中账号下**所有设备**的全部会话。

## 失效凭据的处理约定（只读拒绝）

对已经失效的旧凭据（轮换前的旧 token、已注销会话的 token、被封账号的任意凭据、
从未存在的 token），系统遵循**只读拒绝、绝不改动现状**：

- 拿作废旧凭据调用 `logout`/`refresh`/`validate` 只会得到可区分的拒绝原因
  （`token_replayed` / `session_revoked` / `account_banned` / `session_not_found`），
  不会翻转任何状态。
- 特别地：拿"已轮换掉的旧 token"去注销，返回 `token_replayed`，**绝不会**把当前真正
  在用的那条后继会话顺带作废；有效期也不会被重放操作延长。

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
| `account_banned` | 账号已被后台封禁（所有入口统一拒绝） |
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

# 手动体验 HTTP 层（演示账号 alice/bob/carol/dave/erin，密码 pw-<name>）
python3 main.py   # 或 uvicorn main:app
curl -X POST localhost:8000/login -H 'content-type: application/json' \
     -d '{"user_id":"bob","password":"pw-bob"}'

# 封禁/解封后台口子（erin 的会话会立即全部失效；解封后需重新登录）
curl -X POST localhost:8000/admin/ban   -H 'content-type: application/json' -d '{"user_id":"erin"}'
curl -X POST localhost:8000/admin/unban -H 'content-type: application/json' -d '{"user_id":"erin"}'
```

`tests/test_security.py` 的日志按 **场景标题（`===== SCENARIO: ...`）→ 用例（`CASE ...`）→
结果** 组织，跑测试时可直接从日志确认覆盖了哪些场景、每条用例的输入与结论。覆盖：

- **场景一 封禁生命周期**：封禁后登录/续期/校验/注销全部返回 `account_banned`；
  与密码错误等原因可区分；解封后老会话为 `session_revoked`、重新登录才恢复；幂等与未知用户。
- **场景二 封禁并发竞争**：8 线程并发续期与封禁同时发生（外加 20 轮压力），
  不变量"封禁后不存在任何可用后继凭据"成立；8 线程并发判定与封禁竞争，封禁生效后无一放行。
- **场景三 多设备隔离**：一台设备续期不影响其它设备凭据；一台设备下线不踢其它设备；
  封禁命中全部设备、解封后全部需重登。
- **场景四 失效凭据只读**：轮换旧 token 注销返回 `token_replayed` 且当前有效会话不被
  连带作废、有效期不变；复用已注销 token 返回 `session_revoked` 且兄弟会话存活；
  封禁下旧/新凭据统一 `account_banned`；未知 token 不改任何状态。

此外保留原有用例：正常登录/续期/注销流程、并发续期（8 线程竞争同一旧 token）、
旧凭据重放（拒绝且不延长有效期）、会话撤销（单个与按用户）、会话过期、
跨租户访问、未知权限、请求中途角色/租户变化时的快照一致性、封禁/解封 HTTP 端点冒烟，
以及原有 `GET /` 行为不变的回归断言。
