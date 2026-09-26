# 多租户身份会话与访问控制（离线可验证）

在 FastAPI 骨架上实现的一套纯内存、无外部依赖的多租户会话与访问控制能力。
所有验证均在本地离线完成：不依赖外部身份服务、真实凭据或网络资源。

## 结构

| 文件 | 职责 |
| --- | --- |
| `app/models.py` | 领域模型（User / Session）与可区分的 `FailureReason` |
| `app/clock.py` | 线程安全的可控时钟，测试可显式推进，保证离线可重复 |
| `app/store.py` | 线程安全内存存储（一把 `RLock` 保护用户、会话与 token 索引） |
| `app/sessions.py` | 会话生命周期：登录 / 续期（令牌轮换）/ 注销 / 撤销 |
| `app/authz.py` | 基于租户与角色的访问判定，请求内稳定视图 |
| `main.py` | HTTP 入口：`POST /login` `/refresh` `/logout` `/authorize`，保留原有 `GET /` |
| `tests/` | 离线可重复的 pytest 测试，日志打印关键输入、状态变化与判定依据 |

## 会话生命周期

1. **登录** `login(user_id, password)`：校验账号未禁用、凭据正确后签发会话
   （唯一 token + `expires_at = now + ttl`）。
2. **认证** `authenticate(token)`：每次请求校验会话有效性，失败原因可区分（见下表）。
3. **续期** `refresh(token)`：令牌轮换——校验通过后签发新会话，旧会话立即
   `revoked=True` 并记录 `successor_id`。**旧凭据从此失效**。
4. **注销** `logout(token)`：撤销当前会话。
5. **撤销** `revoke_user_sessions(user_id)`：撤销该用户全部会话，立即影响已建立的会话；
   账号被禁用（`disabled`）同样使已建立会话在下次校验时被拒绝。

## 授权边界

- 权限由角色静态映射（`ROLE_PERMISSIONS`：reader / writer / admin）。
- `RequestContext` 在**构造时**对用户的角色与租户归属做快照；同一次请求处理期间的
  所有判定都基于该快照——即使中途角色或租户归属被修改，同一请求也不会得到
  相互矛盾的结论；新请求（新上下文）才会看到最新角色。
- 跨租户访问、越权、未知权限分别被 `cross_tenant` / `forbidden` /
  `unknown_permission` 拒绝。

## 并发与撤销语义

- 续期的"校验旧令牌 + 轮换为新会话"在 `store.lock` 下**原子完成**：
  N 个线程同时续期同一令牌，**只有一个**产生后继会话，其余得到 `token_reused`。
- 重复使用旧凭据（重放）：不会生成新会话、不会静默扩大任何会话的有效期；
  旧会话保留 `revoked` 与 `successor_id` 链，足以解释拒绝原因。
- 撤销与续期竞争时，无论时序如何，旧令牌最终均不可用，且失败原因可区分。

## 可观察的失败原因

| reason | 含义 |
| --- | --- |
| `bad_credentials` | 用户不存在或密码错误 |
| `account_disabled` | 账号已禁用（登录与已建立会话均被拒） |
| `session_not_found` | 令牌不存在 |
| `session_expired` | 会话已过期（续期同样被拒，不延长有效期） |
| `session_revoked` | 会话被注销或管理员撤销 |
| `token_reused` | 旧凭据重放（该会话已被轮换出后继） |
| `cross_tenant` | 跨租户读写 |
| `forbidden` | 角色不具备该权限 |
| `unknown_permission` | 权限不在任何角色映射中 |

## 本地验证方法

```bash
# 全部测试（离线、可重复，日志打印关键输入/状态变化/判定依据）
python3 -m pytest tests/ -q -s

# 编译检查
python3 -m compileall -q app main.py

# 手动体验 HTTP 接口（演示账号 alice/bob/carol，仅用于本地验证）
python3 main.py   # 监听 127.0.0.1 随机端口
```

测试覆盖：正常登录/续期/注销流程、并发续期（16 线程竞争仅一个后继）、
旧凭据重放（不生成新会话、不扩大有效期）、会话撤销、账号禁用、会话过期、
跨租户访问、越权、未知权限、请求中途角色升降级时的视图稳定性，
以及原有 `GET /` 行为保持不变。
