import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.access import AccessControl
from app.auth import AuthService
from app.models import FailureReason, Role, User
from app.store import InMemoryStore

app = FastAPI()

store = InMemoryStore()
auth = AuthService(store)
access = AccessControl(store)

# 预置两个租户的演示账号（仅本地离线验证用）。
store.add_user(User("alice", "tenant-a", "pw-alice", roles=frozenset({Role.ADMIN})))
store.add_user(User("bob", "tenant-a", "pw-bob", roles=frozenset({Role.MEMBER})))
store.add_user(User("carol", "tenant-b", "pw-carol", roles=frozenset({Role.VIEWER})))
store.add_user(User("dave", "tenant-a", "pw-dave", disabled=True,
                    roles=frozenset({Role.MEMBER})))
# 专供封禁/解封演示与测试的账号
store.add_user(User("erin", "tenant-a", "pw-erin", roles=frozenset({Role.MEMBER})))


class LoginBody(BaseModel):
    user_id: str
    password: str


class TokenBody(BaseModel):
    token: str


class AdminBody(BaseModel):
    user_id: str


def _reject(reason: FailureReason, status: int) -> None:
    raise HTTPException(status_code=status, detail=reason.value)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/login")
def login(body: LoginBody):
    token, reason = auth.login(body.user_id, body.password)
    if reason is not None:
        _reject(reason, 401)
    return {"token": token}


@app.post("/refresh")
def refresh(body: TokenBody):
    token, reason = auth.refresh(body.token)
    if reason is not None:
        _reject(reason, 401)
    return {"token": token}


@app.post("/logout")
def logout(body: TokenBody):
    reason = auth.logout(body.token)
    if reason is not None:
        _reject(reason, 401)
    return {"ok": True}


@app.get("/check")
def check(token: str, tenant_id: str, permission: str):
    # 令牌校验与授权判定必须在同一把锁内：否则封禁可能恰好插在
    # validate 与 check 之间，造成"封禁已生效、本次判定仍放行"。
    with store.lock:
        session, reason = auth.validate(token)
        if reason is not None:
            _reject(reason, 401)
        ctx = access.begin_request(session.user_id)
        if ctx is None:
            # begin_request 已持锁，锁可重入；到这里说明账号刚被封
            _reject(FailureReason.ACCOUNT_BANNED, 401)
        deny = access.check(ctx, tenant_id, permission)
        if deny is not None:
            _reject(deny, 403)
    return {"allowed": True}


@app.post("/admin/ban")
def admin_ban(body: AdminBody):
    ok = auth.ban_account(body.user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="user_not_found")
    return {"banned": body.user_id}


@app.post("/admin/unban")
def admin_unban(body: AdminBody):
    ok = auth.unban_account(body.user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="user_not_found")
    return {"unbanned": body.user_id}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
