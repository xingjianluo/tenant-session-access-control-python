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


class LoginBody(BaseModel):
    user_id: str
    password: str


class TokenBody(BaseModel):
    token: str


class AdminBody(BaseModel):
    user_id: str


# 授权判定类原因走 403；凭据/会话/封禁类原因走 401。
_AUTHZ_REASONS = {
    FailureReason.CROSS_TENANT,
    FailureReason.PERMISSION_DENIED,
    FailureReason.UNKNOWN_PERMISSION,
}


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
    _ctx, reason = access.authorize(auth, token, tenant_id, permission)
    if reason is not None:
        status = 403 if reason in _AUTHZ_REASONS else 401
        _reject(reason, status)
    return {"allowed": True}


@app.post("/admin/ban")
def admin_ban(body: AdminBody):
    """后台封封口子（本地演示未加管理端鉴权，生产应置于管理权限之后）。"""
    revoked, reason = auth.ban_user(body.user_id)
    if reason is not None:
        status = 404 if reason is FailureReason.USER_NOT_FOUND else 400
        _reject(reason, status)
    return {"user_id": body.user_id, "banned": True, "revoked_sessions": revoked}


@app.post("/admin/unban")
def admin_unban(body: AdminBody):
    """后台解封口子；封禁前的老会话不复活，需重新登录。"""
    reason = auth.unban_user(body.user_id)
    if reason is not None:
        status = 404 if reason is FailureReason.USER_NOT_FOUND else 400
        _reject(reason, status)
    return {"user_id": body.user_id, "banned": False}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
