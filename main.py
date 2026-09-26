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
    session, reason = auth.validate(token)
    if reason is not None:
        _reject(reason, 401)
    ctx = access.begin_request(session.user_id)
    deny = access.check(ctx, tenant_id, permission)
    if deny is not None:
        _reject(deny, 403)
    return {"allowed": True}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
