"""HTTP 入口：保留原有根路由，新增登录/续期/注销/授权端点。"""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from app.authz import RequestContext
from app.clock import Clock
from app.models import User
from app.sessions import SessionService
from app.store import Store

store = Store()
clock = Clock()
sessions = SessionService(store, clock)

# 离线演示账号（非真实凭据，仅用于本地验证）
store.add_user(User("alice", "tenant-a", "alice-pw", frozenset({"admin"})))
store.add_user(User("bob", "tenant-a", "bob-pw", frozenset({"reader"})))
store.add_user(User("carol", "tenant-b", "carol-pw", frozenset({"writer"})))

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


class LoginBody(BaseModel):
    user_id: str
    password: str


class TokenBody(BaseModel):
    token: str


class AuthorizeBody(BaseModel):
    token: str
    tenant_id: str
    permission: str


def _result_payload(result):
    return {
        "ok": result.ok,
        "reason": result.reason.value if result.reason else None,
        "session": (
            {
                "session_id": result.session.session_id,
                "token": result.session.token,
                "user_id": result.session.user_id,
                "tenant_id": result.session.tenant_id,
                "expires_at": result.session.expires_at,
            }
            if result.session
            else None
        ),
    }


@app.post("/login")
def login(body: LoginBody):
    return _result_payload(sessions.login(body.user_id, body.password))


@app.post("/refresh")
def refresh(body: TokenBody):
    return _result_payload(sessions.refresh(body.token))


@app.post("/logout")
def logout(body: TokenBody):
    return _result_payload(sessions.logout(body.token))


@app.post("/authorize")
def authorize(body: AuthorizeBody):
    auth = sessions.authenticate(body.token)
    if not auth.ok:
        return {"allowed": False, "reason": auth.reason.value}
    ctx = RequestContext(store, auth.session)
    decision = ctx.authorize(body.tenant_id, body.permission)
    return {"allowed": decision.allowed, "reason": decision.reason.value if decision.reason else None}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
