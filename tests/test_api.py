"""HTTP 层冒烟：原有行为不变，失败原因以可区分形式返回。"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from main import app

logger = logging.getLogger("test")
client = TestClient(app)


def test_root_behavior_unchanged():
    r = client.get("/")
    assert r.status_code == 200 and r.json() == {"Hello": "World"}


def test_login_check_refresh_logout_flow():
    r = client.post("/login", json={"user_id": "bob", "password": "pw-bob"})
    assert r.status_code == 200
    token = r.json()["token"]

    r = client.get("/check", params={"token": token, "tenant_id": "tenant-a",
                                     "permission": "write"})
    assert r.json() == {"allowed": True}

    r = client.get("/check", params={"token": token, "tenant_id": "tenant-b",
                                     "permission": "read"})
    logger.info("cross-tenant -> %s", r.json())
    assert r.status_code == 403 and r.json()["detail"] == "cross_tenant"

    r = client.post("/refresh", json={"token": token})
    new_token = r.json()["token"]
    r = client.post("/refresh", json={"token": token})
    logger.info("replay old token -> %s", r.json())
    assert r.status_code == 401 and r.json()["detail"] == "token_replayed"

    assert client.post("/logout", json={"token": new_token}).status_code == 200
    r = client.get("/check", params={"token": new_token, "tenant_id": "tenant-a",
                                     "permission": "read"})
    assert r.status_code == 401 and r.json()["detail"] == "session_revoked"


def test_login_failures_distinguishable():
    r = client.post("/login", json={"user_id": "bob", "password": "bad"})
    assert r.status_code == 401 and r.json()["detail"] == "bad_credentials"
    r = client.post("/login", json={"user_id": "dave", "password": "pw-dave"})
    assert r.status_code == 401 and r.json()["detail"] == "account_disabled"


def test_admin_ban_unban_lifecycle():
    # 登录拿到两台设备的会话
    r = client.post("/login", json={"user_id": "erin", "password": "pw-erin"})
    token1 = r.json()["token"]
    r = client.post("/login", json={"user_id": "erin", "password": "pw-erin"})
    token2 = r.json()["token"]
    assert client.get("/check", params={"token": token1, "tenant_id": "tenant-a",
                                        "permission": "read"}).json() == {"allowed": True}

    # 后台封禁：立即全设备失效，原因可与密码错误/过期区分
    r = client.post("/admin/ban", json={"user_id": "erin"})
    assert r.status_code == 200 and r.json() == {"banned": "erin"}
    for t in (token1, token2):
        r = client.get("/check", params={"token": t, "tenant_id": "tenant-a",
                                         "permission": "read"})
        logger.info("check after ban -> %s", r.json())
        assert r.status_code == 401 and r.json()["detail"] == "account_banned"
    r = client.post("/login", json={"user_id": "erin", "password": "pw-erin"})
    assert r.status_code == 401 and r.json()["detail"] == "account_banned"

    # 解封不救活老会话，需要重新登录
    r = client.post("/admin/unban", json={"user_id": "erin"})
    assert r.status_code == 200 and r.json() == {"unbanned": "erin"}
    r = client.get("/check", params={"token": token1, "tenant_id": "tenant-a",
                                     "permission": "read"})
    logger.info("old session after unban -> %s", r.json())
    assert r.status_code == 401 and r.json()["detail"] == "session_revoked"
    r = client.post("/login", json={"user_id": "erin", "password": "pw-erin"})
    assert r.status_code == 200 and r.json()["token"]

    # 不存在的用户
    r = client.post("/admin/ban", json={"user_id": "ghost"})
    assert r.status_code == 404 and r.json()["detail"] == "user_not_found"
