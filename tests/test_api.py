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
    # 先登录拿到有效会话
    r = client.post("/login", json={"user_id": "carol", "password": "pw-carol"})
    assert r.status_code == 200
    token = r.json()["token"]

    # 封禁：既有会话立即不可用
    r = client.post("/admin/ban", json={"user_id": "carol"})
    logger.info("ban carol -> %s", r.json())
    assert r.status_code == 200 and r.json()["revoked_sessions"] == 1

    r = client.get("/check", params={"token": token, "tenant_id": "tenant-b",
                                    "permission": "read"})
    logger.info("check after ban -> %s", r.json())
    assert r.status_code == 401 and r.json()["detail"] == "account_disabled"

    r = client.post("/refresh", json={"token": token})
    assert r.status_code == 401 and r.json()["detail"] == "account_disabled"
    r = client.post("/logout", json={"token": token})
    assert r.status_code == 401 and r.json()["detail"] == "account_disabled"

    # 封禁期间不允许登录
    r = client.post("/login", json={"user_id": "carol", "password": "pw-carol"})
    assert r.status_code == 401 and r.json()["detail"] == "account_disabled"

    # 解封：老会话不复活
    r = client.post("/admin/unban", json={"user_id": "carol"})
    logger.info("unban carol -> %s", r.json())
    assert r.status_code == 200
    r = client.get("/check", params={"token": token, "tenant_id": "tenant-b",
                                    "permission": "read"})
    assert r.status_code == 401 and r.json()["detail"] == "session_revoked"

    # 重新登录后恢复正常
    r = client.post("/login", json={"user_id": "carol", "password": "pw-carol"})
    assert r.status_code == 200
    new_token = r.json()["token"]
    r = client.get("/check", params={"token": new_token, "tenant_id": "tenant-b",
                                    "permission": "read"})
    assert r.json() == {"allowed": True}


def test_admin_ban_unknown_user_404():
    r = client.post("/admin/ban", json={"user_id": "ghost"})
    logger.info("ban ghost -> %s", r.json())
    assert r.status_code == 404 and r.json()["detail"] == "user_not_found"
    r = client.post("/admin/unban", json={"user_id": "ghost"})
    assert r.status_code == 404 and r.json()["detail"] == "user_not_found"
