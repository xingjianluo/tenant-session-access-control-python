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
