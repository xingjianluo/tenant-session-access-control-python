"""HTTP 层：原有根路由保持不变，登录/续期/授权端到端可用。"""
from fastapi.testclient import TestClient

from main import app
from tests.conftest import log

client = TestClient(app)


def test_root_behavior_preserved():
    r = client.get("/")
    log.info("观察: GET / -> %s", r.json())
    assert r.status_code == 200 and r.json() == {"Hello": "World"}


def test_end_to_end_login_authorize_refresh():
    r = client.post("/login", json={"user_id": "carol", "password": "carol-pw"}).json()
    log.info("观察: login -> ok=%s", r["ok"])
    assert r["ok"]
    token = r["session"]["token"]

    ok = client.post("/authorize", json={
        "token": token, "tenant_id": "tenant-b", "permission": "doc:write"}).json()
    assert ok["allowed"], ok

    cross = client.post("/authorize", json={
        "token": token, "tenant_id": "tenant-a", "permission": "doc:write"}).json()
    log.info("观察: 跨租户授权 -> %s", cross)
    assert cross["reason"] == "cross_tenant"

    r2 = client.post("/refresh", json={"token": token}).json()
    assert r2["ok"]
    replay = client.post("/refresh", json={"token": token}).json()
    log.info("观察: 旧令牌重放 -> %s", replay)
    assert replay["reason"] == "token_reused"

    out = client.post("/logout", json={"token": r2["session"]["token"]}).json()
    assert out["ok"]
    after = client.post("/authorize", json={
        "token": r2["session"]["token"], "tenant_id": "tenant-b",
        "permission": "doc:read"}).json()
    log.info("观察: 注销后授权 -> %s", after)
    assert after["reason"] == "session_revoked"
