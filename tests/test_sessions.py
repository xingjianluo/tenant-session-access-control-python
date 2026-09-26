"""会话生命周期：登录、续期、注销、撤销、过期、禁用，失败原因可区分。"""
from app.models import FailureReason
from tests.conftest import log


def test_login_success_and_bad_credentials(svc):
    log.info("输入: login(alice, 正确密码)")
    r = svc.login("alice", "alice-pw")
    log.info("观察: ok=%s session=%s", r.ok, r.session.session_id if r.session else None)
    assert r.ok and r.session.tenant_id == "tenant-a"

    log.info("输入: login(alice, 错误密码)")
    r = svc.login("alice", "wrong")
    log.info("观察: ok=%s reason=%s", r.ok, r.reason)
    assert not r.ok and r.reason is FailureReason.BAD_CREDENTIALS

    log.info("输入: login(不存在的用户)")
    r = svc.login("ghost", "x")
    assert not r.ok and r.reason is FailureReason.BAD_CREDENTIALS


def test_disabled_account_rejected_and_existing_session_invalidated(svc, store):
    r = svc.login("bob", "bob-pw")
    token = r.session.token
    assert svc.authenticate(token).ok

    log.info("状态变化: 禁用 bob")
    store.set_user_disabled("bob", True)
    r2 = svc.authenticate(token)
    log.info("观察: 已建立会话 authenticate -> %s", r2.reason)
    assert r2.reason is FailureReason.ACCOUNT_DISABLED

    r3 = svc.login("bob", "bob-pw")
    assert r3.reason is FailureReason.ACCOUNT_DISABLED
    log.info("判定依据: 禁用账号登录与已有会话均被拒绝且原因=account_disabled")


def test_refresh_rotates_token_and_old_token_invalid(svc):
    r1 = svc.login("alice", "alice-pw")
    old_token = r1.session.token
    log.info("输入: refresh(旧令牌) 到期时间=%s", r1.session.expires_at)
    r2 = svc.refresh(old_token)
    log.info("观察: 新会话=%s 旧会话 revoked=%s successor=%s",
             r2.session.session_id, r1.session.revoked, r1.session.successor_id)
    assert r2.ok and r2.session.token != old_token
    assert r1.session.revoked and r1.session.successor_id == r2.session.session_id

    old = svc.authenticate(old_token)
    log.info("观察: 旧令牌 authenticate -> %s", old.reason)
    assert old.reason is FailureReason.TOKEN_REUSED
    assert svc.authenticate(r2.session.token).ok


def test_session_expiry(svc, clock):
    r = svc.login("alice", "alice-pw")
    token = r.session.token
    log.info("输入: 时钟推进 101s (ttl=100s)")
    clock.advance(101)
    r2 = svc.authenticate(token)
    log.info("观察: 过期后 authenticate -> %s", r2.reason)
    assert r2.reason is FailureReason.SESSION_EXPIRED
    r3 = svc.refresh(token)
    assert r3.reason is FailureReason.SESSION_EXPIRED
    log.info("判定依据: 过期会话续期同样被拒绝，不延长有效期")


def test_logout_revokes_session(svc):
    r = svc.login("alice", "alice-pw")
    token = r.session.token
    out = svc.logout(token)
    assert out.ok
    r2 = svc.authenticate(token)
    log.info("观察: 注销后 authenticate -> %s", r2.reason)
    assert r2.reason is FailureReason.SESSION_REVOKED
    assert svc.logout("不存在的令牌").reason is FailureReason.SESSION_NOT_FOUND


def test_revoke_user_sessions_affects_established_sessions(svc):
    r1 = svc.login("alice", "alice-pw")
    r2 = svc.login("alice", "alice-pw")
    n = svc.revoke_user_sessions("alice")
    log.info("观察: 撤销 alice 全部会话, 数量=%d", n)
    assert n == 2
    for r in (r1, r2):
        res = svc.authenticate(r.session.token)
        log.info("观察: 会话 %s -> %s", r.session.session_id, res.reason)
        assert res.reason is FailureReason.SESSION_REVOKED
