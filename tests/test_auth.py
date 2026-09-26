"""会话生命周期：登录、续期轮换、注销撤销、并发续期与旧凭据重放。"""
from __future__ import annotations

import logging
import threading

from app.models import FailureReason
from tests.conftest import FakeClock

logger = logging.getLogger("test")


def test_login_success_and_validate(auth):
    token, reason = auth.login("alice", "pw-alice")
    logger.info("login alice -> token=%s reason=%s", token, reason)
    assert reason is None and token
    session, reason = auth.validate(token)
    logger.info("validate -> user=%s reason=%s", session and session.user_id, reason)
    assert reason is None and session.user_id == "alice"


def test_login_bad_credentials(auth):
    token, reason = auth.login("alice", "wrong")
    logger.info("login wrong password -> reason=%s", reason)
    assert token is None and reason is FailureReason.BAD_CREDENTIALS
    token, reason = auth.login("nobody", "x")
    assert reason is FailureReason.BAD_CREDENTIALS


def test_login_disabled_account(auth):
    token, reason = auth.login("dave", "pw-dave")
    logger.info("login disabled dave -> reason=%s", reason)
    assert token is None and reason is FailureReason.ACCOUNT_DISABLED


def test_refresh_rotates_token_and_old_token_replayed(auth, store):
    old, _ = auth.login("bob", "pw-bob")
    new, reason = auth.refresh(old)
    logger.info("refresh old=%s -> new=%s reason=%s", old, new, reason)
    assert reason is None and new and new != old

    session, reason = auth.validate(old)
    logger.info("validate(old) -> reason=%s", reason)
    assert session is None and reason is FailureReason.TOKEN_REPLAYED

    session, reason = auth.validate(new)
    assert reason is None and session.user_id == "bob"
    logger.info("validate(new) -> ok, rotation=%d", session.rotation)


def test_replay_does_not_extend_expiry(auth, store, clock: FakeClock):
    old, _ = auth.login("bob", "pw-bob")
    clock.advance(50)
    new, _ = auth.refresh(old)
    expiry_after_refresh = store.find_session_by_token(new).expires_at
    # 重放旧凭据：必须被拒绝且不得改变有效期
    token, reason = auth.refresh(old)
    logger.info("replay refresh -> token=%s reason=%s", token, reason)
    assert token is None and reason is FailureReason.TOKEN_REPLAYED
    assert store.find_session_by_token(new).expires_at == expiry_after_refresh
    logger.info("expiry unchanged at %s", expiry_after_refresh)


def test_expired_session_rejected(auth, clock: FakeClock):
    token, _ = auth.login("bob", "pw-bob")
    clock.advance(101)  # ttl=100
    session, reason = auth.validate(token)
    logger.info("validate expired -> reason=%s", reason)
    assert session is None and reason is FailureReason.SESSION_EXPIRED
    new, reason = auth.refresh(token)
    assert new is None and reason is FailureReason.SESSION_EXPIRED


def test_logout_revokes_session(auth):
    token, _ = auth.login("bob", "pw-bob")
    assert auth.logout(token) is None
    session, reason = auth.validate(token)
    logger.info("validate after logout -> reason=%s", reason)
    assert session is None and reason is FailureReason.SESSION_REVOKED
    new, reason = auth.refresh(token)
    assert new is None and reason is FailureReason.SESSION_REVOKED


def test_revoke_user_sessions_affects_established(auth):
    t1, _ = auth.login("bob", "pw-bob")
    t2, _ = auth.login("bob", "pw-bob")
    n = auth.revoke_user_sessions("bob")
    logger.info("revoked %d sessions of bob", n)
    assert n == 2
    for t in (t1, t2):
        _, reason = auth.validate(t)
        assert reason is FailureReason.SESSION_REVOKED


def test_unknown_token(auth):
    _, reason = auth.validate("no-such-token")
    assert reason is FailureReason.SESSION_NOT_FOUND
    assert auth.logout("no-such-token") is FailureReason.SESSION_NOT_FOUND


def test_concurrent_refresh_single_successor(auth, store):
    old, _ = auth.login("bob", "pw-bob")
    results: list[tuple[str | None, FailureReason | None]] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(auth.refresh(old))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [tok for tok, r in results if r is None]
    failures = [r for _, r in results if r is not None]
    logger.info("concurrent refresh: %d success, failures=%s",
                len(successes), failures)
    assert len(successes) == 1
    assert all(r is FailureReason.TOKEN_REPLAYED for r in failures)

    new = successes[0]
    session, reason = auth.validate(new)
    assert reason is None and session.rotation == 1
    _, reason = auth.validate(old)
    assert reason is FailureReason.TOKEN_REPLAYED
    logger.info("only one successor session usable: rotation=%d", session.rotation)
