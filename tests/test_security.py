"""账号安全管控：封禁/解封、多设备隔离、失效凭据只读拒绝。

日志按"场景 -> 用例 -> 结果"组织，便于确认覆盖范围。
"""
from __future__ import annotations

import logging
import threading

import pytest

from app.models import FailureReason

logger = logging.getLogger("test")

SCENARIO = ""


def _case(name: str, **fields) -> None:
    logger.info("[%s] CASE %s -> %s", SCENARIO, name,
                " ".join(f"{k}={v}" for k, v in fields.items()))


@pytest.fixture(autouse=True)
def _log_scenario(request):
    # 每个测试类第一次执行时打印场景标题，便于从日志确认覆盖范围
    cls = request.node.cls
    if cls is not None:
        title = cls.__doc__.strip().splitlines()[0]
        if getattr(cls, "_logged", None) != title:
            logger.info("===== SCENARIO: %s =====", title)
            cls._logged = title
    yield


class TestBanLifecycle:
    """场景一封禁生命周期：封禁立即生效；解封不救活老会话。"""

    def test_banned_login_refresh_validate_logout_all_blocked(self, auth):
        global SCENARIO
        SCENARIO = "ban-lifecycle"
        token, _ = auth.login("alice", "pw-alice")
        assert auth.ban_account("alice") is True
        _case("ban alice", token=token[:8])

        _, reason = auth.login("alice", "pw-alice")
        _case("login while banned", reason=reason)
        assert reason is FailureReason.ACCOUNT_BANNED

        _, reason = auth.validate(token)
        _case("validate old session", reason=reason)
        assert reason is FailureReason.ACCOUNT_BANNED

        new, reason = auth.refresh(token)
        _case("refresh old credential", token=new, reason=reason)
        assert new is None and reason is FailureReason.ACCOUNT_BANNED

        reason = auth.logout(token)
        _case("logout old credential", reason=reason)
        assert reason is FailureReason.ACCOUNT_BANNED

    def test_ban_distinguishable_from_other_failures(self, auth):
        global SCENARIO
        SCENARIO = "ban-reasons"
        # 与密码错误、会话过期、已撤销、重放明确区分
        _, bad = auth.login("alice", "wrong")
        assert bad is FailureReason.BAD_CREDENTIALS
        assert auth.ban_account("alice") is True
        _, banned = auth.login("alice", "pw-alice")
        _case("bad_credentials vs banned", bad=bad, banned=banned)
        assert banned is FailureReason.ACCOUNT_BANNED and banned is not bad

    def test_unban_does_not_revive_old_sessions(self, auth):
        global SCENARIO
        SCENARIO = "unban-no-revival"
        old, _ = auth.login("alice", "pw-alice")
        auth.ban_account("alice")
        assert auth.unban_account("alice") is True
        _case("unban alice", old_token=old[:8])

        # 封禁前的老会话不得被救活，必须重新登录
        _, reason = auth.validate(old)
        _case("old session after unban", reason=reason)
        assert reason is FailureReason.SESSION_REVOKED
        _, reason = auth.refresh(old)
        assert reason is FailureReason.SESSION_REVOKED

        new, reason = auth.login("alice", "pw-alice")
        _case("relogin after unban", reason=reason, new_token=(new or "")[:8])
        assert reason is None and new
        ok, reason = auth.validate(new)
        assert reason is None and ok.user_id == "alice"

    def test_ban_idempotent_and_unknown_user(self, auth):
        global SCENARIO
        SCENARIO = "ban-edge"
        assert auth.ban_account("alice") is True
        assert auth.ban_account("alice") is True
        assert auth.unban_account("alice") is True
        _case("ban/unban idempotent")
        assert auth.ban_account("ghost") is False
        assert auth.unban_account("ghost") is False


class TestBanConcurrency:
    """场景二封禁竞争：与并发续期、判定同时发生时不变量成立。"""

    def test_ban_races_concurrent_refresh(self, auth):
        global SCENARIO
        SCENARIO = "ban-vs-refresh"
        token, _ = auth.login("bob", "pw-bob")
        results: list[tuple[str | None, FailureReason | None]] = []
        results_lock = threading.Lock()

        def refresh_worker(barrier):
            barrier.wait()
            r = auth.refresh(token)
            with results_lock:
                results.append(r)

        def ban_worker(barrier):
            barrier.wait()
            auth.ban_account("bob")

        barrier = threading.Barrier(9)
        threads = [threading.Thread(target=refresh_worker, args=(barrier,))
                   for _ in range(8)]
        threads.append(threading.Thread(target=ban_worker, args=(barrier,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        success = [tok for tok, r in results if r is None]
        reasons = {r for _, r in results if r is not None}
        _case("8 refresh vs 1 ban", success=len(success),
              failures=[r.value if r else None for r in reasons])

        # 关键不变量：
        # 1) 封禁之后不可能仍有人换到了可用新凭据：
        #    即使某续期恰好在封禁前成功，它拿到的新凭据此刻也必须被拦
        # 2) 失败原因只能是重放/已撤销/被封，绝不能是"成功且凭据可用"
        for new_token in success:
            _, reason = auth.validate(new_token)
            _case("successor token after ban", reason=reason)
            assert reason is FailureReason.ACCOUNT_BANNED
        assert reasons <= {
            FailureReason.TOKEN_REPLAYED,
            FailureReason.SESSION_REVOKED,
            FailureReason.ACCOUNT_BANNED,
        }
        # 封禁已完成：当前账号状态必须是封禁态
        _, reason = auth.validate(token)
        assert reason is FailureReason.ACCOUNT_BANNED

    def test_ban_races_concurrent_refresh_stress(self, auth):
        global SCENARIO
        SCENARIO = "ban-vs-refresh-stress"
        # 多轮打乱启动顺序，反复验证同一个不变量
        for round_no in range(20):
            token, _ = auth.login("bob", "pw-bob")
            outcomes: list[tuple[str | None, FailureReason | None]] = []
            out_lock = threading.Lock()

            def worker(barrier, out_lock=out_lock, outcomes=outcomes, token=token):
                barrier.wait()
                with out_lock:
                    outcomes.append(auth.refresh(token))

            def banner(barrier):
                barrier.wait()
                auth.ban_account("bob")

            barrier = threading.Barrier(5)
            ts = [threading.Thread(target=worker, args=(barrier,)) for _ in range(4)]
            ts.append(threading.Thread(target=banner, args=(barrier,)))
            for t in ts:
                t.start()
            for t in ts:
                t.join()

            for new_token, _ in outcomes:
                if new_token is not None:
                    _, reason = auth.validate(new_token)
                    assert reason is FailureReason.ACCOUNT_BANNED, (round_no, reason)
            auth.unban_account("bob")
        _case("20 rounds x 4 refresh vs ban", invariant="no usable successor after ban")

    def test_ban_races_concurrent_check(self, auth, access):
        global SCENARIO
        SCENARIO = "ban-vs-check"
        token, _ = auth.login("alice", "pw-alice")
        verdicts: list[tuple[bool, FailureReason | None]] = []
        v_lock = threading.Lock()

        def check_worker(barrier):
            barrier.wait()
            # 模拟 HTTP 层：validate + begin_request + check 在同一把锁内
            with auth._store.lock:
                session, reason = auth.validate(token)
                if reason is not None:
                    verdict = (False, reason)
                else:
                    ctx = access.begin_request(session.user_id)
                    if ctx is None:
                        deny = FailureReason.ACCOUNT_BANNED
                    else:
                        deny = access.check(ctx, "tenant-a", "read")
                    verdict = (deny is None, deny)
            with v_lock:
                verdicts.append(verdict)

        def ban_worker(barrier):
            barrier.wait()
            auth.ban_account("alice")

        barrier = threading.Barrier(9)
        threads = [threading.Thread(target=check_worker, args=(barrier,))
                   for _ in range(8)]
        threads.append(threading.Thread(target=ban_worker, args=(barrier,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = [v for v in verdicts if v[0]]
        denied_reasons = {v[1] for v in verdicts if not v[0]}
        _case("8 check vs 1 ban", allowed=len(allowed),
              denied=[r.value if r else None for r in denied_reasons])
        # 被拒的只能因为封禁；封禁生效后再判定必拒
        assert denied_reasons <= {FailureReason.ACCOUNT_BANNED}
        _, reason = auth.validate(token)
        assert reason is FailureReason.ACCOUNT_BANNED

        # 解封后老会话仍不可用（不是"解封即放行"）
        auth.unban_account("alice")
        _, reason = auth.validate(token)
        assert reason is FailureReason.SESSION_REVOKED


class TestMultiDeviceIsolation:
    """场景三多设备隔离：续期只换自己，下线只踢自己，封禁全部命中。"""

    def test_refresh_on_one_device_keeps_others_usable(self, auth, store):
        global SCENARIO
        SCENARIO = "multi-device-refresh"
        t_phone, _ = auth.login("bob", "pw-bob")
        t_laptop, _ = auth.login("bob", "pw-bob")
        t_tablet, _ = auth.login("bob", "pw-bob")
        assert len(store.sessions_of_user("bob")) == 3

        new_phone, reason = auth.refresh(t_phone)
        _case("phone refreshed", reason=reason)
        assert reason is None and new_phone != t_phone

        # 别的设备手里的旧凭据照旧有效，不被连带轮换
        for name, tok in (("laptop", t_laptop), ("tablet", t_tablet)):
            session, r = auth.validate(tok)
            _case(f"{name} credential", user=session and session.user_id, reason=r)
            assert r is None and session.user_id == "bob"

        # 手机旧凭据已轮换、新凭据可用
        _, r = auth.validate(t_phone)
        assert r is FailureReason.TOKEN_REPLAYED
        _, r = auth.validate(new_phone)
        assert r is None

    def test_logout_one_device_does_not_kick_others(self, auth, store):
        global SCENARIO
        SCENARIO = "multi-device-logout"
        t_phone, _ = auth.login("bob", "pw-bob")
        t_laptop, _ = auth.login("bob", "pw-bob")

        assert auth.logout(t_phone) is None
        _, r_phone = auth.validate(t_phone)
        s_laptop, r_laptop = auth.validate(t_laptop)
        _case("phone logout", phone=r_phone, laptop=r_laptop)
        assert r_phone is FailureReason.SESSION_REVOKED
        assert r_laptop is None and s_laptop.user_id == "bob"

        # 下线的设备即使续期也无法复活；在线设备还能继续轮换
        _, r = auth.refresh(t_phone)
        assert r is FailureReason.SESSION_REVOKED
        new_laptop, r = auth.refresh(t_laptop)
        assert r is None and new_laptop
        _case("laptop still rotates", reason=r)

    def test_ban_hits_all_devices_unban_requires_relogin(self, auth):
        global SCENARIO
        SCENARIO = "multi-device-ban"
        tokens = [auth.login("bob", "pw-bob")[0] for _ in range(3)]
        auth.ban_account("bob")
        for i, tok in enumerate(tokens):
            _, reason = auth.validate(tok)
            _case(f"device {i} after ban", reason=reason)
            assert reason is FailureReason.ACCOUNT_BANNED
        auth.unban_account("bob")
        for i, tok in enumerate(tokens):
            _, reason = auth.validate(tok)
            _case(f"device {i} old session after unban", reason=reason)
            assert reason is FailureReason.SESSION_REVOKED
        fresh, reason = auth.login("bob", "pw-bob")
        assert reason is None
        _, reason = auth.validate(fresh)
        assert reason is None


class TestStaleCredentialReadOnly:
    """场景四失效凭据只读：拒绝原因可区分，绝不连带作废当前有效会话。"""

    def test_logout_with_rotated_token_does_not_revoke_active(self, auth, store):
        global SCENARIO
        SCENARIO = "stale-logout-rotated"
        old, _ = auth.login("alice", "pw-alice")
        new, _ = auth.refresh(old)

        # 拿已轮换的旧凭据去注销：明确拒绝（token_replayed），
        # 当前真正在用的新会话绝不能被连带作废
        reason = auth.logout(old)
        _case("logout rotated token", reason=reason)
        assert reason is FailureReason.TOKEN_REPLAYED
        session, r = auth.validate(new)
        _case("active session survives", revoked=session.revoked, reason=r)
        assert r is None and session.revoked is False

        # 用旧凭据做其它操作同样只读拒绝，且有效期不变
        expiry = session.expires_at
        _, r = auth.refresh(old)
        assert r is FailureReason.TOKEN_REPLAYED
        assert store.find_session_by_token(new).expires_at == expiry
        _, r = auth.validate(old)
        assert r is FailureReason.TOKEN_REPLAYED

    def test_logout_with_revoked_token_is_read_only(self, auth):
        global SCENARIO
        SCENARIO = "stale-logout-revoked"
        t1, _ = auth.login("alice", "pw-alice")
        t2, _ = auth.login("alice", "pw-alice")
        assert auth.logout(t1) is None

        # 再次拿已注销凭据操作：session_revoked；另一条会话不受影响
        assert auth.logout(t1) is FailureReason.SESSION_REVOKED
        _, r = auth.refresh(t1)
        assert r is FailureReason.SESSION_REVOKED
        _case("reuse revoked token", reason=r)
        session, r = auth.validate(t2)
        assert r is None and session.revoked is False
        _case("sibling session intact", revoked=session.revoked)

    def test_stale_token_while_banned_reports_banned(self, auth):
        global SCENARIO
        SCENARIO = "stale-while-banned"
        old, _ = auth.login("alice", "pw-alice")
        new, _ = auth.refresh(old)
        auth.ban_account("alice")
        # 封禁优先：旧凭据、新凭据的原因都统一为 account_banned
        for name, tok in (("rotated-old", old), ("current", new)):
            assert auth.logout(tok) is FailureReason.ACCOUNT_BANNED
            _, reason = auth.validate(tok)
            _case(f"{name} while banned", reason=reason)
            assert reason is FailureReason.ACCOUNT_BANNED

    def test_unknown_token_never_mutates(self, auth):
        global SCENARIO
        SCENARIO = "unknown-token-readonly"
        assert auth.logout("never-existed") is FailureReason.SESSION_NOT_FOUND
        tok, _ = auth.login("alice", "pw-alice")
        assert auth.logout("never-existed") is FailureReason.SESSION_NOT_FOUND
        session, reason = auth.validate(tok)
        _case("unknown token leaves real session alone", reason=reason,
              revoked=session.revoked)
        assert reason is None and session.revoked is False

