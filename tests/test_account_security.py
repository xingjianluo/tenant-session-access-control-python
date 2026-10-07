"""账号安全管控：后台封禁/解封、多设备会话隔离、作废凭据只读拒绝。

场景分组：
1. 封禁即时生效：旧凭据/新凭据/续期/注销/判定全部以 account_disabled 拒绝，
   且与 bad_credentials / session_expired 可区分。
2. 解封不复活：封禁前的老会话在解封后仍 revoked，必须重新登录。
3. 多设备互不影响：各设备独立轮换、单独下线不牵连同账号其它设备。
4. 作废凭据只读拒绝：旧凭据重放注销/续期/判定被拒绝，且不连累当前有效会话。
5. 并发：封禁与续期、判定同时发生时不存在"封禁生效却换到凭据/判定放行"。
"""
from __future__ import annotations

import logging
import threading

from app.models import FailureReason

logger = logging.getLogger("test")


# ---------- 1. 封禁即时生效 ----------

def test_ban_blocks_old_credential_refresh_and_validate(auth):
    token, _ = auth.login("bob", "pw-bob")
    revoked, reason = auth.ban_user("bob")
    logger.info("ban bob -> revoked=%s reason=%s", revoked, reason)
    assert reason is None and revoked == 1

    # 继续用旧凭据
    s, reason = auth.validate(token)
    logger.info("validate(old credential) after ban -> %s", reason)
    assert s is None and reason is FailureReason.ACCOUNT_DISABLED

    # 尝试续期换新凭据
    new_token, reason = auth.refresh(token)
    logger.info("refresh after ban -> token=%s reason=%s", new_token, reason)
    assert new_token is None and reason is FailureReason.ACCOUNT_DISABLED


def test_ban_blocks_logout_and_recheck(auth, access):
    token, _ = auth.login("bob", "pw-bob")
    auth.ban_user("bob")

    # 发起注销也被拦住，原因是封禁而不是别的
    reason = auth.logout(token)
    logger.info("logout after ban -> %s", reason)
    assert reason is FailureReason.ACCOUNT_DISABLED

    ctx, reason = access.authorize(auth, token, "tenant-a", "read")
    logger.info("authorize after ban -> ctx=%s reason=%s", ctx, reason)
    assert ctx is None and reason is FailureReason.ACCOUNT_DISABLED


def test_ban_reason_distinguishable_from_password_and_expiry(auth, clock):
    # 密码错误 vs 封禁
    _, wrong = auth.login("bob", "bad-password")
    auth.ban_user("bob")
    _, banned = auth.login("bob", "pw-bob")
    logger.info("wrong password -> %s; login while banned -> %s", wrong, banned)
    assert wrong is FailureReason.BAD_CREDENTIALS
    assert banned is FailureReason.ACCOUNT_DISABLED

    # 会话过期原因（未封禁账号）作为可区分对照
    token, _ = auth.login("carol", "pw-carol")
    clock.advance(101)
    _, expired = auth.validate(token)
    logger.info("expired session -> %s (distinct from ban)", expired)
    assert expired is FailureReason.SESSION_EXPIRED

    # 封禁状态优先于过期：即使会话已到期，给的仍是封禁原因
    auth.unban_user("bob")
    token2, _ = auth.login("bob", "pw-bob")
    auth.ban_user("bob")
    clock.advance(200)
    _, banned_after_expiry = auth.validate(token2)
    logger.info("banned+expired -> %s (ban wins)", banned_after_expiry)
    assert banned_after_expiry is FailureReason.ACCOUNT_DISABLED
    auth.unban_user("bob")


def test_ban_revokes_all_existing_sessions_immediately(auth):
    tokens = [auth.login("bob", "pw-bob")[0] for _ in range(3)]
    n, reason = auth.ban_user("bob")
    logger.info("ban bob with 3 live sessions -> n=%s", n)
    assert n == 3 and reason is None
    for t in tokens:
        _, r = auth.validate(t)
        assert r is FailureReason.ACCOUNT_DISABLED


def test_ban_is_idempotent_and_ban_unknown_user(auth):
    auth.login("bob", "pw-bob")
    auth.login("bob", "pw-bob")
    n1, r1 = auth.ban_user("bob")
    n2, r2 = auth.ban_user("bob")  # 重复封禁不报错；会话已撤销故本次撤销数为 0
    logger.info("ban twice -> (%s,%s),(%s,%s)", n1, r1, n2, r2)
    assert (n1, r1) == (2, None) and (n2, r2) == (0, None)

    n, reason = auth.ban_user("ghost")
    logger.info("ban unknown user -> n=%s reason=%s", n, reason)
    assert n is None and reason is FailureReason.USER_NOT_FOUND


# ---------- 2. 解封不复活 ----------

def test_unban_does_not_revive_old_sessions_and_login_works(auth, access):
    old, _ = auth.login("bob", "pw-bob")
    auth.ban_user("bob")
    reason = auth.unban_user("bob")
    logger.info("unban bob -> %s", reason)
    assert reason is None

    # 封禁前的老凭据仍不可用，且原因是会话撤销而非封禁——证明没被"救活"
    s, reason = auth.validate(old)
    logger.info("validate pre-ban credential after unban -> %s", reason)
    assert s is None and reason is FailureReason.SESSION_REVOKED
    assert auth.refresh(old) == (None, FailureReason.SESSION_REVOKED)

    # 必须重新登录
    new, reason = auth.login("bob", "pw-bob")
    logger.info("re-login after unban -> reason=%s", reason)
    assert reason is None and new and new != old
    ctx, reason = access.authorize(auth, new, "tenant-a", "write")
    assert reason is None and ctx is not None
    logger.info("new session usable after unban, tenant=%s roles=%s",
                ctx.tenant_id, {r.value for r in ctx.roles})


def test_unban_unknown_user(auth):
    reason = auth.unban_user("ghost")
    logger.info("unban unknown user -> %s", reason)
    assert reason is FailureReason.USER_NOT_FOUND


# ---------- 3. 多设备会话互不影响 ----------

def test_multiple_devices_independent_refresh(auth):
    phone, _ = auth.login("bob", "pw-bob")
    laptop, _ = auth.login("bob", "pw-bob")
    tablet, _ = auth.login("bob", "pw-bob")

    # 手机端续期：只有它自己换新
    phone2, reason = auth.refresh(phone)
    logger.info("phone rotated: %s -> %s (%s)", phone[:8], phone2[:8], reason)
    assert reason is None and phone2 != phone

    # 旧手机凭据立即作废（重放）
    _, r_old_phone = auth.validate(phone)
    assert r_old_phone is FailureReason.TOKEN_REPLAYED
    # 笔记本、平板凭据照旧可用
    for name, t in (("laptop", laptop), ("tablet", tablet)):
        s, r = auth.validate(t)
        logger.info("%s credential still usable -> %s", name, r)
        assert r is None and s is not None

    # 手机新凭据也可用
    assert auth.validate(phone2)[1] is None


def test_logout_one_device_does_not_kick_others(auth):
    phone, _ = auth.login("bob", "pw-bob")
    laptop, _ = auth.login("bob", "pw-bob")

    assert auth.logout(phone) is None
    logger.info("phone logged out")

    _, r_phone = auth.validate(phone)
    _, r_laptop = auth.validate(laptop)
    logger.info("after phone logout: phone=%s laptop=%s", r_phone, r_laptop)
    assert r_phone is FailureReason.SESSION_REVOKED
    assert r_laptop is None  # 同账号其它设备不被踢


# ---------- 4. 作废凭据只读拒绝、绝不改动现状 ----------

def test_logout_with_rotated_old_token_is_read_only_reject(auth):
    old, _ = auth.login("bob", "pw-bob")
    new, _ = auth.refresh(old)

    # 拿已轮换的旧凭据注销：必须拒绝，且当前有效会话不被连累
    reason = auth.logout(old)
    logger.info("logout with rotated-old credential -> %s", reason)
    assert reason is FailureReason.TOKEN_REPLAYED

    s, r = auth.validate(new)
    logger.info("current session after stale logout -> %s (must stay usable)", r)
    assert r is None and s is not None
    # 当前凭据仍能正常续期
    newer, r = auth.refresh(new)
    assert r is None and newer is not None


def test_logout_twice_is_read_only_reject(auth):
    token, _ = auth.login("bob", "pw-bob")
    assert auth.logout(token) is None
    reason = auth.logout(token)  # 再次拿已注销凭据操作
    logger.info("second logout -> %s", reason)
    assert reason is FailureReason.SESSION_REVOKED


def test_logout_expired_credential_is_distinguishable_reject(auth, clock):
    token, _ = auth.login("bob", "pw-bob")
    clock.advance(101)
    reason = auth.logout(token)
    logger.info("logout expired credential -> %s", reason)
    assert reason is FailureReason.SESSION_EXPIRED


def test_revoked_credential_on_other_device_cannot_revoke_active(auth):
    # 设备 A 注销后，拿 A 的作废凭据再操作，绝不能影响设备 B
    a, _ = auth.login("bob", "pw-bob")
    b, _ = auth.login("bob", "pw-bob")
    auth.logout(a)

    assert auth.refresh(a)[1] is FailureReason.SESSION_REVOKED
    assert auth.logout(a) is FailureReason.SESSION_REVOKED

    _, r_b = auth.validate(b)
    logger.info("device B still usable after operations on dead A -> %s", r_b)
    assert r_b is None


def test_unknown_token_operations_are_read_only(auth):
    assert auth.logout("never-existed") is FailureReason.SESSION_NOT_FOUND
    assert auth.refresh("never-existed") == (None, FailureReason.SESSION_NOT_FOUND)
    logger.info("unknown token rejected without touching any state")


# ---------- 5. 并发：封禁 vs 续期 / 判定 ----------

def test_concurrent_ban_vs_refresh_no_successor_after_ban(auth):
    rounds = 100
    leaked = 0

    for i in range(rounds):
        # 每轮 5 台设备各自登录、各自轮换
        tokens = [auth.login("bob", "pw-bob")[0] for _ in range(5)]
        barrier = threading.Barrier(6)  # 5 个续期线程 + 1 个封禁线程

        def refresher(start_token: str, barrier=barrier):
            token = start_token
            barrier.wait()
            # 被拒前尽量多换几次；最多 50 步避免异常情况下失控
            for _ in range(50):
                nxt, reason = auth.refresh(token)
                if reason is not None:
                    return
                token = nxt

        def banner(barrier=barrier):
            barrier.wait()
            auth.ban_user("bob")

        threads = [threading.Thread(target=refresher, args=(t,)) for t in tokens]
        threads.append(threading.Thread(target=banner))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 不变量：封禁提交后，任何被轮换出来的新凭据都不能再用。
        # bob 名下全部会话的当前凭据必须一律被封禁拦截。
        for s in auth._store.sessions_of_user("bob"):
            _, r = auth.validate(s.token)
            if r is not FailureReason.ACCOUNT_DISABLED:
                leaked += 1
                logger.warning("round %d: fresh token leaked with reason=%s", i, r)

        # 解封便于下一轮重新登录
        auth.unban_user("bob")

    logger.info("concurrent ban/refresh over %d rounds: leaked_tokens=%d",
                rounds, leaked)
    assert leaked == 0


def test_concurrent_ban_vs_authorize_never_allowed_after_ban(auth, access):
    rounds = 100
    leaked = 0
    observed: set[object] = set()

    for i in range(rounds):
        tokens = [auth.login("bob", "pw-bob")[0] for _ in range(5)]
        barrier = threading.Barrier(6)  # 5 个判定线程 + 1 个封禁线程
        observed_lock = threading.Lock()

        def checker(token: str, barrier=barrier, observed_lock=observed_lock):
            barrier.wait()
            _, r = access.authorize(auth, token, "tenant-a", "read")
            with observed_lock:
                observed.add("ALLOWED" if r is None else r)

        def banner(barrier=barrier):
            barrier.wait()
            auth.ban_user("bob")

        threads = [threading.Thread(target=checker, args=(t,)) for t in tokens]
        threads.append(threading.Thread(target=banner))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 封禁后再判定：必须全部 account_disabled，绝无放行
        for s in auth._store.sessions_of_user("bob"):
            _, r = access.authorize(auth, s.token, "tenant-a", "read")
            if r is None:
                leaked += 1
        auth.unban_user("bob")

    logger.info("concurrent ban/authorize over %d rounds, observed=%s, "
                "post-ban allows=%d", rounds, observed, leaked)
    # 并发中可能观察到"放行"（判定线性化在封禁之前），也可能观察到封禁拒绝；
    # 但封禁完成之后的判定一次都不允许放行。
    assert FailureReason.ACCOUNT_DISABLED in observed
    assert leaked == 0


def test_interleaving_refresh_then_ban_then_refresh(auth, store):
    """确定性交错：拿到锁的顺序决定结果，但两种顺序下封禁都站得住。"""
    token, _ = auth.login("bob", "pw-bob")

    # 顺序 A：续期先于封禁——续期成功，随后新凭据立即被封禁拦截
    new1, r = auth.refresh(token)
    assert r is None
    n, _ = auth.ban_user("bob")
    assert n == 1
    assert auth.refresh(new1) == (None, FailureReason.ACCOUNT_DISABLED)
    assert auth.validate(new1)[1] is FailureReason.ACCOUNT_DISABLED
    logger.info("order refresh->ban: successor immediately dead after ban")

    # 顺序 B：解封重新登录后，封禁先于续期——续期连机会都没有
    auth.unban_user("bob")
    token2, _ = auth.login("bob", "pw-bob")
    auth.ban_user("bob")
    new2, r = auth.refresh(token2)
    logger.info("order ban->refresh: token=%s reason=%s", new2, r)
    assert new2 is None and r is FailureReason.ACCOUNT_DISABLED
    auth.unban_user("bob")
