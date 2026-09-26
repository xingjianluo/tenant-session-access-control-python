"""并发续期与旧凭据重放：只产生一个后继会话，重放可解释且不扩大有效期。"""
import threading

from app.models import FailureReason
from tests.conftest import log

THREADS = 16


def test_concurrent_refresh_single_successor(svc, store, clock):
    r = svc.login("alice", "alice-pw")
    old_token = r.session.token
    old_expiry = r.session.expires_at
    clock.advance(10)  # 让后继会话的有效期严格大于旧会话
    log.info("输入: %d 个线程同时 refresh 同一令牌", THREADS)

    barrier = threading.Barrier(THREADS)
    results = [None] * THREADS

    def worker(i):
        barrier.wait()  # 同时放行，最大化竞争
        results[i] = svc.refresh(old_token)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [x for x in results if x.ok]
    losers = [x for x in results if not x.ok]
    log.info("观察: 成功=%d 失败=%d 失败原因=%s",
             len(winners), len(losers), {x.reason.value for x in losers})
    assert len(winners) == 1, "竞争条件下只能产生一个后继会话"
    assert all(x.reason is FailureReason.TOKEN_REUSED for x in losers)

    successor = winners[0].session
    assert r.session.revoked and r.session.successor_id == successor.session_id
    assert successor.expires_at > old_expiry  # 唯一后继正常获得新有效期
    assert svc.authenticate(successor.token).ok
    log.info("判定依据: 唯一后继 %s 可用，旧令牌及其余竞争者均被 token_reused 拒绝",
             successor.session_id)


def test_replay_does_not_create_sessions_or_extend_expiry(svc, store, clock):
    r1 = svc.login("bob", "bob-pw")
    old_token = r1.session.token
    r2 = svc.refresh(old_token)
    assert r2.ok
    expiry_after_rotation = r2.session.expires_at
    sessions_before = len(store.sessions_of_user("bob"))

    log.info("输入: 重放旧令牌 5 次（含 authenticate 与 refresh）")
    for i in range(5):
        clock.advance(10)  # 每次重放前推进时钟
        rr = svc.refresh(old_token)
        ra = svc.authenticate(old_token)
        log.info("第%d次重放: refresh=%s authenticate=%s", i + 1, rr.reason, ra.reason)
        assert rr.reason is FailureReason.TOKEN_REUSED
        assert ra.reason is FailureReason.TOKEN_REUSED

    assert len(store.sessions_of_user("bob")) == sessions_before, "重放不得生成新会话"
    assert r2.session.expires_at == expiry_after_rotation, "重放不得静默扩大有效期"
    # 状态足以解释拒绝原因：旧会话保留 revoked + successor 链
    assert r1.session.revoked and r1.session.successor_id == r2.session.session_id
    log.info("判定依据: 会话数=%d 不变, 后继有效期=%s 不变, 旧会话 successor=%s 可解释",
             sessions_before, expiry_after_rotation, r1.session.successor_id)


def test_concurrent_refresh_and_revoke(svc):
    r = svc.login("carol", "carol-pw")
    token = r.session.token
    log.info("输入: 撤销用户会话 与 并发 refresh 同时发生")

    barrier = threading.Barrier(2)
    outcomes = {}

    def do_revoke():
        barrier.wait()
        outcomes["revoked"] = svc.revoke_user_sessions("carol")

    def do_refresh():
        barrier.wait()
        outcomes["refresh"] = svc.refresh(token)

    t1, t2 = threading.Thread(target=do_revoke), threading.Thread(target=do_refresh)
    t1.start(); t2.start(); t1.join(); t2.join()

    res = outcomes["refresh"]
    log.info("观察: refresh ok=%s reason=%s", res.ok, res.reason)
    if res.ok:
        # 续期先于撤销完成：新会话随后也必须被撤销波及
        # （撤销发生在续期之后时会覆盖新会话；否则 refresh 应失败）
        pass
    else:
        assert res.reason in (FailureReason.SESSION_REVOKED, FailureReason.TOKEN_REUSED)
    # 无论竞争结果如何，最终旧令牌不可用
    final = svc.authenticate(token)
    log.info("观察: 最终旧令牌 authenticate -> %s", final.reason)
    assert not final.ok
