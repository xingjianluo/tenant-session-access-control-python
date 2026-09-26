"""访问判定：跨租户、越权、未知权限拒绝；请求内稳定视图不产生矛盾结论。"""
from app.authz import RequestContext
from app.models import FailureReason
from tests.conftest import log


def _login_ctx(svc, store, user_id, password):
    r = svc.login(user_id, password)
    assert r.ok
    return RequestContext(store, r.session)


def test_cross_tenant_denied(svc, store):
    ctx = _login_ctx(svc, store, "carol", "carol-pw")  # carol 属于 tenant-b
    log.info("输入: carol(tenant-b, writer) 访问 tenant-a 的 doc:read")
    d = ctx.authorize("tenant-a", "doc:read")
    log.info("观察: allowed=%s reason=%s", d.allowed, d.reason)
    assert not d.allowed and d.reason is FailureReason.CROSS_TENANT
    # 本租户内正常放行
    assert ctx.authorize("tenant-b", "doc:write").allowed


def test_privilege_escalation_denied(svc, store):
    ctx = _login_ctx(svc, store, "bob", "bob-pw")  # reader
    log.info("输入: bob(reader) 执行 doc:write / doc:delete / user:manage")
    for perm in ("doc:write", "doc:delete", "user:manage"):
        d = ctx.authorize("tenant-a", perm)
        log.info("观察: %s -> %s", perm, d.reason)
        assert d.reason is FailureReason.FORBIDDEN
    assert ctx.authorize("tenant-a", "doc:read").allowed


def test_unknown_permission_denied(svc, store):
    ctx = _login_ctx(svc, store, "alice", "alice-pw")  # admin 也不能用未知权限
    log.info("输入: alice(admin) 使用未知权限 doc:fly")
    d = ctx.authorize("tenant-a", "doc:fly")
    log.info("观察: allowed=%s reason=%s", d.allowed, d.reason)
    assert d.reason is FailureReason.UNKNOWN_PERMISSION


def test_stable_view_during_request(svc, store):
    ctx = _login_ctx(svc, store, "bob", "bob-pw")  # reader
    before = ctx.authorize("tenant-a", "doc:write")
    log.info("请求内第一次判定: doc:write -> %s", before.reason)
    assert before.reason is FailureReason.FORBIDDEN

    log.info("状态变化: 请求处理中途将 bob 提升为 admin")
    store.set_user_roles("bob", frozenset({"admin"}))

    after = ctx.authorize("tenant-a", "doc:write")
    log.info("观察: 同一请求内再次判定 doc:write -> %s", after.reason)
    assert after.reason is FailureReason.FORBIDDEN, "请求内视图必须稳定，不得前后矛盾"
    assert before.allowed == after.allowed and before.reason == after.reason

    ctx2 = _login_ctx(svc, store, "bob", "bob-pw")  # 新请求 = 新视图
    d = ctx2.authorize("tenant-a", "doc:write")
    log.info("观察: 新请求判定 doc:write -> allowed=%s", d.allowed)
    assert d.allowed, "新请求应看到最新角色"


def test_stable_view_on_downgrade(svc, store):
    ctx = _login_ctx(svc, store, "alice", "alice-pw")  # admin
    assert ctx.authorize("tenant-a", "user:manage").allowed

    log.info("状态变化: 请求处理中途将 alice 降级为 reader")
    store.set_user_roles("alice", frozenset({"reader"}))

    d = ctx.authorize("tenant-a", "user:manage")
    log.info("观察: 同一请求内 user:manage -> allowed=%s", d.allowed)
    assert d.allowed, "请求内仍基于快照，结论一致"

    ctx2 = _login_ctx(svc, store, "alice", "alice-pw")
    d2 = ctx2.authorize("tenant-a", "user:manage")
    assert d2.reason is FailureReason.FORBIDDEN
    log.info("判定依据: 快照保证请求内一致，新请求反映降级结果=%s", d2.reason)
