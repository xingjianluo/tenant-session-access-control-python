"""访问判定：角色权限、跨租户拒绝、未知权限、请求中途变化的稳定视图。"""
from __future__ import annotations

import logging

from app.models import FailureReason, Role

logger = logging.getLogger("test")


def test_role_permissions(access):
    ctx_admin = access.begin_request("alice")
    ctx_member = access.begin_request("bob")
    ctx_viewer = access.begin_request("carol")

    assert access.check(ctx_admin, "tenant-a", "manage_users") is None
    assert access.check(ctx_member, "tenant-a", "write") is None

    reason = access.check(ctx_viewer, "tenant-b", "write")
    logger.info("viewer write -> reason=%s", reason)
    assert reason is FailureReason.PERMISSION_DENIED
    assert access.check(ctx_viewer, "tenant-b", "read") is None


def test_cross_tenant_denied(access):
    ctx = access.begin_request("alice")  # tenant-a 的管理员
    reason = access.check(ctx, "tenant-b", "read")
    logger.info("admin of tenant-a reads tenant-b -> reason=%s", reason)
    assert reason is FailureReason.CROSS_TENANT
    # 即使拥有该权限，跨租户也优先被拒绝
    reason = access.check(ctx, "tenant-b", "manage_users")
    assert reason is FailureReason.CROSS_TENANT


def test_unknown_permission(access):
    ctx = access.begin_request("alice")
    reason = access.check(ctx, "tenant-a", "delete_everything")
    logger.info("unknown permission -> reason=%s", reason)
    assert reason is FailureReason.UNKNOWN_PERMISSION


def test_mid_request_role_change_uses_stable_snapshot(access, store):
    ctx = access.begin_request("alice")
    before = access.check(ctx, "tenant-a", "manage_users")
    # 请求处理中途：alice 被降级为 VIEWER
    store.set_roles("alice", frozenset({Role.VIEWER}))
    after = access.check(ctx, "tenant-a", "manage_users")
    logger.info("same request before=%s after=%s (must be identical)", before, after)
    assert before is None and after is None  # 同一请求内结论一致

    # 新请求基于最新角色，得到不同结论——这是允许的
    ctx2 = access.begin_request("alice")
    reason = access.check(ctx2, "tenant-a", "manage_users")
    logger.info("new request after demotion -> reason=%s", reason)
    assert reason is FailureReason.PERMISSION_DENIED


def test_mid_request_tenant_change_uses_stable_snapshot(access, store):
    ctx = access.begin_request("bob")  # tenant-a
    # 请求中途 bob 被迁到 tenant-b
    user = store.get_user("bob")
    store.add_user(type(user)(user.user_id, "tenant-b", user.password,
                              roles=frozenset({Role.MEMBER})))
    same_req = access.check(ctx, "tenant-a", "write")
    logger.info("same request after tenant move -> reason=%s", same_req)
    assert same_req is None  # 仍按快照中的 tenant-a 判定，结论不矛盾

    ctx2 = access.begin_request("bob")
    assert access.check(ctx2, "tenant-a", "write") is FailureReason.CROSS_TENANT
    assert access.check(ctx2, "tenant-b", "write") is None
