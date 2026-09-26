"""基于租户与角色的访问判定。

RequestContext 在构造时对用户的角色与租户归属做快照，
同一次请求处理期间的多次判定都基于该快照，
即使中途角色/租户发生变化，也不会得到相互矛盾的结论。
"""
from __future__ import annotations

from dataclasses import dataclass

from app.models import FailureReason, Session
from app.store import Store

# 角色 -> 权限集合；不在任何集合中的权限视为未知权限
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "reader": frozenset({"doc:read"}),
    "writer": frozenset({"doc:read", "doc:write"}),
    "admin": frozenset({"doc:read", "doc:write", "doc:delete", "user:manage"}),
}

ALL_PERMISSIONS: frozenset[str] = frozenset().union(*ROLE_PERMISSIONS.values())


@dataclass(frozen=True)
class AuthzDecision:
    allowed: bool
    reason: FailureReason | None = None


class RequestContext:
    """一次请求处理期间的稳定授权视图（构造时快照）。"""

    def __init__(self, store: Store, session: Session) -> None:
        user = store.get_user(session.user_id)
        self._tenant_id = session.tenant_id
        self._roles: frozenset[str] = frozenset(user.roles) if user else frozenset()
        self._permissions: frozenset[str] = frozenset().union(
            *(ROLE_PERMISSIONS[r] for r in self._roles if r in ROLE_PERMISSIONS)
        ) if self._roles else frozenset()

    def authorize(self, tenant_id: str, permission: str) -> AuthzDecision:
        if permission not in ALL_PERMISSIONS:
            return AuthzDecision(False, FailureReason.UNKNOWN_PERMISSION)
        if tenant_id != self._tenant_id:
            return AuthzDecision(False, FailureReason.CROSS_TENANT)
        if permission not in self._permissions:
            return AuthzDecision(False, FailureReason.FORBIDDEN)
        return AuthzDecision(True)
