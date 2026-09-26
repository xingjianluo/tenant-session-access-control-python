"""基于租户与角色的访问判定。

稳定视图：每次请求开始时调用 begin_request() 捕获调用者的
租户归属与角色快照；请求处理期间即使角色或租户归属被修改，
后续判定仍基于快照，同一请求内不会得到相互矛盾的结论。
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import FailureReason, Permission, Role
from .store import InMemoryStore

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset({Permission.READ, Permission.WRITE, Permission.MANAGE_USERS}),
    Role.MEMBER: frozenset({Permission.READ, Permission.WRITE}),
    Role.VIEWER: frozenset({Permission.READ}),
}


@dataclass(frozen=True)
class RequestContext:
    """单次请求的授权快照，创建后不可变。"""

    user_id: str
    tenant_id: str
    roles: frozenset[Role]

    @property
    def permissions(self) -> frozenset[Permission]:
        result: set[Permission] = set()
        for role in self.roles:
            result |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(result)


class AccessControl:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def begin_request(self, user_id: str) -> RequestContext | None:
        """在请求入口捕获快照；用户不存在时返回 None。"""
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is None:
                return None
            return RequestContext(
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                roles=self._store.get_roles(user_id),
            )

    def check(
        self, ctx: RequestContext, tenant_id: str, permission: str
    ) -> FailureReason | None:
        """返回 None 表示允许，否则返回可区分的拒绝原因。"""
        try:
            perm = Permission(permission)
        except ValueError:
            return FailureReason.UNKNOWN_PERMISSION
        if ctx.tenant_id != tenant_id:
            return FailureReason.CROSS_TENANT
        if perm not in ctx.permissions:
            return FailureReason.PERMISSION_DENIED
        return None
