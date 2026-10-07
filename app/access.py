"""基于租户与角色的访问判定。

稳定视图：每次请求开始时调用 begin_request() 捕获调用者的
租户归属与角色快照；请求处理期间即使角色或租户归属被修改，
后续判定仍基于快照，同一请求内不会得到相互矛盾的结论。

原子授权：authorize() 把"令牌校验 → 建快照 → 权限判定"放在
store.lock 内一次完成，使封禁/续期与授权判定线性化：封禁提交后
排队的判定必然得到 account_disabled，不会出现封禁已生效却放行。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import FailureReason, Permission, Role
from .store import InMemoryStore

if TYPE_CHECKING:
    from .auth import AuthService

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

    def authorize(
        self,
        auth: AuthService,
        token: str,
        tenant_id: str,
        permission: str,
    ) -> tuple[RequestContext | None, FailureReason | None]:
        """原子地完成凭据校验与访问判定。

        全过程持有 store.lock（RLock，可与内部方法重入），因此与
        ban_user/refresh/logout 互斥：要么在封禁提交前完成判定，
        要么看到封禁态并拒绝，二者必居其一。
        """
        with self._store.lock:
            session, reason = auth.validate(token)
            if reason is not None:
                return None, reason
            ctx = self.begin_request(session.user_id)
            if ctx is None:
                return None, FailureReason.USER_NOT_FOUND
            return ctx, self.check(ctx, tenant_id, permission)
