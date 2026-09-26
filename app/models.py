"""领域模型与可区分的失败原因定义。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Role(enum.Enum):
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class Permission(enum.Enum):
    READ = "read"
    WRITE = "write"
    MANAGE_USERS = "manage_users"


class FailureReason(enum.Enum):
    """所有被拒绝操作的可区分原因。"""

    ACCOUNT_DISABLED = "account_disabled"
    BAD_CREDENTIALS = "bad_credentials"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    TOKEN_REPLAYED = "token_replayed"
    SESSION_NOT_FOUND = "session_not_found"
    CROSS_TENANT = "cross_tenant"
    PERMISSION_DENIED = "permission_denied"
    UNKNOWN_PERMISSION = "unknown_permission"


@dataclass(frozen=True)
class User:
    user_id: str
    tenant_id: str
    password: str
    disabled: bool = False
    roles: frozenset[Role] = field(default_factory=frozenset)


@dataclass
class Session:
    session_id: str
    user_id: str
    tenant_id: str
    token: str
    expires_at: float
    revoked: bool = False
    rotation: int = 0
