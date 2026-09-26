"""领域模型与失败原因定义（骨架）。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class FailureReason(enum.Enum):
    """可区分的失败原因。"""

    ACCOUNT_DISABLED = "account_disabled"
    BAD_CREDENTIALS = "bad_credentials"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    SESSION_NOT_FOUND = "session_not_found"
    TOKEN_REUSED = "token_reused"
    CROSS_TENANT = "cross_tenant"
    FORBIDDEN = "forbidden"
    UNKNOWN_PERMISSION = "unknown_permission"


@dataclass(frozen=True)
class User:
    user_id: str
    tenant_id: str
    password: str
    roles: frozenset[str] = field(default_factory=frozenset)
    disabled: bool = False


@dataclass
class Session:
    session_id: str
    user_id: str
    tenant_id: str
    token: str
    expires_at: float
    revoked: bool = False
    successor_id: str | None = None
