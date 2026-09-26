"""会话生命周期：登录、续期（令牌轮换）、注销、撤销。

并发语义：续期的"校验旧令牌 + 轮换为新会话"在 store.lock 下原子完成，
因此并发续期只会产生一个后继会话；旧令牌重放被 TOKEN_REUSED 拒绝，
且不会生成新会话、不会延长任何有效期。
"""
from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass

from app.clock import Clock
from app.models import FailureReason, Session
from app.store import Store


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    session: Session | None = None
    reason: FailureReason | None = None


class SessionService:
    def __init__(self, store: Store, clock: Clock, ttl_seconds: float = 300.0) -> None:
        self._store = store
        self._clock = clock
        self._ttl = ttl_seconds
        self._seq = itertools.count(1)

    # ---- 内部 ----
    def _new_session(self, user_id: str, tenant_id: str) -> Session:
        return Session(
            session_id=f"sess-{next(self._seq)}",
            user_id=user_id,
            tenant_id=tenant_id,
            token=uuid.uuid4().hex,
            expires_at=self._clock.now() + self._ttl,
        )

    def _check(self, session: Session | None) -> FailureReason | None:
        """对会话做有效性检查，返回 None 表示可用。调用方须持有 store.lock。"""
        if session is None:
            return FailureReason.SESSION_NOT_FOUND
        if session.revoked:
            # 已被轮换（有后继）与主动撤销可区分
            return FailureReason.TOKEN_REUSED if session.successor_id else FailureReason.SESSION_REVOKED
        if self._clock.now() >= session.expires_at:
            return FailureReason.SESSION_EXPIRED
        user = self._store.get_user(session.user_id)
        if user is not None and user.disabled:
            return FailureReason.ACCOUNT_DISABLED
        return None

    # ---- 生命周期 ----
    def login(self, user_id: str, password: str) -> AuthResult:
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is not None and user.disabled:
                return AuthResult(False, reason=FailureReason.ACCOUNT_DISABLED)
            if user is None or user.password != password:
                return AuthResult(False, reason=FailureReason.BAD_CREDENTIALS)
            session = self._new_session(user.user_id, user.tenant_id)
            self._store.put_session(session)
            return AuthResult(True, session=session)

    def authenticate(self, token: str) -> AuthResult:
        with self._store.lock:
            session = self._store.get_session_by_token(token)
            reason = self._check(session)
            if reason is not None:
                return AuthResult(False, session=session, reason=reason)
            return AuthResult(True, session=session)

    def refresh(self, token: str) -> AuthResult:
        with self._store.lock:  # 校验+轮换原子化：并发下只有一个成功
            old = self._store.get_session_by_token(token)
            reason = self._check(old)
            if reason is not None:
                # 重放/过期/撤销：不产生新会话，不延长有效期，状态保留可解释
                return AuthResult(False, session=old, reason=reason)
            new = self._new_session(old.user_id, old.tenant_id)
            old.revoked = True
            old.successor_id = new.session_id
            self._store.put_session(new)
            return AuthResult(True, session=new)

    def logout(self, token: str) -> AuthResult:
        with self._store.lock:
            session = self._store.get_session_by_token(token)
            if session is None:
                return AuthResult(False, reason=FailureReason.SESSION_NOT_FOUND)
            session.revoked = True
            return AuthResult(True, session=session)

    def revoke_user_sessions(self, user_id: str) -> int:
        with self._store.lock:
            targets = self._store.sessions_of_user(user_id)
            for s in targets:
                s.revoked = True
            return len(targets)
