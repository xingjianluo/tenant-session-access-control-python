"""认证与会话生命周期：登录、续期（令牌轮换）、注销、撤销。

并发语义：
- 续期的"校验旧令牌 + 轮换"在 store.lock 内原子完成，
  同一旧令牌的并发续期只有一个能成功，其余得到 TOKEN_REPLAYED。
- 旧令牌在 token_index 中保留映射，重放旧凭据可被识别并拒绝，
  且不会生成新会话、不会延长有效期。
"""
from __future__ import annotations

import secrets
import time
import uuid
from collections.abc import Callable

from .models import FailureReason, Session
from .store import InMemoryStore


class AuthService:
    def __init__(
        self,
        store: InMemoryStore,
        session_ttl: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._ttl = session_ttl
        self._clock = clock

    # ---- 登录 ----

    def login(self, user_id: str, password: str) -> tuple[str | None, FailureReason | None]:
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is None or user.password != password:
                return None, FailureReason.BAD_CREDENTIALS
            if user.disabled:
                return None, FailureReason.ACCOUNT_DISABLED
            session = Session(
                session_id=uuid.uuid4().hex,
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                token=secrets.token_hex(16),
                expires_at=self._clock() + self._ttl,
            )
            self._store.save_session(session)
            return session.token, None

    # ---- 续期（令牌轮换） ----

    def refresh(self, token: str) -> tuple[str | None, FailureReason | None]:
        with self._store.lock:
            session, reason = self._check_token(token)
            if reason is not None:
                return None, reason
            assert session is not None
            # 原地轮换：旧令牌失效但仍可解释，新令牌指向同一会话。
            session.token = secrets.token_hex(16)
            session.expires_at = self._clock() + self._ttl
            session.rotation += 1
            self._store.save_session(session)
            return session.token, None

    # ---- 注销 / 撤销 ----

    def logout(self, token: str) -> FailureReason | None:
        with self._store.lock:
            session = self._store.find_session_by_token(token)
            if session is None:
                return FailureReason.SESSION_NOT_FOUND
            session.revoked = True
            return None

    def revoke_user_sessions(self, user_id: str) -> int:
        """撤销某用户的全部会话（如账号被禁用时调用）。"""
        with self._store.lock:
            sessions = self._store.sessions_of_user(user_id)
            for s in sessions:
                s.revoked = True
            return len(sessions)

    # ---- 校验 ----

    def validate(self, token: str) -> tuple[Session | None, FailureReason | None]:
        with self._store.lock:
            return self._check_token(token)

    # ---- 内部：统一的令牌判定，保证各入口原因一致 ----

    def _check_token(self, token: str) -> tuple[Session | None, FailureReason | None]:
        session = self._store.find_session_by_token(token)
        if session is None:
            return None, FailureReason.SESSION_NOT_FOUND
        if session.revoked:
            return None, FailureReason.SESSION_REVOKED
        if session.expires_at <= self._clock():
            return None, FailureReason.SESSION_EXPIRED
        if session.token != token:
            # 令牌曾有效但已被轮换：旧凭据重放。
            return None, FailureReason.TOKEN_REPLAYED
        return session, None
