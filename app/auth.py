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
            if user.banned:
                return None, FailureReason.ACCOUNT_BANNED
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

    # ---- 封禁 / 解封（后台管控口子） ----

    def ban_account(self, user_id: str) -> bool:
        """封禁账号并立即撤销其全部会话。

        置封禁标记与撤销会话在同一把锁内完成，因此与并发续期、
        判定串行：封禁生效后，任何旧凭据/新凭据的 refresh、
        validate、logout 都立即得到 ACCOUNT_BANNED。
        账号不存在返回 False；重复封禁返回 True 且为幂等操作。
        """
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is None:
                return False
            self._store.set_banned(user_id, True)
            for s in self._store.sessions_of_user(user_id):
                s.revoked = True
            return True

    def unban_account(self, user_id: str) -> bool:
        """解封账号；刻意不恢复任何老会话，必须重新登录。"""
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is None:
                return False
            self._store.set_banned(user_id, False)
            return True

    # ---- 注销 / 撤销 ----

    def logout(self, token: str) -> FailureReason | None:
        with self._store.lock:
            session, reason = self._check_token(token)
            if reason is not None:
                # 只读拒绝：绝不修改现状。
                # 拿轮换后作废的旧凭据/已注销凭据/被封账号的凭据来注销，
                # 都在这里被拒，且不会碰到当前真正在用的那条会话。
                return reason
            assert session is not None
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
        # 封禁优先于一切会话状态：即使凭据本身仍有效也一律拦截，
        # 且原因与"密码错误/会话过期/已撤销"可区分。
        user = self._store.get_user(session.user_id)
        if user is not None and user.banned:
            return None, FailureReason.ACCOUNT_BANNED
        if session.revoked:
            return None, FailureReason.SESSION_REVOKED
        if session.expires_at <= self._clock():
            return None, FailureReason.SESSION_EXPIRED
        if session.token != token:
            # 令牌曾有效但已被轮换：旧凭据重放。
            return None, FailureReason.TOKEN_REPLAYED
        return session, None
