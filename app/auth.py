"""认证与会话生命周期：登录、续期（令牌轮换）、注销、撤销、封禁/解封。

并发语义：
- 续期的"校验旧令牌 + 轮换"在 store.lock 内原子完成，
  同一旧令牌的并发续期只有一个能成功，其余得到 TOKEN_REPLAYED。
- 旧令牌在 token_index 中保留映射，重放旧凭据可被识别并拒绝，
  且不会生成新会话、不会延长有效期。

账号封禁语义：
- ban_user 与续期/判定/注销在同一把锁内串行化，封禁一旦提交，
  任何在其后排队的操作都必然看到封禁态（ACCOUNT_DISABLED），
  不会出现"封禁已生效却换到了新凭据/判定仍放行"。
- 封禁时撤销该账号全部已有会话，且解封不会清除这些撤销标记，
  因此封禁前的老会话在解封后仍然不可用，必须重新登录。
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
        """作废当前凭据对应的会话。

        作废凭据（已轮换的旧令牌、已注销、已过期、账号已封）只做只读拒绝，
        绝不触碰当前真正有效的会话：例如持轮换后的旧令牌注销，不会把
        正在使用的新凭据连带撤销。
        """
        with self._store.lock:
            _, reason = self._check_token(token)
            if reason is not None:
                return reason
            session = self._store.find_session_by_token(token)
            assert session is not None and session.token == token
            session.revoked = True
            return None

    def revoke_user_sessions(self, user_id: str) -> int:
        """撤销某用户的全部会话（如账号被封禁时调用）。

        返回本次新撤销（revoked 由 False 翻为 True）的会话数，
        已撤销的会话不重复计数。
        """
        with self._store.lock:
            sessions = self._store.sessions_of_user(user_id)
            revoked = 0
            for s in sessions:
                if not s.revoked:
                    s.revoked = True
                    revoked += 1
            return revoked

    # ---- 后台封禁 / 解封 ----

    def ban_user(self, user_id: str) -> tuple[int | None, FailureReason | None]:
        """封禁账号：置封禁态并撤销其全部已有会话。

        返回被撤销的会话数。封禁是幂等的：重复封禁仍成功，
        且会把封禁期间建立的会话也一并撤销（正常流程下登录已被拦截）。
        """
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is None:
                return None, FailureReason.USER_NOT_FOUND
            if not user.disabled:
                self._store.set_disabled(user_id, True)
            revoked = self.revoke_user_sessions(user_id)
            return revoked, None

    def unban_user(self, user_id: str) -> FailureReason | None:
        """解封账号；封禁前被撤销的老会话不会因此复活，需重新登录。"""
        with self._store.lock:
            user = self._store.get_user(user_id)
            if user is None:
                return FailureReason.USER_NOT_FOUND
            if user.disabled:
                self._store.set_disabled(user_id, False)
            return None

    # ---- 校验 ----

    def validate(self, token: str) -> tuple[Session | None, FailureReason | None]:
        with self._store.lock:
            return self._check_token(token)

    # ---- 内部：统一的令牌判定，保证各入口原因一致 ----

    def _check_token(self, token: str) -> tuple[Session | None, FailureReason | None]:
        session = self._store.find_session_by_token(token)
        if session is None:
            return None, FailureReason.SESSION_NOT_FOUND
        user = self._store.get_user(session.user_id)
        if user is not None and user.disabled:
            # 账号封禁对一切入口立即生效，原因与密码错误/会话过期可区分。
            return None, FailureReason.ACCOUNT_DISABLED
        if session.revoked:
            return None, FailureReason.SESSION_REVOKED
        if session.expires_at <= self._clock():
            return None, FailureReason.SESSION_EXPIRED
        if session.token != token:
            # 令牌曾有效但已被轮换：旧凭据重放。
            return None, FailureReason.TOKEN_REPLAYED
        return session, None
