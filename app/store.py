"""线程安全的内存存储：用户、角色、会话与令牌轮换状态。"""
from __future__ import annotations

import threading

from .models import Role, Session, User


class InMemoryStore:
    """集中保存所有可变状态。

    所有读写都在同一把可重入锁内完成，使"检查-修改"序列
    （如续期时的令牌轮换）在并发下是原子的。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._roles: dict[str, frozenset[Role]] = {}
        self._sessions: dict[str, Session] = {}
        # token -> session_id，旧令牌在轮换后仍保留映射，
        # 以便重放旧凭据时能给出"已轮换/重放"而非"不存在"。
        self._token_index: dict[str, str] = {}

    # ---- 用户与角色 ----

    def add_user(self, user: User) -> None:
        with self._lock:
            self._users[user.user_id] = user
            self._roles[user.user_id] = frozenset(user.roles)

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            return self._users.get(user_id)

    def set_disabled(self, user_id: str, disabled: bool) -> None:
        with self._lock:
            user = self._users[user_id]
            self._users[user_id] = User(
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                password=user.password,
                disabled=disabled,
                banned=user.banned,
                roles=user.roles,
            )

    def set_banned(self, user_id: str, banned: bool) -> None:
        """置账号封禁标记，不动会话。

        封禁时的会话撤销由 AuthService.ban_account 在同一把锁内
        一起完成；解封刻意不恢复任何会话，封禁前的老会话必须
        保持撤销状态，用户需要重新登录。
        """
        with self._lock:
            user = self._users[user_id]
            self._users[user_id] = User(
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                password=user.password,
                disabled=user.disabled,
                banned=banned,
                roles=user.roles,
            )

    def get_roles(self, user_id: str) -> frozenset[Role]:
        with self._lock:
            return self._roles.get(user_id, frozenset())

    def set_roles(self, user_id: str, roles: frozenset[Role]) -> None:
        with self._lock:
            self._roles[user_id] = frozenset(roles)

    # ---- 会话 ----

    def save_session(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
            self._token_index[session.token] = session.session_id

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def find_session_by_token(self, token: str) -> Session | None:
        with self._lock:
            session_id = self._token_index.get(token)
            if session_id is None:
                return None
            return self._sessions.get(session_id)

    def sessions_of_user(self, user_id: str) -> list[Session]:
        with self._lock:
            return [s for s in self._sessions.values() if s.user_id == user_id]

    # ---- 锁的受控暴露：供 AuthService 做复合原子操作 ----

    @property
    def lock(self) -> threading.RLock:
        return self._lock
