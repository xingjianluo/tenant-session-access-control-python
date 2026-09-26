"""线程安全的内存存储：用户与会话，含 token 索引。"""
from __future__ import annotations

import dataclasses
import threading

from app.models import Session, User


class Store:
    """所有读写在同一把可重入锁下进行，便于上层做原子复合操作。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._token_index: dict[str, str] = {}  # token -> session_id

    # ---- 用户 ----
    def add_user(self, user: User) -> None:
        with self.lock:
            self._users[user.user_id] = user

    def get_user(self, user_id: str) -> User | None:
        with self.lock:
            return self._users.get(user_id)

    def set_user_disabled(self, user_id: str, disabled: bool) -> None:
        with self.lock:
            user = self._users[user_id]
            self._users[user_id] = dataclasses.replace(user, disabled=disabled)

    def set_user_roles(self, user_id: str, roles: frozenset[str]) -> None:
        with self.lock:
            user = self._users[user_id]
            self._users[user_id] = dataclasses.replace(user, roles=roles)

    # ---- 会话 ----
    def put_session(self, session: Session) -> None:
        with self.lock:
            self._sessions[session.session_id] = session
            self._token_index[session.token] = session.session_id

    def get_session(self, session_id: str) -> Session | None:
        with self.lock:
            return self._sessions.get(session_id)

    def get_session_by_token(self, token: str) -> Session | None:
        with self.lock:
            sid = self._token_index.get(token)
            return self._sessions.get(sid) if sid is not None else None

    def sessions_of_user(self, user_id: str) -> list[Session]:
        with self.lock:
            return [s for s in self._sessions.values() if s.user_id == user_id]
