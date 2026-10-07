"""公共夹具：可推进的假时钟、内存存储、演示账号。"""
from __future__ import annotations

import logging

import pytest

from app.access import AccessControl
from app.auth import AuthService
from app.models import Role, User
from app.store import InMemoryStore

logger = logging.getLogger("test")


class FakeClock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def store() -> InMemoryStore:
    s = InMemoryStore()
    s.add_user(User("alice", "tenant-a", "pw-alice", roles=frozenset({Role.ADMIN})))
    s.add_user(User("bob", "tenant-a", "pw-bob", roles=frozenset({Role.MEMBER})))
    s.add_user(User("carol", "tenant-b", "pw-carol", roles=frozenset({Role.VIEWER})))
    s.add_user(User("dave", "tenant-a", "pw-dave", disabled=True,
                    roles=frozenset({Role.MEMBER})))
    return s


@pytest.fixture()
def auth(store: InMemoryStore, clock: FakeClock) -> AuthService:
    return AuthService(store, session_ttl=100.0, clock=clock)


@pytest.fixture()
def access(store: InMemoryStore) -> AccessControl:
    return AccessControl(store)


# ---- 场景日志：让运行输出能看出覆盖了哪些用例及每个用例的结果 ----


def pytest_runtest_logstart(nodeid, location):
    logger.info(">>>> 场景用例开始: %s", nodeid)


def pytest_runtest_logreport(report):
    if report.when == "call":
        logger.info("<<<< 场景用例结果: %s -> %s", report.nodeid,
                    report.outcome.upper())
