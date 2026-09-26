import logging

import pytest

from app.clock import Clock
from app.models import User
from app.sessions import SessionService
from app.store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TEST] %(message)s")
log = logging.getLogger("test")


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store() -> Store:
    s = Store()
    s.add_user(User("alice", "tenant-a", "alice-pw", frozenset({"admin"})))
    s.add_user(User("bob", "tenant-a", "bob-pw", frozenset({"reader"})))
    s.add_user(User("carol", "tenant-b", "carol-pw", frozenset({"writer"})))
    return s


@pytest.fixture
def svc(store, clock) -> SessionService:
    return SessionService(store, clock, ttl_seconds=100.0)
