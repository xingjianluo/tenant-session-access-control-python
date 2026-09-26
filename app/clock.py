"""可控时钟：默认单调递增，测试可手动推进，保证离线可重复。"""
from __future__ import annotations

import threading


class Clock:
    """线程安全的手动时钟，从 start 开始，只能显式推进。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = start
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("时钟不能倒退")
        with self._lock:
            self._now += seconds
