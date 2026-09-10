"""Event log shared by the whole simulation.

Kept as structured records rather than formatted strings so the dashboard,
the CLI's `show logging`, and stdout can each render them differently.
"""

from __future__ import annotations

import sys
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable

LEVELS = {"debug": 10, "info": 20, "notice": 25, "warn": 30, "error": 40}

COLORS = {
    "debug": "\x1b[90m", "info": "", "notice": "\x1b[36m",
    "warn": "\x1b[33m", "error": "\x1b[31m",
}
RESET = "\x1b[0m"
BOLD = "\x1b[1m"

SOURCE_COLORS = {
    "cmts": "\x1b[35m", "plant": "\x1b[90m", "prov": "\x1b[34m",
    "lab": "\x1b[37m",
}


@dataclass
class Event:
    """One log record: when, from where, and what happened."""
    time: float
    source: str
    level: str
    category: str
    message: str
    #: Monotonically increasing, so a dashboard can ask for "everything
    #: since sequence N" without missing or repeating lines.
    seq: int = 0

    def format(self, color: bool = False, width: int = 0) -> str:
        stamp = f"{self.time:9.6f}"
        src = f"{self.source:<7}"
        cat = f"{self.category:<10}"
        if color:
            sc = SOURCE_COLORS.get(self.source, "\x1b[32m")
            lc = COLORS.get(self.level, "")
            line = (f"\x1b[90m{stamp}{RESET} {sc}{src}{RESET} "
                    f"\x1b[90m{cat}{RESET} {lc}{self.message}{RESET}")
        else:
            line = f"{stamp} {src} {cat} {self.message}"
        return line


class EventLog:
    """Ring buffer of events, shared by every component."""
    def __init__(self, capacity: int = 20000, now: Callable[[], float] | None = None):
        self.events: deque[Event] = deque(maxlen=capacity)
        self._now = now or (lambda: 0.0)
        self.echo = False
        self.echo_level = "info"
        self.color = sys.stdout.isatty()
        self.min_level = "debug"
        #: Categories suppressed from the echo, e.g. the per-MAP chatter.
        self.mute: set[str] = set()
        self.subscribers: list[Callable[[Event], None]] = []
        self.counts: dict[str, int] = {}
        self._seq = 0

    @property
    def last_seq(self) -> int:
        return self._seq

    def since(self, seq: int, limit: int = 500) -> list[Event]:
        return [e for e in self.events if e.seq > seq][-limit:]

    def log(self, source: str, level: str, category: str, message: str) -> Event:
        self._seq += 1
        ev = Event(self._now(), source, level, category, message, seq=self._seq)
        self.events.append(ev)
        self.counts[level] = self.counts.get(level, 0) + 1
        if (self.echo and LEVELS[level] >= LEVELS[self.echo_level]
                and category not in self.mute):
            print(ev.format(self.color), flush=True)
        for sub in list(self.subscribers):
            try:
                sub(ev)
            except Exception:
                pass
        return ev

    def tail(self, n: int = 40, source: str | None = None,
             category: str | None = None, level: str | None = None) -> list[Event]:
        out: Iterable[Event] = self.events
        if source:
            out = [e for e in out if e.source == source]
        if category:
            out = [e for e in out if e.category == category]
        if level:
            floor = LEVELS[level]
            out = [e for e in out if LEVELS[e.level] >= floor]
        out = list(out)
        return out[-n:]

    def logger(self, source: str) -> "SourceLogger":
        return SourceLogger(self, source)


class SourceLogger:
    """A view of the log bound to one component, so call sites stay short."""

    __slots__ = ("_log", "source")

    def __init__(self, log: EventLog, source: str):
        self._log = log
        self.source = source

    def debug(self, category: str, message: str) -> None:
        self._log.log(self.source, "debug", category, message)

    def info(self, category: str, message: str) -> None:
        self._log.log(self.source, "info", category, message)

    def notice(self, category: str, message: str) -> None:
        self._log.log(self.source, "notice", category, message)

    def warn(self, category: str, message: str) -> None:
        self._log.log(self.source, "warn", category, message)

    def error(self, category: str, message: str) -> None:
        self._log.log(self.source, "error", category, message)
