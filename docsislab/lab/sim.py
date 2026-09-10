"""A discrete-event scheduler, paced against the wall clock.

DOCSIS timing lives at the microsecond scale: a 4-tick mini-slot is 25 us and
ranging resolution is 97.65625 ns.  No general-purpose OS timer can honour
that, so the simulation keeps its own virtual clock and advances it event by
event.  Every timestamp the CMTS and modems see is therefore exact.

To stay watchable, the loop optionally paces itself so virtual time tracks
wall-clock time (`speed=1.0`), sleeping when it runs ahead and simply catching
up when it falls behind.  With `speed=0` it runs as fast as the CPU allows,
which is what the tests use.
"""

from __future__ import annotations

import heapq
import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass(order=True)
class _Event:
    when: float
    seq: int
    callback: Callable[[], None] = field(compare=False)
    name: str = field(compare=False, default="")
    cancelled: bool = field(compare=False, default=False)


class Timer:
    """Handle for a scheduled callback, so state machines can cancel their
    protocol timers (T3, T4, T6 ...) the way real implementations do."""

    __slots__ = ("_event",)

    def __init__(self, event: _Event):
        self._event = event

    def cancel(self) -> None:
        self._event.cancelled = True

    @property
    def active(self) -> bool:
        return not self._event.cancelled

    @property
    def when(self) -> float:
        return self._event.when


class Scheduler:
    """The discrete-event clock the whole simulation runs on."""
    def __init__(self, speed: float = 1.0):
        #: virtual seconds since start
        self._now = 0.0
        self._queue: list[_Event] = []
        self._counter = itertools.count()
        self.speed = speed
        self._stop = False
        self._wall_start = 0.0
        #: things to run between events, e.g. draining the control socket queue
        self._pollers: list[Callable[[], None]] = []
        self._poll_interval = 0.005
        self.events_run = 0
        self.lock = threading.RLock()

    # -- clock -----------------------------------------------------------
    def now(self) -> float:
        return self._now

    # -- scheduling ------------------------------------------------------
    def at(self, when: float, callback: Callable[[], None], name: str = "") -> Timer:
        ev = _Event(when, next(self._counter), callback, name)
        heapq.heappush(self._queue, ev)
        return Timer(ev)

    def after(self, delay: float, callback: Callable[[], None], name: str = "") -> Timer:
        return self.at(self._now + max(0.0, delay), callback, name)

    def every(self, interval: float, callback: Callable[[], None],
              name: str = "", first: float | None = None) -> Timer:
        """Repeating timer.  The returned handle cancels the whole series."""
        holder: dict[str, Timer] = {}
        state = {"cancelled": False}

        def tick() -> None:
            if state["cancelled"]:
                return
            callback()
            if not state["cancelled"]:
                holder["t"] = self.after(interval, tick, name)
                holder["t"]._event.cancelled = False

        outer = self.after(interval if first is None else first, tick, name)
        holder["t"] = outer

        class _Series(Timer):
            def __init__(self):
                pass

            def cancel(_self) -> None:
                state["cancelled"] = True
                holder["t"].cancel()

            @property
            def active(_self) -> bool:
                return not state["cancelled"]

            @property
            def when(_self) -> float:
                return holder["t"].when

        return _Series()

    def add_poller(self, fn: Callable[[], None]) -> None:
        self._pollers.append(fn)

    # -- running ---------------------------------------------------------
    def stop(self) -> None:
        self._stop = True

    def run(self, until: float | None = None) -> None:
        self._wall_start = time.monotonic()
        next_poll = 0.0
        while not self._stop:
            # Pollers give the control socket and any host interfaces a chance
            # to inject work without needing their own thread inside the sim.
            if self._now >= next_poll:
                for poll in self._pollers:
                    poll()
                next_poll = self._now + self._poll_interval

            if not self._queue:
                if until is None:
                    # Nothing left to do and no horizon: idle briefly so
                    # pollers keep running (the CLI may still be attached).
                    if self.speed > 0:
                        time.sleep(0.002)
                        self._now += 0.002
                        continue
                    return
                self._now = until
                return

            ev = self._queue[0]
            if until is not None and ev.when > until:
                self._now = until
                return
            # Advance to the next poll point rather than skipping over it.
            if ev.when > next_poll and self.speed > 0:
                target = next_poll
                self._pace(target)
                self._now = max(self._now, target)
                continue

            heapq.heappop(self._queue)
            if ev.cancelled:
                continue
            if self.speed > 0:
                self._pace(ev.when)
            self._now = ev.when
            self.events_run += 1
            ev.callback()

    def _pace(self, virtual_target: float) -> None:
        """Sleep until wall-clock time catches up with `virtual_target`."""
        wall_target = self._wall_start + virtual_target / self.speed
        gap = wall_target - time.monotonic()
        if gap > 0.0005:
            time.sleep(gap)

    def drain(self, seconds: float) -> None:
        """Run for `seconds` of virtual time (used by tests)."""
        self.run(until=self._now + seconds)
