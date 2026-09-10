"""The DOCSIS timebase.

Everything upstream is scheduled against a single clock that lives in the
CMTS and is distributed to every modem in SYNC messages:

    master clock   10.24 MHz, a 32-bit counter (wraps every ~419.4 s)
    timebase tick  6.25 us == 64 master clock counts
    mini-slot      M ticks, M a power of two; the unit MAPs allocate in

A modem never knows the absolute time -- it only knows the timestamp it last
saw in a SYNC, plus how long ago that was.  Because the SYNC took propagation
time to arrive, the modem's idea of "CMTS time now" lags real CMTS time by
the one-way delay, and its upstream bursts consequently arrive late by the
round trip.  Measuring and cancelling that error is exactly what ranging does.
"""

from __future__ import annotations

MASTER_CLOCK_HZ = 10_240_000
TICK_S = 6.25e-6
COUNTS_PER_TICK = 64            # 6.25 us at 10.24 MHz
TIMESTAMP_MODULUS = 1 << 32
TIMESTAMP_WRAP_S = TIMESTAMP_MODULUS / MASTER_CLOCK_HZ   # ~419.43 s

#: One unit of RNG-RSP Timing Adjust: 1/64 of a tick, i.e. one master clock count.
TIMING_ADJUST_UNIT_S = TICK_S / 64


def seconds_to_counts(seconds: float) -> int:
    return int(round(seconds * MASTER_CLOCK_HZ))


def counts_to_seconds(counts: int) -> float:
    return counts / MASTER_CLOCK_HZ


def timestamp_at(elapsed_s: float) -> int:
    """The 32-bit SYNC timestamp for a given elapsed time since CMTS start."""
    return seconds_to_counts(elapsed_s) % TIMESTAMP_MODULUS


def timestamp_delta(later: int, earlier: int) -> int:
    """Signed difference between two 32-bit timestamps, wrap-aware."""
    d = (later - earlier) % TIMESTAMP_MODULUS
    if d >= TIMESTAMP_MODULUS // 2:
        d -= TIMESTAMP_MODULUS
    return d


class MinislotClock:
    """Converts between elapsed seconds and mini-slot numbers.

    Mini-slot 0 begins at CMTS initialisation.  The mini-slot number in a MAP
    is a 32-bit counter of mini-slots since then, which for a 4-tick mini-slot
    wraps roughly every 30 hours -- long enough that the simulation ignores it,
    though `wrap()` is provided for completeness.
    """

    def __init__(self, minislot_ticks: int):
        if minislot_ticks & (minislot_ticks - 1):
            raise ValueError(f"mini-slot size must be a power of two, got {minislot_ticks}")
        self.ticks = minislot_ticks

    @property
    def duration_s(self) -> float:
        return self.ticks * TICK_S

    @property
    def counts(self) -> int:
        """Master clock counts per mini-slot."""
        return self.ticks * COUNTS_PER_TICK

    def number_at(self, elapsed_s: float) -> int:
        """The mini-slot in progress at `elapsed_s`."""
        return int(elapsed_s // self.duration_s)

    def start_of(self, minislot: int) -> float:
        """Elapsed seconds at which `minislot` begins."""
        return minislot * self.duration_s

    def timestamp_of(self, minislot: int) -> int:
        """The 32-bit master-clock timestamp at the start of `minislot`."""
        return (minislot * self.counts) % TIMESTAMP_MODULUS

    def wrap(self, minislot: int) -> int:
        return minislot % TIMESTAMP_MODULUS

    def __repr__(self) -> str:
        return (f"MinislotClock(ticks={self.ticks}, "
                f"{self.duration_s * 1e6:.2f} us, {self.counts} counts)")
