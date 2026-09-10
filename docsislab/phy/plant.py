"""The virtual HFC plant: the only path between the CMTS and the modems.

This is deliberately the *only* way the CMTS and the cable modems can reach
each other.  Neither one holds a reference to the other; they hand byte
strings to the plant and receive byte strings back, which keeps the
simulation honest -- if the modem gets online, it did so by exchanging real
DOCSIS frames.

What the plant models:

  * **Serialisation.**  A downstream frame occupies the channel for
    len*8/payload_bps seconds, and frames queue behind each other.
  * **Propagation delay.**  Each modem sits at a configurable distance; at
    0.87c a 10 km drop is 38.3 us each way.  This is the entire reason
    ranging exists, and it is what the RNG-RSP timing adjust converges on.
  * **Attenuation.**  Received power falls with distance, so the CMTS has
    something real to correct with the RNG-RSP power adjust.
  * **Collisions.**  Two upstream bursts whose transmissions overlap in time
    on the same channel destroy each other.  Contention regions -- initial
    ranging and bandwidth requests -- are where this bites.
  * **Impairments.**  Optional random loss and a noise-burst window, for
    watching the retry and back-off machinery work.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from ..lab.sim import Scheduler
from .channel import DownstreamChannel, UpstreamChannel

#: Velocity of propagation in coaxial cable / fibre, as a fraction of c.
VELOCITY_FACTOR = 0.87
SPEED_OF_LIGHT = 299_792_458.0

#: Coaxial loss per kilometre, before amplification.
LOSS_DB_PER_KM = 1.4
#: A real HFC plant is built for unity gain: amplifiers every couple of
#: kilometres restore the level, so the loss the CMTS actually sees is
#: bounded no matter how long the plant is.  Without this, an 80 km modem
#: would need 112 dB of transmit power and no modem could ever reach the
#: CMTS -- whereas in reality distance changes the *timing*, not the level,
#: which is the whole point of ranging.
MAX_RESIDUAL_LOSS_DB = 18.0


def delay_for_km(km: float) -> float:
    """One-way propagation delay for a length of cable."""
    return (km * 1000.0) / (SPEED_OF_LIGHT * VELOCITY_FACTOR)


@dataclass
class UpstreamBurst:
    """One modem transmission occupying a contiguous span of mini-slots."""
    modem: str
    channel_id: int
    data: bytes
    #: When the modem started and stopped transmitting, in plant time.
    tx_start: float
    tx_end: float
    #: Mini-slots the modem believed it was transmitting in.
    first_minislot: int
    last_minislot: int
    iuc: int
    rx_power_dbmv: float
    #: Arrival window at the CMTS, after propagation.
    rx_start: float = 0.0
    rx_end: float = 0.0
    collided: bool = False
    lost: bool = False
    note: str = ""


@dataclass
class ModemAttachment:
    """One modem's position on the plant: delay, loss and transmit level."""
    name: str
    distance_km: float
    #: One-way propagation delay, seconds.
    delay_s: float
    #: Modem transmit level, dBmV.  Ranging drives this to whatever makes the
    #: CMTS see its target receive level.
    tx_power_dbmv: float = 45.0
    #: Static frequency error of the modem's upstream synthesiser, Hz.
    freq_error_hz: int = 0
    downstream_rx: Callable[[bytes, float], None] | None = None

    #: Bound on the loss the CMTS sees, standing in for the amplifier cascade.
    max_residual_loss_db: float = MAX_RESIDUAL_LOSS_DB

    @property
    def attenuation_db(self) -> float:
        return min(self.distance_km * LOSS_DB_PER_KM, self.max_residual_loss_db)


class HfcPlant:
    """The medium: the only path between the CMTS and the modems."""
    def __init__(self, sched: Scheduler,
                 downstreams: list[DownstreamChannel],
                 upstreams: list[UpstreamChannel],
                 capture=None, rng: random.Random | None = None):
        self.sched = sched
        self.downstreams = {d.channel_id: d for d in downstreams}
        self.upstreams = {u.channel_id: u for u in upstreams}
        self.capture = capture
        self.rng = rng or random.Random(20020101)

        self.modems: dict[str, ModemAttachment] = {}
        #: Set by the CMTS when it attaches.
        self.cmts_upstream_rx: Callable[[UpstreamBurst], None] | None = None

        #: Per-channel "busy until" time, so downstream frames serialise.
        self._ds_busy: dict[int, float] = {cid: 0.0 for cid in self.downstreams}
        #: Bursts in flight, for collision detection.
        self._us_inflight: dict[int, list[UpstreamBurst]] = {cid: [] for cid in self.upstreams}

        # Impairments
        self.ds_loss_prob = 0.0
        self.us_loss_prob = 0.0
        #: (start, end, channel_id) windows during which upstream bursts are
        #: destroyed -- an ingress/noise burst.
        self.noise_windows: list[tuple[float, float, int | None]] = []

        # Counters for `show` commands
        self.stats = {
            "ds_frames": 0, "ds_bytes": 0, "ds_dropped": 0,
            "us_bursts": 0, "us_bytes": 0, "us_collisions": 0, "us_dropped": 0,
        }

    # ------------------------------------------------------------------
    # attachment
    # ------------------------------------------------------------------
    def attach_modem(self, name: str, distance_km: float,
                     downstream_rx: Callable[[bytes, float], None],
                     tx_power_dbmv: float = 45.0,
                     freq_error_hz: int = 0) -> ModemAttachment:
        att = ModemAttachment(name=name, distance_km=distance_km,
                              delay_s=delay_for_km(distance_km),
                              tx_power_dbmv=tx_power_dbmv,
                              freq_error_hz=freq_error_hz,
                              downstream_rx=downstream_rx)
        self.modems[name] = att
        return att

    def detach_modem(self, name: str) -> None:
        self.modems.pop(name, None)

    def attach_cmts(self, upstream_rx: Callable[[UpstreamBurst], None]) -> None:
        self.cmts_upstream_rx = upstream_rx

    # ------------------------------------------------------------------
    # downstream
    # ------------------------------------------------------------------
    def send_downstream(self, channel_id: int, frame: bytes,
                        comment: str = "") -> float:
        """Queue a MAC frame for downstream transmission.

        Returns the time at which the frame finishes going out, which is when
        the CMTS's own view of the channel becomes free again.
        """
        ds = self.downstreams[channel_id]
        now = self.sched.now()
        start = max(now, self._ds_busy.get(channel_id, 0.0))
        duration = ds.serialization_s(len(frame))
        end = start + duration
        self._ds_busy[channel_id] = end

        self.stats["ds_frames"] += 1
        self.stats["ds_bytes"] += len(frame)
        if self.capture:
            self.capture.downstream(start, frame, comment)

        for att in list(self.modems.values()):
            if self.ds_loss_prob and self.rng.random() < self.ds_loss_prob:
                self.stats["ds_dropped"] += 1
                continue
            arrival = end + att.delay_s
            rx = att.downstream_rx
            if rx is None:
                continue
            # Bind the values now; the modem may detach before delivery.
            self.sched.at(arrival, lambda rx=rx, frame=frame, start=start: rx(frame, start),
                          name=f"ds->{att.name}")
        return end

    def downstream_serialization(self, channel_id: int, nbytes: int) -> float:
        return self.downstreams[channel_id].serialization_s(nbytes)

    # ------------------------------------------------------------------
    # upstream
    # ------------------------------------------------------------------
    def transmit_upstream(self, modem: str, channel_id: int, data: bytes,
                          first_minislot: int, last_minislot: int, iuc: int,
                          comment: str = "") -> UpstreamBurst:
        """A modem transmits a burst starting *now* in plant time.

        The modem has already applied its ranging offset when deciding to
        call this, so `tx_start` is simply the current time; the plant's job
        is to add propagation, spot collisions, and hand the burst to the CMTS
        when the last symbol has arrived.
        """
        us = self.upstreams[channel_id]
        att = self.modems[modem]
        now = self.sched.now()
        duration = us.burst_symbols(len(data), iuc) / us.symbol_rate
        burst = UpstreamBurst(
            modem=modem, channel_id=channel_id, data=data,
            tx_start=now, tx_end=now + duration,
            first_minislot=first_minislot, last_minislot=last_minislot,
            iuc=iuc,
            rx_power_dbmv=att.tx_power_dbmv - att.attenuation_db,
            note=comment,
        )
        burst.rx_start = burst.tx_start + att.delay_s
        burst.rx_end = burst.tx_end + att.delay_s

        self.stats["us_bursts"] += 1
        self.stats["us_bytes"] += len(data)

        # Collision check against everything still in flight on this channel.
        inflight = self._us_inflight[channel_id]
        inflight[:] = [b for b in inflight if b.rx_end >= now - 0.05]
        for other in inflight:
            if burst.rx_start < other.rx_end and other.rx_start < burst.rx_end:
                burst.collided = True
                other.collided = True
                if not other.lost:
                    self.stats["us_collisions"] += 1
        if burst.collided:
            self.stats["us_collisions"] += 1
        inflight.append(burst)

        for start, end, cid in self.noise_windows:
            if (cid in (None, channel_id)
                    and burst.rx_start < end and start < burst.rx_end):
                burst.lost = True
                burst.note = (burst.note + " " if burst.note else "") + "[noise burst]"
        if self.us_loss_prob and self.rng.random() < self.us_loss_prob:
            burst.lost = True
            burst.note = (burst.note + " " if burst.note else "") + "[random loss]"

        if self.capture:
            self.capture.upstream(burst.tx_start, data, self._us_comment(burst))
        if burst.collided or burst.lost:
            self.stats["us_dropped"] += 1

        if self.cmts_upstream_rx is not None:
            cb = self.cmts_upstream_rx
            self.sched.at(burst.rx_end, lambda b=burst: cb(b), name=f"us<-{modem}")
        return burst

    def _us_comment(self, burst: UpstreamBurst) -> str:
        bits = [f"{burst.modem} US{burst.channel_id} IUC{burst.iuc} "
                f"minislots {burst.first_minislot}..{burst.last_minislot}",
                f"rx {burst.rx_power_dbmv:+.2f} dBmV"]
        if burst.collided:
            bits.append("COLLISION")
        if burst.lost:
            bits.append("LOST")
        if burst.note:
            bits.append(burst.note)
        return " | ".join(bits)

    def upstream_burst_duration(self, channel_id: int, nbytes: int, iuc: int) -> float:
        us = self.upstreams[channel_id]
        return us.burst_symbols(nbytes, iuc) / us.symbol_rate

    # ------------------------------------------------------------------
    # impairments
    # ------------------------------------------------------------------
    def inject_noise(self, duration: float, channel_id: int | None = None,
                     delay: float = 0.0) -> tuple[float, float]:
        start = self.sched.now() + delay
        window = (start, start + duration, channel_id)
        self.noise_windows.append(window)
        return start, start + duration

    def clear_noise(self) -> None:
        self.noise_windows.clear()

    # ------------------------------------------------------------------
    def describe(self) -> list[str]:
        out = [d.describe() for d in self.downstreams.values()]
        out += [u.describe() for u in self.upstreams.values()]
        for m in self.modems.values():
            capped = m.distance_km * LOSS_DB_PER_KM > m.max_residual_loss_db
            out.append(f"{m.name}: {m.distance_km:.1f} km, one-way "
                       f"{m.delay_s * 1e6:.2f} us, round trip "
                       f"{2 * m.delay_s * 1e6:.2f} us "
                       f"({round(2 * m.delay_s / (6.25e-6 / 64))} timing-adjust "
                       f"units), residual loss {m.attenuation_db:.1f} dB"
                       + (" (amplifier cascade holding the level up)"
                          if capped else ""))
        return out
