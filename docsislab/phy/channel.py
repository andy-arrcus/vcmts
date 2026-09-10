"""Downstream and upstream channel parameters, and the arithmetic that
converts bytes into time.

The PHY itself is modelled rather than implemented -- there are no I/Q
samples here -- but everything the MAC layer can *observe* about the PHY is
computed for real:

  * how long a downstream frame occupies the channel, from the symbol rate,
    the modulation order and the J.83 Annex B FEC/MPEG-TS overhead;
  * how many bytes fit in one upstream mini-slot, which depends on which
    burst profile (IUC) the grant was issued under;
  * how many mini-slots a modem must request to send a given PDU, including
    Reed-Solomon parity, preamble and guard time.

That last one is why a request for a 64-byte packet does not ask for
64/bytes_per_minislot mini-slots, and why the number differs between a Short
and a Long Data Grant.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..docsis.consts import (BITS_PER_SYMBOL, IUC, MODULATION_NAMES,
                             Modulation)
from ..docsis.messages import BurstDescriptor
from ..util.clock import TICK_S, MinislotClock


# --------------------------------------------------------------------------
# Downstream
# --------------------------------------------------------------------------

#: MPEG transport-stream payload rates for ITU-T J.83 Annex B, i.e. after
#: Reed-Solomon, trellis coding and interleaving.  These are the figures the
#: DOCSIS downstream is universally quoted with.
ANNEX_B_TS_BPS = {
    Modulation.QAM64: 26_970_350,
    Modulation.QAM256: 38_810_700,
}

#: An MPEG-TS packet is 188 bytes with a 4-byte header, so DOCSIS payload gets
#: 184/188 of the transport stream.
TS_PAYLOAD_RATIO = 184 / 188


@dataclass
class DownstreamChannel:
    """A downstream carrier, and how long a frame takes on it."""
    channel_id: int = 1
    center_freq_hz: int = 555_000_000
    width_hz: int = 6_000_000
    modulation: int = Modulation.QAM256
    #: J.83 Annex B symbol rate for a 6 MHz channel at 256-QAM.
    symbol_rate: float = 5_360_537.0
    annex: str = "B"
    #: Simulated receive power at the modem, dBmV.
    rx_power_dbmv: float = 0.0
    snr_db: float = 38.0

    @property
    def ts_bps(self) -> int:
        return ANNEX_B_TS_BPS.get(self.modulation, 38_810_700)

    @property
    def payload_bps(self) -> float:
        """DOCSIS MAC-layer bits per second available on this downstream."""
        return self.ts_bps * TS_PAYLOAD_RATIO

    def serialization_s(self, nbytes: int) -> float:
        """How long `nbytes` of MAC frame occupies the downstream."""
        return nbytes * 8 / self.payload_bps

    def describe(self) -> str:
        return (f"DS{self.channel_id} {self.center_freq_hz / 1e6:.3f} MHz "
                f"{MODULATION_NAMES[self.modulation]} Annex {self.annex} "
                f"{self.payload_bps / 1e6:.2f} Mbit/s")


# --------------------------------------------------------------------------
# Upstream
# --------------------------------------------------------------------------

#: The upstream channel widths DOCSIS allows, and their symbol rates.
#: 5.12 Msym/s (6.4 MHz) is the one DOCSIS 2.0 added; DOCSIS 1.x stops at
#: 2.56 Msym/s, which is why a 6.4 MHz channel cannot be described by a
#: type-2 UCD at all.
SYMBOL_RATES = {
    200_000: 160,
    400_000: 320,
    800_000: 640,
    1_600_000: 1280,
    3_200_000: 2560,
    6_400_000: 5120,          # DOCSIS 2.0 A-TDMA only
}

DOCSIS_1X_MAX_KSYM = 2560


def default_burst_profiles(advanced: bool, data_modulation: int) -> list[BurstDescriptor]:
    """A plausible modulation profile.

    The maintenance and request IUCs stay at QPSK because they have to work
    for a modem that has not been equalised yet; only the data grants use the
    higher-order modulation.  This mirrors how operators actually configure
    modulation profiles.
    """
    profiles = [
        # Contention region for bandwidth requests: tiny bursts, no FEC.
        BurstDescriptor(iuc=IUC.REQUEST, modulation=Modulation.QPSK,
                        preamble_length=64, fec_t=0, fec_k=16,
                        max_burst=1, guard_time=8, last_codeword_shortened=False),
        # Initial ranging: long preamble and a big guard time, because the
        # modem's transmit timing is not yet known and its burst may land
        # anywhere inside the region.
        BurstDescriptor(iuc=IUC.INITIAL_MAINT, modulation=Modulation.QPSK,
                        preamble_length=128, fec_t=5, fec_k=34,
                        max_burst=0, guard_time=48),
        # Periodic ranging: timing is known by now, so the guard time shrinks.
        BurstDescriptor(iuc=IUC.STATION_MAINT, modulation=Modulation.QPSK,
                        preamble_length=128, fec_t=5, fec_k=34,
                        max_burst=0, guard_time=8),
        BurstDescriptor(iuc=IUC.SHORT_DATA_GRANT, modulation=Modulation.QAM16,
                        preamble_length=128, fec_t=5, fec_k=75,
                        max_burst=12, guard_time=8),
        BurstDescriptor(iuc=IUC.LONG_DATA_GRANT, modulation=Modulation.QAM16,
                        preamble_length=128, fec_t=8, fec_k=220,
                        max_burst=0, guard_time=8),
    ]
    if advanced:
        profiles += [
            BurstDescriptor(iuc=IUC.ADV_PHY_SHORT_DATA, modulation=data_modulation,
                            preamble_length=128, fec_t=5, fec_k=75, max_burst=12,
                            guard_time=8, preamble_type=2, rs_interleaver_depth=1,
                            rs_interleaver_block_size=2000, scdma_spreader_on=2),
            BurstDescriptor(iuc=IUC.ADV_PHY_LONG_DATA, modulation=data_modulation,
                            preamble_length=128, fec_t=10, fec_k=232, max_burst=0,
                            guard_time=8, preamble_type=2, rs_interleaver_depth=1,
                            rs_interleaver_block_size=2000, scdma_spreader_on=2),
        ]
    return profiles


@dataclass
class UpstreamChannel:
    """An upstream carrier, its burst profiles, and its mini-slot arithmetic."""
    channel_id: int = 1
    center_freq_hz: int = 30_000_000
    width_hz: int = 3_200_000
    #: Mini-slot size in 6.25 us timebase ticks; must be a power of two.
    minislot_ticks: int = 4
    #: A-TDMA is the DOCSIS 2.0 TDMA mode; "tdma" is the 1.x mode.
    phy_mode: str = "atdma"
    data_modulation: int = Modulation.QAM64
    burst_profiles: list[BurstDescriptor] = field(default_factory=list)
    #: Nominal modem transmit level the CMTS is aiming for, dBmV.
    target_rx_power_dbmv: float = 0.0
    snr_db: float = 33.0

    def __post_init__(self):
        if not self.burst_profiles:
            self.burst_profiles = default_burst_profiles(
                self.advanced, self.data_modulation)
        self.clock = MinislotClock(self.minislot_ticks)

    # -- basic parameters ------------------------------------------------
    @property
    def advanced(self) -> bool:
        """True for a DOCSIS 2.0 PHY (A-TDMA or S-CDMA)."""
        return self.phy_mode in ("atdma", "scdma")

    @property
    def symbol_rate(self) -> int:
        return self.width_hz // 1.25 if self.width_hz not in SYMBOL_RATES else \
            {200_000: 200_000, 400_000: 400_000, 800_000: 800_000,
             1_600_000: 1_600_000, 3_200_000: 2_560_000,
             6_400_000: 5_120_000}[self.width_hz]

    @property
    def symbol_rate_ksym(self) -> int:
        return SYMBOL_RATES[self.width_hz]

    @property
    def describable_by_docsis_1x(self) -> bool:
        """Whether a type-2 UCD can describe this channel at all."""
        return self.symbol_rate_ksym <= DOCSIS_1X_MAX_KSYM

    @property
    def minislot_s(self) -> float:
        return self.minislot_ticks * TICK_S

    @property
    def symbols_per_minislot(self) -> float:
        return self.minislot_s * self.symbol_rate

    def profile(self, iuc: int) -> BurstDescriptor | None:
        for p in self.burst_profiles:
            if p.iuc == iuc:
                return p
        return None

    # -- the byte <-> mini-slot conversions ------------------------------
    def bits_per_symbol(self, iuc: int) -> int:
        prof = self.profile(iuc)
        return BITS_PER_SYMBOL[prof.modulation] if prof else 2

    def bytes_per_minislot(self, iuc: int) -> int:
        """Raw capacity of one mini-slot under a given burst profile.

        A mini-slot is a fixed slice of *time*, so its byte capacity depends
        entirely on the modulation the grant's IUC specifies -- 16 bytes at
        QPSK becomes 48 bytes at 64-QAM for the same 25 us.
        """
        return int(self.symbols_per_minislot * self.bits_per_symbol(iuc) // 8)

    def fec_encoded_size(self, payload_bytes: int, iuc: int) -> int:
        """Payload plus Reed-Solomon parity, per the profile's T and k."""
        prof = self.profile(iuc)
        if prof is None or prof.fec_t == 0:
            return payload_bytes
        k, t = prof.fec_k, prof.fec_t
        full = payload_bytes // k
        remainder = payload_bytes % k
        codewords = full + (1 if remainder else 0)
        if remainder and not prof.last_codeword_shortened:
            # Fixed-length codewords pad the last one out to k bytes.
            payload_bytes = codewords * k
        return payload_bytes + codewords * 2 * t

    def burst_symbols(self, payload_bytes: int, iuc: int) -> float:
        """Total symbols on the wire for a burst carrying `payload_bytes`."""
        prof = self.profile(iuc)
        coded = self.fec_encoded_size(payload_bytes, iuc)
        data_symbols = coded * 8 / self.bits_per_symbol(iuc)
        if prof is None:
            return data_symbols
        # The preamble is always QPSK (2 bits/symbol) regardless of the
        # modulation the data uses.
        preamble_symbols = prof.preamble_length / 2
        return data_symbols + preamble_symbols + prof.guard_time

    def minislots_for(self, payload_bytes: int, iuc: int) -> int:
        """How many mini-slots a modem must request to send `payload_bytes`."""
        if payload_bytes <= 0:
            return 0
        return max(1, math.ceil(self.burst_symbols(payload_bytes, iuc)
                                / self.symbols_per_minislot))

    def payload_capacity(self, minislots: int, iuc: int) -> int:
        """The inverse: the largest payload that fits in `minislots`.

        Used by the modem to decide whether a grant it just received is big
        enough for the frame it is holding.
        """
        if minislots <= 0:
            return 0
        lo, hi = 0, minislots * self.bytes_per_minislot(iuc) + 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.minislots_for(mid, iuc) <= minislots:
                lo = mid
            else:
                hi = mid - 1
            if lo == hi:
                break
        return lo

    def raw_bps(self) -> float:
        return self.symbol_rate * BITS_PER_SYMBOL[self.data_modulation]

    def data_iuc(self, long_grant: bool) -> int:
        """Which IUC a data grant should use on this channel."""
        if self.advanced:
            return IUC.ADV_PHY_LONG_DATA if long_grant else IUC.ADV_PHY_SHORT_DATA
        return IUC.LONG_DATA_GRANT if long_grant else IUC.SHORT_DATA_GRANT

    def describe(self) -> str:
        mode = {"tdma": "TDMA (DOCSIS 1.x)", "atdma": "A-TDMA (DOCSIS 2.0)",
                "scdma": "S-CDMA (DOCSIS 2.0)"}[self.phy_mode]
        return (f"US{self.channel_id} {self.center_freq_hz / 1e6:.3f} MHz "
                f"{self.width_hz / 1e6:.1f} MHz {self.symbol_rate_ksym} ksym/s "
                f"{mode} {MODULATION_NAMES[self.data_modulation]} "
                f"minislot={self.minislot_ticks} ticks "
                f"({self.minislot_s * 1e6:.2f} us) "
                f"{self.raw_bps() / 1e6:.2f} Mbit/s raw")
