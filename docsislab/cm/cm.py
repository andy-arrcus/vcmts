"""The virtual DOCSIS 2.0 cable modem.

This is the full initialisation sequence from CM-SP-RFIv2.0 section 11.2, in
order, with the real protocol timers:

    scan downstream            pick a downstream, "lock" it
    acquire SYNC               slave the local clock to the CMTS timestamp
    obtain upstream params     a UCD; a 2.0 modem prefers the type-29 one
    ranging                    contend for a broadcast Initial Maintenance
                               opportunity, then converge via unicast Station
                               Maintenance until the CMTS says SUCCESS
    establish IP               DHCP, over the DOCSIS data path
    time of day                RFC 868
    transfer operational params TFTP download of the config file, MIC checked
    register                   REG-REQ / REG-RSP / REG-ACK
    operational                forward CPE traffic

Two mechanisms are worth watching in particular:

**The clock.**  The modem's only time reference is the timestamp inside SYNC,
which arrived one propagation delay ago.  Its idea of "CMTS time now" is
therefore always that much behind, and everything it transmits lands late by
the round trip -- until ranging gives it an offset to transmit early by.

**Contention resolution** (RFIv2.0 8.2.6).  The modem may not simply transmit
in the first opportunity it sees.  It draws a random number from a back-off
window, counts that many transmit opportunities going past, and only then
transmits; a lost burst doubles the window.  This is what stops a hundred
modems powering up together from colliding forever.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum

from ..docsis import frames as F
from ..docsis import machdr
from ..docsis import messages as M
from ..docsis.cfgfile import decode as decode_config
from ..docsis.cfgfile import modem_capabilities, vendor_class_identifier
from ..docsis.cfgfile import verify as verify_config
from ..docsis.consts import (CfgTLV, DocsisVersion, IUC, LOST_SYNC_TIMEOUT,
                             MgmtType, RangingStatus, RegRspCode, SID_BROADCAST,
                             T1_UCD_WAIT, T2_INITIAL_MAINT_WAIT, T3_RNG_RSP_WAIT,
                             T4_STATION_MAINT_WAIT, T6_REG_RSP_WAIT,
                             ConfirmationCode)
from ..lab.sim import Scheduler, Timer
from ..net import dhcp as D
from ..net import packet as P
from ..net import tftp as TFTP
from ..net import tod as TOD
from ..net.packet import decode_ethernet, mac_str
from ..net.stack import IpStack
from ..phy.channel import UpstreamChannel
from ..phy.plant import HfcPlant
from ..util import tlv
from ..util.clock import (MASTER_CLOCK_HZ, TIMING_ADJUST_UNIT_S, MinislotClock,
                          timestamp_delta)
from ..util.crc import with_fcs


class CmState(str, Enum):
    """Where the modem is in the DOCSIS initialisation sequence."""
    OFFLINE = "offline"
    DS_SCAN = "ds-scan"
    DS_LOCK = "ds-lock"
    SYNC_WAIT = "sync-wait"
    UCD_WAIT = "ucd-wait"
    RANGING_WAIT = "ranging-wait"       # waiting for a broadcast Initial Maint
    RANGING_INITIAL = "ranging-initial"
    RANGING_STATION = "ranging-station"
    RANGING_COMPLETE = "ranging-complete"
    DHCP = "dhcp"
    TOD = "time-of-day"
    TFTP = "tftp-config"
    REGISTERING = "registering"
    OPERATIONAL = "operational"
    REJECTED = "rejected"


STATE_MEANING = {
    CmState.OFFLINE: "powered off",
    CmState.DS_SCAN: "scanning the downstream spectrum for a DOCSIS carrier",
    CmState.DS_LOCK: "QAM and FEC lock acquired on a downstream",
    CmState.SYNC_WAIT: "waiting for a SYNC message to establish the timebase",
    CmState.UCD_WAIT: "waiting for a UCD describing a usable upstream (T1)",
    CmState.RANGING_WAIT: "waiting for a broadcast Initial Maintenance "
                          "opportunity, deferring per the ranging back-off (T2)",
    CmState.RANGING_INITIAL: "initial RNG-REQ sent with SID 0, waiting for "
                             "RNG-RSP (T3)",
    CmState.RANGING_STATION: "applying timing/power corrections via unicast "
                             "Station Maintenance",
    CmState.RANGING_COMPLETE: "upstream timing locked",
    CmState.DHCP: "acquiring an IP address by DHCP over the DOCSIS data path",
    CmState.TOD: "acquiring time of day (RFC 868)",
    CmState.TFTP: "downloading the configuration file over TFTP",
    CmState.REGISTERING: "REG-REQ sent, waiting for REG-RSP (T6)",
    CmState.OPERATIONAL: "online and forwarding",
    CmState.REJECTED: "registration rejected by the CMTS",
}


@dataclass
class CmConfig:
    """One modem's identity, position on the plant and capabilities."""
    name: str = "cm0"
    mac: bytes = field(default_factory=lambda: bytes.fromhex("001dcf112233"))
    distance_km: float = 10.0
    #: Where the modem starts its downstream scan, and how far it steps.
    scan_start_hz: int = 543_000_000
    scan_step_hz: int = 6_000_000
    scan_dwell: float = 0.010
    #: Initial upstream transmit level, dBmV.  Ranging corrects it.
    tx_power_dbmv: float = 45.0
    #: DOCSIS 2.0 upstream transmit range (RFIv2.0 Table 6-12): +8 dBmV is
    #: genuinely as low as a modem can go, so a modem on a short drop stays
    #: pinned at the floor and the CMTS simply sees it a few dB hot.
    min_tx_power_dbmv: float = 8.0
    max_tx_power_dbmv: float = 58.0
    #: Static synthesiser error the CMTS will measure and correct.
    freq_error_hz: int = 0
    docsis_version: int = DocsisVersion.V20
    concatenation: bool = True
    fragmentation: bool = True
    max_cpe: int = 4
    #: Timing jitter added to every upstream burst, in 1/64-tick units, so
    #: ranging has to iterate rather than converging in a single step.
    timing_jitter_units: int = 3
    seed: int = 0


@dataclass
class Contention:
    """Back-off state for one contention process (RFIv2.0 8.2.6)."""
    exponent: int = 0
    start: int = 0
    end: int = 4
    #: Opportunities still to be skipped before transmitting.
    defer: int | None = None
    attempts: int = 0

    def arm(self, rng: random.Random, start: int, end: int) -> int:
        self.start, self.end = start, end
        if self.defer is None:
            self.exponent = max(self.exponent, start)
            window = 1 << self.exponent
            self.defer = rng.randrange(window)
        return self.defer

    def backoff(self) -> None:
        self.exponent = min(self.exponent + 1, self.end)
        self.defer = None
        self.attempts += 1

    def reset(self) -> None:
        self.exponent = self.start
        self.defer = None
        self.attempts = 0

    @property
    def window(self) -> int:
        return 1 << self.exponent


class CableModem:
    """A DOCSIS 2.0 cable modem, from cold start to forwarding."""
    def __init__(self, sched: Scheduler, plant: HfcPlant, cfg: CmConfig, log,
                 capture=None):
        self.sched = sched
        self.plant = plant
        self.cfg = cfg
        self.log = log
        self.capture = capture
        self.rng = random.Random(cfg.seed or (int.from_bytes(cfg.mac, "big") & 0xFFFFFFFF))

        self.state = CmState.OFFLINE
        self.state_history: list[tuple[float, str]] = []

        # --- PHY / timing ---------------------------------------------
        self.ds_channel_id: int | None = None
        self.ds_freq_hz: int | None = None
        #: cmts_elapsed_time == local_time + clock_offset
        self.clock_offset: float | None = None
        self.last_sync_at: float | None = None
        self.sync_count = 0
        self.ucd: M.Ucd | None = None
        self.ucd_is_type29 = False
        self.ucd_ccc: int | None = None
        self.us_channel: UpstreamChannel | None = None
        self.minislot_clock: MinislotClock | None = None
        #: Set by a UCC-REQ: the only channel whose UCD we will accept until
        #: we have moved there.
        self.ucc_target: int | None = None
        #: Channels we have already reported holding out on, so the message
        #: is not repeated every UCD interval.
        self._held_out_for_type29: set[int] = set()
        #: True once registration has completed at least once, so a channel
        #: change re-ranges rather than re-provisioning from scratch.
        self.registered = False

        #: Ranging state, in 1/64-tick units.
        self.ranging_offset = 0
        self.tx_power_dbmv = cfg.tx_power_dbmv
        self.sid = 0
        self.ranging_attempts = 0
        self.rng_rsp_received = 0

        # --- contention -----------------------------------------------
        self.ranging_contention = Contention()
        self.request_contention = Contention()

        # --- provisioning ----------------------------------------------
        self.ip: str | None = None
        self.netmask: str | None = None
        self.gateway: str | None = None
        self.tftp_server: str | None = None
        self.tod_server: str | None = None
        self.config_filename: str | None = None
        self.config_blob: bytes = b""
        self.config_settings: list[tlv.TLV] = []
        self.time_of_day: float | None = None
        self.dhcp_xid = 0
        self.dhcp_server_id: str | None = None
        self._tftp_block = 0
        self._tftp_buf = b""
        self._tftp_port = 0

        # --- data path -------------------------------------------------
        #: Ethernet frames waiting for upstream bandwidth.
        self.us_queue: list[bytes] = []
        self.outstanding_request = 0
        self.request_minislot: int | None = None
        self.grant_pending = False
        #: The IUC the CMTS most recently granted under, so the next request
        #: can be sized against the profile actually in use.
        self.granted_iuc: int | None = None
        self.cpe_macs: list[bytes] = []
        self.lan_transmit = None            # set by the CPE / TUN attachment
        self.counters = {
            "ds_frames": 0, "ds_mgmt": 0, "ds_pdu": 0, "ds_filtered": 0,
            "us_bursts": 0, "us_bytes": 0, "requests": 0, "grants": 0,
            "grant_pending": 0, "t3_timeouts": 0, "t4_timeouts": 0,
            "collisions_assumed": 0, "maps_seen": 0, "concatenated": 0,
        }

        # --- timers ----------------------------------------------------
        self._t1: Timer | None = None
        self._t2: Timer | None = None
        self._t3: Timer | None = None
        self._t4: Timer | None = None
        self._t6: Timer | None = None
        self._lost_sync: Timer | None = None
        self._scan_timer: Timer | None = None
        self._pending_tx: list[Timer] = []

        # --- management IP stack ---------------------------------------
        self.stack = IpStack(cfg.name, cfg.mac, self._queue_upstream, sched.now)
        self.stack.bind_udp(D.CLIENT_PORT, self._on_dhcp)
        # RFC 868 replies come back to whatever source port the request went
        # out from, so the modem has to listen there rather than on port 37.
        self.tod_port = 1037
        self.stack.bind_udp(self.tod_port, self._on_tod)

        self.attachment = None

    # ==================================================================
    # lifecycle
    # ==================================================================
    def power_on(self) -> None:
        self.attachment = self.plant.attach_modem(
            self.cfg.name, self.cfg.distance_km, self._on_downstream_frame,
            tx_power_dbmv=self.cfg.tx_power_dbmv,
            freq_error_hz=self.cfg.freq_error_hz)
        self.attachment.mac = self.cfg.mac
        self.log.notice("power", f"{self.cfg.name} powering on: "
                                 f"MAC {mac_str(self.cfg.mac)}, "
                                 f"{self.cfg.distance_km:.1f} km from the CMTS "
                                 f"(round trip "
                                 f"{2 * self.attachment.delay_s * 1e6:.2f} us)")
        self._set_state(CmState.DS_SCAN)
        self._begin_scan()

    def power_off(self) -> None:
        for t in (self._t1, self._t2, self._t3, self._t4, self._t6,
                  self._lost_sync, self._scan_timer):
            if t:
                t.cancel()
        for t in self._pending_tx:
            t.cancel()
        self._pending_tx.clear()
        self.plant.detach_modem(self.cfg.name)
        self._set_state(CmState.OFFLINE)

    def _set_state(self, state: CmState) -> None:
        if state == self.state:
            return
        self.state = state
        now = self.sched.now()
        self.state_history.append((now, state.value))
        self.log.notice("state", f"{state.value}: {STATE_MEANING[state]}")

    def reinitialize(self, why: str) -> None:
        """Re-initialise the MAC -- what a real modem does on T4 expiry or
        loss of SYNC.  Everything above the PHY is discarded."""
        self.log.error("reinit", f"re-initialising MAC: {why}")
        self.sid = 0
        self.ranging_offset = 0
        self.clock_offset = None
        self.ucd = None
        self.us_channel = None
        self.ip = None
        self.stack.configure("0.0.0.0")
        self.stack.ip = None
        self.us_queue.clear()
        self.outstanding_request = 0
        self.ucc_target = None
        self.registered = False
        self._held_out_for_type29.clear()
        self.ranging_contention.reset()
        self.request_contention.reset()
        for t in (self._t1, self._t2, self._t3, self._t4, self._t6, self._lost_sync):
            if t:
                t.cancel()
        self._set_state(CmState.DS_SCAN)
        self._begin_scan()

    # ==================================================================
    # downstream acquisition
    # ==================================================================
    def _begin_scan(self) -> None:
        self._scan_freq = self.cfg.scan_start_hz
        self._try_next_frequency()

    def _try_next_frequency(self) -> None:
        if self.state not in (CmState.DS_SCAN,):
            return
        freq = self._scan_freq
        match = next((d for d in self.plant.downstreams.values()
                      if abs(d.center_freq_hz - freq) < 100_000), None)
        self.log.info("scan", f"tuning {freq / 1e6:.3f} MHz ... "
                              + ("energy detected" if match else "no carrier"))
        if match is not None:
            self.ds_channel_id = match.channel_id
            self.ds_freq_hz = match.center_freq_hz
            self._set_state(CmState.DS_LOCK)
            self.log.notice("scan",
                            f"downstream lock on {freq / 1e6:.3f} MHz: "
                            f"{match.describe()}")
            self._set_state(CmState.SYNC_WAIT)
            self._arm_lost_sync()
            return
        self._scan_freq += self.cfg.scan_step_hz
        if self._scan_freq > self.cfg.scan_start_hz + 40 * self.cfg.scan_step_hz:
            self._scan_freq = self.cfg.scan_start_hz
        self._scan_timer = self.sched.after(self.cfg.scan_dwell,
                                            self._try_next_frequency, "ds-scan")

    def _arm_lost_sync(self) -> None:
        if self._lost_sync:
            self._lost_sync.cancel()
        self._lost_sync = self.sched.after(
            LOST_SYNC_TIMEOUT, lambda: self.reinitialize(
                f"no SYNC for {LOST_SYNC_TIMEOUT * 1000:.0f} ms (lost sync)"),
            "lost-sync")

    # ==================================================================
    # downstream receive
    # ==================================================================
    def _on_downstream_frame(self, frame: bytes, tx_start: float) -> None:
        if self.state in (CmState.OFFLINE, CmState.DS_SCAN):
            return
        self.counters["ds_frames"] += 1
        try:
            parsed = F.parse(frame)
        except Exception as exc:
            self.log.debug("downstream", f"undecodable downstream frame: {exc}")
            return
        if not parsed.mac.hcs_ok:
            self.log.warn("downstream", "downstream MAC header HCS bad, discarded")
            return
        if parsed.mgmt is not None:
            self.counters["ds_mgmt"] += 1
            self._on_mgmt(parsed, len(frame))
        elif parsed.eth is not None:
            self.counters["ds_pdu"] += 1
            self._on_downstream_pdu(parsed.eth)

    def _on_mgmt(self, parsed: F.ParsedFrame, frame_len: int) -> None:
        mm = parsed.mgmt
        msg = parsed.message
        if msg is None:
            return
        # Management messages are either broadcast to all modems or unicast
        # to one; ignore anything unicast to somebody else.
        if (mm.dst != self.cfg.mac
                and not (mm.dst[0] & 0x01)):
            self.counters["ds_filtered"] += 1
            return

        if isinstance(msg, M.Sync):
            self._on_sync(msg, frame_len)
        elif isinstance(msg, M.Ucd):
            self._on_ucd(msg)
        elif isinstance(msg, M.Map):
            self._on_map(msg)
        elif isinstance(msg, M.RngRsp):
            self._on_rng_rsp(msg)
        elif isinstance(msg, M.RegRsp):
            self._on_reg_rsp(msg)
        elif isinstance(msg, M.UccReq):
            self._on_ucc_req(msg)

    # -- SYNC ------------------------------------------------------------
    def _on_sync(self, msg: M.Sync, frame_len: int) -> None:
        now = self.sched.now()
        ds = self.plant.downstreams[self.ds_channel_id]
        # The CMTS latched the timestamp as the first symbol went out, so by
        # the time the last symbol has arrived the value is one serialisation
        # time stale.  The modem knows the frame length and the downstream
        # rate, so it can correct for that -- but not for the propagation
        # delay, which it has no way to measure.  That residue is exactly
        # what ranging removes.
        serialization = ds.serialization_s(frame_len)
        ts_seconds = msg.timestamp / MASTER_CLOCK_HZ

        if self.clock_offset is None:
            self.clock_offset = (ts_seconds + serialization) - now
            self.log.notice("sync",
                            f"first SYNC: timestamp {msg.timestamp} -> timebase "
                            f"acquired, local clock offset "
                            f"{self.clock_offset * 1e6:+.3f} us "
                            f"(the residual error is the one-way propagation "
                            f"delay, still unknown to the modem)")
        else:
            estimate = now + self.clock_offset
            est_counts = int(round(estimate * MASTER_CLOCK_HZ)) & 0xFFFFFFFF
            drift_counts = timestamp_delta(msg.timestamp, est_counts)
            err = drift_counts / MASTER_CLOCK_HZ + serialization
            self.clock_offset += err
        self.sync_count += 1
        self.last_sync_at = now
        self._arm_lost_sync()

        if self.state == CmState.SYNC_WAIT:
            self._set_state(CmState.UCD_WAIT)
            self._t1 = self.sched.after(
                T1_UCD_WAIT, lambda: self.reinitialize(
                    f"T1 expired: no usable UCD in {T1_UCD_WAIT:.0f} s"), "T1")

    # -- UCD -------------------------------------------------------------
    def _on_ucd(self, msg: M.Ucd) -> None:
        advanced = msg.msg_type == MgmtType.UCD2
        is_20_modem = self.cfg.docsis_version >= DocsisVersion.V20

        if advanced and not is_20_modem:
            return          # a 1.x modem cannot parse a type-29 UCD
        channel = self.plant.upstreams.get(msg.upstream_channel_id)
        if channel is None:
            return

        # Which channel are we interested in at all?
        #
        # A UCC-REQ names one, and until we have moved there nothing else
        # matters.  Otherwise: take the lowest-numbered usable upstream and
        # stay on it, since only a UCC-REQ or a MAC re-initialisation moves a
        # modem afterwards.
        if self.ucc_target is not None:
            if msg.upstream_channel_id != self.ucc_target:
                return
        elif self.ucd is not None:
            current = self.ucd.upstream_channel_id
            if msg.upstream_channel_id != current:
                if (self.state is CmState.OPERATIONAL
                        or msg.upstream_channel_id > current):
                    return
            else:
                if msg.msg_type != self.ucd.msg_type and (
                        self.ucd_is_type29 or not advanced):
                    return      # mixed mode: keep the view we already chose
                if msg.config_change_count == self.ucd_ccc:
                    return      # unchanged, nothing to do
                self.log.notice("ucd",
                                f"UCD change count {self.ucd_ccc} -> "
                                f"{msg.config_change_count}, re-reading "
                                f"upstream parameters")

        if not advanced and channel.advanced and is_20_modem:
            # A 2.0 modem holds out for the type-29 UCD so it can use the
            # advanced-PHY IUCs rather than the 1.x-compatible subset.  Said
            # once per channel, since the CMTS repeats the UCD forever.
            if msg.upstream_channel_id not in self._held_out_for_type29:
                self._held_out_for_type29.add(msg.upstream_channel_id)
                self.log.info("ucd",
                              f"type 2 UCD for US{msg.upstream_channel_id} "
                              f"seen; holding out for the type 29 UCD so the "
                              f"A-TDMA grants are available")
            return

        self.ucd = msg
        self.ucd_is_type29 = advanced
        self.ucd_ccc = msg.config_change_count
        self.us_channel = channel
        self.ucc_target = None
        self.minislot_clock = MinislotClock(msg.minislot_size)
        if self._t1:
            self._t1.cancel()
        self.log.notice("ucd",
                        f"upstream parameters from {'type 29 (DOCSIS 2.0)' if advanced else 'type 2 (DOCSIS 1.x)'} "
                        f"UCD: US{msg.upstream_channel_id} "
                        f"{msg.frequency_hz / 1e6:.3f} MHz "
                        f"{msg.symbol_rate_ksym} ksym/s, mini-slot "
                        f"{msg.minislot_size} ticks "
                        f"({self.minislot_clock.duration_s * 1e6:.2f} us), "
                        f"burst profiles for IUCs "
                        f"{[int(b.iuc) for b in msg.burst_descriptors]}")
        for bd in msg.burst_descriptors:
            self.log.info("ucd", "  " + bd.label())

        if self.state == CmState.UCD_WAIT:
            self._set_state(CmState.RANGING_WAIT)
            self._t2 = self.sched.after(
                T2_INITIAL_MAINT_WAIT, lambda: self.reinitialize(
                    f"T2 expired: no broadcast Initial Maintenance opportunity "
                    f"in {T2_INITIAL_MAINT_WAIT:.0f} s"), "T2")

    # -- MAP -------------------------------------------------------------
    def _on_map(self, themap: M.Map) -> None:
        if self.us_channel is None or themap.upstream_channel_id != self.us_channel.channel_id:
            return
        if self.ucd_ccc is not None and themap.ucd_count != self.ucd_ccc:
            self.log.warn("map", f"MAP references UCD count {themap.ucd_count} "
                                 f"but we hold {self.ucd_ccc}; ignoring MAP")
            return
        self.counters["maps_seen"] += 1
        pending_request = self.request_minislot

        for index, ie in enumerate(themap.ies):
            if ie.iuc == IUC.NULL_IE:
                continue
            start, end = themap.grant_span(index)
            length = end - start
            if ie.sid == SID_BROADCAST and ie.iuc == IUC.INITIAL_MAINT:
                self._offer_initial_maintenance(themap, start, length)
            elif ie.sid == SID_BROADCAST and ie.iuc == IUC.REQUEST:
                self._offer_request_region(themap, start, length)
            elif self.sid and ie.sid == self.sid and ie.iuc == IUC.STATION_MAINT:
                self._offer_station_maintenance(start, length)
            elif self.sid and ie.sid == self.sid and ie.iuc in (
                    IUC.SHORT_DATA_GRANT, IUC.LONG_DATA_GRANT,
                    IUC.ADV_PHY_SHORT_DATA, IUC.ADV_PHY_LONG_DATA):
                if length == 0:
                    self.grant_pending = True
                    self.counters["grant_pending"] += 1
                    self.log.info("bandwidth",
                                  f"zero-length grant for sid {self.sid}: the CMTS "
                                  f"has our request queued but no room yet")
                else:
                    self._use_data_grant(start, length, int(ie.iuc))

        # A request counts as lost only once the CMTS has acknowledged every
        # mini-slot up to the one it went out in (RFIv2.0 8.2.6) *and* this
        # MAP carried neither a grant nor a zero-length grant for us.  The
        # ack-time check has to come after walking the IEs, or a MAP that
        # contains the grant would still look like a loss.
        if (pending_request is not None
                and self.request_minislot == pending_request
                and themap.ack_time >= pending_request
                and not self.grant_pending):
            self.log.warn("bandwidth",
                          f"request sent in mini-slot {pending_request} was not "
                          f"acknowledged by ack-time {themap.ack_time} and this "
                          f"MAP holds no grant for sid {self.sid}: assuming "
                          f"collision, back-off window "
                          f"{self.request_contention.window} -> "
                          f"{min(self.request_contention.window * 2, 1 << self.request_contention.end)}")
            self.counters["collisions_assumed"] += 1
            self.request_minislot = None
            self.outstanding_request = 0
            self.request_contention.backoff()
            self._maybe_request()

    # -- transmit scheduling --------------------------------------------
    def _local_time_of_minislot(self, minislot: int) -> float | None:
        """When this modem must start transmitting to land on `minislot`."""
        if self.clock_offset is None or self.minislot_clock is None:
            return None
        cmts_time = self.minislot_clock.start_of(minislot)
        # Transmit early by the ranging offset, and convert from the CMTS's
        # timebase into local time.
        return cmts_time - self.ranging_offset * TIMING_ADJUST_UNIT_S - self.clock_offset

    def _schedule_burst(self, minislot: int, length: int, iuc: int,
                        data: bytes, comment: str, jitter: bool = True,
                        on_sent: list | None = None) -> bool:
        when = self._local_time_of_minislot(minislot)
        if when is None:
            return False
        if jitter and self.cfg.timing_jitter_units:
            j = self.rng.randint(-self.cfg.timing_jitter_units,
                                 self.cfg.timing_jitter_units)
            when += j * TIMING_ADJUST_UNIT_S
        now = self.sched.now()
        if when < now:
            self.log.warn("upstream",
                          f"missed the transmit opportunity at mini-slot "
                          f"{minislot} ({(now - when) * 1e6:.1f} us late) -- "
                          f"MAP arrived too late")
            return False
        needed = self.us_channel.minislots_for(len(data), iuc)
        if needed > length:
            self.log.warn("upstream",
                          f"{len(data)} bytes needs {needed} mini-slots but the "
                          f"grant is {length}; not transmitting")
            return False
        timer = self.sched.at(when, lambda: self._transmit(
            minislot, minislot + length - 1, iuc, data, comment,
            on_sent or []), name="us-tx")
        self._pending_tx.append(timer)
        return True

    def _transmit(self, first: int, last: int, iuc: int, data: bytes,
                  comment: str, on_sent: list | None = None) -> None:
        if self.us_channel is None:
            return
        self.counters["us_bursts"] += 1
        self.counters["us_bytes"] += len(data)
        self.attachment.tx_power_dbmv = self.tx_power_dbmv
        self.plant.transmit_upstream(self.cfg.name, self.us_channel.channel_id,
                                      data, first, last, iuc, comment)
        for callback in (on_sent or []):
            callback()

    # -- Initial Maintenance --------------------------------------------
    def _offer_initial_maintenance(self, themap: M.Map, start: int, length: int) -> None:
        if self.state != CmState.RANGING_WAIT:
            return
        if self._t2:
            self._t2.cancel()
        c = self.ranging_contention
        defer = c.arm(self.rng, themap.ranging_backoff_start,
                      themap.ranging_backoff_end)
        # The whole region is one transmit opportunity, because it is sized
        # for a burst plus the plant's round-trip uncertainty.
        if defer > 0:
            c.defer -= 1
            self.log.info("ranging",
                          f"Initial Maintenance opportunity at mini-slot {start} "
                          f"({length} mini-slots): deferring, {c.defer + 1} -> "
                          f"{c.defer} left of a random draw from the "
                          f"[0,{c.window - 1}] back-off window")
            return
        c.defer = None
        self.ranging_attempts += 1
        req = M.RngReq(sid=0, downstream_channel_id=self.ds_channel_id or 1)
        frame = F.encode_mgmt(req, self.cfg.mac)
        comment = (f"initial RNG-REQ (SID 0), attempt {self.ranging_attempts}, "
                   f"ranging offset {self.ranging_offset} units -- the burst "
                   f"will arrive late by the round trip")
        if self._schedule_burst(start, length, int(IUC.INITIAL_MAINT), frame, comment):
            self._set_state(CmState.RANGING_INITIAL)
            self.log.notice("ranging",
                            f"transmitting initial RNG-REQ with SID 0 in the "
                            f"Initial Maintenance region at mini-slot {start}")
            self._arm_t3()

    def _arm_t3(self) -> None:
        if self._t3:
            self._t3.cancel()
        self._t3 = self.sched.after(T3_RNG_RSP_WAIT, self._t3_expired, "T3")

    def _t3_expired(self) -> None:
        self.counters["t3_timeouts"] += 1
        if self.state in (CmState.OPERATIONAL, CmState.DHCP, CmState.TOD,
                          CmState.TFTP, CmState.REGISTERING,
                          CmState.RANGING_COMPLETE):
            # A missed RNG-RSP during periodic maintenance is not fatal; T4 is
            # what eventually declares the modem lost.
            self.log.warn("ranging",
                          f"no RNG-RSP for a periodic Station Maintenance "
                          f"RNG-REQ (T3); T4 has "
                          f"{(self._t4.when - self.sched.now()) if self._t4 else 0:.1f} s "
                          f"left before the MAC re-initialises")
            return
        c = self.ranging_contention
        c.backoff()
        self.log.warn("ranging",
                      f"T3 expired ({T3_RNG_RSP_WAIT * 1000:.0f} ms with no "
                      f"RNG-RSP): retry {c.attempts}, back-off window now "
                      f"[0,{c.window - 1}]")
        if c.attempts >= 16:
            self.reinitialize("16 consecutive T3 timeouts: upstream unusable")
            return
        # Nudge the transmit level up a little, as a real modem does when it
        # gets no answer at all.
        self.tx_power_dbmv = min(self.cfg.max_tx_power_dbmv,
                                 self.tx_power_dbmv + 3.0)
        self._set_state(CmState.RANGING_WAIT)

    # -- Station Maintenance --------------------------------------------
    def _offer_station_maintenance(self, start: int, length: int) -> None:
        if self.state in (CmState.OFFLINE, CmState.DS_SCAN):
            return
        self._arm_t4()
        if self.state in (CmState.OFFLINE, CmState.DS_SCAN, CmState.DS_LOCK,
                          CmState.SYNC_WAIT, CmState.UCD_WAIT,
                          CmState.RANGING_WAIT, CmState.REJECTED):
            return
        # A modem answers every Station Maintenance opportunity for as long as
        # it is in service, not just while it is still ranging: that periodic
        # exchange is how the CMTS keeps its timing and level trued up, and
        # how it notices a modem that has gone away.
        req = M.RngReq(sid=self.sid,
                       downstream_channel_id=self.ds_channel_id or 1)
        frame = F.encode_mgmt(req, self.cfg.mac)
        self.ranging_attempts += 1
        comment = (f"RNG-REQ sid={self.sid} in unicast Station Maintenance, "
                   f"ranging offset now {self.ranging_offset} units "
                   f"({self.ranging_offset * TIMING_ADJUST_UNIT_S * 1e6:.2f} us)")
        if self._schedule_burst(start, length, int(IUC.STATION_MAINT),
                                 frame, comment):
            if self.state in (CmState.RANGING_INITIAL, CmState.RANGING_STATION):
                self._set_state(CmState.RANGING_STATION)
            self._arm_t3()

    def _arm_t4(self) -> None:
        if self._t4:
            self._t4.cancel()
        self._t4 = self.sched.after(
            T4_STATION_MAINT_WAIT, lambda: self._t4_expired(), "T4")

    def _t4_expired(self) -> None:
        self.counters["t4_timeouts"] += 1
        self.reinitialize(f"T4 expired: no unicast Station Maintenance "
                          f"opportunity for {T4_STATION_MAINT_WAIT:.0f} s")

    # -- RNG-RSP ---------------------------------------------------------
    def _on_rng_rsp(self, msg: M.RngRsp) -> None:
        if self._t3:
            self._t3.cancel()
        self.rng_rsp_received += 1
        if msg.ranging_status == RangingStatus.ABORT:
            self.reinitialize("CMTS sent ranging status ABORT")
            return
        if self.sid == 0 and msg.sid:
            self.sid = msg.sid
            self.log.notice("ranging", f"CMTS assigned temporary SID {msg.sid}")
        before = self.ranging_offset
        if msg.timing_adjust:
            self.ranging_offset += msg.timing_adjust
        if msg.power_adjust:
            wanted = self.tx_power_dbmv + msg.power_adjust / 4.0
            self.tx_power_dbmv = max(self.cfg.min_tx_power_dbmv,
                                     min(self.cfg.max_tx_power_dbmv, wanted))
            if abs(wanted - self.tx_power_dbmv) > 0.01:
                self.log.warn("ranging",
                              f"CMTS asked for {wanted:.2f} dBmV but the "
                              f"transmitter clamps at "
                              f"{self.tx_power_dbmv:.2f} dBmV "
                              f"(DOCSIS range "
                              f"{self.cfg.min_tx_power_dbmv:.0f}.."
                              f"{self.cfg.max_tx_power_dbmv:.0f} dBmV)")
        if msg.frequency_adjust:
            self.cfg.freq_error_hz += msg.frequency_adjust
            if self.attachment:
                self.attachment.freq_error_hz = self.cfg.freq_error_hz

        self.log.info("ranging",
                      f"RNG-RSP: timing adjust {msg.timing_adjust:+d} units -> "
                      f"ranging offset {before} -> {self.ranging_offset} "
                      f"({self.ranging_offset * TIMING_ADJUST_UNIT_S * 1e6:.2f} us, "
                      f"i.e. transmit this much earlier), tx power now "
                      f"{self.tx_power_dbmv:.2f} dBmV, status "
                      f"{RangingStatus(msg.ranging_status).name}")

        if msg.ranging_status == RangingStatus.SUCCESS:
            self.ranging_contention.reset()
            if self.state not in (CmState.RANGING_INITIAL,
                                  CmState.RANGING_STATION):
                return          # routine maintenance for a modem in service
            self._set_state(CmState.RANGING_COMPLETE)
            self.log.notice("ranging",
                            f"ranging complete: SID {self.sid}, offset "
                            f"{self.ranging_offset} units, "
                            f"tx {self.tx_power_dbmv:.2f} dBmV")
            self._arm_t4()
            if self.registered:
                # This was a re-range after an upstream channel change.  The
                # registration, SID and service flows all survive it, so
                # there is nothing to provision again.
                self.log.notice("ucc",
                                f"back in service on US"
                                f"{self.us_channel.channel_id} with the same "
                                f"SID and service flows -- a channel change "
                                f"re-ranges, it does not re-register")
                self._set_state(CmState.OPERATIONAL)
            else:
                self._start_dhcp()
        elif self.state in (CmState.RANGING_INITIAL, CmState.RANGING_STATION):
            self._set_state(CmState.RANGING_STATION)

    # -- UCC -------------------------------------------------------------
    def _on_ucc_req(self, msg: M.UccReq) -> None:
        if self.us_channel is not None and \
                msg.upstream_channel_id == self.us_channel.channel_id:
            self.log.notice("ucc", f"UCC-REQ names US{msg.upstream_channel_id}, "
                                   f"which we are already using")
            self._queue_management_frame(
                F.encode_mgmt(M.UccRsp(msg.upstream_channel_id), self.cfg.mac),
                "UCC-RSP")
            return
        new = self.plant.upstreams.get(msg.upstream_channel_id)
        if new is None:
            self.log.warn("ucc", f"UCC-REQ names unknown "
                                 f"US{msg.upstream_channel_id}; ignoring")
            return
        self.log.notice("ucc", f"UCC-REQ: move to US{msg.upstream_channel_id}")
        # Acknowledge on the *old* channel before leaving it.
        self._queue_management_frame(
            F.encode_mgmt(M.UccRsp(msg.upstream_channel_id), self.cfg.mac),
            "UCC-RSP", on_sent=self._leave_upstream)
        self.ucc_target = msg.upstream_channel_id

    def _leave_upstream(self) -> None:
        target = self.ucc_target
        self.us_channel = None
        self.ucd = None
        self.ucd_ccc = None
        self.ucd_is_type29 = False
        # Timing is a property of the channel, so the offset does not carry
        # over -- the modem must range again from scratch.
        self.ranging_offset = 0
        self.us_queue.clear()
        self.outstanding_request = 0
        self.request_minislot = None
        self.grant_pending = False
        self.granted_iuc = None
        self.ranging_contention.reset()
        self.request_contention.reset()
        self.log.notice("ucc", f"left the old upstream; waiting for the UCD "
                               f"for US{target} and re-ranging there")
        self._set_state(CmState.RANGING_WAIT)

    # ==================================================================
    # upstream data path
    # ==================================================================
    def _queue_upstream(self, eth_frame: bytes) -> None:
        """Called by the modem's own IP stack and by the CPE bridge."""
        self.us_queue.append(eth_frame)
        self._maybe_request()

    def _queue_management_frame(self, mac_frame: bytes, label: str,
                                on_sent=None) -> None:
        """MAC management messages the modem originates (REG-REQ, REG-ACK,
        UCC-RSP) still need upstream bandwidth like any other frame.

        `on_sent` fires when the frame is actually handed to the plant, not
        when it is queued -- which matters for REG-ACK, since the modem is
        not in service until that acknowledgement has genuinely left.
        """
        self.us_queue.append(("mgmt", mac_frame, label, on_sent))
        self._maybe_request()

    def _queue_size_bytes(self) -> int:
        total = 0
        for item in self.us_queue:
            if isinstance(item, tuple):
                total += len(item[1])
            else:
                total += machdr.HDR_BASE_LEN + 2 + len(item) + 4
        return total

    def _usable_data_iucs(self, long_grant: bool) -> list[int]:
        """Data IUCs this modem could legitimately be granted under.

        Driven by the UCD the modem parsed, not by what the channel is
        capable of: a DOCSIS 1.x modem reads the type-2 UCD, never sees the
        advanced-PHY burst descriptors, and so can only be granted IUC 5/6.
        """
        legacy = int(IUC.LONG_DATA_GRANT if long_grant else IUC.SHORT_DATA_GRANT)
        if self.ucd is None:
            return [legacy]
        have = {int(bd.iuc) for bd in self.ucd.burst_descriptors}
        out = [legacy] if legacy in have else []
        if self.ucd_is_type29:
            adv = int(IUC.ADV_PHY_LONG_DATA if long_grant
                      else IUC.ADV_PHY_SHORT_DATA)
            if adv in have:
                out.append(adv)
        return out or [legacy]

    def _sizing_iuc(self, long_grant: bool) -> int:
        """Which burst profile to size a bandwidth request against.

        A request is denominated in mini-slots, but how many bytes a mini-slot
        holds depends on the modulation of the profile the *CMTS* eventually
        grants under -- and the modem cannot know that choice in advance.  On
        a mixed-mode channel the CMTS withholds advanced-PHY grants until it
        has evidence the modem is DOCSIS 2.0, so early requests may be
        granted at 16-QAM and later ones at 64-QAM.

        The modem therefore sizes against the *least* efficient profile it
        might be handed, which is always sufficient, and narrows to the
        efficient one once it has seen what the CMTS actually grants.
        """
        candidates = self._usable_data_iucs(long_grant)
        if self.granted_iuc is not None and self.granted_iuc in candidates:
            return self.granted_iuc
        return min(candidates,
                   key=lambda i: self.us_channel.bytes_per_minislot(i))

    def _maybe_request(self) -> None:
        if not self.us_queue or self.us_channel is None or not self.sid:
            return
        if self.outstanding_request or self.grant_pending:
            return
        size = self._queue_size_bytes()
        iuc = self._sizing_iuc(long_grant=size > 400)
        need = self.us_channel.minislots_for(size, iuc)
        prof = self.us_channel.profile(iuc)
        if prof and prof.max_burst:
            need = min(need, prof.max_burst)
        self.outstanding_request = max(1, min(255, need))

    def _offer_request_region(self, themap: M.Map, start: int, length: int) -> None:
        if not self.outstanding_request or self.request_minislot is not None:
            return
        if self.us_channel is None:
            return
        prof = self.us_channel.profile(IUC.REQUEST)
        per = max(1, prof.max_burst if prof and prof.max_burst else 1)
        opportunities = max(1, length // per)
        c = self.request_contention
        defer = c.arm(self.rng, themap.data_backoff_start, themap.data_backoff_end)
        if defer >= opportunities:
            c.defer -= opportunities
            self.log.debug("bandwidth",
                           f"Request region has {opportunities} transmit "
                           f"opportunities; deferring past all of them, "
                           f"{c.defer} to go")
            return
        slot = start + defer * per
        c.defer = None
        frame = machdr.build_request(self.sid, self.outstanding_request)
        comment = (f"REQ sid={self.sid} for {self.outstanding_request} mini-slots "
                   f"in contention opportunity {defer + 1}/{opportunities} "
                   f"(back-off window [0,{c.window - 1}])")
        if self._schedule_burst(slot, per, int(IUC.REQUEST), frame, comment):
            self.counters["requests"] += 1
            self.request_minislot = slot
            self.log.info("bandwidth",
                          f"REQ for {self.outstanding_request} mini-slots in "
                          f"contention opportunity {defer + 1} of {opportunities} "
                          f"at mini-slot {slot}")

    def _use_data_grant(self, start: int, length: int, iuc: int) -> None:
        self.grant_pending = False
        self.request_minislot = None
        self.outstanding_request = 0
        self.request_contention.reset()
        if not self.us_queue:
            return
        self.counters["grants"] += 1
        if self.granted_iuc != iuc:
            if self.granted_iuc is not None:
                self.log.notice("bandwidth",
                                f"CMTS switched our data grants from IUC "
                                f"{self.granted_iuc} to IUC {iuc} "
                                f"({self.us_channel.bytes_per_minislot(self.granted_iuc)} "
                                f"-> {self.us_channel.bytes_per_minislot(iuc)} "
                                f"bytes per mini-slot)")
            self.granted_iuc = iuc
        capacity = self.us_channel.payload_capacity(length, iuc)

        frames: list[bytes] = []
        labels: list[str] = []
        callbacks: list = []
        used = 0
        while self.us_queue:
            item = self.us_queue[0]
            if isinstance(item, tuple):
                mac_frame = item[1]
                label = item[2]
                callback = item[3] if len(item) > 3 else None
            else:
                callback = None
                mac_frame = machdr.build_packet_pdu(with_fcs(item))
                label = P.describe(item)
            extra = len(mac_frame)
            if frames and used + extra + machdr.HDR_BASE_LEN + 2 > capacity:
                break
            if not frames and extra > capacity:
                self.log.warn("bandwidth",
                              f"grant of {length} mini-slots under IUC {iuc} "
                              f"holds {capacity} bytes but the head frame is "
                              f"{extra}; re-requesting sized for this profile")
                self.outstanding_request = 0
                self._maybe_request()
                return
            self.us_queue.pop(0)
            frames.append(mac_frame)
            labels.append(label)
            if callback is not None:
                callbacks.append(callback)
            used += extra
            if not self.cfg.concatenation:
                break

        if not frames:
            return
        if len(frames) > 1:
            payload = machdr.build_concatenation(frames)
            self.counters["concatenated"] += 1
            comment = (f"concatenated burst, {len(frames)} MAC frames in one "
                       f"grant: " + "; ".join(labels))
        else:
            payload = frames[0]
            comment = f"data grant: {labels[0]}"
        comment += (f" | grant {length} mini-slots IUC{iuc} "
                    f"({capacity} bytes usable), sid {self.sid}")
        if self._schedule_burst(start, length, iuc, payload, comment,
                                on_sent=callbacks):
            pass
        if self.us_queue:
            self._maybe_request()

    # ==================================================================
    # provisioning: DHCP -> ToD -> TFTP -> registration
    # ==================================================================
    def _start_dhcp(self) -> None:
        self._set_state(CmState.DHCP)
        self.dhcp_xid = self.rng.getrandbits(32)
        msg = D.discover(self.dhcp_xid, self.cfg.mac,
                         vendor_class=vendor_class_identifier(
                             self.cfg.docsis_version,
                             concatenation=self.cfg.concatenation,
                             fragmentation=self.cfg.fragmentation),
                         hostname=self.cfg.name)
        self.log.notice("dhcp",
                        f"DHCPDISCOVER xid={self.dhcp_xid:#010x} -- this is the "
                        f"first thing the modem sends through a data grant "
                        f"rather than a maintenance region")
        self.stack.send_udp("255.255.255.255", D.SERVER_PORT, msg.encode(),
                            sport=D.CLIENT_PORT, src_ip="0.0.0.0")

    def _on_dhcp(self, src_ip: str, sport: int, payload: bytes) -> None:
        msg = D.decode(payload)
        if msg is None or msg.xid != self.dhcp_xid:
            return
        if msg.chaddr[:6] != self.cfg.mac:
            return
        if msg.msg_type == D.OFFER:
            self.dhcp_server_id = P.ip_str(msg.option(D.OPT_SERVER_ID) or b"\x00" * 4)
            self.log.notice("dhcp",
                            f"DHCPOFFER {msg.yiaddr} from {self.dhcp_server_id} "
                            f"(relayed via giaddr {msg.giaddr})")
            req = D.request(self.dhcp_xid, self.cfg.mac, msg.yiaddr,
                            self.dhcp_server_id,
                            vendor_class=vendor_class_identifier(
                                self.cfg.docsis_version,
                                concatenation=self.cfg.concatenation,
                                fragmentation=self.cfg.fragmentation))
            self.stack.send_udp("255.255.255.255", D.SERVER_PORT, req.encode(),
                                sport=D.CLIENT_PORT, src_ip="0.0.0.0")
            return
        if msg.msg_type == D.NAK:
            self.log.error("dhcp", "DHCPNAK; restarting DHCP")
            self.sched.after(1.0, self._start_dhcp, "dhcp-retry")
            return
        if msg.msg_type != D.ACK:
            return

        self.ip = msg.yiaddr
        mask = msg.option(D.OPT_SUBNET_MASK)
        router = msg.option(D.OPT_ROUTER)
        self.netmask = P.ip_str(mask) if mask else "255.255.255.0"
        self.gateway = P.ip_str(router) if router else None
        self.stack.configure(self.ip, self.netmask, self.gateway)
        tod_opt = msg.option(D.OPT_TIME_SERVER)
        self.tod_server = P.ip_str(tod_opt) if tod_opt else None
        self.tftp_server = msg.siaddr if msg.siaddr != "0.0.0.0" else None
        if not self.tftp_server:
            name = msg.option(D.OPT_TFTP_SERVER_NAME)
            self.tftp_server = name.decode(errors="replace") if name else None
        self.config_filename = msg.file.decode(errors="replace") or None
        self.log.notice("dhcp",
                        f"DHCPACK: ip {self.ip}/{self.netmask} gw {self.gateway}, "
                        f"time server {self.tod_server}, "
                        f"tftp {self.tftp_server}, config file "
                        f"{self.config_filename!r}")
        if self.tod_server:
            self._start_tod()
        else:
            self._start_tftp()

    def _start_tod(self) -> None:
        self._set_state(CmState.TOD)
        self.log.notice("tod", f"requesting time of day from {self.tod_server}:37")
        self.stack.send_udp(self.tod_server, TOD.PORT, b"", sport=self.tod_port)
        self._tod_timer = self.sched.after(3.0, self._tod_timeout, "tod")

    def _tod_timeout(self) -> None:
        if self.state == CmState.TOD:
            self.log.warn("tod", "no Time-of-Day response; DOCSIS lets the modem "
                                 "continue and retry later, so carrying on")
            self._start_tftp()

    def _on_tod(self, src_ip: str, sport: int, payload: bytes) -> None:
        value = TOD.decode(payload)
        if value is None:
            return
        self.time_of_day = value
        import datetime
        stamp = datetime.datetime.fromtimestamp(value, datetime.UTC)
        self.log.notice("tod", f"time of day acquired: {stamp:%Y-%m-%d %H:%M:%S} UTC")
        if self.state == CmState.TOD:
            self._start_tftp()

    def _start_tftp(self) -> None:
        if not self.tftp_server or not self.config_filename:
            self.log.error("tftp", "no TFTP server or config file name from DHCP; "
                                   "cannot transfer operational parameters")
            return
        self._set_state(CmState.TFTP)
        self._tftp_block = 0
        self._tftp_buf = b""
        self._tftp_port = 1024 + self.rng.randrange(30000)
        self.stack.bind_udp(self._tftp_port, self._on_tftp)
        self.log.notice("tftp",
                        f"TFTP RRQ {self.config_filename!r} from "
                        f"{self.tftp_server}:69")
        self.stack.send_udp(self.tftp_server, 69,
                            TFTP.rrq(self.config_filename),
                            sport=self._tftp_port)
        self._tftp_timer = self.sched.after(5.0, self._tftp_timeout, "tftp")

    def _tftp_timeout(self) -> None:
        if self.state == CmState.TFTP:
            self.log.error("tftp", "config file download timed out; "
                                   "re-initialising")
            self.reinitialize("TFTP config file download failed")

    def _on_tftp(self, src_ip: str, sport: int, payload: bytes) -> None:
        pkt = TFTP.decode(payload)
        if pkt is None:
            return
        if pkt.opcode == TFTP.ERROR:
            self.log.error("tftp", f"TFTP error {pkt.error_code}: {pkt.message}")
            return
        if pkt.opcode != TFTP.DATA:
            return
        if pkt.block != self._tftp_block + 1:
            self.stack.send_udp(src_ip, sport, TFTP.ack(self._tftp_block),
                                sport=self._tftp_port)
            return
        self._tftp_block = pkt.block
        self._tftp_buf += pkt.payload
        self.stack.send_udp(src_ip, sport, TFTP.ack(pkt.block),
                            sport=self._tftp_port)
        self.log.info("tftp", f"TFTP DATA block {pkt.block} "
                              f"({len(pkt.payload)} bytes), ACKed")
        if len(pkt.payload) < TFTP.BLOCK_SIZE:
            self.config_blob = self._tftp_buf
            self.log.notice("tftp",
                            f"config file complete: {len(self.config_blob)} bytes")
            self._process_config()

    def _process_config(self) -> None:
        self.config_settings = decode_config(self.config_blob)
        # The modem checks the CM MIC to be sure the download was not
        # corrupted.  It cannot check the CMTS MIC -- it has no shared secret,
        # which is the entire point of having two digests.
        result = verify_config(self.config_settings, b"")
        if not result.cm_mic_ok:
            self.log.error("config",
                           f"CM MIC does not match the file contents "
                           f"({result.explain()}); re-initialising")
            self.reinitialize("config file failed its CM MIC check")
            return
        self.log.notice("config",
                        f"CM MIC verifies; {len(self.config_settings)} settings:")
        from ..docsis.cfgfile import dump
        for line in dump(self.config_settings).split("\n"):
            self.log.info("config", "  " + line)
        self._register()

    def _register(self) -> None:
        self._set_state(CmState.REGISTERING)
        # Everything from the config file goes back to the CMTS verbatim, in
        # order -- including both MICs -- plus the modem's own capabilities,
        # which were never in the file.
        settings = [t for t in self.config_settings
                    if t.type not in (int(CfgTLV.PAD), int(CfgTLV.END_OF_DATA))]
        settings = settings + [modem_capabilities(
            docsis_version=self.cfg.docsis_version,
            concatenation=self.cfg.concatenation,
            fragmentation=self.cfg.fragmentation)]
        req = M.RegReq(sid=self.sid, settings=settings)
        frame = F.encode_mgmt(req, self.cfg.mac)
        self.log.notice("registration",
                        f"REG-REQ sid={self.sid}: echoing "
                        f"{len(self.config_settings)} config settings plus "
                        f"modem capabilities (DOCSIS "
                        f"{['1.0', '1.1', '2.0', '3.0'][self.cfg.docsis_version]})")
        self._queue_management_frame(frame, f"REG-REQ sid={self.sid}")
        self._t6 = self.sched.after(T6_REG_RSP_WAIT, self._t6_expired, "T6")

    def _t6_expired(self) -> None:
        self.log.error("registration",
                       f"T6 expired: no REG-RSP within {T6_REG_RSP_WAIT:.0f} s")
        self.reinitialize("T6 expired waiting for REG-RSP")

    def _on_reg_rsp(self, msg: M.RegRsp) -> None:
        if self._t6:
            self._t6.cancel()
        if msg.response != RegRspCode.OK:
            name = RegRspCode(msg.response).name if msg.response in set(RegRspCode) \
                else str(msg.response)
            self.log.error("registration", f"REG-RSP rejected: {name}")
            self._set_state(CmState.REJECTED)
            return
        flows = []
        for t in msg.settings:
            from ..docsis.consts import SFTLV
            sfid = t.get_int(int(SFTLV.SERVICE_FLOW_IDENTIFIER))
            sid = t.get_int(int(SFTLV.SERVICE_IDENTIFIER))
            direction = "us" if t.type == int(CfgTLV.UPSTREAM_SERVICE_FLOW) else "ds"
            flows.append(f"{direction} sfid={sfid}" + (f" sid={sid}" if sid else ""))
        self.log.notice("registration",
                        f"REG-RSP ok: service flows " + ", ".join(flows))
        ack = M.RegAck(sid=self.sid, confirmation_code=ConfirmationCode.OKAY)
        # The modem is not in service until the acknowledgement has actually
        # been transmitted -- it still needs a grant to send it, and on a
        # noisy upstream that burst can be lost like any other.
        self._queue_management_frame(F.encode_mgmt(ack, self.cfg.mac),
                                     f"REG-ACK sid={self.sid}",
                                     on_sent=self._registration_complete)

    def _registration_complete(self) -> None:
        if self.state is CmState.OPERATIONAL:
            return
        self.registered = True
        self._set_state(CmState.OPERATIONAL)
        self.log.notice("online",
                        f"{self.cfg.name} is ONLINE: ip {self.ip}, sid {self.sid}, "
                        f"ranging offset {self.ranging_offset} units, "
                        f"tx {self.tx_power_dbmv:.2f} dBmV")

    # ==================================================================
    # bridging: downstream PDU -> CPE, CPE -> upstream
    # ==================================================================
    def _on_downstream_pdu(self, eth_with_fcs: bytes) -> None:
        eth_frame = eth_with_fcs[:-4] if len(eth_with_fcs) > 4 else eth_with_fcs
        eth = decode_ethernet(eth_frame)
        if eth is None:
            return
        if eth.dst == self.cfg.mac:
            self.stack.receive(eth_frame)
            return
        if eth.is_broadcast or eth.is_multicast:
            self.stack.receive(eth_frame)
            if self.lan_transmit and self.state == CmState.OPERATIONAL:
                self.lan_transmit(eth_frame)
            return
        # A frame for something behind us: bridge it to the LAN side.
        if self.lan_transmit and (eth.dst in self.cpe_macs
                                  or self.state == CmState.OPERATIONAL):
            self.lan_transmit(eth_frame)
        else:
            self.counters["ds_filtered"] += 1

    def attach_lan(self, transmit) -> None:
        """Wire up the LAN side (a simulated CPE, or a host tun interface)."""
        self.lan_transmit = transmit

    def from_lan(self, eth_frame: bytes) -> None:
        """A frame arriving from the CPE side, to be bridged upstream."""
        eth = decode_ethernet(eth_frame)
        if eth is None:
            return
        if self.capture:
            self.capture.cpe(self.sched.now(), eth_frame,
                             f"CPE -> {self.cfg.name}: {P.describe(eth_frame)}")
        if eth.src not in self.cpe_macs and eth.src != self.cfg.mac:
            if len(self.cpe_macs) >= self.cfg.max_cpe:
                self.log.warn("bridge", f"max-cpe {self.cfg.max_cpe} reached, "
                                        f"dropping {mac_str(eth.src)}")
                return
            self.cpe_macs.append(eth.src)
            self.log.notice("bridge", f"learned CPE {mac_str(eth.src)} on the "
                                      f"LAN side")
        if self.state != CmState.OPERATIONAL:
            # Before registration the modem forwards nothing but its own
            # management traffic -- DHCP for a CPE has to wait.
            self.log.debug("bridge", f"not online yet ({self.state.value}); "
                                     f"dropping CPE frame")
            return
        self._queue_upstream(eth_frame)

    def to_lan(self, eth_frame: bytes) -> None:
        if self.lan_transmit:
            if self.capture:
                self.capture.cpe(self.sched.now(), eth_frame,
                                 f"{self.cfg.name} -> CPE: {P.describe(eth_frame)}")
            self.lan_transmit(eth_frame)

    # ==================================================================
    def snapshot(self) -> dict:
        return {
            "name": self.cfg.name,
            "mac": mac_str(self.cfg.mac),
            "state": self.state.value,
            "state_meaning": STATE_MEANING[self.state],
            "ds_freq": self.ds_freq_hz,
            "us_channel": self.us_channel.channel_id if self.us_channel else None,
            "ucd_type": "type 29 (2.0)" if self.ucd_is_type29 else
                        ("type 2 (1.x)" if self.ucd else None),
            "sid": self.sid,
            "ip": self.ip,
            "ranging_offset": self.ranging_offset,
            "ranging_offset_us": self.ranging_offset * TIMING_ADJUST_UNIT_S * 1e6,
            "tx_power": self.tx_power_dbmv,
            "clock_offset_us": (self.clock_offset * 1e6
                                if self.clock_offset is not None else None),
            "sync_count": self.sync_count,
            "config_file": self.config_filename,
            "time_of_day": self.time_of_day,
            "queue": len(self.us_queue),
            "outstanding_request": self.outstanding_request,
            "cpes": [mac_str(m) for m in self.cpe_macs],
            "counters": dict(self.counters),
            "ranging_backoff": self.ranging_contention.window,
            "request_backoff": self.request_contention.window,
        }
