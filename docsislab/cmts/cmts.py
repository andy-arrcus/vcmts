"""The virtual CMTS.

Responsibilities, in the order a modem meets them:

  1. **Downstream timing.**  Emit SYNC at the configured interval so modems
     can slave their clocks, and UCDs describing each upstream.  On a DOCSIS
     2.0 A-TDMA channel narrow enough for DOCSIS 1.x to understand, the CMTS
     emits *both* a type-2 UCD (IUCs 1-6, the 1.x view) and a type-29 UCD
     (adding the advanced-PHY IUCs 9-11) for the same physical channel --
     mixed-mode operation.

  2. **MAPs.**  Delegated to `UpstreamScheduler`.

  3. **Ranging.**  Measure when a burst actually arrived against when it was
     granted, and tell the modem how far to advance its transmit clock.  Same
     for received power and frequency error.  This is the loop that turns
     `init(r1)` into `init(rc)`.

  4. **Provisioning transit.**  Relay the modem's DHCP through to the
     provisioning server (filling in `giaddr` so modems and CPEs land in
     different pools), and forward its Time-of-Day and TFTP traffic.

  5. **Registration.**  Verify the CM MIC and the CMTS MIC over the settings
     the modem echoes back, admit or reject the requested service flows, hand
     out SIDs, and mark the modem `online`.

  6. **Forwarding.**  Route between the cable interface and the network side
     once the modem is online and network access is enabled.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..docsis import frames as F
from ..docsis import machdr
from ..docsis import messages as M
from ..docsis.cfgfile import verify as verify_config
from ..docsis.consts import (CapTLV, CfgTLV, DOCSIS_MGMT_MULTICAST, DocsisVersion,
                             IUC, MgmtType, RangingStatus, RegRspCode, SFTLV,
                             ConfirmationCode)
from ..lab.sim import Scheduler
from ..net import dhcp as D
from ..net import packet as P
from ..net.packet import (ETHERTYPE_IPV4, decode_ethernet, decode_ipv4,
                          mac_bytes, mac_str)
from ..net.stack import IpStack
from ..phy.channel import DownstreamChannel, UpstreamChannel
from ..phy.plant import HfcPlant, UpstreamBurst
from ..util import tlv
from ..util.clock import (TIMING_ADJUST_UNIT_S, MinislotClock, timestamp_at)
from ..util.crc import with_fcs
from .modemdb import ModemDatabase, ModemRecord, ServiceFlow
from .scheduler import SchedulerConfig, UpstreamScheduler


@dataclass
class CmtsConfig:
    """Addressing, timing and admission policy for the CMTS."""
    hostname: str = "vcmts01"
    cable_mac: bytes = field(default_factory=lambda: mac_bytes("0005ca000001"))
    nsi_mac: bytes = field(default_factory=lambda: mac_bytes("0005ca0000fe"))
    #: Cable interface addressing: modems on the primary, CPEs on the secondary.
    cm_gateway: str = "10.10.0.1"
    cm_netmask: str = "255.255.255.0"
    cpe_gateway: str = "10.20.0.1"
    cpe_netmask: str = "255.255.255.0"
    #: Network-side interface.
    nsi_ip: str = "10.30.0.1"
    nsi_netmask: str = "255.255.255.0"
    #: `cable helper-address`: where relayed DHCP goes.
    dhcp_helper: str = "10.30.0.2"
    #: Timing.
    sync_interval: float = 0.020
    #: RFIv2.0 caps the UCD interval at 2 s.  Real CMTSes sit near that
    #: limit, which means a modem that has just locked the downstream can
    #: genuinely wait two seconds for upstream parameters.  The lab default
    #: is faster so a run is watchable; set it to 2.0 for spec-max behaviour.
    ucd_interval: float = 0.5
    #: The provisioning shared secret used to check the CMTS MIC.
    shared_secret: bytes = b"docsislab"
    #: Ranging convergence thresholds.
    timing_tolerance_units: int = 4          # 1/64-tick units (~390 ns)
    #: The receive level the CMTS keeps trimming towards.  It never stops
    #: trimming -- station maintenance corrects power for the modem's whole
    #: life -- so this is a target, not a gate.
    power_tolerance_db: float = 1.0
    #: How far outside the target the receive level may be and still be
    #: demodulated.  Beyond this the burst is not usable and ranging cannot
    #: complete.  A modem sitting at its +8 dBmV floor on a short drop is a
    #: real condition, and it must still be allowed online.
    power_window_db: float = 12.0
    #: Emit a DOCSIS 1.x-compatible type-2 UCD alongside the type-29 UCD.
    mixed_mode_ucd: bool = True
    #: Refuse to admit a service flow asking for more than this.
    max_admitted_us_bps: int = 100_000_000
    max_admitted_ds_bps: int = 1_000_000_000
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)


class Cmts:
    """The CMTS: timing, MAPs, ranging, registration and forwarding."""
    def __init__(self, sched: Scheduler, plant: HfcPlant, cfg: CmtsConfig,
                 log, capture=None):
        self.sched = sched
        self.plant = plant
        self.cfg = cfg
        self.log = log
        self.capture = capture

        self.downstreams: list[DownstreamChannel] = list(plant.downstreams.values())
        self.upstreams: list[UpstreamChannel] = list(plant.upstreams.values())
        self.primary_ds = self.downstreams[0]

        self.modems = ModemDatabase()
        self.schedulers: dict[int, UpstreamScheduler] = {
            us.channel_id: UpstreamScheduler(us, cfg.scheduler, sched.now)
            for us in self.upstreams
        }
        for us_id, scheduler in self.schedulers.items():
            scheduler.iuc_selector = (
                lambda sid, long_grant, _s=scheduler: self._iuc_for(_s, sid, long_grant))
        #: first mini-slot -> (sid, iuc); how the CMTS knows who a burst is from.
        self.region_owner: dict[int, dict[int, tuple[int, int]]] = {
            us.channel_id: {} for us in self.upstreams
        }
        self.ucd_change_count: dict[int, int] = {us.channel_id: 1 for us in self.upstreams}

        self.stats = {
            "sync": 0, "ucd": 0, "maps": 0, "rng_req": 0, "rng_rsp": 0,
            "reg_req": 0, "reg_rsp": 0, "reg_ack": 0, "requests": 0,
            "us_pdus": 0, "ds_pdus": 0, "bad_hcs": 0, "collisions": 0,
            "relayed_dhcp": 0, "rejected": 0, "unknown_sid": 0,
            "out_of_window": 0,
        }
        self.started_at = 0.0
        self._timers: list = []

        # --- IP interfaces ------------------------------------------------
        self.cable_if = IpStack("cable0", cfg.cable_mac, self._transmit_cable,
                                sched.now)
        self.cable_if.configure(cfg.cm_gateway, cfg.cm_netmask,
                                secondary=[(cfg.cpe_gateway, cfg.cpe_netmask)])
        self.cable_if.bind_udp(D.SERVER_PORT, self._relay_from_cable)

        self.nsi_if = IpStack("nsi0", cfg.nsi_mac, self._transmit_nsi, sched.now)
        self.nsi_if.configure(cfg.nsi_ip, cfg.nsi_netmask)
        self.nsi_if.bind_udp(D.SERVER_PORT, self._relay_from_nsi)
        #: Something on the network side to hand non-local traffic to.
        self.nsi_peer: IpStack | None = None
        self.default_gateway: str | None = None

    # ==================================================================
    # lifecycle
    # ==================================================================
    def start(self) -> None:
        self.started_at = self.sched.now()
        self.plant.attach_cmts(self._on_upstream_burst)
        cfg = self.cfg
        for ds in self.downstreams:
            self._timers.append(self.sched.every(
                cfg.sync_interval, lambda ds=ds: self._send_sync(ds),
                name="sync", first=0.0))
        for us in self.upstreams:
            self._timers.append(self.sched.every(
                cfg.ucd_interval, lambda us=us: self._send_ucds(us),
                name="ucd", first=0.001))
            self._timers.append(self.sched.every(
                cfg.scheduler.map_interval, lambda us=us: self._send_map(us),
                name="map", first=0.002))
        self.log.notice("boot", f"{cfg.hostname} up: "
                        f"{len(self.downstreams)} downstream, "
                        f"{len(self.upstreams)} upstream")
        for line in self.plant.describe():
            self.log.info("boot", line)

    def stop(self) -> None:
        for t in self._timers:
            t.cancel()
        self._timers.clear()

    # ==================================================================
    # downstream transmit
    # ==================================================================
    def _send_frame(self, frame: bytes, comment: str, ds: DownstreamChannel | None = None) -> None:
        ds = ds or self.primary_ds
        self.plant.send_downstream(ds.channel_id, frame, comment)

    def _send_mgmt(self, msg, comment: str, dst: bytes = DOCSIS_MGMT_MULTICAST,
                   ds: DownstreamChannel | None = None) -> None:
        frame = F.encode_mgmt(msg, self.cfg.cable_mac, dst)
        self._send_frame(frame, comment, ds)

    def _send_sync(self, ds: DownstreamChannel) -> None:
        now = self.sched.now()
        # The timestamp is latched as the first symbol goes out, so it must
        # reflect the moment of transmission, not the moment of scheduling.
        ts = timestamp_at(now - self.started_at)
        msg = M.Sync(ts)
        self.stats["sync"] += 1
        self._send_mgmt(msg, f"SYNC timestamp={ts} (t={now:.6f}s, "
                             f"10.24 MHz master clock)", ds=ds)

    def _send_ucds(self, us: UpstreamChannel) -> None:
        ccc = self.ucd_change_count[us.channel_id]
        ds_id = self.primary_ds.channel_id
        sched = self.schedulers[us.channel_id]
        sched.ucd_count = ccc

        if us.advanced:
            adv = M.Ucd(
                upstream_channel_id=us.channel_id, config_change_count=ccc,
                minislot_size=us.minislot_ticks, downstream_channel_id=ds_id,
                symbol_rate_ksym=us.symbol_rate_ksym,
                frequency_hz=us.center_freq_hz,
                preamble_pattern=bytes.fromhex("cccccccc" * 8),
                burst_descriptors=list(us.burst_profiles),
                scdma_mode=1 if us.phy_mode == "scdma" else 0,
                maintain_psd=0, ranging_required=1,
                msg_type=MgmtType.UCD2)
            self.stats["ucd"] += 1
            self._send_mgmt(adv, f"Type 29 UCD (DOCSIS 2.0) US{us.channel_id} "
                                 f"ccc={ccc} {us.symbol_rate_ksym} ksym/s "
                                 f"{us.phy_mode.upper()} -- describes IUCs "
                                 f"{[int(b.iuc) for b in us.burst_profiles]}")

        if self.cfg.mixed_mode_ucd and us.describable_by_docsis_1x:
            # A DOCSIS 1.x modem cannot parse a type-29 UCD, so the same
            # channel is advertised again the old way, minus the IUCs that
            # only exist on a 2.0 PHY.
            legacy = [b for b in us.burst_profiles
                      if b.iuc not in (IUC.ADV_PHY_SHORT_DATA,
                                       IUC.ADV_PHY_LONG_DATA, IUC.ADV_PHY_UGS)]
            old = M.Ucd(
                upstream_channel_id=us.channel_id, config_change_count=ccc,
                minislot_size=us.minislot_ticks, downstream_channel_id=ds_id,
                symbol_rate_ksym=us.symbol_rate_ksym,
                frequency_hz=us.center_freq_hz,
                preamble_pattern=bytes.fromhex("cccccccc" * 8),
                burst_descriptors=legacy, msg_type=MgmtType.UCD)
            self.stats["ucd"] += 1
            self._send_mgmt(old, f"Type 2 UCD (DOCSIS 1.x view of the same "
                                 f"US{us.channel_id}) ccc={ccc} -- IUCs "
                                 f"{[int(b.iuc) for b in legacy]}")

    def _send_map(self, us: UpstreamChannel) -> None:
        sched = self.schedulers[us.channel_id]
        themap, record = sched.build()
        owners = self.region_owner[us.channel_id]
        for i, ie in enumerate(record.ies):
            if ie.iuc == IUC.NULL_IE:
                continue
            nxt = (record.ies[i + 1].offset if i + 1 < len(record.ies)
                   else ie.offset)
            owners[record.alloc_start + ie.offset] = (
                ie.sid, int(ie.iuc), max(0, nxt - ie.offset))
        # Keep the lookup table from growing without bound.
        if len(owners) > 4000:
            cutoff = record.alloc_start - 2 * sched.span
            for k in [k for k in owners if k < cutoff]:
                del owners[k]
        self.stats["maps"] += 1
        self._send_mgmt(themap, sched.annotate(record))

    def _iuc_for(self, scheduler: UpstreamScheduler, sid: int,
                 long_grant: bool) -> int:
        """Which data IUC to grant this SID under.

        Advanced-PHY grants (IUC 9/10) only go to modems the CMTS knows are
        DOCSIS 2.0.  Until it has that evidence -- and it has none at all
        when the modem first asks for bandwidth to send DHCP -- it falls back
        to the 1.x-compatible Short/Long Data Grant, which every modem on the
        channel can demodulate.  Watching a modem's grants change from IUC 6
        to IUC 10 partway through provisioning is this rule in action.
        """
        rec = self.modems.by_sid_or_none(sid)
        channel = scheduler.channel
        if rec is not None and rec.adv_phy and channel.advanced:
            return channel.data_iuc(long_grant)
        return int(IUC.LONG_DATA_GRANT if long_grant else IUC.SHORT_DATA_GRANT)

    # ==================================================================
    # upstream receive
    # ==================================================================
    def _on_upstream_burst(self, burst: UpstreamBurst) -> None:
        if burst.collided:
            self.stats["collisions"] += 1
            self.log.warn("upstream",
                          f"burst collision on US{burst.channel_id} "
                          f"minislots {burst.first_minislot}..{burst.last_minislot} "
                          f"(IUC {burst.iuc}) -- both transmissions destroyed")
            self._note_burst_owner(burst, collided=True)
            return
        if burst.lost:
            self.log.warn("upstream",
                          f"burst lost on US{burst.channel_id} "
                          f"minislots {burst.first_minislot}.. {burst.note}")
            return

        entry = self.region_owner[burst.channel_id].get(burst.first_minislot)
        sid = entry[0] if entry else None
        if entry is not None and not self._burst_in_window(burst, entry):
            return
        for frame in machdr.decode_all(burst.data):
            if not frame.hcs_ok:
                self.stats["bad_hcs"] += 1
                self.log.warn("upstream", "MAC header HCS check failed, frame discarded")
                continue
            self._dispatch(frame, burst, sid)

    def _burst_in_window(self, burst: UpstreamBurst,
                         entry: tuple[int, int, int]) -> bool:
        """Did the burst actually land inside the region it was granted?

        The CMTS receiver only listens for a given burst profile during the
        mini-slots it allocated to it.  A modem that transmits too late --
        because it is further away than the plant was engineered for, so its
        round trip exceeds the headroom built into the region -- has its
        burst run off the end and is simply not received.  That is the real
        reason DOCSIS has a maximum plant reach, and it shows up as repeated
        T3 timeouts rather than as any explicit error.
        """
        _sid, _iuc, length = entry
        us = self.plant.upstreams[burst.channel_id]
        region_start = us.clock.start_of(burst.first_minislot)
        region_end = us.clock.start_of(burst.first_minislot + max(1, length))
        # A little slack for the guard time already built into the profile.
        slack = us.minislot_s
        if burst.rx_start < region_start - slack or burst.rx_end > region_end + slack:
            late = (burst.rx_start - region_start) * 1e6
            self.log.warn("upstream",
                          f"burst from a modem in mini-slots "
                          f"{burst.first_minislot}..+{length} arrived "
                          f"{late:+.1f} us from its region "
                          f"({(region_end - region_start) * 1e6:.1f} us long) and "
                          f"ran outside it -- not received. The plant is "
                          f"engineered for {self.cfg.scheduler.max_reach_km:.0f} km; "
                          f"this modem's round trip needs more headroom than "
                          f"the region provides.")
            self.stats["out_of_window"] = self.stats.get("out_of_window", 0) + 1
            return False
        return True

    def _note_burst_owner(self, burst: UpstreamBurst, collided: bool) -> None:
        entry = self.region_owner[burst.channel_id].get(burst.first_minislot)
        rec = self.modems.by_sid_or_none(entry[0]) if entry and entry[0] else None
        if rec and collided:
            rec.us_collisions += 1

    def _dispatch(self, frame: machdr.MacFrame, burst: UpstreamBurst,
                  granted_sid: int | None) -> None:
        if frame.is_request:
            self._handle_request(frame, burst)
            return
        if frame.is_mgmt:
            try:
                parsed = F.parse(frame.raw or frame.encode())
            except Exception as exc:
                self.log.warn("upstream", f"undecodable MAC management message: {exc}")
                return
            self._handle_mgmt(parsed, burst, granted_sid)
            return
        if frame.is_packet_pdu:
            self.stats["us_pdus"] += 1
            self._handle_upstream_pdu(frame.payload, burst, granted_sid)
            return
        self.log.debug("upstream", f"unhandled upstream frame: {frame.describe()}")

    # -- bandwidth requests ---------------------------------------------
    def _handle_request(self, frame: machdr.MacFrame, burst: UpstreamBurst) -> None:
        sid, minislots = frame.sid, frame.mac_parm
        self.stats["requests"] += 1
        rec = self.modems.by_sid_or_none(sid)
        if rec is None:
            self.stats["unknown_sid"] += 1
            self.log.warn("bandwidth", f"Request from unknown SID {sid}, ignored")
            return
        rec.requests_received += 1
        rec.last_heard = self.sched.now()
        sched = self.schedulers[burst.channel_id]
        sched.add_request(sid, minislots)
        iuc = sched.channel.data_iuc(long_grant=minislots > 12)
        self.log.info("bandwidth",
                      f"REQ sid={sid} ({rec.mac_text}) for {minislots} minislots "
                      f"~{sched.channel.payload_capacity(minislots, iuc)} bytes")

    # -- MAC management --------------------------------------------------
    def _handle_mgmt(self, parsed: F.ParsedFrame, burst: UpstreamBurst,
                     granted_sid: int | None) -> None:
        msg = parsed.message
        mm = parsed.mgmt
        if mm is None or msg is None:
            return
        src = mm.src
        if isinstance(msg, M.RngReq):
            self._handle_rng_req(msg, src, burst)
        elif isinstance(msg, M.RegReq):
            self._handle_reg_req(msg, src, burst)
        elif isinstance(msg, M.RegAck):
            self._handle_reg_ack(msg, src, burst)
        elif isinstance(msg, M.UccRsp):
            self.log.info("ucc", f"{mac_str(src)} confirmed move to "
                                 f"US{msg.upstream_channel_id}")
        else:
            self.log.debug("upstream", f"{mac_str(src)}: {msg.summary()}")

    # ==================================================================
    # ranging
    # ==================================================================
    def _handle_rng_req(self, msg: M.RngReq, src: bytes, burst: UpstreamBurst) -> None:
        now = self.sched.now()
        self.stats["rng_req"] += 1
        us = self.plant.upstreams[burst.channel_id]
        sched = self.schedulers[burst.channel_id]
        clock: MinislotClock = us.clock

        initial = msg.sid == 0
        rec = self.modems.get(src)
        if rec is not None and rec.upstream_channel != burst.channel_id:
            # The modem has moved upstream channel (a UCC), so its scheduling
            # moves with it.  Registration and SID survive the move.
            self.schedulers[rec.upstream_channel].untrack_modem(rec.sid)
            self.region_owner.setdefault(burst.channel_id, {})
            rec.upstream_channel = burst.channel_id
            rec.timing_offset = 0
            sched.track_modem(rec.sid, ranging=True)
            self.log.notice("ucc",
                            f"{mac_str(src)} sid={rec.sid} is now ranging on "
                            f"US{burst.channel_id}; it keeps its registration "
                            f"and service flows")
        if rec is None:
            if not initial:
                self.log.warn("ranging", f"RNG-REQ with SID {msg.sid} from unknown "
                                         f"{mac_str(src)}; treating as initial")
            rec = self.modems.create(src, burst.channel_id,
                                     msg.downstream_channel_id or self.primary_ds.channel_id,
                                     now)
            rec.set_state("init(r1)", now)
            sched.track_modem(rec.sid, ranging=True)
            self.log.notice("ranging",
                            f"initial ranging from {mac_str(src)} in the broadcast "
                            f"Initial Maintenance region -- assigned temporary "
                            f"SID {rec.sid}")
        rec.last_heard = now
        rec.ranging_attempts += 1
        rec.us_bursts += 1

        # --- the measurement ------------------------------------------
        # The burst was granted mini-slots starting at `first_minislot`, so
        # that mini-slot's start time is when its first symbol should have
        # arrived.  Anything later is uncorrected round-trip delay.
        expected = clock.start_of(burst.first_minislot)
        error_s = burst.rx_start - expected
        timing_adjust = int(round(error_s / TIMING_ADJUST_UNIT_S))

        target = us.target_rx_power_dbmv
        power_error_db = target - burst.rx_power_dbmv
        power_adjust = int(round(power_error_db * 4))          # 0.25 dB units
        power_adjust = max(-128, min(127, power_adjust))

        att = self.plant.modems.get(self._modem_name(src))
        freq_adjust = -att.freq_error_hz if att else 0
        freq_adjust = max(-32768, min(32767, freq_adjust))

        rec.rx_power_dbmv = burst.rx_power_dbmv
        rec.timing_offset += timing_adjust
        rec.residual_timing_error = timing_adjust
        rec.freq_offset_hz = att.freq_error_hz if att else 0
        rec.snr_db = us.snr_db

        # Ranging exists to fix *timing*: once the burst lands on its
        # mini-slot boundary the modem can be let onto the channel.  Receive
        # level only has to be inside the window the receiver can demodulate;
        # trimming it to the exact target continues for the modem's whole
        # life through station maintenance, which is why every RNG-RSP -- even
        # a successful one -- still carries a power adjustment.
        timing_ok = abs(timing_adjust) <= self.cfg.timing_tolerance_units
        power_usable = abs(power_error_db) <= self.cfg.power_window_db
        converged = timing_ok and power_usable
        if initial:
            # Never finish ranging on the very first exchange: the modem has
            # not yet proved it can hit a unicast Station Maintenance slot.
            converged = False
        if timing_ok and not power_usable:
            self.log.warn("ranging",
                          f"{mac_str(src)} receive level "
                          f"{burst.rx_power_dbmv:+.2f} dBmV is "
                          f"{abs(power_error_db):.1f} dB from the target, "
                          f"outside the {self.cfg.power_window_db:.0f} dB "
                          f"window -- ranging cannot complete until the modem "
                          f"can reach a usable level")
        if abs(power_error_db) <= 0.125:
            power_adjust = 0

        status = RangingStatus.SUCCESS if converged else RangingStatus.CONTINUE
        rsp = M.RngRsp(sid=rec.sid, upstream_channel_id=burst.channel_id,
                       timing_adjust=timing_adjust,
                       power_adjust=power_adjust,
                       frequency_adjust=freq_adjust if freq_adjust else None,
                       ranging_status=status)
        self.stats["rng_rsp"] += 1
        rec.rng_rsp_sent += 1

        detail = (f"RNG-RSP to {mac_str(src)} sid={rec.sid}: burst arrived "
                  f"{error_s * 1e6:+.3f} us from its mini-slot boundary "
                  f"({timing_adjust:+d} x 97.66 ns units), rx power "
                  f"{burst.rx_power_dbmv:+.2f} dBmV vs target {target:+.2f} "
                  f"({power_adjust / 4:+.2f} dB), status "
                  f"{RangingStatus(status).name}")
        self._send_mgmt(rsp, detail, dst=src)
        self.log.info("ranging", detail)

        if status == RangingStatus.SUCCESS:
            if rec.state in ("online", "online(d)"):
                # Routine station maintenance for a modem already in service.
                sched.ranging_complete(rec.sid)
                return
            rec.set_state("init(rc)", now)
            sched.ranging_complete(rec.sid)
            self.log.notice("ranging",
                            f"{mac_str(src)} sid={rec.sid} ranging complete: "
                            f"total timing offset {rec.timing_offset} units "
                            f"({rec.timing_offset * TIMING_ADJUST_UNIT_S * 1e6:.2f} us "
                            f"round trip)")
        elif rec.state not in ("online", "online(d)"):
            if rec.state == "offline":
                rec.set_state("init(r1)", now)
            elif rec.state == "init(r1)" and rec.ranging_attempts > 1:
                rec.set_state("init(r2)", now)

    def _modem_name(self, mac: bytes) -> str:
        """Which plant attachment a MAC address belongs to.

        Only used to read back the modem's synthesiser error so the CMTS has
        something real to correct with the RNG-RSP frequency adjustment; a
        real CMTS measures it off the burst.
        """
        for name, att in self.plant.modems.items():
            if getattr(att, "mac", None) == mac:
                return name
        return ""

    # ==================================================================
    # registration
    # ==================================================================
    def _handle_reg_req(self, msg: M.RegReq, src: bytes, burst: UpstreamBurst) -> None:
        now = self.sched.now()
        self.stats["reg_req"] += 1
        rec = self.modems.get(src) or self.modems.by_sid_or_none(msg.sid)
        if rec is None:
            self.log.warn("registration",
                          f"REG-REQ from unranged modem {mac_str(src)}, ignored")
            return
        rec.last_heard = now
        settings = msg.settings

        # --- capabilities ---------------------------------------------
        caps = tlv.find(settings, int(CfgTLV.MODEM_CAPABILITIES))
        if caps is not None:
            for sub in caps.sub:
                rec.capabilities[CapTLV(sub.type).name
                                 if sub.type in set(CapTLV) else str(sub.type)] = sub.as_int
            ver = caps.get_int(int(CapTLV.DOCSIS_VERSION), 0)
            rec.docsis_version = {0: "1.0", 1: "1.1", 2: "2.0", 3: "3.0"}.get(ver, str(ver))
            rec.adv_phy = ver >= int(DocsisVersion.V20)
            rates = caps.get_int(int(CapTLV.UPSTREAM_SYMBOL_RATES))
            if rates is not None:
                supported = [r for bit, r in ((0x01, 160), (0x02, 320), (0x04, 640),
                                              (0x08, 1280), (0x10, 2560), (0x20, 5120))
                             if rates & bit]
                self.log.info("registration",
                              f"{mac_str(src)} supports upstream symbol rates "
                              f"{supported} ksym/s"
                              + (" -- includes the 5120 ksym/s that only a "
                                 "DOCSIS 2.0 transmitter can produce"
                                 if rates & 0x20 else ""))

        # --- MIC verification -----------------------------------------
        result = verify_config(settings, self.cfg.shared_secret)
        if not result.ok:
            rec.set_state("reject(m)", now)
            self.stats["rejected"] += 1
            self.log.error("registration",
                           f"REG-REQ from {mac_str(src)} rejected: {result.explain()}")
            rsp = M.RegRsp(sid=rec.sid, response=RegRspCode.AUTH_FAILURE)
            self.stats["reg_rsp"] += 1
            self._send_mgmt(rsp, f"REG-RSP authentication failure to {mac_str(src)}: "
                                 f"{result.explain()}", dst=src)
            return

        # --- admission control ----------------------------------------
        rec.network_access = bool(tlv.find(settings, int(CfgTLV.NETWORK_ACCESS_CONTROL))
                                  and tlv.find(settings, int(CfgTLV.NETWORK_ACCESS_CONTROL)).as_int)
        max_cpe = tlv.find(settings, int(CfgTLV.MAX_CPE))
        rec.max_cpe = max_cpe.as_int if max_cpe else 1
        priv = tlv.find(settings, int(CfgTLV.PRIVACY_ENABLE))
        rec.privacy_enabled = bool(priv and priv.as_int)

        flows, reply_tlvs, reject = self._admit_service_flows(rec, settings)
        if reject is not None:
            rec.set_state("reject(c)", now)
            self.stats["rejected"] += 1
            self.log.error("registration",
                           f"REG-REQ from {mac_str(src)} rejected: {reject}")
            rsp = M.RegRsp(sid=rec.sid, response=RegRspCode.CLASS_OF_SERVICE_FAILURE)
            self.stats["reg_rsp"] += 1
            self._send_mgmt(rsp, f"REG-RSP class-of-service failure: {reject}", dst=src)
            return

        rec.service_flows = flows
        rsp = M.RegRsp(sid=rec.sid, response=RegRspCode.OK, settings=reply_tlvs)
        self.stats["reg_rsp"] += 1
        detail = (f"REG-RSP ok to {mac_str(src)} sid={rec.sid}: "
                  + "; ".join(sf.describe() for sf in flows))
        self._send_mgmt(rsp, detail, dst=src)
        self.log.notice("registration", detail)

    def _admit_service_flows(self, rec: ModemRecord, settings: list[tlv.TLV]):
        """Turn the config file's service flow encodings into admitted flows.

        The CMTS assigns the SFIDs and, for upstream flows, the SIDs -- the
        config file only carries *references*, which is what lets the same
        file be handed to every modem.
        """
        flows: list[ServiceFlow] = []
        reply: list[tlv.TLV] = []
        first_us = True
        first_ds = True
        for t in settings:
            upstream = t.type == int(CfgTLV.UPSTREAM_SERVICE_FLOW)
            downstream = t.type == int(CfgTLV.DOWNSTREAM_SERVICE_FLOW)
            if not (upstream or downstream):
                continue
            ref = t.get_int(int(SFTLV.SERVICE_FLOW_REFERENCE), 0)
            rate = t.get_int(int(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE), 0) or 0
            limit = (self.cfg.max_admitted_us_bps if upstream
                     else self.cfg.max_admitted_ds_bps)
            if rate > limit:
                return [], [], (f"service flow ref {ref} asks for "
                                f"{rate / 1e6:.1f} Mbit/s, above the "
                                f"{limit / 1e6:.1f} Mbit/s admission limit")
            sfid = self.modems.allocate_sfid()
            sf = ServiceFlow(
                sfid=sfid, sid=rec.sid if upstream else None,
                direction="us" if upstream else "ds",
                scheduling=t.get_int(int(SFTLV.SCHEDULING_TYPE), 2) or 2,
                max_sustained_bps=rate,
                min_reserved_bps=t.get_int(int(SFTLV.MIN_RESERVED_TRAFFIC_RATE), 0) or 0,
                max_burst_bytes=t.get_int(int(SFTLV.MAX_TRAFFIC_BURST), 0) or 0,
                priority=t.get_int(int(SFTLV.TRAFFIC_PRIORITY), 0) or 0,
                primary=(first_us if upstream else first_ds),
            )
            if upstream:
                first_us = False
            else:
                first_ds = False
            flows.append(sf)
            subs = [tlv.u16(SFTLV.SERVICE_FLOW_REFERENCE, ref),
                    tlv.u32(SFTLV.SERVICE_FLOW_IDENTIFIER, sfid)]
            if upstream:
                subs.append(tlv.u16(SFTLV.SERVICE_IDENTIFIER, rec.sid))
            reply.append(tlv.compound(
                CfgTLV.UPSTREAM_SERVICE_FLOW if upstream
                else CfgTLV.DOWNSTREAM_SERVICE_FLOW, subs))
        return flows, reply, None

    def _handle_reg_ack(self, msg: M.RegAck, src: bytes, burst: UpstreamBurst) -> None:
        now = self.sched.now()
        self.stats["reg_ack"] += 1
        rec = self.modems.get(src) or self.modems.by_sid_or_none(msg.sid)
        if rec is None:
            return
        rec.last_heard = now
        if msg.confirmation_code != ConfirmationCode.OKAY:
            self.log.error("registration",
                           f"REG-ACK from {mac_str(src)} reports "
                           f"confirmation code {msg.confirmation_code}")
            rec.set_state("reject(c)", now)
            return
        state = "online" if rec.network_access else "online(d)"
        rec.set_state(state, now)
        self.schedulers[rec.upstream_channel].track_modem(rec.sid, ranging=False)
        self.log.notice("registration",
                        f"{mac_str(src)} sid={rec.sid} is {state.upper()} "
                        f"(DOCSIS {rec.docsis_version}, "
                        f"{len(rec.service_flows)} service flows, "
                        f"privacy {'on' if rec.privacy_enabled else 'off'})")

    # ==================================================================
    # forwarding
    # ==================================================================
    def _transmit_cable(self, eth_frame: bytes) -> None:
        """Send an Ethernet frame downstream inside a Packet PDU."""
        pdu = machdr.build_packet_pdu(with_fcs(eth_frame))
        self.stats["ds_pdus"] += 1
        self._send_frame(pdu, f"downstream PDU: {P.describe(eth_frame)}")

    def _transmit_nsi(self, eth_frame: bytes) -> None:
        if self.capture:
            self.capture.nsi(self.sched.now(), eth_frame,
                             f"CMTS NSI tx: {P.describe(eth_frame)}")
        if self.nsi_peer is not None:
            peer = self.nsi_peer
            self.sched.after(0.000_050, lambda: peer.receive(eth_frame),
                             name="nsi")

    @property
    def local_addresses(self) -> set[str]:
        return set(self.cable_if.addresses) | set(self.nsi_if.addresses)

    def _deliver_local(self, ip, ingress: IpStack) -> None:
        """Handle a packet addressed to one of our own IP addresses.

        A DHCP relay makes this necessary: the server replies to `giaddr`,
        which is the *cable* interface address, but the reply arrives on the
        network side.  A router accepts traffic for any of its addresses on
        any interface, so the relay handler has to be reachable that way.
        """
        if ip.proto == P.IPPROTO_UDP:
            udp = P.decode_udp(ip.payload)
            if udp is None:
                return
            handler = (ingress.udp_handlers.get(udp.dport)
                       or self.cable_if.udp_handlers.get(udp.dport)
                       or self.nsi_if.udp_handlers.get(udp.dport))
            if handler:
                handler(ip.src, udp.sport, udp.payload)
            return
        if ip.proto == P.IPPROTO_ICMP:
            icmp = P.decode_icmp(ip.payload)
            if icmp and icmp.type == P.ICMP_ECHO_REQUEST:
                reply = P.icmp_echo(ip.dst, ip.src, icmp.ident, icmp.seq,
                                    icmp.payload, reply=True)
                out = P.decode_ipv4(reply)
                if self.cable_if.address_for(ip.src):
                    self.cable_if.send_ip(reply, ip.src,
                                          self.cable_if.arp_cache.get(ip.src))
                else:
                    self.nsi_if.send_ip(reply, ip.src)

    def receive_nsi(self, eth_frame: bytes) -> None:
        if self.capture:
            self.capture.nsi(self.sched.now(), eth_frame,
                             f"CMTS NSI rx: {P.describe(eth_frame)}")
        eth = decode_ethernet(eth_frame)
        if eth is None:
            return
        self.nsi_if.receive(eth_frame)
        if eth.ethertype == ETHERTYPE_IPV4 and eth.dst == self.cfg.nsi_mac:
            ip = decode_ipv4(eth.payload)
            if ip is None or self.nsi_if.is_local_address(ip.dst):
                return
            if ip.dst in self.local_addresses:
                self._deliver_local(ip, self.nsi_if)
                return
            self._route(ip, from_cable=False)

    def _handle_upstream_pdu(self, eth_with_fcs: bytes, burst: UpstreamBurst,
                             sid: int | None) -> None:
        eth_frame = eth_with_fcs[:-4] if len(eth_with_fcs) > 4 else eth_with_fcs
        eth = decode_ethernet(eth_frame)
        if eth is None:
            return
        rec = self.modems.by_sid_or_none(sid) if sid else None
        if rec is None:
            self.stats["unknown_sid"] += 1
            self.log.warn("forwarding",
                          f"upstream PDU in mini-slots granted to no known SID "
                          f"({sid}), discarded")
            return
        rec.last_heard = self.sched.now()
        rec.us_bursts += 1

        # A frame whose source is not the modem itself came from a CPE behind it.
        if eth.src != rec.mac:
            if eth.src not in self.modems.cpe_owner:
                if self.modems.learn_cpe(eth.src, rec):
                    self.log.notice("forwarding",
                                    f"learned CPE {mac_str(eth.src)} behind "
                                    f"{rec.mac_text} (sid {rec.sid}), "
                                    f"{len(rec.cpe_macs)}/{rec.max_cpe} used")
                else:
                    self.log.warn("forwarding",
                                  f"CPE {mac_str(eth.src)} behind {rec.mac_text} "
                                  f"exceeds max-cpe {rec.max_cpe}, dropped")
                    return
            if not rec.network_access or rec.state not in ("online",):
                self.log.warn("forwarding",
                              f"dropping CPE traffic from {mac_str(eth.src)}: "
                              f"modem is {rec.state}"
                              + ("" if rec.network_access else " with network access off"))
                return

        sf = rec.primary_sf("us")
        if sf:
            sf.packets += 1
            sf.bytes += len(eth_frame)
        if eth.src == rec.mac:
            self._track_provisioning(rec, eth)

        self.cable_if.receive(eth_frame)
        if eth.ethertype == ETHERTYPE_IPV4 and eth.dst == self.cfg.cable_mac:
            ip = decode_ipv4(eth.payload)
            if ip is None or self.cable_if.is_local_address(ip.dst):
                return
            if ip.dst in self.local_addresses:
                self._deliver_local(ip, self.cable_if)
                return
            self._route(ip, from_cable=True)

    def _track_provisioning(self, rec: ModemRecord, eth) -> None:
        """Watch a modem's own traffic to report how far it has got.

        A CMTS has no direct visibility into the modem's state machine, so
        the `init(t)` and `init(o)` states are inferred exactly this way:
        by noticing the Time-of-Day and TFTP traffic going past.  That is why
        those states are such a useful diagnostic -- they say which
        *provisioning server* the modem is stuck on.
        """
        if eth.ethertype != ETHERTYPE_IPV4:
            return
        ip = decode_ipv4(eth.payload)
        if ip is None or ip.proto != P.IPPROTO_UDP:
            return
        udp = P.decode_udp(ip.payload)
        if udp is None:
            return
        now = self.sched.now()
        if udp.dport == 37 and rec.state in ("init(i)", "init(d)", "init(rc)"):
            rec.set_state("init(t)", now)
            self.log.info("provisioning",
                          f"{rec.mac_text} is asking {ip.dst} for time of day")
        elif udp.dport == 69 and rec.state in ("init(i)", "init(t)", "init(d)",
                                               "init(rc)"):
            rec.set_state("init(o)", now)
            self.log.info("provisioning",
                          f"{rec.mac_text} is fetching its configuration file "
                          f"from {ip.dst}")

    def _route(self, ip, from_cable: bool) -> None:
        """Forward an IP packet between the cable interface and the NSI."""
        if ip.ttl <= 1:
            self.log.debug("forwarding", f"TTL expired for {ip.src} -> {ip.dst}")
            return
        ip.ttl -= 1
        pkt = ip.encode()
        if self.cable_if.address_for(ip.dst):
            dst_mac = self._cable_mac_for(ip.dst)
            self.cable_if.send_ip(pkt, ip.dst, dst_mac)
        elif self.nsi_if.address_for(ip.dst):
            self.nsi_if.send_ip(pkt, ip.dst)
        elif self.default_gateway:
            self.nsi_if.send_ip(pkt, self.default_gateway)
        else:
            self.log.debug("forwarding", f"no route for {ip.dst}")

    def _cable_mac_for(self, dst_ip: str) -> bytes | None:
        return self.cable_if.arp_cache.get(dst_ip)

    # -- DHCP relay ------------------------------------------------------
    def _relay_from_cable(self, src_ip: str, sport: int, payload: bytes) -> None:
        """`cable helper-address`: stamp giaddr and forward to the server."""
        msg = D.decode(payload)
        if msg is None or msg.op != D.BOOTREQUEST:
            return
        chaddr = msg.chaddr[:6]
        rec = self.modems.get(chaddr)
        if rec is not None:
            giaddr = self.cfg.cm_gateway
            who = f"cable modem {mac_str(chaddr)} (sid {rec.sid})"
            if rec.state in ("init(rc)", "init(r2)", "init(r1)"):
                rec.set_state("init(d)", self.sched.now())
            # DHCP option 60 on a cable modem is "docsisX.Y:" followed by its
            # capability TLVs in ASCII hex.  It is the earliest point at which
            # the CMTS can tell a 2.0 modem from a 1.1 one, which is what
            # decides whether it may be given advanced-PHY grants.
            vendor = msg.option(D.OPT_VENDOR_CLASS) or b""
            if vendor.startswith(b"docsis") and b":" in vendor:
                version = vendor.split(b":", 1)[0][len(b"docsis"):].decode(
                    errors="replace")
                if rec.docsis_version != version:
                    rec.docsis_version = version
                    rec.adv_phy = version >= "2.0"
                    self.log.notice(
                        "dhcp",
                        f"{mac_str(chaddr)} identifies as DOCSIS {version} in "
                        f"its DHCP vendor class; advanced-PHY grants "
                        f"(IUC 9/10) {'enabled' if rec.adv_phy else 'withheld'}")
        else:
            giaddr = self.cfg.cpe_gateway
            owner = self.modems.cpe_owner.get(chaddr)
            who = (f"CPE {mac_str(chaddr)} behind "
                   f"{owner.mac_text if owner else 'unknown modem'}")
        msg.giaddr = giaddr
        self.stats["relayed_dhcp"] += 1
        self.log.info("dhcp",
                      f"relaying {msg.msg_name} from {who} to helper "
                      f"{self.cfg.dhcp_helper}, giaddr={giaddr} "
                      f"(giaddr is what selects the address pool)")
        self.nsi_if.send_udp(self.cfg.dhcp_helper, D.SERVER_PORT, msg.encode(),
                             sport=D.SERVER_PORT, src_ip=self.cfg.nsi_ip)

    def _relay_from_nsi(self, src_ip: str, sport: int, payload: bytes) -> None:
        """Server -> relay -> client, back down the cable."""
        msg = D.decode(payload)
        if msg is None or msg.op != D.BOOTREPLY:
            return
        chaddr = msg.chaddr[:6]
        rec = self.modems.get(chaddr)
        now = self.sched.now()
        if rec is not None and msg.msg_type == D.ACK:
            rec.ip = msg.yiaddr
            rec.config_file = msg.file.decode(errors="replace") or None
            if rec.state in ("init(d)", "init(rc)"):
                rec.set_state("init(i)", now)
        source = (self.cfg.cm_gateway if rec is not None else self.cfg.cpe_gateway)
        self.log.info("dhcp",
                      f"relaying {msg.msg_name} to {mac_str(chaddr)} "
                      f"yiaddr={msg.yiaddr}"
                      + (f" tftp={msg.siaddr} file={msg.file.decode(errors='replace')}"
                         if msg.siaddr != "0.0.0.0" else ""))
        # Unicast to the client's MAC: it has no IP configured yet, so it is
        # matching on xid and chaddr rather than on destination address.
        dst_ip = msg.yiaddr if msg.yiaddr != "0.0.0.0" else "255.255.255.255"
        self.cable_if.send_udp(dst_ip, D.CLIENT_PORT, msg.encode(),
                               sport=D.SERVER_PORT, src_ip=source,
                               dst_mac=chaddr)

    # ==================================================================
    # operator-visible state
    # ==================================================================
    def snapshot(self) -> dict:
        now = self.sched.now()
        return {
            "hostname": self.cfg.hostname,
            "now": now,
            "uptime": now - self.started_at,
            "stats": dict(self.stats),
            "plant": dict(self.plant.stats),
            "states": self.modems.count_by_state(),
            "modems": [
                {
                    "mac": r.mac_text, "sid": r.sid, "state": r.state,
                    "ip": r.ip, "us": r.upstream_channel, "ds": r.downstream_channel,
                    "timing": r.timing_offset, "rx_power": r.rx_power_dbmv,
                    "snr": r.snr_db, "version": r.docsis_version,
                    "uptime": r.uptime(now), "flows": len(r.service_flows),
                    "cpes": len(r.cpe_macs), "requests": r.requests_received,
                    "ranging": r.ranging_attempts, "flaps": r.flaps,
                    "config": r.config_file,
                }
                for r in self.modems.modems
            ],
            "upstreams": [
                {
                    "id": us.channel_id,
                    "describe": us.describe(),
                    "maps": self.schedulers[us.channel_id].maps_sent,
                    "pending": len(self.schedulers[us.channel_id].pending),
                    "granted": self.schedulers[us.channel_id].granted_minislots,
                    "contention": self.schedulers[us.channel_id].contention_minislots,
                    "next_minislot": self.schedulers[us.channel_id].next_minislot,
                }
                for us in self.upstreams
            ],
            "downstreams": [{"id": ds.channel_id, "describe": ds.describe()}
                            for ds in self.downstreams],
        }
