"""The upstream scheduler: everything that ends up inside a MAP.

The MAP is the only thing that lets a modem transmit at all, so this module
is the heart of the CMTS.  Every MAP tiles a fixed span of mini-slots and
divides it between:

  * an **Initial Maintenance** region (IUC 3, broadcast SID) offered
    periodically, into which unranged modems fire their first RNG-REQ.  It is
    sized to hold one ranging burst *plus* the worst-case round trip of the
    plant, because a modem that has never ranged transmits with no timing
    correction and its burst therefore lands late by up to that round trip.
    That is why it counts as a single transmit opportunity no matter how many
    mini-slots long it is.

  * **Station Maintenance** regions (IUC 4, unicast) that poll each known
    modem so it can keep its timing trued up -- fast while a modem is still
    ranging, slow once it is online.

  * **Data grants** (IUC 9/10 on a DOCSIS 2.0 channel, 5/6 on 1.x) issued in
    response to Request frames.  A request the CMTS cannot satisfy yet gets a
    zero-length grant, which tells the modem "heard you, wait" rather than
    letting it time out and re-request.

  * a **Request** contention region (IUC 1) where modems ask for bandwidth,
    and where they collide with each other.

  * a closing **Null IE**, whose offset is what actually terminates the last
    grant -- a grant runs from its own offset to the offset of the next IE.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..docsis.consts import IUC, SID_BROADCAST
from ..docsis.messages import Map, MapIE
from ..phy.channel import UpstreamChannel
from ..util.clock import MinislotClock


@dataclass
class SchedulerConfig:
    """MAP cadence, region sizing and the advertised back-off windows."""
    #: How much upstream time one MAP describes.
    map_interval: float = 0.004
    #: How far ahead of its Alloc Start Time a MAP is transmitted.  Must
    #: exceed the downstream propagation plus the modem's processing time
    #: plus the largest ranging offset in the plant.
    map_advance: float = 0.002
    #: How often a broadcast Initial Maintenance region is offered.
    initial_maint_interval: float = 0.200
    #: Unicast Station Maintenance cadence while a modem is still ranging...
    station_maint_interval_ranging: float = 0.020
    #: ...and once it is online.
    station_maint_interval: float = 5.0
    #: Mini-slots of contention Request region per MAP.
    request_region_minislots: int = 6
    #: Furthest a modem may be from the CMTS; sizes the Initial Maintenance
    #: region and bounds how large a timing correction ranging can apply.
    max_reach_km: float = 25.0
    #: Back-off exponents advertised in every MAP (RFIv2.0 8.2.6).
    ranging_backoff_start: int = 0
    ranging_backoff_end: int = 4
    data_backoff_start: int = 0
    data_backoff_end: int = 4
    #: Largest data grant in one MAP, mini-slots (0 = only the IUC's own cap).
    max_grant_minislots: int = 0


@dataclass
class PendingRequest:
    """A bandwidth request the CMTS has not yet satisfied."""
    sid: int
    minislots: int
    requested_at: float
    #: True once the CMTS has told the modem "pending" at least once.
    acknowledged: bool = False


@dataclass
class MapRecord:
    """What the scheduler decided, kept for `show` commands and annotations."""
    alloc_start: int
    ack_time: int
    span: int
    ies: list[MapIE]
    initial_maint: bool
    station_maint_sids: list[int]
    grants: list[tuple[int, int, int]]      # (sid, minislots, iuc)
    pending_grants: list[int]


class UpstreamScheduler:
    """Builds the MAPs for one upstream channel."""
    def __init__(self, channel: UpstreamChannel, cfg: SchedulerConfig,
                 now: callable):
        self.channel = channel
        self.cfg = cfg
        self._now = now
        self.clock: MinislotClock = channel.clock
        #: Next mini-slot not yet described by any MAP.
        self.next_minislot = 0
        self.ucd_count = 1
        self.maps_sent = 0

        self.pending: dict[int, PendingRequest] = {}
        #: sid -> next time a Station Maintenance opportunity is due
        self.station_maint_due: dict[int, float] = {}
        #: sids still ranging, so they get the fast maintenance cadence
        self.ranging_sids: set[int] = set()
        self._next_initial_maint = 0.0
        self.last_map: MapRecord | None = None
        self.granted_minislots = 0
        self.contention_minislots = 0
        #: Chooses the data IUC for a SID.  The CMTS supplies this so that a
        #: DOCSIS 1.x modem is never handed an advanced-PHY grant it cannot
        #: demodulate; the default is the channel's own preference.
        self.iuc_selector = lambda sid, long_grant: self.channel.data_iuc(long_grant)

    # ------------------------------------------------------------------
    # region sizing
    # ------------------------------------------------------------------
    @property
    def span(self) -> int:
        return max(1, int(round(self.cfg.map_interval / self.clock.duration_s)))

    @property
    def round_trip_minislots(self) -> int:
        """Worst-case plant round trip, in mini-slots."""
        from ..phy.plant import delay_for_km
        rtt = 2 * delay_for_km(self.cfg.max_reach_km)
        return int(math.ceil(rtt / self.clock.duration_s))

    def initial_maint_minislots(self, rng_req_bytes: int = 30) -> int:
        """One ranging burst plus the plant's round-trip uncertainty."""
        burst = self.channel.minislots_for(rng_req_bytes, IUC.INITIAL_MAINT)
        return burst + self.round_trip_minislots

    def station_maint_minislots(self, rng_req_bytes: int = 30) -> int:
        """A ranged modem transmits on time, so no uncertainty padding."""
        return self.channel.minislots_for(rng_req_bytes, IUC.STATION_MAINT) + 1

    # ------------------------------------------------------------------
    # bookkeeping driven by the CMTS
    # ------------------------------------------------------------------
    def add_request(self, sid: int, minislots: int) -> None:
        """Record a Request frame.  A new request replaces any older one
        (RFIv2.0 8.2.5: a request is for the modem's *total* current need)."""
        self.pending[sid] = PendingRequest(sid, minislots, self._now())

    def add_unsolicited(self, sid: int, minislots: int) -> None:
        """Queue a grant the modem did not ask for -- used to get the first
        DHCP DISCOVER out before the modem has a data path to request on."""
        existing = self.pending.get(sid)
        want = max(minislots, existing.minislots if existing else 0)
        self.pending[sid] = PendingRequest(sid, want, self._now())

    def track_modem(self, sid: int, ranging: bool = True) -> None:
        self.station_maint_due.setdefault(sid, self._now())
        if ranging:
            self.ranging_sids.add(sid)
        else:
            self.ranging_sids.discard(sid)

    def untrack_modem(self, sid: int) -> None:
        self.station_maint_due.pop(sid, None)
        self.ranging_sids.discard(sid)
        self.pending.pop(sid, None)

    def ranging_complete(self, sid: int) -> None:
        self.ranging_sids.discard(sid)
        self.station_maint_due[sid] = self._now() + self.cfg.station_maint_interval

    # ------------------------------------------------------------------
    # the MAP itself
    # ------------------------------------------------------------------
    def build(self) -> tuple[Map, MapRecord]:
        now = self._now()
        cfg = self.cfg
        span = self.span

        # A MAP must start far enough ahead that every modem can receive it,
        # apply its ranging offset and still hit the first mini-slot.
        earliest = self.clock.number_at(now + cfg.map_advance) + 1
        alloc_start = max(self.next_minislot, earliest)
        ack_time = self.clock.number_at(now)

        ies: list[MapIE] = []
        offset = 0
        record_sm: list[int] = []
        record_grants: list[tuple[int, int, int]] = []
        record_pending: list[int] = []
        did_initial_maint = False

        map_end_time = self.clock.start_of(alloc_start + span)

        # --- Initial Maintenance ---------------------------------------
        if now + cfg.map_advance >= self._next_initial_maint:
            need = self.initial_maint_minislots()
            if offset + need <= span:
                ies.append(MapIE(SID_BROADCAST, IUC.INITIAL_MAINT, offset))
                offset += need
                did_initial_maint = True
                self._next_initial_maint = (self.clock.start_of(alloc_start)
                                            + cfg.initial_maint_interval)

        # --- Station Maintenance ---------------------------------------
        sm_need = self.station_maint_minislots()
        for sid in sorted(self.station_maint_due):
            if self.station_maint_due[sid] > map_end_time:
                continue
            if offset + sm_need > span:
                break
            ies.append(MapIE(sid, IUC.STATION_MAINT, offset))
            offset += sm_need
            record_sm.append(sid)
            interval = (cfg.station_maint_interval_ranging if sid in self.ranging_sids
                        else cfg.station_maint_interval)
            self.station_maint_due[sid] = self.clock.start_of(alloc_start) + interval

        # --- Data grants ------------------------------------------------
        # Reserve room for the Request region so bandwidth requests never
        # get starved out by data.
        reserve = cfg.request_region_minislots
        for sid in sorted(self.pending):
            req = self.pending[sid]
            iuc = self.iuc_selector(sid, req.minislots > 12)
            prof = self.channel.profile(iuc)
            cap = req.minislots
            if prof and prof.max_burst:
                cap = min(cap, prof.max_burst)
            if cfg.max_grant_minislots:
                cap = min(cap, cfg.max_grant_minislots)
            room = span - reserve - offset
            if room <= 0:
                # No space at all: tell the modem we heard it (zero-length
                # grant) so it does not re-request or time out.
                ies.append(MapIE(sid, iuc, offset))
                record_pending.append(sid)
                req.acknowledged = True
                continue
            grant = min(cap, room)
            if grant <= 0:
                ies.append(MapIE(sid, iuc, offset))
                record_pending.append(sid)
                req.acknowledged = True
                continue
            ies.append(MapIE(sid, iuc, offset))
            offset += grant
            record_grants.append((sid, grant, int(iuc)))
            self.granted_minislots += grant
            req.minislots -= grant
            if req.minislots <= 0:
                del self.pending[sid]

        # --- Request contention region ----------------------------------
        req_room = min(cfg.request_region_minislots, span - offset)
        if req_room > 0:
            ies.append(MapIE(SID_BROADCAST, IUC.REQUEST, offset))
            offset += req_room
            self.contention_minislots += req_room

        # --- Null IE closes the final grant -----------------------------
        # Its offset is what terminates the last allocation, so it goes
        # immediately after the regions actually handed out.  Mini-slots
        # between here and the end of the MAP's span stay unallocated, which
        # is simply what an idle upstream looks like.
        ies.append(MapIE(0, IUC.NULL_IE, offset))

        self.next_minislot = alloc_start + span
        self.maps_sent += 1
        themap = Map(upstream_channel_id=self.channel.channel_id,
                     ucd_count=self.ucd_count,
                     alloc_start_time=alloc_start, ack_time=ack_time,
                     ranging_backoff_start=cfg.ranging_backoff_start,
                     ranging_backoff_end=cfg.ranging_backoff_end,
                     data_backoff_start=cfg.data_backoff_start,
                     data_backoff_end=cfg.data_backoff_end,
                     ies=ies)
        record = MapRecord(alloc_start=alloc_start, ack_time=ack_time, span=span,
                           ies=ies, initial_maint=did_initial_maint,
                           station_maint_sids=record_sm, grants=record_grants,
                           pending_grants=record_pending)
        self.last_map = record
        return themap, record

    # ------------------------------------------------------------------
    def annotate(self, record: MapRecord) -> str:
        bits = [f"MAP US{self.channel.channel_id} minislots "
                f"{record.alloc_start}..{record.alloc_start + record.span - 1}"]
        if record.initial_maint:
            bits.append(f"Initial Maintenance ({self.initial_maint_minislots()} "
                        f"minislots = 1 transmit opportunity, sized for "
                        f"{self.round_trip_minislots} minislots of round trip)")
        if record.station_maint_sids:
            bits.append("Station Maintenance sid " +
                        ",".join(str(s) for s in record.station_maint_sids))
        for sid, ms, iuc in record.grants:
            bytes_ = self.channel.payload_capacity(ms, iuc)
            bits.append(f"grant sid {sid}: {ms} minislots IUC{iuc} "
                        f"(~{bytes_} bytes)")
        for sid in record.pending_grants:
            bits.append(f"grant pending sid {sid} (zero length)")
        return " | ".join(bits)
