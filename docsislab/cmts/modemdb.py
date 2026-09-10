"""The CMTS's view of each cable modem.

The state names are the ones an operator reads off a real CMTS, because they
are the most useful diagnostic in DOCSIS: each one says exactly how far
through initialisation the modem got before it stopped, so `init(d)` means
"ranged fine, DHCP is broken" and `init(o)` means "DHCP worked, the TFTP
config download did not".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..net.packet import mac_str

#: Ordered so that progress can be compared.
STATES = [
    "offline",
    "init(r1)",   # initial RNG-REQ received, temporary SID assigned
    "init(r2)",   # ranging in progress: adjustments still being applied
    "init(rc)",   # ranging complete
    "init(d)",    # DHCP in progress
    "init(i)",    # IP address assigned
    "init(t)",    # Time of Day exchange
    "init(o)",    # config file download (TFTP "option file")
    "reject(m)",  # bad MIC -- config file was tampered with
    "reject(c)",  # class of service the CMTS will not admit
    "online(d)",  # registered but network access disabled
    "online",
]

STATE_MEANING = {
    "offline": "not heard from",
    "init(r1)": "initial ranging: first RNG-REQ received on the broadcast "
                "Initial Maintenance region, temporary SID assigned",
    "init(r2)": "ranging: applying timing/power/frequency corrections via "
                "unicast Station Maintenance",
    "init(rc)": "ranging complete: upstream timing is locked",
    "init(d)": "DHCP DISCOVER seen, waiting for the exchange to finish",
    "init(i)": "IP address assigned by DHCP",
    "init(t)": "Time of Day exchange",
    "init(o)": "downloading the configuration file over TFTP",
    "reject(m)": "registration rejected: MIC check failed",
    "reject(c)": "registration rejected: class of service not admitted",
    "online(d)": "registered, but network access is disabled in the config file",
    "online": "registered and forwarding",
}


@dataclass
class ServiceFlow:
    """One admitted service flow, with its CMTS-assigned identifiers."""
    sfid: int
    sid: int | None
    direction: str                # "us" or "ds"
    scheduling: int = 2
    max_sustained_bps: int = 0
    min_reserved_bps: int = 0
    max_burst_bytes: int = 0
    priority: int = 0
    primary: bool = False
    packets: int = 0
    bytes: int = 0

    def describe(self) -> str:
        rate = f"{self.max_sustained_bps / 1e6:.2f} Mbit/s" if self.max_sustained_bps else "unlimited"
        return (f"sfid {self.sfid} {self.direction} "
                f"{'primary' if self.primary else 'secondary'} "
                f"sid={self.sid if self.sid is not None else '-'} max {rate}")


@dataclass
class ModemRecord:
    """Everything the CMTS knows about one modem."""
    mac: bytes
    sid: int
    upstream_channel: int
    downstream_channel: int
    state: str = "offline"
    ip: str | None = None
    #: PHY measurements, updated on every ranging exchange.
    timing_offset: int = 0            # 1/64-tick units, as reported to the modem
    residual_timing_error: int = 0
    rx_power_dbmv: float = 0.0
    power_adjust_total: float = 0.0
    freq_offset_hz: int = 0
    snr_db: float = 0.0
    #: Provisioning
    docsis_version: str = "?"
    #: Whether this modem may be given advanced-PHY (IUC 9/10) grants.  Set
    #: once the CMTS has evidence the modem is DOCSIS 2.0 -- initially from
    #: the DHCP option 60 vendor class that passes through the relay, and
    #: confirmed by the Modem Capabilities in REG-REQ.
    adv_phy: bool = False
    capabilities: dict[str, int] = field(default_factory=dict)
    config_file: str | None = None
    max_cpe: int = 1
    privacy_enabled: bool = False
    network_access: bool = True
    service_flows: list[ServiceFlow] = field(default_factory=list)
    cpe_macs: list[bytes] = field(default_factory=list)
    #: Counters
    ranging_attempts: int = 0
    rng_rsp_sent: int = 0
    requests_received: int = 0
    minislots_granted: int = 0
    us_bursts: int = 0
    us_collisions: int = 0
    ds_frames: int = 0
    flaps: int = 0
    #: Timeline
    first_seen: float = 0.0
    online_since: float | None = None
    last_heard: float = 0.0
    state_history: list[tuple[float, str]] = field(default_factory=list)

    @property
    def mac_text(self) -> str:
        return mac_str(self.mac)

    def set_state(self, state: str, now: float) -> bool:
        if state == self.state:
            return False
        if self.state == "online" and state != "online":
            self.flaps += 1
        self.state = state
        self.state_history.append((now, state))
        if state == "online":
            self.online_since = now
        elif state != "online(d)":
            self.online_since = None
        return True

    def primary_sf(self, direction: str) -> ServiceFlow | None:
        for sf in self.service_flows:
            if sf.direction == direction and sf.primary:
                return sf
        return None

    def uptime(self, now: float) -> float:
        return 0.0 if self.online_since is None else now - self.online_since


class ModemDatabase:
    """The modem table, and the SID and SFID allocators."""
    def __init__(self):
        self.by_mac: dict[bytes, ModemRecord] = {}
        self.by_sid: dict[int, ModemRecord] = {}
        self._next_sid = 1
        self._next_sfid = 1
        #: Learned CPE MAC -> owning modem, for downstream forwarding.
        self.cpe_owner: dict[bytes, ModemRecord] = {}

    def allocate_sid(self) -> int:
        sid = self._next_sid
        self._next_sid += 1
        if self._next_sid > 0x1FFF:
            self._next_sid = 1
        return sid

    def allocate_sfid(self) -> int:
        sfid = self._next_sfid
        self._next_sfid += 1
        return sfid

    def create(self, mac: bytes, upstream: int, downstream: int,
               now: float) -> ModemRecord:
        rec = ModemRecord(mac=mac, sid=self.allocate_sid(),
                          upstream_channel=upstream, downstream_channel=downstream,
                          first_seen=now, last_heard=now)
        self.by_mac[mac] = rec
        self.by_sid[rec.sid] = rec
        return rec

    def get(self, mac: bytes) -> ModemRecord | None:
        return self.by_mac.get(mac)

    def by_sid_or_none(self, sid: int) -> ModemRecord | None:
        return self.by_sid.get(sid)

    def find(self, text: str) -> ModemRecord | None:
        """Look a modem up by MAC address, SID, or IP -- whatever the operator
        happened to type."""
        text = text.strip().lower()
        for rec in self.by_mac.values():
            if rec.mac_text == text or rec.mac_text.replace(":", "") == text.replace(":", ""):
                return rec
            if rec.ip and rec.ip == text:
                return rec
        if text.isdigit():
            return self.by_sid.get(int(text))
        return None

    def remove(self, rec: ModemRecord) -> None:
        self.by_mac.pop(rec.mac, None)
        self.by_sid.pop(rec.sid, None)
        for cpe in list(self.cpe_owner):
            if self.cpe_owner[cpe] is rec:
                del self.cpe_owner[cpe]

    def learn_cpe(self, cpe_mac: bytes, rec: ModemRecord) -> bool:
        if cpe_mac in self.cpe_owner:
            return False
        if len(rec.cpe_macs) >= rec.max_cpe:
            return False
        self.cpe_owner[cpe_mac] = rec
        rec.cpe_macs.append(cpe_mac)
        return True

    @property
    def modems(self) -> list[ModemRecord]:
        return sorted(self.by_mac.values(), key=lambda r: r.sid)

    def count_by_state(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for rec in self.by_mac.values():
            out[rec.state] = out.get(rec.state, 0) + 1
        return out
