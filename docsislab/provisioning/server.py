"""The provisioning host on the CMTS's network side.

One simulated machine running the three services a DOCSIS 1.x/2.0 modem needs
before it may register:

    DHCP (67)  address, gateway, time server, TFTP server, config file name
    ToD  (37)  RFC 868 time of day
    TFTP (69)  the binary configuration file

The DHCP server picks a pool from `giaddr` -- the address the CMTS's relay
stamped in -- which is how one server gives cable modems addresses out of the
modem subnet and CPEs addresses out of the subscriber subnet, without either
of them knowing the other pool exists.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..docsis import cfgfile
from ..net import dhcp as D
from ..net import packet as P
from ..net import tftp as TFTP
from ..net import tod as TOD
from ..net.packet import mac_bytes, mac_str
from ..net.stack import IpStack


@dataclass
class Pool:
    """One DHCP address pool, selected by the relay address that stamped giaddr."""
    name: str
    #: The relay address (giaddr) that selects this pool.
    relay: str
    subnet: str
    netmask: str
    gateway: str
    first: int
    last: int
    lease: int = 3600
    #: Only set for the cable-modem pool: DOCSIS provisioning parameters.
    tftp_server: str | None = None
    time_server: str | None = None
    log_server: str | None = None
    dns: str | None = None
    default_config: str | None = None
    leases: dict[bytes, str] = field(default_factory=dict)

    def allocate(self, chaddr: bytes) -> str | None:
        if chaddr in self.leases:
            return self.leases[chaddr]
        used = set(self.leases.values())
        base = P.ip_int(self.subnet) & P.ip_int(self.netmask)
        for host in range(self.first, self.last + 1):
            addr = P.ip_str((base | host).to_bytes(4, "big"))
            if addr not in used:
                self.leases[chaddr] = addr
                return addr
        return None


@dataclass
class ProvisioningConfig:
    """Addressing, pools and the shared secret for the provisioning host."""
    mac: bytes = field(default_factory=lambda: mac_bytes("020000c0ffee"))
    ip: str = "10.30.0.2"
    netmask: str = "255.255.255.0"
    gateway: str = "10.30.0.1"
    shared_secret: bytes = b"docsislab"
    time_offset: int = 0
    pools: list[Pool] = field(default_factory=list)
    #: MAC address (as text) -> config file name, for per-modem provisioning.
    config_by_mac: dict[str, str] = field(default_factory=dict)


class ProvisioningServer:
    """The DHCP, Time-of-Day and TFTP host behind the CMTS."""
    def __init__(self, sched, cfg: ProvisioningConfig, log, capture=None,
                 wall_epoch: float | None = None):
        self.sched = sched
        self.cfg = cfg
        self.log = log
        self.capture = capture
        self.wall_epoch = wall_epoch if wall_epoch is not None else time.time()
        self.peer: "object | None" = None       # the CMTS, set by the lab

        self.files: dict[str, bytes] = {}
        self.stats = {"discover": 0, "offer": 0, "request": 0, "ack": 0,
                      "nak": 0, "tod": 0, "rrq": 0, "blocks": 0, "errors": 0}
        #: (client ip, port) -> (filename, next block to send)
        self._transfers: dict[tuple[str, int], tuple[str, int]] = {}

        self.stack = IpStack("prov0", cfg.mac, self._transmit, sched.now)
        self.stack.configure(cfg.ip, cfg.netmask, cfg.gateway)
        self.stack.bind_udp(D.SERVER_PORT, self._on_dhcp)
        self.stack.bind_udp(TOD.PORT, self._on_tod)
        self.stack.bind_udp(69, self._on_tftp)

    # ------------------------------------------------------------------
    def add_config_file(self, name: str, spec: dict) -> bytes:
        """Compile a readable spec into a DOCSIS config file and serve it."""
        settings = cfgfile.build(spec)
        blob = cfgfile.encode(settings, self.cfg.shared_secret)
        self.files[name] = blob
        self.log.info("tftp", f"serving {name} ({len(blob)} bytes, "
                              f"{len(settings)} settings)")
        return blob

    def add_raw_file(self, name: str, blob: bytes) -> None:
        self.files[name] = blob
        self.log.info("tftp", f"serving {name} ({len(blob)} bytes, verbatim)")

    def _transmit(self, eth_frame: bytes) -> None:
        if self.capture:
            self.capture.nsi(self.sched.now(), eth_frame,
                             f"provisioning tx: {P.describe(eth_frame)}")
        if self.peer is not None:
            peer = self.peer
            self.sched.after(0.000_050, lambda: peer.receive_nsi(eth_frame),
                             name="nsi")

    def receive(self, eth_frame: bytes) -> None:
        self.stack.receive(eth_frame)

    # ------------------------------------------------------------------
    # DHCP
    # ------------------------------------------------------------------
    def _pool_for(self, giaddr: str) -> Pool | None:
        for pool in self.cfg.pools:
            if pool.relay == giaddr:
                return pool
        return self.cfg.pools[0] if self.cfg.pools else None

    def _on_dhcp(self, src_ip: str, sport: int, payload: bytes) -> None:
        msg = D.decode(payload)
        if msg is None or msg.op != D.BOOTREQUEST:
            return
        chaddr = msg.chaddr[:6]
        pool = self._pool_for(msg.giaddr)
        if pool is None:
            return
        vendor = msg.option(D.OPT_VENDOR_CLASS) or b""
        is_modem = vendor.startswith(b"docsis")

        addr = pool.allocate(chaddr)
        if addr is None:
            self.stats["nak"] += 1
            self.log.error("dhcp", f"pool {pool.name} exhausted for "
                                   f"{mac_str(chaddr)}")
            return

        config = None
        if pool.default_config:
            config = self.cfg.config_by_mac.get(mac_str(chaddr), pool.default_config)

        if msg.msg_type == D.DISCOVER:
            self.stats["discover"] += 1
            kind = "cable modem" if is_modem else "CPE"
            self.log.notice("dhcp",
                            f"DISCOVER from {kind} {mac_str(chaddr)} via relay "
                            f"{msg.giaddr} -> pool {pool.name}, offering {addr}"
                            + (f", config {config!r}" if config else ""))
            out = D.reply(msg, D.OFFER, addr, self.cfg.ip, pool.netmask,
                          pool.gateway, pool.lease,
                          time_server=pool.time_server,
                          time_offset=self.cfg.time_offset,
                          log_server=pool.log_server, dns=pool.dns,
                          tftp_server=pool.tftp_server, config_file=config)
            self.stats["offer"] += 1
        elif msg.msg_type == D.REQUEST:
            self.stats["request"] += 1
            self.log.notice("dhcp",
                            f"REQUEST from {mac_str(chaddr)} for {addr}, ACKing"
                            + (f" with tftp={pool.tftp_server} file={config!r}"
                               if config else ""))
            out = D.reply(msg, D.ACK, addr, self.cfg.ip, pool.netmask,
                          pool.gateway, pool.lease,
                          time_server=pool.time_server,
                          time_offset=self.cfg.time_offset,
                          log_server=pool.log_server, dns=pool.dns,
                          tftp_server=pool.tftp_server, config_file=config)
            self.stats["ack"] += 1
        else:
            return
        # Replies go back to the relay that forwarded the request.
        self.stack.send_udp(msg.giaddr, D.SERVER_PORT, out.encode(),
                            sport=D.SERVER_PORT)

    # ------------------------------------------------------------------
    # Time of Day
    # ------------------------------------------------------------------
    def _on_tod(self, src_ip: str, sport: int, payload: bytes) -> None:
        self.stats["tod"] += 1
        now = self.wall_epoch + self.sched.now()
        self.log.info("tod", f"time-of-day request from {src_ip}, "
                             f"answering {int(now)}")
        self.stack.send_udp(src_ip, sport, TOD.encode(now), sport=TOD.PORT)

    # ------------------------------------------------------------------
    # TFTP
    # ------------------------------------------------------------------
    def _on_tftp(self, src_ip: str, sport: int, payload: bytes) -> None:
        pkt = TFTP.decode(payload)
        if pkt is None:
            return
        if pkt.opcode == TFTP.RRQ:
            self.stats["rrq"] += 1
            blob = self.files.get(pkt.filename)
            if blob is None:
                self.stats["errors"] += 1
                self.log.error("tftp", f"RRQ for unknown file "
                                       f"{pkt.filename!r} from {src_ip}")
                self.stack.send_udp(src_ip, sport,
                                    TFTP.error(TFTP.ERR_NOT_FOUND, "file not found"),
                                    sport=69)
                return
            self.log.notice("tftp", f"RRQ {pkt.filename!r} from {src_ip}: "
                                    f"sending {len(blob)} bytes")
            self._transfers[(src_ip, sport)] = (pkt.filename, 1)
            self._send_block(src_ip, sport)
            return
        if pkt.opcode == TFTP.ACK:
            key = (src_ip, sport)
            entry = self._transfers.get(key)
            if entry is None:
                return
            name, block = entry
            if pkt.block != block:
                return
            blob = self.files.get(name, b"")
            if block * TFTP.BLOCK_SIZE >= len(blob):
                del self._transfers[key]
                self.log.info("tftp", f"transfer of {name!r} to {src_ip} complete")
                return
            self._transfers[key] = (name, block + 1)
            self._send_block(src_ip, sport)

    def _send_block(self, ip: str, port: int) -> None:
        name, block = self._transfers[(ip, port)]
        blob = self.files.get(name, b"")
        start = (block - 1) * TFTP.BLOCK_SIZE
        chunk = blob[start:start + TFTP.BLOCK_SIZE]
        self.stats["blocks"] += 1
        self.stack.send_udp(ip, port, TFTP.data(block, chunk), sport=69)

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        return {
            "ip": self.cfg.ip,
            "stats": dict(self.stats),
            "files": {name: len(blob) for name, blob in self.files.items()},
            "pools": [
                {"name": p.name, "relay": p.relay, "subnet": p.subnet,
                 "leases": {mac_str(m): a for m, a in p.leases.items()}}
                for p in self.cfg.pools
            ],
        }
