"""A simulated host behind the cable modem.

Exists so the data plane can be exercised without needing root: it DHCPs
through the modem (which is how you see a CPE DHCP travel up through the
DOCSIS MAC, get relayed by the CMTS into the subscriber pool, and come back),
and can ping.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..net import dhcp as D
from ..net import packet as P
from ..net.packet import ICMP, ICMP_ECHO_REPLY, mac_bytes, mac_str
from ..net.stack import IpStack


@dataclass
class CpeConfig:
    """Identity of a simulated host behind a modem."""
    name: str = "cpe0"
    mac: bytes = field(default_factory=lambda: mac_bytes("020e00000001"))
    hostname: str = "cpe0"
    #: Wait this long after the modem comes online before starting DHCP.
    dhcp_delay: float = 0.2


class Cpe:
    """A simulated host on the modem's LAN side: DHCP and ping."""
    def __init__(self, sched, modem, cfg: CpeConfig, log, capture=None):
        self.sched = sched
        self.modem = modem
        self.cfg = cfg
        self.log = log
        self.capture = capture
        self.ip: str | None = None
        self.gateway: str | None = None
        self.xid = 0
        self.dhcp_server_id: str | None = None
        self.pings: dict[int, float] = {}
        self.ping_results: list[tuple[int, float]] = []
        self.ping_lost = 0
        self._ident = 0x4242

        self.stack = IpStack(cfg.name, cfg.mac, self._transmit, sched.now)
        self.stack.bind_udp(D.CLIENT_PORT, self._on_dhcp)
        self.stack.icmp_handler = self._on_icmp
        modem.attach_lan(self.stack.receive)

    def _transmit(self, eth_frame: bytes) -> None:
        self.modem.from_lan(eth_frame)

    # ------------------------------------------------------------------
    def start_dhcp(self) -> None:
        self.xid = 0xC0DE0000 | (int.from_bytes(self.cfg.mac[-2:], "big"))
        msg = D.discover(self.xid, self.cfg.mac, vendor_class=b"",
                         hostname=self.cfg.hostname)
        self.log.notice("dhcp", f"{self.cfg.name}: DHCPDISCOVER through the "
                                f"cable modem")
        self.stack.send_udp("255.255.255.255", D.SERVER_PORT, msg.encode(),
                            sport=D.CLIENT_PORT, src_ip="0.0.0.0")

    def _on_dhcp(self, src_ip: str, sport: int, payload: bytes) -> None:
        msg = D.decode(payload)
        if msg is None or msg.xid != self.xid or msg.chaddr[:6] != self.cfg.mac:
            return
        if msg.msg_type == D.OFFER:
            self.dhcp_server_id = P.ip_str(msg.option(D.OPT_SERVER_ID) or b"\x00" * 4)
            self.log.info("dhcp", f"{self.cfg.name}: OFFER {msg.yiaddr}")
            req = D.request(self.xid, self.cfg.mac, msg.yiaddr,
                            self.dhcp_server_id, vendor_class=b"")
            self.stack.send_udp("255.255.255.255", D.SERVER_PORT, req.encode(),
                                sport=D.CLIENT_PORT, src_ip="0.0.0.0")
        elif msg.msg_type == D.ACK:
            self.ip = msg.yiaddr
            mask = msg.option(D.OPT_SUBNET_MASK)
            router = msg.option(D.OPT_ROUTER)
            self.gateway = P.ip_str(router) if router else None
            self.stack.configure(self.ip, P.ip_str(mask) if mask else "255.255.255.0",
                                 self.gateway)
            self.log.notice("dhcp",
                            f"{self.cfg.name}: online at {self.ip}, "
                            f"gateway {self.gateway} -- this address came out of "
                            f"the subscriber pool because the CMTS relayed with "
                            f"a different giaddr than the modem's own DHCP")

    # ------------------------------------------------------------------
    def ping(self, dst: str, count: int = 3, interval: float = 0.2) -> None:
        if self.ip is None:
            self.log.warn("ping", f"{self.cfg.name} has no IP address yet")
            return
        for i in range(count):
            seq = self._ident + i
            self.sched.after(i * interval,
                             lambda seq=seq, dst=dst: self._send_ping(dst, seq),
                             name="ping")
        self._ident += count

    def _send_ping(self, dst: str, seq: int) -> None:
        self.pings[seq] = self.sched.now()
        self.stack.send_ping(dst, 0x1234, seq)
        self.log.info("ping", f"{self.cfg.name}: echo request to {dst} seq={seq}")
        self.sched.after(2.0, lambda: self._ping_timeout(seq), name="ping-timeout")

    def _ping_timeout(self, seq: int) -> None:
        if seq in self.pings:
            del self.pings[seq]
            self.ping_lost += 1
            self.log.warn("ping", f"{self.cfg.name}: no reply for seq={seq}")

    def _on_icmp(self, src_ip: str, icmp: ICMP) -> None:
        if icmp.type != ICMP_ECHO_REPLY:
            self.log.info("ping", f"{self.cfg.name}: ICMP type {icmp.type} "
                                  f"from {src_ip}")
            return
        sent = self.pings.pop(icmp.seq, None)
        if sent is None:
            return
        rtt = self.sched.now() - sent
        self.ping_results.append((icmp.seq, rtt))
        self.log.notice("ping",
                        f"{self.cfg.name}: {len(icmp.payload) + 8} bytes from "
                        f"{src_ip}: seq={icmp.seq} time={rtt * 1000:.3f} ms "
                        f"(through the DOCSIS upstream and back)")

    def snapshot(self) -> dict:
        return {"name": self.cfg.name, "mac": mac_str(self.cfg.mac),
                "ip": self.ip, "gateway": self.gateway,
                "pings_ok": len(self.ping_results), "pings_lost": self.ping_lost}
