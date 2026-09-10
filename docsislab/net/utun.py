"""macOS utun: a real network interface on the host, wired to the CPE port.

macOS has no /dev/net/tun, but it does expose a kernel control socket that
creates point-to-point `utunN` interfaces without any kext.  Opening one puts
a real interface in the host's routing table, so `ping 10.20.0.1` from the
Mac's own stack goes through the virtual cable modem, up the simulated DOCSIS
upstream, and out of the CMTS.

The interface is layer 3: each read and write is a single IP packet preceded
by a 4-byte address family in network order.  The simulation's CPE port is
layer 2, so this module adds and strips a synthetic Ethernet header.

Creating a utun requires root, which is why this is opt-in (`--cpe utun`).
"""

from __future__ import annotations

import errno
import fcntl
import os
import socket
import struct
import subprocess
from dataclasses import dataclass

# <sys/kern_control.h> / <net/if_utun.h>
AF_SYSTEM = getattr(socket, "AF_SYSTEM", 32)
SYSPROTO_CONTROL = getattr(socket, "SYSPROTO_CONTROL", 2)
UTUN_OPT_IFNAME = 2
#: _IOWR('N', 3, struct ctl_info); ctl_info is 4 + 96 bytes.
CTLIOCGINFO = 0xC0644E03
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
#: sc_unit N+1 creates utun<N>, so unit 1 is utun0.
MAX_UTUN_UNIT = 32

AF_INET_BE = struct.pack(">I", socket.AF_INET)


class UtunError(RuntimeError):
    """A utun interface that could not be created or configured."""
    pass


@dataclass
class UtunConfig:
    """Addressing and routing for the host end of the utun link."""
    #: Address given to the host end of the link (the CPE).
    local_ip: str = "10.20.0.10"
    #: The far end -- the CMTS's subscriber-side gateway.
    peer_ip: str = "10.20.0.1"
    netmask: str = "255.255.255.0"
    mtu: int = 1500
    #: Routes to push down the interface, so host traffic for the simulated
    #: network goes through the cable modem.
    routes: tuple[str, ...] = ("10.20.0.0/24", "10.30.0.0/24", "10.10.0.0/24")
    #: Synthetic MAC for the CPE side, since utun has no link layer.
    mac: bytes = b"\x02\x0e\x00\x00\x00\x01"
    unit: int = 0                   # 0 = let the kernel pick


class Utun:
    """A macOS utun interface: read and write IP packets from the host stack."""
    def __init__(self, cfg: UtunConfig):
        self.cfg = cfg
        self.name: str = ""
        self._sock: socket.socket | None = None
        self._routes_added: list[str] = []

    # ------------------------------------------------------------------
    def open(self) -> str:
        if os.geteuid() != 0:
            raise UtunError(
                "creating a utun interface needs root. Re-run with sudo, or "
                "use the simulated CPE (--cpe sim), which needs no privileges.")
        sock = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
        # The utun kernel control has a dynamically assigned id; ask for it.
        info = struct.pack("I96s", 0, UTUN_CONTROL_NAME)
        info = fcntl.ioctl(sock.fileno(), CTLIOCGINFO, info)
        ctl_id = struct.unpack("I96s", info)[0]
        # CPython takes a PF_SYSTEM address as an (id, unit) pair rather than
        # a packed sockaddr_ctl.
        units = [self.cfg.unit] if self.cfg.unit else range(1, MAX_UTUN_UNIT)
        last: OSError | None = None
        for unit in units:
            try:
                sock.connect((ctl_id, unit))
                break
            except OSError as exc:
                last = exc
                if exc.errno == errno.EPERM:
                    sock.close()
                    raise UtunError(
                        "the kernel refused to create a utun interface "
                        "(EPERM). This needs root: re-run with sudo, or use "
                        "--cpe sim.") from exc
                if exc.errno not in (errno.EBUSY, errno.EADDRINUSE):
                    sock.close()
                    raise UtunError(f"utun connect failed: {exc}") from exc
        else:
            sock.close()
            raise UtunError(f"no free utun unit (last error: {last})")
        name = sock.getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 32)
        self.name = name.split(b"\x00", 1)[0].decode()
        sock.setblocking(False)
        self._sock = sock
        self._configure()
        return self.name

    def _configure(self) -> None:
        c = self.cfg
        # utun is point to point, so it takes a local and a peer address and
        # no netmask; the kernel installs a host route to the peer.
        self._run(["ifconfig", self.name, "inet", c.local_ip, c.peer_ip, "up"])
        self._run(["ifconfig", self.name, "mtu", str(c.mtu)], check=False)
        # Everything the simulation owns is then routed down the interface,
        # which is what puts host traffic through the cable modem.
        for route in c.routes:
            if self._run(["route", "-q", "add", "-net", route,
                          "-interface", self.name], check=False):
                self._routes_added.append(route)

    def _run(self, argv: list[str], check: bool = True) -> bool:
        res = subprocess.run(argv, capture_output=True, text=True)
        if res.returncode != 0:
            if check:
                raise UtunError(f"{' '.join(argv)} failed: "
                                f"{res.stderr.strip() or res.stdout.strip()}")
            return False
        return True

    # ------------------------------------------------------------------
    def read_packets(self, limit: int = 64) -> list[bytes]:
        """Non-blocking: return whatever IP packets the host has queued."""
        out: list[bytes] = []
        if self._sock is None:
            return out
        for _ in range(limit):
            try:
                data = self._sock.recv(self.cfg.mtu + 4)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            if len(data) <= 4:
                continue
            family = struct.unpack(">I", data[:4])[0]
            if family != socket.AF_INET:
                continue            # IPv6 and anything else is ignored
            out.append(data[4:])
        return out

    def write_packet(self, ip_packet: bytes) -> None:
        if self._sock is None:
            return
        try:
            self._sock.send(AF_INET_BE + ip_packet)
        except OSError:
            pass

    def close(self) -> None:
        for route in self._routes_added:
            self._run(["route", "-q", "delete", "-net", route,
                       "-interface", self.name], check=False)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class UtunCpe:
    """Bridges a host utun interface onto a cable modem's CPE port.

    The modem's LAN side speaks Ethernet, so this fabricates the link layer:
    frames going up get the utun's MAC as source and the CMTS's cable MAC as
    destination, and ARP is answered locally rather than being carried over
    the utun (which has no link layer to ARP on).
    """

    def __init__(self, sched, modem, cmts, cfg: UtunConfig, log, capture=None):
        self.sched = sched
        self.modem = modem
        self.cmts = cmts
        self.cfg = cfg
        self.log = log
        self.capture = capture
        self.utun = Utun(cfg)
        self.name = ""
        self.rx_packets = 0
        self.tx_packets = 0
        modem.attach_lan(self._from_modem)

    def start(self) -> str:
        self.name = self.utun.open()
        self.sched.add_poller(self._poll)
        self.log.notice("utun",
                        f"{self.name} up: {self.cfg.local_ip} -> "
                        f"{self.cfg.peer_ip}, routes "
                        f"{', '.join(self.cfg.routes)}. Host traffic for those "
                        f"networks now goes through {self.modem.cfg.name}.")
        return self.name

    def stop(self) -> None:
        self.utun.close()

    # ------------------------------------------------------------------
    def _poll(self) -> None:
        from .packet import Ethernet, ETHERTYPE_IPV4, decode_ipv4
        for ip_packet in self.utun.read_packets():
            self.rx_packets += 1
            ip = decode_ipv4(ip_packet)
            if ip is None:
                continue
            # The modem bridges, so the frame must be addressed to whatever
            # the next hop is at layer 2 -- always the CMTS cable interface.
            frame = Ethernet(dst=self.cmts.cfg.cable_mac, src=self.cfg.mac,
                             ethertype=ETHERTYPE_IPV4,
                             payload=ip_packet).encode()
            self.modem.from_lan(frame)

    def _from_modem(self, eth_frame: bytes) -> None:
        from .packet import (ARP_REQUEST, ETHERTYPE_ARP, ETHERTYPE_IPV4, Arp,
                             decode_arp, decode_ethernet, ip_bytes, ip_str)
        eth = decode_ethernet(eth_frame)
        if eth is None:
            return
        if self.capture:
            from . import packet as P
            self.capture.cpe(self.sched.now(), eth_frame,
                             f"{self.modem.cfg.name} -> utun {self.name}: "
                             f"{P.describe(eth_frame)}")
        if eth.ethertype == ETHERTYPE_ARP:
            # utun is layer 3, so ARP never reaches the host.  Answer on its
            # behalf with the synthetic CPE MAC.
            arp = decode_arp(eth.payload)
            if arp and arp.opcode == ARP_REQUEST and \
                    ip_str(arp.target_ip) == self.cfg.local_ip:
                from .packet import ARP_REPLY, Ethernet
                reply = Arp(ARP_REPLY, self.cfg.mac, ip_bytes(self.cfg.local_ip),
                            arp.sender_mac, arp.sender_ip)
                self.modem.from_lan(Ethernet(dst=arp.sender_mac, src=self.cfg.mac,
                                             ethertype=ETHERTYPE_ARP,
                                             payload=reply.encode()).encode())
            return
        if eth.ethertype != ETHERTYPE_IPV4:
            return
        self.tx_packets += 1
        self.utun.write_packet(eth.payload)

    def snapshot(self) -> dict:
        return {"name": self.name or "(not open)", "mac": self.cfg.mac.hex(":"),
                "ip": self.cfg.local_ip, "gateway": self.cfg.peer_ip,
                "pings_ok": self.tx_packets, "pings_lost": 0,
                "from_host": self.rx_packets, "to_host": self.tx_packets}
