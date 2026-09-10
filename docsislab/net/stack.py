"""A very small IPv4 stack.

Shared by every simulated host that needs an IP address: the cable modem's
management interface, the CPE behind it, and the provisioning server on the
CMTS's network side.  It does just enough to make the DOCSIS provisioning
exchange real -- ARP resolution with queueing, ICMP echo, and UDP demultiplexed
by port -- and no more.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import packet as P
from .packet import (ARP_REPLY, ARP_REQUEST, Arp, ETHERTYPE_ARP, ETHERTYPE_IPV4,
                     Ethernet, ICMP, ICMP_ECHO_REQUEST, IPPROTO_ICMP,
                     IPPROTO_UDP, decode_arp, decode_ethernet, decode_icmp,
                     decode_ipv4, decode_udp, ip_bytes, ip_int, ip_str)

UdpHandler = Callable[[str, int, bytes], None]
IcmpHandler = Callable[[str, ICMP], None]


@dataclass
class _Pending:
    dst_ip: str
    frames: list[bytes] = field(default_factory=list)
    tries: int = 0


class IpStack:
    """A very small IPv4 stack: ARP, ICMP echo, and UDP by port."""
    def __init__(self, name: str, mac: bytes,
                 transmit: Callable[[bytes], None],
                 now: Callable[[], float] | None = None,
                 log: Callable[[str, str], None] | None = None):
        self.name = name
        self.mac = mac
        self._transmit = transmit
        self._now = now or (lambda: 0.0)
        self._log = log or (lambda level, msg: None)

        self.ip: str | None = None
        #: A CMTS cable interface carries the modem subnet and the CPE subnet
        #: at once (a primary plus secondary addresses, in Cisco terms), so a
        #: stack may answer for several addresses.
        self.addresses: list[str] = []
        self.netmask: str = "255.255.255.0"
        self.gateway: str | None = None
        self.mtu = 1500

        self.arp_cache: dict[str, bytes] = {}
        self._pending: dict[str, _Pending] = {}
        self.udp_handlers: dict[int, UdpHandler] = {}
        self.icmp_handler: IcmpHandler | None = None
        self.subnets: list[tuple[str, str]] = []
        #: Accept traffic for any address (used by the CMTS host stack).
        self.promiscuous = False
        self.stats = {"rx": 0, "tx": 0, "rx_drop": 0, "arp_rx": 0, "arp_tx": 0}

    # ------------------------------------------------------------------
    def configure(self, ip: str, netmask: str = "255.255.255.0",
                  gateway: str | None = None,
                  secondary: list[tuple[str, str]] | None = None) -> None:
        self.ip = ip
        self.netmask = netmask
        self.gateway = gateway
        self.addresses = [ip]
        self.subnets: list[tuple[str, str]] = [(ip, netmask)]
        for addr, mask in (secondary or []):
            self.addresses.append(addr)
            self.subnets.append((addr, mask))

    def address_for(self, dst_ip: str) -> str | None:
        """Which of our addresses is on the same subnet as `dst_ip`."""
        for addr, mask in getattr(self, "subnets", [(self.ip, self.netmask)]):
            if addr and (ip_int(dst_ip) & ip_int(mask)) == (ip_int(addr) & ip_int(mask)):
                return addr
        return None

    def is_local_address(self, addr: str) -> bool:
        return addr in self.addresses

    @property
    def prefix_len(self) -> int:
        return bin(ip_int(self.netmask)).count("1")

    def on_link(self, dst_ip: str) -> bool:
        if self.ip is None:
            return True
        return self.address_for(dst_ip) is not None

    def bind_udp(self, port: int, handler: UdpHandler) -> None:
        self.udp_handlers[port] = handler

    # ------------------------------------------------------------------
    # transmit
    # ------------------------------------------------------------------
    def send_ip(self, ip_packet: bytes, dst_ip: str | None = None,
                dst_mac: bytes | None = None) -> None:
        """Send an already-built IPv4 packet, resolving ARP if needed."""
        if dst_mac is not None:
            self._emit(dst_mac, ETHERTYPE_IPV4, ip_packet)
            return
        if dst_ip is None:
            decoded = decode_ipv4(ip_packet)
            dst_ip = decoded.dst if decoded else "255.255.255.255"
        if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            self._emit(P.BROADCAST_MAC, ETHERTYPE_IPV4, ip_packet)
            return
        next_hop = dst_ip if self.on_link(dst_ip) else (self.gateway or dst_ip)
        mac = self.arp_cache.get(next_hop)
        if mac is not None:
            self._emit(mac, ETHERTYPE_IPV4, ip_packet)
            return
        pending = self._pending.setdefault(next_hop, _Pending(next_hop))
        pending.frames.append(ip_packet)
        self._send_arp_request(next_hop)

    def send_udp(self, dst_ip: str, dport: int, payload: bytes,
                 sport: int = 0, src_ip: str | None = None,
                 dst_mac: bytes | None = None, ttl: int = 64) -> None:
        src = src_ip or self.address_for(dst_ip) or self.ip or "0.0.0.0"
        pkt = P.udp_datagram(src, dst_ip, sport, dport, payload, ttl=ttl)
        if dst_ip == "255.255.255.255":
            self._emit(P.BROADCAST_MAC, ETHERTYPE_IPV4, pkt)
        else:
            self.send_ip(pkt, dst_ip, dst_mac)

    def send_ping(self, dst_ip: str, ident: int, seq: int,
                  payload: bytes = b"docsislab") -> None:
        pkt = P.icmp_echo(self.ip or "0.0.0.0", dst_ip, ident, seq, payload)
        self.send_ip(pkt, dst_ip)

    def _emit(self, dst_mac: bytes, ethertype: int, payload: bytes) -> None:
        self.stats["tx"] += 1
        self._transmit(Ethernet(dst=dst_mac, src=self.mac,
                                ethertype=ethertype, payload=payload).encode())

    # ------------------------------------------------------------------
    # ARP
    # ------------------------------------------------------------------
    def _send_arp_request(self, target_ip: str) -> None:
        if self.ip is None:
            return
        self.stats["arp_tx"] += 1
        source = self.address_for(target_ip) or self.ip
        arp = Arp(ARP_REQUEST, self.mac, ip_bytes(source),
                  P.ZERO_MAC, ip_bytes(target_ip))
        self._emit(P.BROADCAST_MAC, ETHERTYPE_ARP, arp.encode())

    def _learn(self, ip: str, mac: bytes) -> None:
        if ip == "0.0.0.0":
            return
        self.arp_cache[ip] = mac
        pending = self._pending.pop(ip, None)
        if pending:
            for frame in pending.frames:
                self._emit(mac, ETHERTYPE_IPV4, frame)

    def _handle_arp(self, eth: Ethernet) -> None:
        arp = decode_arp(eth.payload)
        if arp is None:
            return
        self.stats["arp_rx"] += 1
        self._learn(ip_str(arp.sender_ip), arp.sender_mac)
        target = ip_str(arp.target_ip)
        if arp.opcode == ARP_REQUEST and self.is_local_address(target):
            reply = Arp(ARP_REPLY, self.mac, ip_bytes(target),
                        arp.sender_mac, arp.sender_ip)
            self._emit(arp.sender_mac, ETHERTYPE_ARP, reply.encode())

    # ------------------------------------------------------------------
    # receive
    # ------------------------------------------------------------------
    def receive(self, eth_frame: bytes) -> None:
        eth = decode_ethernet(eth_frame)
        if eth is None:
            self.stats["rx_drop"] += 1
            return
        if not (eth.dst == self.mac or eth.is_broadcast or eth.is_multicast
                or self.promiscuous):
            return
        self.stats["rx"] += 1
        if eth.ethertype == ETHERTYPE_ARP:
            self._handle_arp(eth)
            return
        if eth.ethertype != ETHERTYPE_IPV4:
            return
        ip = decode_ipv4(eth.payload)
        if ip is None:
            return
        self._learn(ip.src, eth.src)
        mine = (self.ip is None or self.is_local_address(ip.dst)
                or ip.dst == "255.255.255.255" or self.promiscuous
                or ip.dst.endswith(".255"))
        if not mine:
            return
        if ip.proto == IPPROTO_UDP:
            udp = decode_udp(ip.payload)
            if udp is None:
                return
            handler = self.udp_handlers.get(udp.dport)
            if handler:
                handler(ip.src, udp.sport, udp.payload)
            return
        if ip.proto == IPPROTO_ICMP:
            icmp = decode_icmp(ip.payload)
            if icmp is None:
                return
            if icmp.type == ICMP_ECHO_REQUEST and self.is_local_address(ip.dst):
                reply = P.icmp_echo(ip.dst, ip.src, icmp.ident, icmp.seq,
                                    icmp.payload, reply=True)
                self.send_ip(reply, ip.src, eth.src)
            elif self.icmp_handler:
                self.icmp_handler(ip.src, icmp)
