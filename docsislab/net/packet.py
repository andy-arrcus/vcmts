"""Minimal Ethernet / ARP / IPv4 / UDP / ICMP encoding.

Hand-rolled rather than pulled from a library so that every byte a modem
puts on the wire is visible in this repository, and so the DHCP and TFTP
exchanges that bring the modem online are real packets that Wireshark
dissects out of the DOCSIS payload.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ETH_HDR_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

IPPROTO_ICMP = 1
IPPROTO_UDP = 17
IPPROTO_TCP = 6

BROADCAST_MAC = b"\xff" * 6
ZERO_MAC = b"\x00" * 6


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def mac_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def mac_bytes(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", "").replace("-", "").replace(".", ""))


def ip_str(addr: bytes | int) -> str:
    if isinstance(addr, int):
        addr = addr.to_bytes(4, "big")
    return ".".join(str(b) for b in addr)


def ip_bytes(text: str) -> bytes:
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError(f"bad IPv4 address {text!r}")
    return bytes(int(p) for p in parts)


def ip_int(text: str) -> int:
    return int.from_bytes(ip_bytes(text), "big")


def checksum16(data: bytes) -> int:
    """The one's-complement Internet checksum (RFC 1071)."""
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def in_subnet(addr: str, network: str, prefix: int) -> bool:
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ip_int(addr) & mask) == (ip_int(network) & mask)


# --------------------------------------------------------------------------
# Ethernet
# --------------------------------------------------------------------------

@dataclass
class Ethernet:
    """An Ethernet II frame, padded to the 60-byte minimum on encode."""
    dst: bytes
    src: bytes
    ethertype: int = ETHERTYPE_IPV4
    payload: bytes = b""

    def encode(self, min_len: int = 60) -> bytes:
        frame = (self.dst + self.src
                 + self.ethertype.to_bytes(2, "big") + self.payload)
        # Real interfaces pad to the 60-byte minimum before the FCS.
        if len(frame) < min_len:
            frame += b"\x00" * (min_len - len(frame))
        return frame

    @property
    def is_multicast(self) -> bool:
        return bool(self.dst[0] & 0x01)

    @property
    def is_broadcast(self) -> bool:
        return self.dst == BROADCAST_MAC


def decode_ethernet(data: bytes) -> Ethernet | None:
    if len(data) < ETH_HDR_LEN:
        return None
    return Ethernet(dst=data[0:6], src=data[6:12],
                    ethertype=int.from_bytes(data[12:14], "big"),
                    payload=data[ETH_HDR_LEN:])


# --------------------------------------------------------------------------
# ARP
# --------------------------------------------------------------------------

ARP_REQUEST = 1
ARP_REPLY = 2


@dataclass
class Arp:
    """An ARP request or reply over Ethernet and IPv4."""
    opcode: int
    sender_mac: bytes
    sender_ip: bytes
    target_mac: bytes
    target_ip: bytes

    def encode(self) -> bytes:
        return (struct.pack(">HHBBH", 1, ETHERTYPE_IPV4, 6, 4, self.opcode)
                + self.sender_mac + self.sender_ip
                + self.target_mac + self.target_ip)


def decode_arp(data: bytes) -> Arp | None:
    if len(data) < 28:
        return None
    _htype, _ptype, hlen, plen, op = struct.unpack(">HHBBH", data[:8])
    if hlen != 6 or plen != 4:
        return None
    return Arp(opcode=op, sender_mac=data[8:14], sender_ip=data[14:18],
               target_mac=data[18:24], target_ip=data[24:28])


# --------------------------------------------------------------------------
# IPv4
# --------------------------------------------------------------------------

@dataclass
class IPv4:
    """An IPv4 packet; the header checksum is computed on encode."""
    src: str
    dst: str
    proto: int = IPPROTO_UDP
    payload: bytes = b""
    ttl: int = 64
    ident: int = 0
    tos: int = 0
    flags_frag: int = 0

    def encode(self) -> bytes:
        total_len = 20 + len(self.payload)
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, self.tos, total_len,
                          self.ident & 0xFFFF, self.flags_frag, self.ttl,
                          self.proto, 0, ip_bytes(self.src), ip_bytes(self.dst))
        csum = checksum16(hdr)
        hdr = hdr[:10] + csum.to_bytes(2, "big") + hdr[12:]
        return hdr + self.payload


def decode_ipv4(data: bytes) -> IPv4 | None:
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl:
        return None
    total_len = int.from_bytes(data[2:4], "big")
    ident = int.from_bytes(data[4:6], "big")
    flags_frag = int.from_bytes(data[6:8], "big")
    ttl, proto = data[8], data[9]
    src, dst = ip_str(data[12:16]), ip_str(data[16:20])
    body = data[ihl:total_len] if 20 <= total_len <= len(data) else data[ihl:]
    return IPv4(src=src, dst=dst, proto=proto, payload=body, ttl=ttl,
                ident=ident, tos=data[1], flags_frag=flags_frag)


def _pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    return ip_bytes(src) + ip_bytes(dst) + bytes([0, proto]) + length.to_bytes(2, "big")


# --------------------------------------------------------------------------
# UDP
# --------------------------------------------------------------------------

@dataclass
class UDP:
    """A UDP datagram; the checksum needs the IP addresses, so encode takes them."""
    sport: int
    dport: int
    payload: bytes = b""

    def encode(self, src_ip: str, dst_ip: str) -> bytes:
        length = 8 + len(self.payload)
        hdr = struct.pack(">HHHH", self.sport, self.dport, length, 0)
        csum = checksum16(_pseudo_header(src_ip, dst_ip, IPPROTO_UDP, length)
                          + hdr + self.payload)
        # A zero checksum means "not computed", so RFC 768 says send 0xFFFF.
        if csum == 0:
            csum = 0xFFFF
        return hdr[:6] + csum.to_bytes(2, "big") + self.payload


def decode_udp(data: bytes) -> UDP | None:
    if len(data) < 8:
        return None
    sport, dport, length, _csum = struct.unpack(">HHHH", data[:8])
    body = data[8:length] if 8 <= length <= len(data) else data[8:]
    return UDP(sport=sport, dport=dport, payload=body)


def udp_datagram(src_ip: str, dst_ip: str, sport: int, dport: int,
                 payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    """A complete IPv4 packet carrying UDP."""
    udp = UDP(sport, dport, payload).encode(src_ip, dst_ip)
    return IPv4(src=src_ip, dst=dst_ip, proto=IPPROTO_UDP,
                payload=udp, ttl=ttl, ident=ident).encode()


# --------------------------------------------------------------------------
# ICMP
# --------------------------------------------------------------------------

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11


@dataclass
class ICMP:
    """An ICMP message, echo request and reply in practice."""
    type: int
    code: int = 0
    ident: int = 0
    seq: int = 0
    payload: bytes = b""

    def encode(self) -> bytes:
        hdr = struct.pack(">BBHHH", self.type, self.code, 0, self.ident, self.seq)
        csum = checksum16(hdr + self.payload)
        return hdr[:2] + csum.to_bytes(2, "big") + hdr[4:] + self.payload


def decode_icmp(data: bytes) -> ICMP | None:
    if len(data) < 8:
        return None
    type_, code, _csum, ident, seq = struct.unpack(">BBHHH", data[:8])
    return ICMP(type=type_, code=code, ident=ident, seq=seq, payload=data[8:])


def icmp_echo(src_ip: str, dst_ip: str, ident: int, seq: int,
              payload: bytes = b"", reply: bool = False, ttl: int = 64) -> bytes:
    icmp = ICMP(ICMP_ECHO_REPLY if reply else ICMP_ECHO_REQUEST,
                0, ident, seq, payload).encode()
    return IPv4(src=src_ip, dst=dst_ip, proto=IPPROTO_ICMP,
                payload=icmp, ttl=ttl).encode()


# --------------------------------------------------------------------------
# convenience: describe a packet in one line, for logs and pcap comments
# --------------------------------------------------------------------------

def describe(eth_frame: bytes) -> str:
    """One line summarising an Ethernet frame, for logs and pcap comments."""
    eth = decode_ethernet(eth_frame)
    if eth is None:
        return f"{len(eth_frame)}B (not Ethernet)"
    if eth.ethertype == ETHERTYPE_ARP:
        arp = decode_arp(eth.payload)
        if arp:
            what = "who-has" if arp.opcode == ARP_REQUEST else "is-at"
            return f"ARP {what} {ip_str(arp.target_ip)} tell {ip_str(arp.sender_ip)}"
        return "ARP (malformed)"
    if eth.ethertype != ETHERTYPE_IPV4:
        return f"ethertype {eth.ethertype:#06x} {len(eth.payload)}B"
    ip = decode_ipv4(eth.payload)
    if ip is None:
        return "IPv4 (malformed)"
    if ip.proto == IPPROTO_UDP:
        udp = decode_udp(ip.payload)
        if udp:
            return f"UDP {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} {len(udp.payload)}B"
    if ip.proto == IPPROTO_ICMP:
        icmp = decode_icmp(ip.payload)
        if icmp:
            names = {ICMP_ECHO_REQUEST: "echo request", ICMP_ECHO_REPLY: "echo reply",
                     ICMP_DEST_UNREACH: "dest unreachable", ICMP_TIME_EXCEEDED: "TTL exceeded"}
            name = names.get(icmp.type, f"type {icmp.type}")
            return f"ICMP {name} {ip.src} -> {ip.dst} id={icmp.ident} seq={icmp.seq}"
    return f"IP proto {ip.proto} {ip.src} -> {ip.dst} {len(ip.payload)}B"
