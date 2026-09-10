"""A small pcapng writer.

Why pcapng rather than classic pcap: a DOCSIS capture is really several
different links seen at once, and pcapng can carry them in one file with
per-interface link types and names.  We use four interfaces:

    0  docsis-ds   DLT 143 (DOCSIS)   CMTS -> modems
    1  docsis-us   DLT 143 (DOCSIS)   modems -> CMTS
    2  cmts-nsi    DLT 1   (Ethernet) CMTS network-side interface
    3  cpe         DLT 1   (Ethernet) behind the modem

DLT 143 has no direction bit, so splitting downstream from upstream into
separate interfaces is what lets you tell a CMTS transmission from a modem
transmission in Wireshark (the "Interface name" column, or `frame.interface_name`).

Each packet may also carry an opt_comment, which Wireshark shows in the packet
detail and in the comment column.  We use it to annotate what the simulation
was thinking at that moment -- "initial ranging attempt 2, backoff window
0..15, chose 6" -- which turns a capture into something you can actually read.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Block types
SHB = 0x0A0D0D0A
IDB = 0x00000001
EPB = 0x00000006

# Link types
DLT_EN10MB = 1
DLT_RAW = 101
DLT_DOCSIS = 143

BYTE_ORDER_MAGIC = 0x1A2B3C4D


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + _pad4(value)


def _opt_end() -> bytes:
    return struct.pack("<HH", 0, 0)


def _block(block_type: int, body: bytes) -> bytes:
    total = len(body) + 12
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


@dataclass
class Interface:
    """One pcapng interface: its name, link type and timestamp resolution."""
    name: str
    linktype: int
    description: str = ""
    #: 10^-tsresol seconds per timestamp unit; 9 == nanoseconds
    tsresol: int = 9


class PcapngWriter:
    """Append-only pcapng writer.  Not thread safe; the simulation is
    single-threaded and calls it from the event loop."""

    def __init__(self, path: str, interfaces: list[Interface],
                 hardware: str = "docsislab virtual HFC plant",
                 os_name: str = "",
                 app: str = "docsislab"):
        self.path = path
        self.interfaces = interfaces
        self._fh = open(path, "wb")
        self._closed = False
        self._count = 0
        self._write_shb(hardware, os_name, app)
        for iface in interfaces:
            self._write_idb(iface)
        self._fh.flush()

    # -- header blocks ---------------------------------------------------
    def _write_shb(self, hardware: str, os_name: str, app: str) -> None:
        body = struct.pack("<IHHq", BYTE_ORDER_MAGIC, 1, 0, -1)
        opts = b""
        if hardware:
            opts += _option(2, hardware.encode())
        if os_name:
            opts += _option(3, os_name.encode())
        if app:
            opts += _option(4, app.encode())
        if opts:
            opts += _opt_end()
        self._fh.write(_block(SHB, body + opts))

    def _write_idb(self, iface: Interface) -> None:
        body = struct.pack("<HHI", iface.linktype, 0, 0)  # linktype, rsvd, snaplen=0 (no limit)
        opts = _option(2, iface.name.encode())            # if_name
        if iface.description:
            opts += _option(3, iface.description.encode())  # if_description
        opts += _option(9, bytes([iface.tsresol]))          # if_tsresol
        opts += _opt_end()
        self._fh.write(_block(IDB, body + opts))

    # -- packets ---------------------------------------------------------
    def packet(self, iface: int, timestamp: float, data: bytes,
               comment: str = "") -> None:
        """Write an Enhanced Packet Block.

        `timestamp` is seconds since the epoch as a float; we store
        nanosecond resolution so mini-slot-scale events (6.25 us ticks and
        finer) stay distinguishable.
        """
        if self._closed:
            return
        ts = int(round(timestamp * 1e9))
        body = struct.pack("<IIIII", iface, (ts >> 32) & 0xFFFFFFFF,
                           ts & 0xFFFFFFFF, len(data), len(data))
        body += _pad4(data)
        if comment:
            body += _option(1, comment.encode()[:65000]) + _opt_end()
        self._fh.write(_block(EPB, body))
        self._count += 1

    def flush(self) -> None:
        if not self._closed:
            self._fh.flush()

    @property
    def count(self) -> int:
        return self._count

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._fh.close()

    def __enter__(self) -> "PcapngWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


DEFAULT_INTERFACES = [
    Interface("docsis-ds", DLT_DOCSIS, "DOCSIS downstream (CMTS transmit)"),
    Interface("docsis-us", DLT_DOCSIS, "DOCSIS upstream (cable modem transmit)"),
    Interface("cmts-nsi", DLT_EN10MB, "CMTS network-side interface"),
    Interface("cpe", DLT_EN10MB, "CPE LAN behind the cable modem"),
]

IF_DS, IF_US, IF_NSI, IF_CPE = 0, 1, 2, 3
