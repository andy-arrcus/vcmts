"""TFTP (RFC 1350) -- how a cable modem fetches its configuration file."""

from __future__ import annotations

from dataclasses import dataclass

RRQ, WRQ, DATA, ACK, ERROR, OACK = 1, 2, 3, 4, 5, 6
BLOCK_SIZE = 512

ERR_NOT_FOUND = 1
ERR_ACCESS = 2
ERR_ILLEGAL = 4

OPCODE_NAMES = {RRQ: "RRQ", WRQ: "WRQ", DATA: "DATA", ACK: "ACK",
                ERROR: "ERROR", OACK: "OACK"}


def rrq(filename: str, mode: str = "octet") -> bytes:
    return (RRQ).to_bytes(2, "big") + filename.encode() + b"\x00" + mode.encode() + b"\x00"


def data(block: int, payload: bytes) -> bytes:
    return (DATA).to_bytes(2, "big") + (block & 0xFFFF).to_bytes(2, "big") + payload


def ack(block: int) -> bytes:
    return (ACK).to_bytes(2, "big") + (block & 0xFFFF).to_bytes(2, "big")


def error(code: int, message: str) -> bytes:
    return (ERROR).to_bytes(2, "big") + code.to_bytes(2, "big") + message.encode() + b"\x00"


@dataclass
class Packet:
    """A decoded TFTP packet of any opcode."""
    opcode: int
    filename: str = ""
    mode: str = ""
    block: int = 0
    payload: bytes = b""
    error_code: int = 0
    message: str = ""

    def summary(self) -> str:
        name = OPCODE_NAMES.get(self.opcode, str(self.opcode))
        if self.opcode in (RRQ, WRQ):
            return f"TFTP {name} {self.filename} ({self.mode})"
        if self.opcode == DATA:
            return f"TFTP DATA block {self.block} ({len(self.payload)} bytes)"
        if self.opcode == ACK:
            return f"TFTP ACK block {self.block}"
        if self.opcode == ERROR:
            return f"TFTP ERROR {self.error_code} {self.message}"
        return f"TFTP {name}"


def decode(buf: bytes) -> Packet | None:
    if len(buf) < 2:
        return None
    opcode = int.from_bytes(buf[0:2], "big")
    if opcode in (RRQ, WRQ):
        parts = buf[2:].split(b"\x00")
        if len(parts) < 2:
            return None
        return Packet(opcode, filename=parts[0].decode(errors="replace"),
                      mode=parts[1].decode(errors="replace"))
    if opcode == DATA and len(buf) >= 4:
        return Packet(opcode, block=int.from_bytes(buf[2:4], "big"), payload=buf[4:])
    if opcode == ACK and len(buf) >= 4:
        return Packet(opcode, block=int.from_bytes(buf[2:4], "big"))
    if opcode == ERROR and len(buf) >= 4:
        return Packet(opcode, error_code=int.from_bytes(buf[2:4], "big"),
                      message=buf[4:].split(b"\x00")[0].decode(errors="replace"))
    return Packet(opcode)
