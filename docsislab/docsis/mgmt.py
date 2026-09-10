"""The MAC management message header -- RFIv2.0 section 6.4.

Every MAC management message (SYNC, UCD, MAP, RNG-REQ/RSP, REG-*, DSx, ...)
carries this 20-byte header inside a MAC-specific MAC frame:

    dst MAC (6) | src MAC (6) | msg length (2) | DSAP | SSAP | control
                | version | type | RSVD | payload...

The `msg length` field is an 802.2 LLC length: it counts from DSAP to the end
of the payload, i.e. 6 + len(payload).  DSAP and SSAP are both zero and
control is 0x03 (unnumbered information), which is what marks the frame as
DOCSIS MAC management rather than a normal LLC frame.
"""

from __future__ import annotations

from dataclasses import dataclass

from .consts import DOCSIS_MGMT_MULTICAST, MgmtType

HEADER_LEN = 20
LLC_OVERHEAD = 6   # DSAP..RSVD, counted by msg_length


class MgmtError(ValueError):
    """A MAC management header that cannot be encoded or decoded."""
    pass


@dataclass
class MgmtMessage:
    """The 20-byte MAC management header and its payload."""
    type: int
    version: int
    src: bytes
    dst: bytes = DOCSIS_MGMT_MULTICAST
    payload: bytes = b""
    dsap: int = 0x00
    ssap: int = 0x00
    control: int = 0x03
    rsvd: int = 0x00

    @property
    def type_name(self) -> str:
        try:
            return MgmtType(self.type).name
        except ValueError:
            return f"TYPE-{self.type}"

    def encode(self) -> bytes:
        if len(self.src) != 6 or len(self.dst) != 6:
            raise MgmtError("MAC addresses must be 6 bytes")
        msg_len = LLC_OVERHEAD + len(self.payload)
        return (self.dst + self.src
                + msg_len.to_bytes(2, "big")
                + bytes([self.dsap, self.ssap, self.control,
                         self.version, self.type, self.rsvd])
                + self.payload)


def decode(data: bytes) -> MgmtMessage:
    """Decode a MAC management header and split off its payload."""
    if len(data) < HEADER_LEN:
        raise MgmtError(f"MAC management message too short: {len(data)} bytes")
    dst = data[0:6]
    src = data[6:12]
    msg_len = int.from_bytes(data[12:14], "big")
    dsap, ssap, control, version, type_, rsvd = data[14:20]
    payload_len = msg_len - LLC_OVERHEAD
    if payload_len < 0:
        raise MgmtError(f"msg_length {msg_len} is below the LLC overhead")
    payload = data[HEADER_LEN:HEADER_LEN + payload_len]
    if len(payload) < payload_len:
        raise MgmtError(
            f"{MgmtType(type_).name if type_ in set(MgmtType) else type_}: "
            f"msg_length says {payload_len} payload bytes, {len(payload)} present")
    return MgmtMessage(type=type_, version=version, src=src, dst=dst,
                       payload=payload, dsap=dsap, ssap=ssap, control=control,
                       rsvd=rsvd)
