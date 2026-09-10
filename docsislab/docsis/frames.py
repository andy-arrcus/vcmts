"""Putting a MAC management message on the wire, and taking it off again.

This is the single seam between "a message object" and "bytes in a burst":

    encode_mgmt(Sync(ts), src=cmts_mac)      -> full MAC frame, ready to send
    parse(frame_bytes)                       -> ParsedFrame with the message

Keeping the version-byte lookup here means no caller has to remember that a
MAP is version 1 while a type-29 UCD is version 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import machdr, mgmt
from . import messages as M
from .consts import (DOCSIS_MGMT_MULTICAST, FCParm, FCType, MGMT_MSG_VERSION,
                     MGMT_VERSION_11, MgmtType)


def mgmt_version(msg_type: int) -> int:
    """The `version` byte a given message type must carry."""
    return MGMT_MSG_VERSION.get(msg_type, MGMT_VERSION_11)


def encode_mgmt(msg: Any, src: bytes, dst: bytes = DOCSIS_MGMT_MULTICAST) -> bytes:
    """Encode a message object into a complete DOCSIS MAC frame."""
    msg_type = int(msg.TYPE)
    body = msg.encode()
    mm = mgmt.MgmtMessage(type=msg_type, version=mgmt_version(msg_type),
                          src=src, dst=dst, payload=body)
    # SYNC rides in a Timing header rather than a MAC management header.
    return machdr.build_mgmt_frame(mm.encode(), timing=(msg_type == MgmtType.SYNC))


@dataclass
class ParsedFrame:
    """A decoded MAC frame plus, where applicable, its decoded contents."""
    mac: machdr.MacFrame
    mgmt: mgmt.MgmtMessage | None = None
    message: Any = None
    #: For Packet PDUs: the Ethernet frame, FCS included.
    eth: bytes | None = None

    @property
    def kind(self) -> str:
        if self.message is not None and self.mgmt is not None:
            return self.mgmt.type_name
        if self.mac.is_request:
            return "REQ"
        if self.mac.is_packet_pdu:
            return "PDU"
        if self.mac.fc_type == FCType.MAC_SPECIFIC and self.mac.fc_parm == FCParm.CONCATENATION:
            return "CONCAT"
        return self.mac.describe()

    def summary(self) -> str:
        if self.message is not None and hasattr(self.message, "summary"):
            return self.message.summary()
        return self.mac.describe()


def parse(data: bytes) -> ParsedFrame:
    """Decode a MAC frame and, where applicable, its management message."""
    mac = machdr.decode(data)
    out = ParsedFrame(mac=mac)
    if mac.is_mgmt:
        out.mgmt = mgmt.decode(mac.payload)
        out.message = M.decode_body(out.mgmt.type, out.mgmt.payload)
    elif mac.is_packet_pdu:
        out.eth = mac.payload
    return out
