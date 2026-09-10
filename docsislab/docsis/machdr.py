"""The DOCSIS MAC frame header -- RFIv2.0 section 6.2.1.

Every byte that crosses the virtual HFC plant starts with one of these:

    +----+----------+-----------+----------+-----+---------+
    | FC | MAC_PARM |  LEN/SID  |   EHDR   | HCS | payload |
    +----+----------+-----------+----------+-----+---------+
      1       1           2       0..240      2

FC packs three fields:

    bits 7..6  FC_TYPE   packet PDU / ATM / isolation / MAC-specific
    bits 5..1  FC_PARM   meaning depends on FC_TYPE
    bit  0     EHDR_ON   an extended header follows LEN/SID

The one field that reliably trips people up is LEN.  Per RFIv2.0 Table 6-3 it
is "the sum of the number of bytes in the extended header and the number of
bytes following the HCS field" -- so when an EHDR is present the EHDR is
counted twice over, once via MAC_PARM and once inside LEN.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..util.crc import hcs, hcs_bytes, hcs_from_wire
from .consts import FCType, FCParm, EHdrType

HDR_BASE_LEN = 6


class MacFrameError(ValueError):
    """A MAC frame that cannot be encoded or decoded."""
    pass


@dataclass
class EHdrElement:
    """One element inside the extended header."""
    type: int
    value: bytes = b""

    def encode(self) -> bytes:
        if self.type == EHdrType.EXTENDED:
            # EH_TYPE 15: the length nibble is 0 and real type/len follow.
            return bytes([0xF0 | 0]) + bytes([self.type, len(self.value)]) + self.value
        if len(self.value) > 15:
            raise MacFrameError(f"EHDR element {self.type} too long ({len(self.value)})")
        return bytes([((self.type & 0x0F) << 4) | (len(self.value) & 0x0F)]) + self.value


def ehdr_request(sid: int, minislots: int) -> EHdrElement:
    """A piggybacked bandwidth request (EH_TYPE 1): request `minislots` for `sid`."""
    return EHdrElement(EHdrType.REQUEST,
                       bytes([minislots & 0xFF]) + (sid & 0x3FFF).to_bytes(2, "big"))


def encode_ehdr(elements: list[EHdrElement]) -> bytes:
    """Serialise extended header elements into the EHDR field."""
    return b"".join(e.encode() for e in elements)


@dataclass
class MacFrame:
    """A decoded DOCSIS MAC frame."""
    fc_type: int
    fc_parm: int
    mac_parm: int = 0
    len_sid: int = 0
    ehdr: bytes = b""
    payload: bytes = b""
    hcs_ok: bool = True
    #: filled in by decode() so callers can report on malformed input
    raw: bytes = b""

    @property
    def ehdr_on(self) -> bool:
        return len(self.ehdr) > 0

    @property
    def header_len(self) -> int:
        return HDR_BASE_LEN + len(self.ehdr)

    @property
    def is_mac_specific(self) -> bool:
        return self.fc_type == FCType.MAC_SPECIFIC

    @property
    def is_request(self) -> bool:
        return self.is_mac_specific and self.fc_parm == FCParm.REQUEST

    @property
    def is_mgmt(self) -> bool:
        return self.is_mac_specific and self.fc_parm in (FCParm.TIMING, FCParm.MAC_MGMT)

    @property
    def is_packet_pdu(self) -> bool:
        return self.fc_type == FCType.PACKET

    @property
    def sid(self) -> int:
        """Only meaningful for Request frames, where LEN/SID holds a SID."""
        return self.len_sid & 0x3FFF

    def encode(self) -> bytes:
        fc = ((self.fc_type & 0x03) << 6) | ((self.fc_parm & 0x1F) << 1) | (1 if self.ehdr else 0)
        hdr = bytes([fc, self.mac_parm & 0xFF]) + (self.len_sid & 0xFFFF).to_bytes(2, "big") + self.ehdr
        return hdr + hcs_bytes(hdr) + self.payload

    def describe(self) -> str:
        if self.is_request:
            return f"REQ sid={self.sid} minislots={self.mac_parm}"
        if self.fc_type == FCType.MAC_SPECIFIC:
            name = {FCParm.TIMING: "TIMING", FCParm.MAC_MGMT: "MAC-MGMT",
                    FCParm.FRAGMENTATION: "FRAG",
                    FCParm.QUEUE_DEPTH_REQ: "QUEUE-DEPTH-REQ",
                    FCParm.CONCATENATION: "CONCAT"}.get(self.fc_parm, f"MACSPC/{self.fc_parm}")
            return f"{name} len={self.len_sid}"
        return f"PDU len={self.len_sid}"


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------

def build_mgmt_frame(mgmt_bytes: bytes, timing: bool = False,
                     ehdr: list[EHdrElement] | None = None) -> bytes:
    """Wrap an already-encoded MAC management message in a MAC header.

    SYNC uses the Timing header (FC_PARM 0); everything else uses the MAC
    management header (FC_PARM 1).
    """
    eh = encode_ehdr(ehdr) if ehdr else b""
    frame = MacFrame(
        fc_type=FCType.MAC_SPECIFIC,
        fc_parm=FCParm.TIMING if timing else FCParm.MAC_MGMT,
        mac_parm=len(eh),
        len_sid=len(eh) + len(mgmt_bytes),
        ehdr=eh,
        payload=mgmt_bytes,
    )
    return frame.encode()


def build_packet_pdu(eth_frame_with_fcs: bytes,
                     ehdr: list[EHdrElement] | None = None) -> bytes:
    """Wrap an Ethernet frame (including its 4-byte FCS) as a Packet PDU."""
    eh = encode_ehdr(ehdr) if ehdr else b""
    frame = MacFrame(
        fc_type=FCType.PACKET,
        fc_parm=0,
        mac_parm=len(eh),
        len_sid=len(eh) + len(eth_frame_with_fcs),
        ehdr=eh,
        payload=eth_frame_with_fcs,
    )
    return frame.encode()


def build_request(sid: int, minislots: int) -> bytes:
    """A bandwidth Request frame: six bytes, no payload.

    MAC_PARM carries the number of mini-slots requested and LEN/SID carries
    the SID doing the asking (RFIv2.0 section 6.2.4).
    """
    if not 0 <= minislots <= 255:
        raise MacFrameError(f"request of {minislots} mini-slots does not fit in MAC_PARM")
    frame = MacFrame(
        fc_type=FCType.MAC_SPECIFIC,
        fc_parm=FCParm.REQUEST,
        mac_parm=minislots,
        len_sid=sid & 0x3FFF,
    )
    return frame.encode()


def build_concatenation(frames: list[bytes]) -> bytes:
    """Concatenation header (DOCSIS 1.1+): several MAC frames in one burst."""
    body = b"".join(frames)
    frame = MacFrame(
        fc_type=FCType.MAC_SPECIFIC,
        fc_parm=FCParm.CONCATENATION,
        mac_parm=len(frames),
        len_sid=len(body),
        payload=body,
    )
    return frame.encode()


# --------------------------------------------------------------------------
# decoder
# --------------------------------------------------------------------------

def decode(data: bytes) -> MacFrame:
    """Decode one MAC frame, verifying the HCS."""
    if len(data) < HDR_BASE_LEN:
        raise MacFrameError(f"runt MAC frame, {len(data)} bytes")
    fc = data[0]
    fc_type = (fc >> 6) & 0x03
    fc_parm = (fc >> 1) & 0x1F
    ehdr_on = fc & 0x01
    mac_parm = data[1]
    len_sid = int.from_bytes(data[2:4], "big")

    ehdr_len = mac_parm if ehdr_on else 0
    if ehdr_on and fc_type == FCType.MAC_SPECIFIC and fc_parm == FCParm.REQUEST:
        # A Request frame has no EHDR: MAC_PARM is the mini-slot count.
        ehdr_len = 0
    if len(data) < HDR_BASE_LEN + ehdr_len:
        raise MacFrameError("MAC frame truncated inside extended header")
    ehdr = data[4:4 + ehdr_len]
    hcs_off = 4 + ehdr_len
    got_hcs = hcs_from_wire(data[hcs_off:hcs_off + 2])
    hcs_ok = got_hcs == hcs(data[:hcs_off])

    body = data[hcs_off + 2:]
    if fc_type == FCType.MAC_SPECIFIC and fc_parm == FCParm.REQUEST:
        payload = b""
    else:
        want = len_sid - ehdr_len
        if want < 0:
            raise MacFrameError(f"LEN {len_sid} smaller than EHDR {ehdr_len}")
        payload = body[:want]
        if len(payload) < want:
            raise MacFrameError(
                f"MAC frame claims {want} payload bytes, only {len(body)} present")
    return MacFrame(fc_type=fc_type, fc_parm=fc_parm, mac_parm=mac_parm,
                    len_sid=len_sid, ehdr=ehdr, payload=payload,
                    hcs_ok=hcs_ok, raw=data)


def decode_all(data: bytes) -> list[MacFrame]:
    """Decode a concatenation body / burst containing several MAC frames."""
    out: list[MacFrame] = []
    off = 0
    while off < len(data):
        try:
            frame = decode(data[off:])
        except MacFrameError:
            break
        out.append(frame)
        consumed = frame.header_len + 2 + len(frame.payload)
        if frame.is_request:
            consumed = HDR_BASE_LEN
        if consumed <= 0:
            break
        off += consumed
    return out
