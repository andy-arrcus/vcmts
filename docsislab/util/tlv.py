"""Type/Length/Value encoding, as used everywhere in DOCSIS.

DOCSIS uses single-byte type and single-byte length fields throughout: in
MAC management messages (UCD channel parameters, RNG-RSP adjustments,
REG-REQ/RSP settings) and in the binary configuration file the modem pulls
over TFTP.  Compound TLVs simply carry more TLVs as their value, which is how
service flow and class-of-service encodings nest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


class TLVError(ValueError):
    """A TLV stream that cannot be encoded or decoded."""
    pass


@dataclass
class TLV:
    """One type/length/value encoding, with optional sub-TLVs."""
    type: int
    value: bytes = b""
    #: Sub-TLVs, for compound encodings.  When present, `value` is ignored on
    #: encode and rebuilt from the children.
    sub: list["TLV"] = field(default_factory=list)

    def encode(self) -> bytes:
        value = encode(self.sub) if self.sub else self.value
        if len(value) > 255:
            raise TLVError(f"TLV {self.type} value is {len(value)} bytes, max 255")
        return bytes([self.type, len(value)]) + value

    # -- typed accessors -------------------------------------------------
    @property
    def as_int(self) -> int:
        return int.from_bytes(self.value, "big")

    @property
    def as_sint(self) -> int:
        return int.from_bytes(self.value, "big", signed=True)

    def sub_map(self) -> dict[int, "TLV"]:
        return {t.type: t for t in self.sub}

    def get(self, type_: int) -> "TLV | None":
        for t in self.sub:
            if t.type == type_:
                return t
        return None

    def get_int(self, type_: int, default: int | None = None) -> int | None:
        t = self.get(type_)
        return t.as_int if t is not None else default


# --------------------------------------------------------------------------
# constructors
# --------------------------------------------------------------------------

def u8(type_: int, value: int) -> TLV:
    return TLV(type_, bytes([value & 0xFF]))


def u16(type_: int, value: int) -> TLV:
    return TLV(type_, (value & 0xFFFF).to_bytes(2, "big"))


def u32(type_: int, value: int) -> TLV:
    return TLV(type_, (value & 0xFFFFFFFF).to_bytes(4, "big"))


def s8(type_: int, value: int) -> TLV:
    return TLV(type_, int(value).to_bytes(1, "big", signed=True))


def s16(type_: int, value: int) -> TLV:
    return TLV(type_, int(value).to_bytes(2, "big", signed=True))


def s32(type_: int, value: int) -> TLV:
    return TLV(type_, int(value).to_bytes(4, "big", signed=True))


def raw(type_: int, value: bytes) -> TLV:
    return TLV(type_, bytes(value))


def compound(type_: int, subs: Iterable[TLV]) -> TLV:
    return TLV(type_, b"", list(subs))


# --------------------------------------------------------------------------
# codec
# --------------------------------------------------------------------------

def encode(tlvs: Iterable[TLV]) -> bytes:
    return b"".join(t.encode() for t in tlvs)


def decode(data: bytes, compound_types: set[int] | None = None,
           strict: bool = True) -> list[TLV]:
    """Decode a TLV stream.

    `compound_types` names the types whose values should be recursively
    decoded.  Everything else is left as opaque bytes, because the same type
    number means different things in different messages and only the caller
    knows the context.
    """
    compound_types = compound_types or set()
    out: list[TLV] = []
    i = 0
    end = len(data)
    while i < end:
        # A lone 0x00 is a Pad, and 0xFF is the end-of-data marker: neither
        # carries a length byte.
        type_ = data[i]
        if type_ == 0:
            i += 1
            continue
        if type_ == 255:
            out.append(TLV(255, b""))
            i += 1
            continue
        if i + 2 > end:
            if strict:
                raise TLVError(f"truncated TLV header at offset {i}")
            break
        length = data[i + 1]
        if i + 2 + length > end:
            if strict:
                raise TLVError(
                    f"TLV type {type_} at offset {i} claims {length} bytes, "
                    f"only {end - i - 2} remain")
            break
        value = data[i + 2:i + 2 + length]
        tlv = TLV(type_, value)
        if type_ in compound_types:
            try:
                tlv.sub = decode(value, compound_types, strict=strict)
            except TLVError:
                pass
        out.append(tlv)
        i += 2 + length
    return out


def find(tlvs: Iterable[TLV], type_: int) -> TLV | None:
    for t in tlvs:
        if t.type == type_:
            return t
    return None


def find_all(tlvs: Iterable[TLV], type_: int) -> list[TLV]:
    return [t for t in tlvs if t.type == type_]
