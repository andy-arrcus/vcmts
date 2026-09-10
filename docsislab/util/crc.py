"""CRC routines used by DOCSIS.

Two checksums matter on a DOCSIS wire:

  * The MAC header HCS -- a CRC-16 over every byte of the MAC header that
    precedes the HCS field itself.  DOCSIS (CM-SP-RFIv2.0 6.2.1.6) specifies
    the CRC-CCITT polynomial x^16 + x^12 + x^5 + 1 with an all-ones preset.
  * The Ethernet FCS carried inside a Packet PDU -- a standard CRC-32.  A
    DOCSIS Packet PDU carries the *whole* Ethernet frame including its FCS,
    which is why LEN is 4 bytes longer than you might expect.

`hcs()` is the one the rest of the codebase calls.  The other CRC-16 variants
exist because the exact bit ordering of the HCS is the sort of thing that is
easy to get subtly wrong, so `tools/probe_wireshark.py` emits one frame per
variant and lets Wireshark's dissector tell us which one is right.
"""

from __future__ import annotations

POLY_CCITT = 0x1021
POLY_CCITT_REVERSED = 0x8408


def _table_msb(poly: int) -> list[int]:
    table = []
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        table.append(crc)
    return table


def _table_lsb(poly: int) -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc & 0xFFFF)
    return table


_MSB = _table_msb(POLY_CCITT)
_LSB = _table_lsb(POLY_CCITT_REVERSED)


def crc16_unreflected(data: bytes, init: int = 0xFFFF, xorout: int = 0x0000) -> int:
    crc = init
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _MSB[((crc >> 8) ^ byte) & 0xFF]
    return crc ^ xorout


def crc16_reflected(data: bytes, init: int = 0xFFFF, xorout: int = 0x0000) -> int:
    crc = init
    for byte in data:
        crc = (crc >> 8) ^ _LSB[(crc ^ byte) & 0xFF]
    return crc ^ xorout


# Named variants, so the Wireshark probe can label its findings.
CRC16_VARIANTS: dict[str, callable] = {
    # poly 0x1021, init 0xFFFF, no reflection, no final xor
    "ccitt-false": lambda d: crc16_unreflected(d, 0xFFFF, 0x0000),
    # ... plus a final complement
    "genibus": lambda d: crc16_unreflected(d, 0xFFFF, 0xFFFF),
    # reflected, init 0xFFFF, final complement (a.k.a. CRC-16/X-25, the HDLC FCS)
    "x25": lambda d: crc16_reflected(d, 0xFFFF, 0xFFFF),
    # reflected, init 0xFFFF, no final xor
    "mcrf4xx": lambda d: crc16_reflected(d, 0xFFFF, 0x0000),
    # reflected, init 0x0000 (a.k.a. CRC-16/KERMIT, "true CCITT")
    "kermit": lambda d: crc16_reflected(d, 0x0000, 0x0000),
    "xmodem": lambda d: crc16_unreflected(d, 0x0000, 0x0000),
}

#: Which CRC-16 variant DOCSIS uses for the MAC header HCS.
#:
#: The DOCSIS spec names the CRC-CCITT polynomial x^16+x^12+x^5+1 with an
#: all-ones preset, which describes a family rather than a single algorithm.
#: The concrete answer -- reflected input and output with a final complement,
#: i.e. CRC-16/X-25, the same FCS-16 that HDLC and PPP use -- was pinned down
#: by brute-forcing the parameter space against the expected values that
#: Wireshark's dissector reports.  See tools/probe_wireshark.py and
#: docs/WIRESHARK.md.
HCS_VARIANT = "x25"

#: ...and like the HDLC FCS it goes on the wire least-significant byte first,
#: which is the detail that actually catches people out: the polynomial can be
#: right and the frame still fails validation.
HCS_LITTLE_ENDIAN = True


def hcs(header_without_hcs: bytes) -> int:
    """The 16-bit MAC-header Header Check Sequence."""
    return CRC16_VARIANTS[HCS_VARIANT](header_without_hcs)


def hcs_bytes(header_without_hcs: bytes) -> bytes:
    return hcs(header_without_hcs).to_bytes(2, "little" if HCS_LITTLE_ENDIAN else "big")


def hcs_from_wire(two_bytes: bytes) -> int:
    """Read an HCS field off the wire back into a comparable integer."""
    return int.from_bytes(two_bytes, "little" if HCS_LITTLE_ENDIAN else "big")


# --------------------------------------------------------------------------
# Ethernet FCS
# --------------------------------------------------------------------------

_CRC32_TABLE: list[int] = []
for _byte in range(256):
    _c = _byte
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC32_TABLE.append(_c)


def eth_fcs(frame: bytes) -> int:
    """CRC-32 as used for the Ethernet frame check sequence."""
    crc = 0xFFFFFFFF
    for byte in frame:
        crc = (crc >> 8) ^ _CRC32_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


def eth_fcs_bytes(frame: bytes) -> bytes:
    """Ethernet transmits the FCS least-significant byte first."""
    return eth_fcs(frame).to_bytes(4, "little")


def with_fcs(frame: bytes) -> bytes:
    return frame + eth_fcs_bytes(frame)
