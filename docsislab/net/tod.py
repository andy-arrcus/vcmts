"""Time of Day (RFC 868), UDP port 37.

A DOCSIS modem must acquire time of day before it registers -- it needs it to
timestamp its own event log, and BPI+ needs it to check certificate validity.
The payload is a single 32-bit count of seconds since 1900-01-01 00:00 UTC.
"""

from __future__ import annotations

PORT = 37

#: Seconds between the RFC 868 epoch (1900) and the Unix epoch (1970).
EPOCH_OFFSET = 2_208_988_800


def encode(unix_time: float) -> bytes:
    return (int(unix_time) + EPOCH_OFFSET & 0xFFFFFFFF).to_bytes(4, "big")


def decode(payload: bytes) -> float | None:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[0:4], "big") - EPOCH_OFFSET
