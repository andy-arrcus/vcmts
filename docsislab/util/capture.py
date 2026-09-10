"""Capture point for the whole simulation.

Writes a single pcapng with four interfaces so that Wireshark can show a
DOCSIS downstream frame, the modem's upstream burst that answered it, and the
DHCP relay traffic on the CMTS network side in one timeline.  Every packet
carries a comment describing what the simulation was doing, which is what
makes the capture readable rather than merely correct.
"""

from __future__ import annotations

import os

from .pcapng import (DEFAULT_INTERFACES, IF_CPE, IF_DS, IF_NSI, IF_US,
                     PcapngWriter)


class Capture:
    """The simulation's pcapng capture point."""
    def __init__(self, path: str, epoch: float, enabled: bool = True,
                 comments: bool = True):
        self.path = path
        self.epoch = epoch
        self.enabled = enabled
        self.comments = comments
        self._writer: PcapngWriter | None = None
        if enabled:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            self._writer = PcapngWriter(path, DEFAULT_INTERFACES)

    def _write(self, iface: int, t: float, data: bytes, comment: str) -> None:
        if self._writer is None:
            return
        self._writer.packet(iface, self.epoch + t, data,
                            comment if self.comments else "")

    def downstream(self, t: float, frame: bytes, comment: str = "") -> None:
        self._write(IF_DS, t, frame, comment)

    def upstream(self, t: float, frame: bytes, comment: str = "") -> None:
        self._write(IF_US, t, frame, comment)

    def nsi(self, t: float, frame: bytes, comment: str = "") -> None:
        self._write(IF_NSI, t, frame, comment)

    def cpe(self, t: float, frame: bytes, comment: str = "") -> None:
        self._write(IF_CPE, t, frame, comment)

    @property
    def count(self) -> int:
        return self._writer.count if self._writer else 0

    def flush(self) -> None:
        if self._writer:
            self._writer.flush()

    def close(self) -> None:
        if self._writer:
            self._writer.close()
            self._writer = None
