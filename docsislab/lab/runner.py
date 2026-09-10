"""Wires the plant, CMTS, provisioning server, modems and CPEs together.

Deliberately the only module that knows about all of them.  Everything else
talks through the HFC plant or the network-side link.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..cm.cm import CableModem, CmState
from ..cm.cpe import Cpe
from ..cmts.cmts import Cmts
from ..phy.plant import HfcPlant
from ..provisioning.server import ProvisioningServer
from ..util.capture import Capture
from ..util.log import EventLog
from .sim import Scheduler
from .topology import Topology


@dataclass
class LabOptions:
    """How to run a lab: time scale, capture path, logging."""
    speed: float = 1.0
    capture_path: str | None = "captures/docsis.pcapng"
    capture_comments: bool = True
    echo: bool = True
    echo_level: str = "info"
    mute: tuple[str, ...] = ()
    seed: int = 20020101
    #: Start the simulated CPE's DHCP once its modem is online.
    cpe_autostart: bool = True


class Lab:
    """Wires the plant, CMTS, provisioning host, modems and CPEs together."""
    def __init__(self, topo: Topology, opts: LabOptions | None = None):
        self.topo = topo
        self.opts = opts or LabOptions()
        self.wall_epoch = time.time()

        self.sched = Scheduler(speed=self.opts.speed)
        self.log = EventLog(now=self.sched.now)
        self.log.echo = self.opts.echo
        self.log.echo_level = self.opts.echo_level
        self.log.mute = set(self.opts.mute)

        self.capture = Capture(self.opts.capture_path or "",
                               epoch=self.wall_epoch,
                               enabled=bool(self.opts.capture_path),
                               comments=self.opts.capture_comments)

        import random
        self.plant = HfcPlant(self.sched, topo.downstreams, topo.upstreams,
                              capture=self.capture,
                              rng=random.Random(self.opts.seed))

        self.cmts = Cmts(self.sched, self.plant, topo.cmts,
                         self.log.logger("cmts"), self.capture)
        self.provisioning = ProvisioningServer(
            self.sched, topo.provisioning, self.log.logger("prov"),
            self.capture, wall_epoch=self.wall_epoch)
        # The CMTS network-side interface and the provisioning host share a
        # simulated Ethernet segment.
        self.cmts.nsi_peer = self.provisioning.stack
        self.provisioning.peer = self.cmts
        self.cmts.default_gateway = topo.provisioning.ip

        for name, spec in topo.config_files.items():
            self.provisioning.add_config_file(name, spec)

        self.modems: dict[str, CableModem] = {}
        self.cpes: dict[str, Cpe] = {}
        for cm_cfg in topo.modems:
            modem = CableModem(self.sched, self.plant, cm_cfg,
                               self.log.logger(cm_cfg.name), self.capture)
            self.modems[cm_cfg.name] = modem
        for i, cpe_cfg in enumerate(topo.cpes):
            names = list(self.modems)
            if i >= len(names):
                break
            modem = self.modems[names[i]]
            self.cpes[cpe_cfg.name] = Cpe(self.sched, modem, cpe_cfg,
                                          self.log.logger(cpe_cfg.name),
                                          self.capture)
        self._cpe_started: set[str] = set()
        self._online_at: dict[str, float] = {}

    # ------------------------------------------------------------------
    def start(self) -> None:
        self.log.logger("lab").notice("boot",
            f"topology {self.topo.name!r}: {len(self.topo.downstreams)} DS, "
            f"{len(self.topo.upstreams)} US, {len(self.modems)} modem(s), "
            f"capture -> {self.opts.capture_path or 'disabled'}")
        self.cmts.start()
        for modem in self.modems.values():
            # Stagger power-up slightly so several modems contend for the
            # same Initial Maintenance region rather than lining up neatly.
            delay = 0.05 + 0.013 * len(self._online_at)
            self.sched.after(delay, modem.power_on, name="power-on")
        self.sched.add_poller(self._watch)

    def _watch(self) -> None:
        for name, modem in self.modems.items():
            if modem.state == CmState.OPERATIONAL and name not in self._online_at:
                self._online_at[name] = self.sched.now()
                self.log.logger("lab").notice(
                    "online", f"{name} reached operational state after "
                              f"{self.sched.now():.3f} s of simulated time")
            if (self.opts.cpe_autostart and modem.state == CmState.OPERATIONAL
                    and name not in self._cpe_started):
                self._cpe_started.add(name)
                for cpe in self.cpes.values():
                    if cpe.modem is modem:
                        self.sched.after(cpe.cfg.dhcp_delay, cpe.start_dhcp,
                                         name="cpe-dhcp")

    # ------------------------------------------------------------------
    def run_until_online(self, timeout: float = 30.0) -> bool:
        """Run until every modem is operational, or `timeout` elapses."""
        deadline = self.sched.now() + timeout
        while self.sched.now() < deadline:
            self.sched.drain(0.010)
            if all(m.state == CmState.OPERATIONAL for m in self.modems.values()):
                return True
        return all(m.state == CmState.OPERATIONAL for m in self.modems.values())

    def run(self, until: float | None = None) -> None:
        self.sched.run(until=until)

    def close(self) -> None:
        self.capture.flush()
        self.capture.close()

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        return {
            "now": self.sched.now(),
            "wall_epoch": self.wall_epoch,
            "speed": self.opts.speed,
            "capture": {"path": self.opts.capture_path,
                        "packets": self.capture.count},
            "cmts": self.cmts.snapshot(),
            "provisioning": self.provisioning.snapshot(),
            "modems": {n: m.snapshot() for n, m in self.modems.items()},
            "cpes": {n: c.snapshot() for n, c in self.cpes.items()},
            "online_at": dict(self._online_at),
            "events": self.sched.events_run,
        }
