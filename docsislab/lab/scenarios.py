"""Pre-built situations worth watching.

Each returns a (Topology, LabOptions-overrides, description) triple.  They
exist because the interesting parts of DOCSIS are mostly failure and
contention behaviour, which a single healthy modem never shows you.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from typing import Callable

from ..cm.cm import CmConfig
from ..cm.cpe import CpeConfig
from ..docsis.consts import DocsisVersion
from ..net.packet import mac_bytes
from .topology import DEFAULT_CM_CONFIG, Topology, second_upstream


@dataclass
class Scenario:
    """A named situation, and what is worth watching in it."""
    name: str
    description: str
    build: Callable[[], Topology]
    watch: str = ""


def _mac(n: int) -> bytes:
    return mac_bytes(f"001dcf{n:06x}")


def _cpe_mac(n: int) -> bytes:
    return mac_bytes(f"020e00{n:06x}")


# --------------------------------------------------------------------------

def _default() -> Topology:
    return Topology(name="default")


def _mixed() -> Topology:
    """A DOCSIS 1.1 modem and a DOCSIS 2.0 modem sharing one upstream."""
    t = Topology(name="mixed")
    t.modems = [
        CmConfig(name="cm20", mac=_mac(0x112233), distance_km=10.0,
                 docsis_version=DocsisVersion.V20, freq_error_hz=120),
        CmConfig(name="cm11", mac=_mac(0x445566), distance_km=4.0,
                 docsis_version=DocsisVersion.V11, freq_error_hz=-80,
                 concatenation=True, fragmentation=True),
    ]
    t.cpes = [CpeConfig(name="cpe0", mac=_cpe_mac(1), hostname="laptop")]
    return t


def _two_upstream() -> Topology:
    """Adds a 6.4 MHz A-TDMA channel that DOCSIS 1.x cannot even see."""
    t = _mixed()
    t.name = "two-upstream"
    t.upstreams = list(t.upstreams) + [second_upstream()]
    return t


def _crowd(count: int = 8) -> Topology:
    """Modems powering up together, contending for the same Initial
    Maintenance region."""
    t = Topology(name="crowd")
    t.modems = [
        CmConfig(name=f"cm{i}", mac=_mac(0x100000 + i),
                 distance_km=2.0 + 3.0 * i,
                 freq_error_hz=(-1) ** i * 40 * i,
                 seed=1000 + i)
        for i in range(count)
    ]
    t.cpes = []
    return t


def _noisy() -> Topology:
    t = Topology(name="noisy")
    t.modems = [CmConfig(name="cm0", mac=_mac(0x112233), distance_km=10.0,
                         freq_error_hz=120)]
    return t


def _far() -> Topology:
    """A modem beyond the distance the plant was engineered for."""
    t = Topology(name="far")
    t.modems = [CmConfig(name="cm-far", mac=_mac(0xfa0001), distance_km=60.0,
                         tx_power_dbmv=58.0)]
    t.cpes = []
    return t


def _bad_secret() -> Topology:
    """The provisioning system signs config files with the wrong shared
    secret, so the CMTS MIC will not verify."""
    t = Topology(name="bad-secret")
    t.provisioning = replace(t.provisioning, shared_secret=b"not-the-secret")
    t.cpes = []
    return t


def _no_access() -> Topology:
    """Network access disabled in the config file: the modem registers but
    forwards nothing, and the CMTS shows it as online(d)."""
    t = Topology(name="no-access")
    spec = copy.deepcopy(DEFAULT_CM_CONFIG)
    spec["network_access"] = False
    t.config_files = {"cm-default.cfg": spec}
    return t


def _over_rate() -> Topology:
    """A config file asking for more upstream than the CMTS will admit."""
    t = Topology(name="over-rate")
    spec = copy.deepcopy(DEFAULT_CM_CONFIG)
    spec["upstream_service_flows"][0]["max_sustained_bps"] = 500_000_000
    t.config_files = {"cm-default.cfg": spec}
    t.cpes = []
    return t


def _long_haul() -> Topology:
    """A plant engineered for 100 km, with a modem 80 km out.  Shows the
    Initial Maintenance region growing to cover the round trip."""
    t = Topology(name="long-haul")
    t.cmts = replace(t.cmts,
                     scheduler=replace(t.cmts.scheduler, max_reach_km=100.0))
    t.modems = [CmConfig(name="cm-80km", mac=_mac(0x800080), distance_km=80.0,
                         tx_power_dbmv=58.0)]
    t.cpes = []
    return t


SCENARIOS: dict[str, Scenario] = {
    "default": Scenario(
        "default", "one DOCSIS 2.0 modem, one CPE, mixed-mode UCDs",
        _default,
        watch="the ranging offset converging on the round trip, then the "
              "grants switching from IUC 6 to IUC 10 once DHCP option 60 "
              "reveals the modem is DOCSIS 2.0"),
    "mixed": Scenario(
        "mixed", "a DOCSIS 1.1 modem and a 2.0 modem on the same upstream",
        _mixed,
        watch="cm11 ignoring the type-29 UCD and using IUC 5/6 grants while "
              "cm20 gets IUC 9/10 on the same channel"),
    "two-upstream": Scenario(
        "two-upstream", "adds a 6.4 MHz A-TDMA channel (DOCSIS 2.0 only)",
        _two_upstream,
        watch="'show cable ucd' -- US2 gets no type-2 UCD at all, because "
              "5120 ksym/s cannot be expressed in one"),
    "crowd": Scenario(
        "crowd", "eight modems powering up at once",
        _crowd,
        watch="collisions in the broadcast Initial Maintenance region, and "
              "the ranging back-off window doubling on each failure"),
    "noisy": Scenario(
        "noisy", "one modem on an upstream with 25% burst loss",
        _noisy,
        watch="T3 timeouts, back-off growth and transmit level creeping up"),
    "far": Scenario(
        "far", "a modem 60 km out on a plant engineered for 25 km",
        _far,
        watch="ranging bursts arriving after the end of the Initial "
              "Maintenance region and simply not being received"),
    "long-haul": Scenario(
        "long-haul", "a 100 km plant with a modem 80 km out",
        _long_haul,
        watch="'show cable timing' -- the Initial Maintenance region is much "
              "larger, and the final ranging offset is over 6000 units"),
    "bad-secret": Scenario(
        "bad-secret", "config files signed with the wrong shared secret",
        _bad_secret,
        watch="the modem completes TFTP and registration is then refused with "
              "authentication failure; CMTS state reject(m)"),
    "no-access": Scenario(
        "no-access", "config file with network access disabled",
        _no_access,
        watch="the modem reaches online(d): registered, but the CMTS drops "
              "its CPE traffic"),
    "over-rate": Scenario(
        "over-rate", "config file requesting 500 Mbit/s upstream",
        _over_rate,
        watch="REG-RSP class-of-service failure; CMTS state reject(c)"),
}


def apply_runtime(name: str, lab) -> None:
    """Scenario tweaks that need the running lab rather than the topology."""
    if name == "noisy":
        lab.plant.us_loss_prob = 0.25
        lab.log.logger("lab").notice(
            "scenario", "upstream burst loss set to 25%")
