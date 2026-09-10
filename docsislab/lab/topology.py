"""The default lab: one CMTS, one downstream, one upstream, one modem, one CPE.

Everything is expressed as plain dataclasses so a scenario file can override
any of it, and so `docsis show topology` can print what is actually running
rather than what the defaults say.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..cm.cm import CmConfig
from ..cm.cpe import CpeConfig
from ..cmts.cmts import CmtsConfig
from ..docsis.consts import Modulation
from ..net.packet import mac_bytes
from ..phy.channel import DownstreamChannel, UpstreamChannel
from ..provisioning.server import Pool, ProvisioningConfig

#: A DOCSIS 2.0 config file granting a modest service tier.  Privacy is
#: disabled, so the modem goes straight from registration to operational
#: without a BPI+ key exchange.
DEFAULT_CM_CONFIG = {
    "network_access": True,
    "upstream_service_flows": [{
        "ref": 1,
        "qos_param_set": 7,
        "traffic_priority": 1,
        "max_sustained_bps": 2_000_000,
        "max_burst_bytes": 3044,
        "min_reserved_bps": 0,
        "max_concatenated_burst": 1522,
        "scheduling_type": 2,               # best effort
    }],
    "downstream_service_flows": [{
        "ref": 2,
        "qos_param_set": 7,
        "traffic_priority": 1,
        "max_sustained_bps": 20_000_000,
        "max_burst_bytes": 3044,
    }],
    "max_cpe": 4,
    "max_classifiers": 8,
    "privacy_enable": False,
}


@dataclass
class Topology:
    """What a lab is made of: channels, CMTS, modems, CPEs, config files."""
    name: str = "default"
    #: Wall-clock time the simulation pretends to start at; the pcap uses it.
    downstreams: list[DownstreamChannel] = field(default_factory=lambda: [
        DownstreamChannel(channel_id=1, center_freq_hz=555_000_000,
                          modulation=Modulation.QAM256),
    ])
    upstreams: list[UpstreamChannel] = field(default_factory=lambda: [
        # 3.2 MHz A-TDMA.  Narrow enough that a type-2 UCD can describe it
        # too, which is what makes the mixed-mode UCD pair meaningful.
        UpstreamChannel(channel_id=1, center_freq_hz=30_000_000,
                        width_hz=3_200_000, minislot_ticks=4,
                        phy_mode="atdma", data_modulation=Modulation.QAM64),
    ])
    cmts: CmtsConfig = field(default_factory=CmtsConfig)
    modems: list[CmConfig] = field(default_factory=lambda: [
        CmConfig(name="cm0", mac=mac_bytes("001dcf112233"), distance_km=10.0,
                 tx_power_dbmv=45.0, freq_error_hz=120),
    ])
    cpes: list[CpeConfig] = field(default_factory=lambda: [
        CpeConfig(name="cpe0", mac=mac_bytes("020e00000001"), hostname="laptop"),
    ])
    provisioning: ProvisioningConfig = field(default_factory=lambda: ProvisioningConfig(
        pools=[
            Pool(name="cable-modems", relay="10.10.0.1", subnet="10.10.0.0",
                 netmask="255.255.255.0", gateway="10.10.0.1",
                 first=10, last=99, tftp_server="10.30.0.2",
                 time_server="10.30.0.2", log_server="10.30.0.2",
                 default_config="cm-default.cfg"),
            Pool(name="subscribers", relay="10.20.0.1", subnet="10.20.0.0",
                 netmask="255.255.255.0", gateway="10.20.0.1",
                 first=10, last=200, dns="10.30.0.2"),
        ]))
    config_files: dict[str, dict] = field(default_factory=lambda: {
        "cm-default.cfg": dict(DEFAULT_CM_CONFIG),
    })


def second_upstream() -> UpstreamChannel:
    """A 6.4 MHz A-TDMA channel: DOCSIS 2.0 only.

    At 5.12 Msym/s no type-2 UCD can describe it, so a DOCSIS 1.x modem
    cannot see this channel at all.  Handy for demonstrating what the
    type-29 UCD actually buys you.
    """
    from ..docsis.consts import Modulation as Mod
    return UpstreamChannel(channel_id=2, center_freq_hz=36_000_000,
                           width_hz=6_400_000, minislot_ticks=4,
                           phy_mode="atdma", data_modulation=Mod.QAM64)
