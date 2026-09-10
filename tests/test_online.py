"""End-to-end: does a cable modem actually come online, and for the right
reasons?

These run the whole simulation with `speed=0`, so they finish in well under a
second of wall-clock time while still using exact DOCSIS timing internally.
"""

import pytest

from docsislab.cm.cm import CmState
from docsislab.lab.runner import Lab, LabOptions
from docsislab.lab.scenarios import SCENARIOS, apply_runtime
from docsislab.lab.topology import Topology
from docsislab.phy.plant import delay_for_km
from docsislab.util.clock import TIMING_ADJUST_UNIT_S


def build(scenario="default", **overrides):
    topo = SCENARIOS[scenario].build()
    for key, value in overrides.items():
        setattr(topo, key, value)
    lab = Lab(topo, LabOptions(speed=0.0, capture_path=None, echo=False))
    apply_runtime(scenario, lab)
    lab.start()
    return lab


@pytest.fixture
def online_lab():
    lab = build()
    assert lab.run_until_online(timeout=20.0), "modem never came online"
    lab.sched.drain(1.0)
    yield lab
    lab.close()


# --------------------------------------------------------------------------
# the headline
# --------------------------------------------------------------------------

def test_modem_reaches_operational(online_lab):
    modem = online_lab.modems["cm0"]
    assert modem.state is CmState.OPERATIONAL
    assert modem.ip == "10.10.0.10"
    assert modem.sid > 0


def test_cmts_agrees_the_modem_is_online(online_lab):
    record = online_lab.cmts.modems.get(online_lab.modems["cm0"].cfg.mac)
    assert record is not None
    assert record.state == "online"
    assert record.docsis_version == "2.0"
    assert record.config_file == "cm-default.cfg"


def test_it_passes_through_every_initialisation_step_in_order(online_lab):
    seen = [state for _t, state in online_lab.modems["cm0"].state_history]
    expected = ["ds-scan", "ds-lock", "sync-wait", "ucd-wait", "ranging-wait",
                "ranging-initial", "ranging-station", "ranging-complete",
                "dhcp", "time-of-day", "tftp-config", "registering",
                "operational"]
    assert seen == expected


def test_cmts_side_states_track_the_provisioning_servers(online_lab):
    record = online_lab.cmts.modems.get(online_lab.modems["cm0"].cfg.mac)
    seen = [state for _t, state in record.state_history]
    # init(t) and init(o) are inferred from the ToD and TFTP traffic, which is
    # what makes them useful for saying which server a modem is stuck on.
    for expected in ["init(r1)", "init(rc)", "init(d)", "init(i)",
                     "init(t)", "init(o)", "online"]:
        assert expected in seen, f"{expected} missing from {seen}"
    assert seen.index("init(rc)") < seen.index("init(d)") < seen.index("online")


# --------------------------------------------------------------------------
# the physics
# --------------------------------------------------------------------------

def test_ranging_offset_converges_on_the_round_trip():
    """The whole point of ranging: the offset the modem ends up transmitting
    early by must equal the plant's round-trip delay."""
    lab = build()
    lab.run_until_online(timeout=20.0)
    modem = lab.modems["cm0"]
    expected_units = 2 * delay_for_km(modem.cfg.distance_km) / TIMING_ADJUST_UNIT_S
    assert modem.ranging_offset == pytest.approx(expected_units, abs=6)
    lab.close()


@pytest.mark.parametrize("km", [1.0, 5.0, 25.0])
def test_ranging_offset_scales_with_distance(km):
    from docsislab.cm.cm import CmConfig
    from docsislab.net.packet import mac_bytes
    topo = Topology()
    topo.modems = [CmConfig(name="cm0", mac=mac_bytes("001dcf112233"),
                            distance_km=km)]
    topo.cpes = []
    lab = Lab(topo, LabOptions(speed=0.0, capture_path=None, echo=False))
    lab.start()
    assert lab.run_until_online(timeout=25.0)
    expected = 2 * delay_for_km(km) / TIMING_ADJUST_UNIT_S
    assert lab.modems["cm0"].ranging_offset == pytest.approx(expected, abs=6)
    lab.close()


def test_modem_clock_lags_by_exactly_the_one_way_delay(online_lab):
    """A modem's only time reference is a SYNC that took one propagation
    delay to arrive, so its estimate of CMTS time is behind by that much --
    and that residue is what ranging measures."""
    modem = online_lab.modems["cm0"]
    expected = -delay_for_km(modem.cfg.distance_km)
    assert modem.clock_offset == pytest.approx(expected, abs=0.5e-6)


def test_receive_level_is_driven_to_the_target(online_lab):
    record = online_lab.cmts.modems.get(online_lab.modems["cm0"].cfg.mac)
    assert abs(record.rx_power_dbmv) < 1.0


def test_station_maintenance_keeps_running_after_the_modem_is_online():
    lab = build()
    lab.run_until_online(timeout=20.0)
    before = lab.cmts.stats["rng_req"]
    lab.sched.drain(12.0)             # station maintenance is every 5 s
    assert lab.cmts.stats["rng_req"] > before
    assert lab.modems["cm0"].state is CmState.OPERATIONAL
    lab.close()


# --------------------------------------------------------------------------
# the MAC layer
# --------------------------------------------------------------------------

def test_modem_only_transmits_where_it_was_granted(online_lab):
    """Every upstream burst must fall inside a region the CMTS allocated;
    anything else would be rejected as out of window."""
    assert online_lab.cmts.stats["out_of_window"] == 0
    assert online_lab.cmts.stats["bad_hcs"] == 0
    assert online_lab.cmts.stats["unknown_sid"] == 0


def test_grants_move_to_advanced_phy_once_the_modem_is_known_to_be_20(online_lab):
    """The CMTS withholds IUC 9/10 until DHCP option 60 identifies the modem
    as DOCSIS 2.0, so the granted profile changes partway through."""
    from docsislab.docsis.consts import IUC
    modem = online_lab.modems["cm0"]
    assert modem.granted_iuc in (int(IUC.ADV_PHY_SHORT_DATA),
                                 int(IUC.ADV_PHY_LONG_DATA))
    record = online_lab.cmts.modems.get(modem.cfg.mac)
    assert record.adv_phy


def test_service_flows_are_admitted_with_cmts_assigned_identifiers(online_lab):
    record = online_lab.cmts.modems.get(online_lab.modems["cm0"].cfg.mac)
    assert len(record.service_flows) == 2
    upstream = record.primary_sf("us")
    downstream = record.primary_sf("ds")
    assert upstream.sid == record.sid          # upstream flows carry a SID
    assert downstream.sid is None              # downstream ones do not
    assert upstream.max_sustained_bps == 2_000_000
    assert downstream.max_sustained_bps == 20_000_000
    assert {sf.sfid for sf in record.service_flows} == {1, 2}


# --------------------------------------------------------------------------
# the data plane
# --------------------------------------------------------------------------

def test_cpe_gets_an_address_from_the_subscriber_pool(online_lab):
    cpe = online_lab.cpes["cpe0"]
    assert cpe.ip == "10.20.0.10", "CPE should land in the subscriber pool"
    assert cpe.gateway == "10.20.0.1"
    # ...which is a different pool from the modem's own address.
    assert online_lab.modems["cm0"].ip.startswith("10.10.")


def test_cpe_is_learned_behind_its_modem(online_lab):
    record = online_lab.cmts.modems.get(online_lab.modems["cm0"].cfg.mac)
    assert online_lab.cpes["cpe0"].cfg.mac in record.cpe_macs


def test_ping_traverses_the_docsis_upstream(online_lab):
    cpe = online_lab.cpes["cpe0"]
    cpe.ping("10.30.0.2", count=3, interval=0.05)
    online_lab.sched.drain(2.0)
    assert len(cpe.ping_results) == 3
    assert cpe.ping_lost == 0
    # Latency is dominated by the request/grant round trip, not propagation.
    for _seq, rtt in cpe.ping_results:
        assert 0.001 < rtt < 0.05


def test_ping_reaches_the_cmts_cable_interface(online_lab):
    cpe = online_lab.cpes["cpe0"]
    cpe.ping("10.20.0.1", count=2, interval=0.05)
    online_lab.sched.drain(2.0)
    assert len(cpe.ping_results) == 2


# --------------------------------------------------------------------------
# failure modes
# --------------------------------------------------------------------------

def test_wrong_shared_secret_is_rejected_at_registration():
    lab = build("bad-secret")
    lab.sched.drain(6.0)
    modem = lab.modems["cm0"]
    record = lab.cmts.modems.get(modem.cfg.mac)
    assert modem.state is CmState.REJECTED
    assert record.state == "reject(m)"
    # It got all the way through TFTP first -- the failure is at the MIC check.
    assert record.ip is not None
    assert lab.cmts.stats["rejected"] == 1
    lab.close()


def test_unadmittable_service_flow_is_rejected():
    lab = build("over-rate")
    lab.sched.drain(6.0)
    record = lab.cmts.modems.get(lab.modems["cm0"].cfg.mac)
    assert record.state == "reject(c)"
    assert lab.modems["cm0"].state is CmState.REJECTED
    lab.close()


def test_network_access_disabled_registers_but_does_not_forward():
    lab = build("no-access")
    assert lab.run_until_online(timeout=20.0)
    lab.sched.drain(2.0)
    record = lab.cmts.modems.get(lab.modems["cm0"].cfg.mac)
    assert record.state == "online(d)"
    assert record.network_access is False
    # The CPE cannot get an address, because its DHCP is not forwarded.
    assert lab.cpes["cpe0"].ip is None
    lab.close()


def test_a_modem_beyond_the_plant_reach_never_ranges():
    """Its ranging burst arrives after the end of the Initial Maintenance
    region, so the CMTS simply does not receive it."""
    lab = build("far")
    lab.sched.drain(6.0)
    modem = lab.modems["cm-far"]
    assert modem.state is not CmState.OPERATIONAL
    assert modem.sid == 0
    assert lab.cmts.stats["out_of_window"] > 0
    assert len(lab.cmts.modems.modems) == 0
    lab.close()


def test_a_long_haul_plant_sized_for_the_distance_works():
    """Same 80 km modem, but with the Initial Maintenance region sized for a
    100 km plant: it ranges fine, just with a much larger offset."""
    lab = build("long-haul")
    assert lab.run_until_online(timeout=25.0)
    modem = lab.modems["cm-80km"]
    expected = 2 * delay_for_km(80.0) / TIMING_ADJUST_UNIT_S
    assert modem.ranging_offset == pytest.approx(expected, abs=8)
    assert modem.ranging_offset > 6000
    lab.close()


def test_a_lossy_upstream_still_gets_online_after_retries():
    lab = build("noisy")
    assert lab.run_until_online(timeout=25.0), "should recover from 25% loss"
    modem = lab.modems["cm0"]
    counters = modem.counters
    assert counters["t3_timeouts"] + counters["collisions_assumed"] > 0, \
        "the retry machinery should have been exercised"
    lab.close()


def test_reinitialisation_brings_a_modem_back():
    lab = build()
    assert lab.run_until_online(timeout=20.0)
    first_sid = lab.modems["cm0"].sid
    lab.modems["cm0"].reinitialize("test")
    assert lab.modems["cm0"].state is CmState.DS_SCAN
    lab._online_at.clear()
    assert lab.run_until_online(timeout=25.0), "modem should recover"
    assert lab.modems["cm0"].ranging_offset > 0
    lab.close()


# --------------------------------------------------------------------------
# mixed 1.x / 2.0
# --------------------------------------------------------------------------

def test_a_docsis_11_modem_reads_the_type2_ucd_and_gets_1x_grants():
    from docsislab.docsis.consts import IUC
    lab = build("mixed")
    assert lab.run_until_online(timeout=25.0)
    lab.sched.drain(1.0)
    old, new = lab.modems["cm11"], lab.modems["cm20"]
    assert old.ucd_is_type29 is False, "a 1.1 modem cannot parse a type-29 UCD"
    assert new.ucd_is_type29 is True
    assert old.granted_iuc in (int(IUC.SHORT_DATA_GRANT), int(IUC.LONG_DATA_GRANT))
    assert new.granted_iuc in (int(IUC.ADV_PHY_SHORT_DATA),
                               int(IUC.ADV_PHY_LONG_DATA))
    # Both are online on the same physical upstream.
    assert old.us_channel.channel_id == new.us_channel.channel_id
    lab.close()


def test_contending_modems_collide_and_still_all_get_online():
    lab = build("crowd")
    assert lab.run_until_online(timeout=30.0)
    assert len(lab.modems) == 8
    assert lab.plant.stats["us_collisions"] > 0, \
        "modems powering up together should collide in contention regions"
    sids = {m.sid for m in lab.modems.values()}
    assert len(sids) == 8, "every modem must end up with a distinct SID"
    lab.close()


# --------------------------------------------------------------------------
# upstream channel change
# --------------------------------------------------------------------------

def test_modem_picks_the_lowest_numbered_usable_upstream():
    lab = build("two-upstream")
    assert lab.run_until_online(timeout=25.0)
    for modem in lab.modems.values():
        assert modem.us_channel.channel_id == 1, \
            "with two usable upstreams a modem should settle on the lower one"
    lab.close()


def test_a_docsis_1x_modem_cannot_see_a_6_4_mhz_channel():
    """5120 ksym/s is above the DOCSIS 1.x maximum, so no type-2 UCD can
    describe the channel and a 1.x modem never learns it exists."""
    lab = build("two-upstream")
    wide = lab.plant.upstreams[2]
    assert not wide.describable_by_docsis_1x
    assert lab.cmts.cfg.mixed_mode_ucd
    lab.run_until_online(timeout=25.0)
    # Only the type-29 UCD is emitted for it, so a 1.1 modem has nothing to
    # read even if the CMTS moved it there.
    lab.close()


def test_upstream_channel_change_re_ranges_without_re_registering():
    from docsislab.docsis import messages as M
    lab = build("two-upstream")
    assert lab.run_until_online(timeout=25.0)
    modem = lab.modems["cm20"]
    record = lab.cmts.modems.get(modem.cfg.mac)
    sid_before = record.sid
    flows_before = [sf.sfid for sf in record.service_flows]
    ip_before = modem.ip
    dhcp_before = lab.provisioning.stats["discover"]

    lab.cmts._send_mgmt(M.UccReq(upstream_channel_id=2),
                        "UCC-REQ from the test", dst=record.mac)
    lab.sched.drain(4.0)

    assert modem.us_channel.channel_id == 2, "the modem should have moved"
    assert modem.state is CmState.OPERATIONAL, "and be back in service"
    assert record.upstream_channel == 2, "the CMTS should be scheduling it there"
    # Registration survives a channel change: same SID, same flows, same IP,
    # and no second trip through DHCP.
    assert record.sid == sid_before
    assert [sf.sfid for sf in record.service_flows] == flows_before
    assert modem.ip == ip_before
    assert lab.provisioning.stats["discover"] == dhcp_before
    # Timing does not carry over -- it is a property of the channel.
    assert modem.ranging_offset > 0
    lab.close()
