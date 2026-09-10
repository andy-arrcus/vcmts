"""Timing arithmetic, channel capacity, and configuration-file integrity."""

import pytest

from docsislab.docsis import cfgfile
from docsislab.docsis.consts import (CapTLV, CfgTLV, IUC, Modulation, SFTLV,
                                     SYMBOL_RATES_DOCSIS_1X,
                                     SYMBOL_RATES_DOCSIS_20)
from docsislab.phy.channel import (DownstreamChannel, UpstreamChannel,
                                   DOCSIS_1X_MAX_KSYM)
from docsislab.phy.plant import LOSS_DB_PER_KM, delay_for_km
from docsislab.util import tlv
from docsislab.util.clock import (COUNTS_PER_TICK, MASTER_CLOCK_HZ, TICK_S,
                                  TIMESTAMP_MODULUS, MinislotClock,
                                  timestamp_at, timestamp_delta)


# --------------------------------------------------------------------------
# timebase
# --------------------------------------------------------------------------

def test_tick_is_64_master_clock_counts():
    assert TICK_S * MASTER_CLOCK_HZ == COUNTS_PER_TICK == 64


def test_timing_adjust_unit_is_one_master_clock_count():
    from docsislab.util.clock import TIMING_ADJUST_UNIT_S
    assert TIMING_ADJUST_UNIT_S == pytest.approx(1 / MASTER_CLOCK_HZ)
    assert TIMING_ADJUST_UNIT_S * 1e9 == pytest.approx(97.65625)


def test_timestamp_wraps_after_about_419_seconds():
    assert timestamp_at(0) == 0
    assert timestamp_at(TIMESTAMP_MODULUS / MASTER_CLOCK_HZ) == 0
    assert 419.0 < TIMESTAMP_MODULUS / MASTER_CLOCK_HZ < 419.5


def test_timestamp_delta_is_wrap_aware():
    assert timestamp_delta(10, 5) == 5
    assert timestamp_delta(5, 10) == -5
    # Just past a wrap: 5 counts later, not 4.29 billion earlier.
    assert timestamp_delta(4, TIMESTAMP_MODULUS - 1) == 5


def test_minislot_clock_maps_numbers_to_timestamps():
    clock = MinislotClock(4)
    assert clock.duration_s == pytest.approx(25e-6)
    assert clock.counts == 256
    assert clock.timestamp_of(1000) == 256_000
    assert clock.number_at(clock.start_of(1234)) == 1234


def test_minislot_size_must_be_a_power_of_two():
    with pytest.raises(ValueError):
        MinislotClock(3)


# --------------------------------------------------------------------------
# channels
# --------------------------------------------------------------------------

def test_downstream_payload_rate_is_the_usual_38_megabits():
    ds = DownstreamChannel(modulation=Modulation.QAM256)
    assert 37.5e6 < ds.payload_bps < 38.5e6
    # A full-size Ethernet frame takes about 320 us at that rate.
    assert ds.serialization_s(1518) == pytest.approx(320e-6, rel=0.02)


def test_minislot_byte_capacity_scales_with_modulation():
    """A mini-slot is a slice of time, so its byte capacity depends entirely
    on the burst profile the grant was issued under."""
    us = UpstreamChannel(minislot_ticks=4, width_hz=3_200_000)
    assert us.bytes_per_minislot(IUC.REQUEST) == 16          # QPSK
    assert us.bytes_per_minislot(IUC.SHORT_DATA_GRANT) == 32  # 16-QAM
    assert us.bytes_per_minislot(IUC.ADV_PHY_LONG_DATA) == 48  # 64-QAM


def test_request_burst_fits_one_minislot():
    """The Request profile is deliberately sized so a six-byte Request frame
    fits in a single contention mini-slot."""
    us = UpstreamChannel()
    assert us.minislots_for(6, IUC.REQUEST) == 1


def test_grant_sizing_accounts_for_fec_preamble_and_guard():
    us = UpstreamChannel()
    raw = 1518 * 8 / (us.bits_per_symbol(IUC.ADV_PHY_LONG_DATA)
                      * us.symbols_per_minislot)
    needed = us.minislots_for(1518, IUC.ADV_PHY_LONG_DATA)
    # Overhead means the real answer is bigger than the naive division.
    assert needed > raw


def test_payload_capacity_inverts_minislots_for():
    us = UpstreamChannel()
    for iuc in (IUC.REQUEST, IUC.STATION_MAINT, IUC.ADV_PHY_SHORT_DATA,
                IUC.ADV_PHY_LONG_DATA):
        for minislots in (1, 2, 3, 6, 12, 40):
            capacity = us.payload_capacity(minislots, iuc)
            if capacity:
                assert us.minislots_for(capacity, iuc) <= minislots
                assert us.minislots_for(capacity + 1, iuc) > minislots


def test_64_symbol_rate_beyond_docsis_1x():
    """A 6.4 MHz channel runs at 5120 ksym/s, which no type-2 UCD can
    describe -- so DOCSIS 1.x modems cannot see the channel at all."""
    wide = UpstreamChannel(width_hz=6_400_000)
    narrow = UpstreamChannel(width_hz=3_200_000)
    assert wide.symbol_rate_ksym == 5120
    assert not wide.describable_by_docsis_1x
    assert narrow.symbol_rate_ksym == DOCSIS_1X_MAX_KSYM
    assert narrow.describable_by_docsis_1x
    assert wide.raw_bps() == pytest.approx(30.72e6)


def test_atdma_offers_the_advanced_phy_iucs():
    atdma = UpstreamChannel(phy_mode="atdma")
    tdma = UpstreamChannel(phy_mode="tdma")
    assert atdma.data_iuc(False) == IUC.ADV_PHY_SHORT_DATA
    assert atdma.data_iuc(True) == IUC.ADV_PHY_LONG_DATA
    assert tdma.data_iuc(False) == IUC.SHORT_DATA_GRANT
    assert atdma.profile(IUC.ADV_PHY_LONG_DATA) is not None
    assert tdma.profile(IUC.ADV_PHY_LONG_DATA) is None


# --------------------------------------------------------------------------
# plant
# --------------------------------------------------------------------------

def test_propagation_delay_matches_the_velocity_factor():
    # 10 km at 0.87c is 38.3 us one way, so 785 timing-adjust units round trip.
    assert delay_for_km(10) == pytest.approx(38.34e-6, rel=0.01)
    units = round(2 * delay_for_km(10) / (TICK_S / 64))
    assert units == 785


def test_attenuation_is_bounded_by_the_amplifier_cascade():
    from docsislab.phy.plant import MAX_RESIDUAL_LOSS_DB, ModemAttachment
    near = ModemAttachment("near", 2.0, delay_for_km(2.0))
    far = ModemAttachment("far", 80.0, delay_for_km(80.0))
    assert near.attenuation_db == pytest.approx(2.0 * LOSS_DB_PER_KM)
    assert far.attenuation_db == MAX_RESIDUAL_LOSS_DB


# --------------------------------------------------------------------------
# configuration file
# --------------------------------------------------------------------------

SPEC = {
    "network_access": True,
    "upstream_service_flows": [{"ref": 1, "max_sustained_bps": 2_000_000,
                                "scheduling_type": 2}],
    "downstream_service_flows": [{"ref": 2, "max_sustained_bps": 20_000_000}],
    "max_cpe": 4,
    "privacy_enable": False,
}


def test_config_file_verifies_with_the_right_secret():
    blob = cfgfile.encode(cfgfile.build(SPEC), b"s3cret")
    assert cfgfile.verify(cfgfile.decode(blob), b"s3cret").ok


def test_config_file_ends_with_the_end_marker_and_is_padded():
    blob = cfgfile.encode(cfgfile.build(SPEC), b"s3cret")
    assert len(blob) % 4 == 0
    types = [t.type for t in cfgfile.decode(blob)]
    assert types[-3:] == [int(CfgTLV.CM_MIC), int(CfgTLV.CMTS_MIC),
                          int(CfgTLV.END_OF_DATA)]


def test_wrong_shared_secret_fails_only_the_cmts_mic():
    blob = cfgfile.encode(cfgfile.build(SPEC), b"s3cret")
    result = cfgfile.verify(cfgfile.decode(blob), b"wrong")
    assert result.cm_mic_ok          # the modem's own integrity check still passes
    assert not result.cmts_mic_ok    # but the CMTS refuses it
    assert not result.ok
    assert "shared secret" in result.explain()


def test_rewriting_the_rate_breaks_the_cmts_mic():
    """The point of the CMTS MIC: a modem cannot hand itself a better service
    tier, because it cannot recompute a digest salted with a secret it has
    never seen."""
    blob = cfgfile.encode(cfgfile.build(SPEC), b"s3cret")
    settings = cfgfile.decode(blob)
    for t in settings:
        if t.type == int(CfgTLV.UPSTREAM_SERVICE_FLOW):
            for sub in t.sub:
                if sub.type == int(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE):
                    sub.value = (500_000_000).to_bytes(4, "big")
    forged = b"".join(t.encode() for t in settings)
    result = cfgfile.verify(cfgfile.decode(forged), b"s3cret")
    assert not result.cmts_mic_ok


def test_recomputing_the_cm_mic_does_not_help_an_attacker():
    blob = cfgfile.encode(cfgfile.build(SPEC), b"s3cret")
    settings = cfgfile.decode(blob)
    for t in settings:
        if t.type == int(CfgTLV.UPSTREAM_SERVICE_FLOW):
            for sub in t.sub:
                if sub.type == int(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE):
                    sub.value = (500_000_000).to_bytes(4, "big")
    core = [t for t in settings if t.type not in
            (int(CfgTLV.CM_MIC), int(CfgTLV.CMTS_MIC), int(CfgTLV.END_OF_DATA))]
    fixed = core + [tlv.TLV(int(CfgTLV.CM_MIC), cfgfile.cm_mic(core))]
    fixed += [t for t in settings if t.type == int(CfgTLV.CMTS_MIC)]
    result = cfgfile.verify(fixed, b"s3cret")
    assert result.cm_mic_ok           # they can fix this one
    assert not result.cmts_mic_ok     # but not this one


def test_modem_capabilities_numbering():
    """Sub-TLV numbering runs contiguously from 1; a gap shifts every field
    after it. Confirmed against Wireshark's dissector."""
    assert int(CapTLV.OPTIONAL_FILTERING) == 9
    assert int(CapTLV.TRANSMIT_EQ_TAPS_PER_SYMBOL) == 10
    assert int(CapTLV.TRANSMIT_EQ_TAPS) == 11
    assert int(CapTLV.DCC_SUPPORT) == 12
    assert int(CapTLV.UPSTREAM_SYMBOL_RATES) == 21


def test_only_a_20_modem_claims_the_5120_ksps_symbol_rate():
    from docsislab.docsis.consts import DocsisVersion
    caps20 = cfgfile.modem_capabilities(docsis_version=DocsisVersion.V20)
    caps11 = cfgfile.modem_capabilities(docsis_version=DocsisVersion.V11)
    assert caps20.get_int(int(CapTLV.UPSTREAM_SYMBOL_RATES)) == SYMBOL_RATES_DOCSIS_20
    assert caps11.get_int(int(CapTLV.UPSTREAM_SYMBOL_RATES)) == SYMBOL_RATES_DOCSIS_1X
    assert SYMBOL_RATES_DOCSIS_20 & 0x20      # bit 5 is 5120 ksps
    assert not SYMBOL_RATES_DOCSIS_1X & 0x20


def test_vendor_class_identifier_is_ascii_hex_capabilities():
    """DHCP option 60 on a cable modem is "docsisX.Y:" followed by the
    capability TLVs as ASCII hex, which is how a provisioning system can
    identify a 2.0 modem before it registers."""
    from docsislab.docsis.consts import DocsisVersion
    vc = cfgfile.vendor_class_identifier(DocsisVersion.V20)
    assert vc.startswith(b"docsis2.0:")
    body = bytes.fromhex(vc.split(b":", 1)[1].decode())
    caps = {t.type: t.as_int for t in tlv.decode(body)}
    assert caps[int(CapTLV.DOCSIS_VERSION)] == int(DocsisVersion.V20)
