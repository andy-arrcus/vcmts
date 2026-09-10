"""Byte-level tests: CRCs, TLVs, MAC headers, message codecs."""

import pytest

from docsislab.docsis import frames, machdr, messages as M, mgmt
from docsislab.docsis.consts import (IUC, MGMT_MSG_VERSION, MgmtType,
                                     Modulation, RangingStatus, SID_BROADCAST)
from docsislab.util import tlv
from docsislab.util.crc import (CRC16_VARIANTS, eth_fcs, hcs, hcs_bytes,
                                hcs_from_wire, with_fcs)

CMTS_MAC = bytes.fromhex("0005ca000001")
CM_MAC = bytes.fromhex("001dcf112233")


# --------------------------------------------------------------------------
# CRC
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("ccitt-false", 0x29B1), ("x25", 0x906E), ("kermit", 0x2189),
    ("xmodem", 0x31C3), ("genibus", 0xD64E), ("mcrf4xx", 0x6F91),
])
def test_crc16_check_values(name, expected):
    """Each variant against its published check value for b"123456789"."""
    assert CRC16_VARIANTS[name](b"123456789") == expected


def test_crc32_check_value():
    assert eth_fcs(b"123456789") == 0xCBF43926


@pytest.mark.parametrize("header,wire", [
    # These are the values Wireshark's DOCSIS dissector expects; see
    # tools/probe_wireshark.py and docs/WIRESHARK.md.
    ("c0000018", "ce5b"),   # Timing header, 24-byte SYNC
    ("c2000034", "d689"),   # MAC management header, 52-byte MAP
    ("c2000018", "b862"),   # MAC management header, 24-byte RNG-REQ
    ("c4030009", "4ec7"),   # Request frame, SID 9, 3 mini-slots
    ("0000002e", "a234"),   # Packet PDU, 46 bytes
])
def test_hcs_matches_wireshark(header, wire):
    assert hcs_bytes(bytes.fromhex(header)).hex() == wire


def test_hcs_wire_roundtrip():
    hdr = bytes.fromhex("c2000034")
    assert hcs_from_wire(hcs_bytes(hdr)) == hcs(hdr)


# --------------------------------------------------------------------------
# TLV
# --------------------------------------------------------------------------

def test_tlv_roundtrip_nested():
    original = tlv.compound(24, [tlv.u16(1, 7), tlv.u8(6, 7),
                                 tlv.u32(8, 2_000_000)])
    decoded = tlv.decode(original.encode(), compound_types={24})
    assert len(decoded) == 1
    assert [(t.type, t.as_int) for t in decoded[0].sub] == [
        (1, 7), (6, 7), (8, 2_000_000)]


def test_tlv_signed_values():
    assert tlv.decode(tlv.s32(1, -785).encode())[0].as_sint == -785
    assert tlv.decode(tlv.s8(2, -6).encode())[0].as_sint == -6


def test_tlv_rejects_oversized_value():
    with pytest.raises(tlv.TLVError):
        tlv.TLV(1, b"x" * 256).encode()


def test_tlv_truncated_is_an_error_when_strict():
    with pytest.raises(tlv.TLVError):
        tlv.decode(bytes([5, 10, 1, 2]))
    assert tlv.decode(bytes([5, 10, 1, 2]), strict=False) == []


def test_tlv_pad_and_end_markers_have_no_length():
    decoded = tlv.decode(bytes([0, 0, 3, 1, 1, 255]))
    assert [(t.type, t.value) for t in decoded] == [(3, b"\x01"), (255, b"")]


# --------------------------------------------------------------------------
# MAC header
# --------------------------------------------------------------------------

def test_request_frame_is_six_bytes():
    frame = machdr.build_request(sid=9, minislots=3)
    assert len(frame) == 6
    decoded = machdr.decode(frame)
    assert decoded.is_request and decoded.sid == 9 and decoded.mac_parm == 3
    assert decoded.hcs_ok


def test_request_frame_rejects_oversized_count():
    with pytest.raises(machdr.MacFrameError):
        machdr.build_request(sid=1, minislots=256)


def test_packet_pdu_len_counts_the_ethernet_fcs():
    """RFIv2.0 Table 6-3: LEN counts every byte after the HCS, and a Packet
    PDU carries the whole Ethernet frame including its FCS."""
    eth = b"\xff" * 6 + CM_MAC + b"\x08\x00" + b"payload".ljust(46, b"\x00")
    pdu = machdr.build_packet_pdu(with_fcs(eth))
    decoded = machdr.decode(pdu)
    assert decoded.len_sid == len(eth) + 4
    assert decoded.payload == with_fcs(eth)
    assert eth_fcs(decoded.payload[:-4]).to_bytes(4, "little") == decoded.payload[-4:]


def test_ehdr_is_counted_twice_in_len():
    """When an extended header is present, LEN includes it as well as the
    payload -- the detail that catches implementations out."""
    eh = [machdr.ehdr_request(sid=9, minislots=4)]
    body = b"x" * 20
    frame = machdr.MacFrame(
        fc_type=0, fc_parm=0, mac_parm=len(machdr.encode_ehdr(eh)),
        len_sid=len(machdr.encode_ehdr(eh)) + len(body),
        ehdr=machdr.encode_ehdr(eh), payload=body).encode()
    decoded = machdr.decode(frame)
    assert decoded.ehdr_on
    assert decoded.len_sid == len(decoded.ehdr) + len(decoded.payload)
    assert decoded.payload == body
    assert decoded.hcs_ok


def test_bad_hcs_is_detected():
    frame = bytearray(machdr.build_request(9, 3))
    frame[-1] ^= 0xFF
    assert machdr.decode(bytes(frame)).hcs_ok is False


def test_concatenation_splits_back_into_frames():
    parts = [machdr.build_request(9, 3),
             machdr.build_request(10, 4),
             machdr.build_mgmt_frame(b"x" * 24)]
    body = machdr.build_concatenation(parts)
    outer = machdr.decode(body)
    assert outer.mac_parm == 3
    inner = machdr.decode_all(outer.payload)
    assert len(inner) == 3
    assert inner[0].sid == 9 and inner[1].sid == 10


# --------------------------------------------------------------------------
# MAC management
# --------------------------------------------------------------------------

def test_mgmt_msglen_counts_from_dsap():
    msg = mgmt.MgmtMessage(type=MgmtType.SYNC, version=1, src=CMTS_MAC,
                           payload=b"\x00\x00\x00\x01")
    raw = msg.encode()
    assert int.from_bytes(raw[12:14], "big") == mgmt.LLC_OVERHEAD + 4
    assert raw[14:17] == b"\x00\x00\x03"      # DSAP, SSAP, control
    assert mgmt.decode(raw).payload == b"\x00\x00\x00\x01"


def test_map_version_must_be_one():
    """DOCSIS 3.1 reused version 5 for a differently shaped MAP, so a
    2.0 MAP has to say version 1 or decoders will refuse it."""
    assert MGMT_MSG_VERSION[MgmtType.MAP] == 1


def test_type29_ucd_is_a_docsis_11_plus_message():
    assert MGMT_MSG_VERSION[MgmtType.UCD2] == 2
    assert MGMT_MSG_VERSION[MgmtType.UCD] == 1


@pytest.mark.parametrize("message", [
    M.Sync(0x0BADF00D),
    M.RngReq(sid=0, downstream_channel_id=1),
    M.RngReq(sid=9, downstream_channel_id=1, pending_till_complete=2),
    M.RngRsp(sid=9, upstream_channel_id=1, timing_adjust=-785,
             power_adjust=-6, frequency_adjust=-120,
             ranging_status=RangingStatus.SUCCESS),
    M.RegAck(sid=9, confirmation_code=0),
    M.UccRsp(upstream_channel_id=2),
])
def test_message_roundtrip(message):
    encoded = frames.encode_mgmt(message, CM_MAC)
    parsed = frames.parse(encoded)
    assert parsed.mac.hcs_ok
    assert parsed.message.encode() == message.encode()


def test_map_information_element_bit_packing():
    ie = M.MapIE(sid=SID_BROADCAST, iuc=IUC.INITIAL_MAINT, offset=8)
    word = ie.encode()
    assert (word >> 18) & 0x3FFF == SID_BROADCAST
    assert (word >> 14) & 0x0F == int(IUC.INITIAL_MAINT)
    assert word & 0x3FFF == 8
    assert M.MapIE.from_word(word) == ie


def test_map_grant_spans_run_to_the_next_element():
    themap = M.Map(1, 1, alloc_start_time=1000, ack_time=990, ies=[
        M.MapIE(SID_BROADCAST, IUC.INITIAL_MAINT, 0),
        M.MapIE(9, IUC.ADV_PHY_LONG_DATA, 13),
        M.MapIE(0, IUC.NULL_IE, 40),
    ])
    assert themap.grant_span(0) == (1000, 1013)
    assert themap.grant_span(1) == (1013, 1040)
    assert M.Map.decode(themap.encode()).encode() == themap.encode()


def test_ucd_burst_descriptor_roundtrip_keeps_20_only_fields():
    bd = M.BurstDescriptor(iuc=IUC.ADV_PHY_LONG_DATA,
                           modulation=Modulation.QAM64, fec_t=10, fec_k=232,
                           preamble_type=2, rs_interleaver_depth=1,
                           rs_interleaver_block_size=2000,
                           scdma_spreader_on=2)
    ucd = M.Ucd(1, 1, 4, 1, burst_descriptors=[bd], msg_type=MgmtType.UCD2)
    back = M.Ucd.decode(ucd.encode(), MgmtType.UCD2)
    got = back.burst_descriptors[0]
    assert got.modulation == Modulation.QAM64
    assert got.preamble_type == 2
    assert got.rs_interleaver_block_size == 2000


def test_type2_ucd_omits_the_20_only_subtlvs():
    """A type-4 burst descriptor has no way to carry the interleaver or
    preamble-type fields, so encoding as 1.x must drop them."""
    bd = M.BurstDescriptor(iuc=IUC.LONG_DATA_GRANT, preamble_type=2,
                           rs_interleaver_depth=1)
    ucd_1x = M.Ucd(1, 1, 4, 1, burst_descriptors=[bd], msg_type=MgmtType.UCD)
    back = M.Ucd.decode(ucd_1x.encode(), MgmtType.UCD)
    assert back.burst_descriptors[0].preamble_type is None
    assert back.burst_descriptors[0].rs_interleaver_depth is None


def test_reg_req_carries_nested_service_flow_encodings():
    from docsislab.docsis.consts import CfgTLV, SFTLV
    settings = [tlv.compound(CfgTLV.UPSTREAM_SERVICE_FLOW, [
        tlv.u16(SFTLV.SERVICE_FLOW_REFERENCE, 1),
        tlv.u32(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE, 2_000_000)])]
    back = M.RegReq.decode(M.RegReq(sid=9, settings=settings).encode())
    assert back.sid == 9
    flow = back.settings[0]
    assert flow.get_int(int(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE)) == 2_000_000
