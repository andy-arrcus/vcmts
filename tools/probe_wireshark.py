#!/usr/bin/env python3
"""Ask Wireshark which of several plausible encodings DOCSIS actually uses.

Some low-level details -- the exact CRC-16 variant behind the MAC header HCS,
whether a Packet PDU's LEN counts the Ethernet FCS, which MAC management
`version` byte each message type wants -- are easy to get subtly wrong and
hard to confirm from prose.  Wireshark's DOCSIS dissector is a very carefully
maintained second implementation, so this script emits one frame per candidate
and reports back what the dissector made of each.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from docsislab.util import crc
from docsislab.util.pcapng import (DEFAULT_INTERFACES, IF_DS, IF_US,
                                   PcapngWriter)
from docsislab.docsis import machdr, mgmt
from docsislab.docsis.consts import (FCParm, FCType, IUC, MgmtType, Modulation,
                                     MGMT_VERSION_10, RangingStatus)
from docsislab.docsis import messages as M

#: Wireshark's tshark, wherever it happens to live.
TSHARK = (shutil.which("tshark")
          or next((c for c in ("/Applications/Wireshark.app/Contents/MacOS/tshark",
                               "/usr/local/bin/tshark",
                               "/opt/homebrew/bin/tshark")
                   if os.path.exists(c)), None))
OUT = os.path.join(tempfile.gettempdir(), "docsislab-probe.pcapng")

CMTS_MAC = bytes.fromhex("0005ca000001")
CM_MAC = bytes.fromhex("001dcf112233")


def mgmt_bytes(msg, version, src, dst=None, type_override=None):
    body = msg.encode()
    t = type_override if type_override is not None else msg.TYPE
    mm = mgmt.MgmtMessage(type=int(t), version=version, src=src,
                          dst=dst or bytes.fromhex("01e02f000001"), payload=body)
    return mm.encode()


def canonical(msg, src, dst=None):
    """Encode with the version byte the version table says to use."""
    from docsislab.docsis import frames
    return frames.encode_mgmt(msg, src, dst or bytes.fromhex("01e02f000001"))


def frame_with_hcs_variant(mgmt_encoded: bytes, variant: str, timing: bool) -> bytes:
    fc = ((FCType.MAC_SPECIFIC & 3) << 6) | \
         (((FCParm.TIMING if timing else FCParm.MAC_MGMT) & 0x1F) << 1)
    hdr = bytes([fc, 0]) + len(mgmt_encoded).to_bytes(2, "big")
    h = crc.CRC16_VARIANTS[variant](hdr)
    return hdr + h.to_bytes(2, "big") + mgmt_encoded


def eth_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (bytes.fromhex("ffffffffffff") + CM_MAC
            + ethertype.to_bytes(2, "big") + payload)


def build() -> list[str]:
    """Returns a parallel list of labels, one per frame written."""
    labels: list[str] = []
    w = PcapngWriter(OUT, DEFAULT_INTERFACES)
    t = 1757500000.0

    def add(iface, data, label, comment=""):
        nonlocal t
        w.packet(iface, t, data, comment or label)
        labels.append(label)
        t += 0.001

    # --- Q1/Q2: which CRC-16 is the HCS? --------------------------------
    sync = M.Sync(0x0BADF00D)
    for variant in crc.CRC16_VARIANTS:
        add(IF_DS, frame_with_hcs_variant(mgmt_bytes(sync, MGMT_VERSION_10, CMTS_MAC), variant, True),
            f"hcs:{variant}")

    # --- Q3: MAC management `version` byte per message type -------------
    ucd_bds = [
        M.BurstDescriptor(iuc=IUC.REQUEST, modulation=Modulation.QPSK, fec_t=0, fec_k=16,
                          preamble_length=64, guard_time=8, max_burst=1),
        M.BurstDescriptor(iuc=IUC.INITIAL_MAINT, modulation=Modulation.QPSK, fec_t=5, fec_k=34,
                          preamble_length=128, guard_time=48, max_burst=0),
        M.BurstDescriptor(iuc=IUC.STATION_MAINT, modulation=Modulation.QPSK, fec_t=5, fec_k=34,
                          preamble_length=128, guard_time=8, max_burst=0),
        M.BurstDescriptor(iuc=IUC.SHORT_DATA_GRANT, modulation=Modulation.QAM16, fec_t=5, fec_k=75,
                          preamble_length=128, guard_time=8, max_burst=6),
        M.BurstDescriptor(iuc=IUC.LONG_DATA_GRANT, modulation=Modulation.QAM16, fec_t=8, fec_k=220,
                          preamble_length=128, guard_time=8, max_burst=0),
    ]
    adv_bds = ucd_bds + [
        M.BurstDescriptor(iuc=IUC.ADV_PHY_SHORT_DATA, modulation=Modulation.QAM64, fec_t=5,
                          fec_k=75, preamble_type=2, rs_interleaver_depth=1,
                          rs_interleaver_block_size=2000, scdma_spreader_on=2),
        M.BurstDescriptor(iuc=IUC.ADV_PHY_LONG_DATA, modulation=Modulation.QAM64, fec_t=10,
                          fec_k=232, preamble_type=2, rs_interleaver_depth=1,
                          rs_interleaver_block_size=2000, scdma_spreader_on=2),
    ]
    ucd1 = M.Ucd(1, 1, 4, 1, symbol_rate_ksym=2560, frequency_hz=30_000_000,
                 preamble_pattern=bytes.fromhex("cccccccc" * 4),
                 burst_descriptors=ucd_bds, msg_type=MgmtType.UCD)
    add(IF_DS, canonical(ucd1, CMTS_MAC), "ucd-type2")
    ucd29 = M.Ucd(1, 1, 4, 1, symbol_rate_ksym=2560, frequency_hz=30_000_000,
                  preamble_pattern=bytes.fromhex("cccccccc" * 4),
                  burst_descriptors=adv_bds, msg_type=MgmtType.UCD2,
                  scdma_mode=0, maintain_psd=0, ranging_required=1)
    add(IF_DS, canonical(ucd29, CMTS_MAC), "ucd-type29")
    themap = M.Map(1, 1, 10000, 9980, ranging_backoff_start=0, ranging_backoff_end=4,
                   data_backoff_start=0, data_backoff_end=4,
                   ies=[M.MapIE(0x3FFF, IUC.REQUEST, 0),
                        M.MapIE(0x3FFF, IUC.INITIAL_MAINT, 8),
                        M.MapIE(9, IUC.ADV_PHY_SHORT_DATA, 24),
                        M.MapIE(0, IUC.NULL_IE, 32)])
    add(IF_DS, canonical(themap, CMTS_MAC), "map")

    # --- ranging + registration ----------------------------------------
    add(IF_US, canonical(M.RngReq(0, 1), CM_MAC), "rng-req-initial")
    add(IF_DS, canonical(M.RngRsp(9, 1, timing_adjust=785, power_adjust=-6,
                                  frequency_adjust=0,
                                  ranging_status=RangingStatus.CONTINUE),
                         CMTS_MAC, CM_MAC), "rng-rsp-continue")
    add(IF_US, canonical(M.RngReq(9, 1), CM_MAC), "rng-req-station")
    add(IF_DS, canonical(M.RngRsp(9, 1, timing_adjust=0, power_adjust=0,
                                  ranging_status=RangingStatus.SUCCESS),
                         CMTS_MAC, CM_MAC), "rng-rsp-success")

    from docsislab.util import tlv as T
    from docsislab.docsis.consts import CapTLV, CfgTLV, DocsisVersion, SFTLV, QoSParamSet, SchedulingType
    regreq_tlvs = [
        T.u8(CfgTLV.NETWORK_ACCESS_CONTROL, 1),
        T.compound(CfgTLV.MODEM_CAPABILITIES, [
            T.u8(CapTLV.CONCATENATION, 1),
            T.u8(CapTLV.DOCSIS_VERSION, DocsisVersion.V20),
            T.u8(CapTLV.FRAGMENTATION, 1),
            T.u8(CapTLV.PHS_SUPPORT, 1),
            T.u8(CapTLV.IGMP_SUPPORT, 1),
            T.u8(CapTLV.PRIVACY_SUPPORT, 1),
            T.u8(CapTLV.DOWNSTREAM_SAID_SUPPORT, 4),
            T.u8(CapTLV.UPSTREAM_SID_SUPPORT, 8),
        ]),
        T.compound(CfgTLV.UPSTREAM_SERVICE_FLOW, [
            T.u16(SFTLV.SERVICE_FLOW_REFERENCE, 1),
            T.u8(SFTLV.QOS_PARAM_SET_TYPE, QoSParamSet.ALL),
            T.u32(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE, 2_000_000),
            T.u8(SFTLV.SCHEDULING_TYPE, SchedulingType.BEST_EFFORT),
        ]),
        T.compound(CfgTLV.DOWNSTREAM_SERVICE_FLOW, [
            T.u16(SFTLV.SERVICE_FLOW_REFERENCE, 2),
            T.u8(SFTLV.QOS_PARAM_SET_TYPE, QoSParamSet.ALL),
            T.u32(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE, 20_000_000),
        ]),
        T.u8(CfgTLV.PRIVACY_ENABLE, 0),
        T.raw(CfgTLV.CM_MIC, bytes(range(16))),
        T.raw(CfgTLV.CMTS_MIC, bytes(range(16, 32))),
    ]
    add(IF_US, canonical(M.RegReq(9, regreq_tlvs), CM_MAC), "reg-req")
    add(IF_DS, canonical(M.RegRsp(9, 0, [
        T.compound(CfgTLV.UPSTREAM_SERVICE_FLOW, [
            T.u16(SFTLV.SERVICE_FLOW_REFERENCE, 1),
            T.u32(SFTLV.SERVICE_FLOW_IDENTIFIER, 5),
            T.u16(SFTLV.SERVICE_IDENTIFIER, 9)]),
        T.compound(CfgTLV.DOWNSTREAM_SERVICE_FLOW, [
            T.u16(SFTLV.SERVICE_FLOW_REFERENCE, 2),
            T.u32(SFTLV.SERVICE_FLOW_IDENTIFIER, 6)]),
    ]), CMTS_MAC, CM_MAC), "reg-rsp")
    add(IF_US, canonical(M.RegAck(9), CM_MAC), "reg-ack")

    # --- Q4: Request frame ----------------------------------------------
    add(IF_US, machdr.build_request(9, 3), "req-frame")

    # --- Q5: does a Packet PDU's LEN include the Ethernet FCS? ----------
    udp_payload = bytes.fromhex("4500001c000100004011000a0a0a0a0a0a0a0a01") + b"\x00\x44\x00\x43\x00\x08\x00\x00"
    eth = eth_frame(udp_payload)
    add(IF_US, machdr.build_packet_pdu(crc.with_fcs(eth)), "pdu-with-fcs")
    add(IF_US, machdr.build_packet_pdu(eth), "pdu-no-fcs")
    # and with a deliberately wrong FCS, to see whether Wireshark checks it
    add(IF_US, machdr.build_packet_pdu(eth + b"\xde\xad\xbe\xef"), "pdu-bad-fcs")

    w.close()
    return labels


def run():
    if TSHARK is None:
        print("tshark not found -- install Wireshark to run this probe",
              file=sys.stderr)
        return 1
    labels = build()
    print(f"wrote {OUT} with {len(labels)} frames\n")
    fields = ["frame.number", "frame.interface_name", "docsis.hcs.status",
              "docsis.fctype", "docsis_mgmt.type", "docsis_mgmt.version",
              "_ws.expert.message", "_ws.col.protocol", "_ws.col.info"]
    cmd = [TSHARK, "-r", OUT, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("tshark failed:", res.stderr)
        return 1
    print(f"{'#':>3} {'label':22} {'hcs':4} {'fct':3} {'mt':3} {'v':2} {'proto':14} info / expert")
    print("-" * 118)
    for label, line in zip(labels, res.stdout.rstrip("\n").split("\n")):
        parts = line.split("|")
        while len(parts) < len(fields):
            parts.append("")
        num, _iface, hcs_st, fct, mt, ver, expert, proto, info = parts[:9]
        hcs_txt = {"0": "BAD", "1": "GOOD", "2": "unv", "3": "n/a", "4": "ill", "": "-"}.get(hcs_st, hcs_st)
        note = info if not expert else f"{info}   !! {expert}"
        print(f"{num:>3} {label:22} {hcs_txt:4} {fct:3} {mt:3} {ver:2} {proto:14} {note[:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
