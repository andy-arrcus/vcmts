"""The DOCSIS configuration file: encode, decode, and the two MICs.

The modem downloads this binary TLV blob over TFTP and then echoes almost all
of it back to the CMTS inside REG-REQ.  Two MD5 digests ride along:

  * **CM MIC** (TLV 6) -- a digest over every configuration setting in the
    file except the two MIC settings themselves.  It lets the modem, and then
    the CMTS, detect a corrupted download.

  * **CMTS MIC** (TLV 7) -- a digest over a *specific ordered subset* of the
    settings with a shared secret appended.  Only the provisioning system and
    the CMTS know that secret, so a modem cannot hand itself a config file
    granting 200 Mbit/s: the CMTS would recompute the digest, get a different
    answer, and reject registration with authentication failure.

That is the whole security model of DOCSIS 1.x/2.0 provisioning, and
`tools/forge_config.py` demonstrates it failing on purpose.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..util import tlv
from ..util.tlv import TLV
from .consts import (CapTLV, CfgTLV, ClassOfServiceTLV, DocsisVersion,
                     QoSParamSet, SFTLV, SYMBOL_RATES_DOCSIS_1X,
                     SYMBOL_RATES_DOCSIS_20, SchedulingType)
from .messages import CFG_COMPOUND

#: The order in which configuration settings are fed to the CMTS MIC digest
#: (RFIv2.0 Annex C.1.3.2).  Settings absent from the file are simply skipped.
#: The order is normative: two implementations that disagree about it will
#: fail to authenticate each other even with the same shared secret.
CMTS_MIC_ORDER = [
    CfgTLV.DOWNSTREAM_FREQUENCY,        # 1
    CfgTLV.UPSTREAM_CHANNEL_ID,         # 2
    CfgTLV.NETWORK_ACCESS_CONTROL,      # 3
    CfgTLV.CLASS_OF_SERVICE,            # 4
    CfgTLV.BASELINE_PRIVACY_CFG,        # 17
    CfgTLV.VENDOR_SPECIFIC,             # 43
    CfgTLV.CM_MIC,                      # 6
    CfgTLV.MAX_CPE,                     # 18
    CfgTLV.TFTP_SERVER_TIMESTAMP,       # 19
    CfgTLV.TFTP_SERVER_ADDRESS,         # 20
    CfgTLV.UPSTREAM_CLASSIFIER,         # 22
    CfgTLV.DOWNSTREAM_CLASSIFIER,       # 23
    CfgTLV.UPSTREAM_SERVICE_FLOW,       # 24
    CfgTLV.DOWNSTREAM_SERVICE_FLOW,     # 25
    CfgTLV.MAX_CLASSIFIERS,             # 28
    CfgTLV.PRIVACY_ENABLE,              # 29
    CfgTLV.PAYLOAD_HEADER_SUPPRESSION,  # 26
    CfgTLV.SUBSCRIBER_MGMT_CONTROL,     # 35
    CfgTLV.SUBSCRIBER_MGMT_CPE_TABLE,   # 36
    CfgTLV.SUBSCRIBER_MGMT_FILTER_GROUPS,  # 37
]

#: Settings excluded from the CM MIC digest.
CM_MIC_EXCLUDE = {int(CfgTLV.CM_MIC), int(CfgTLV.CMTS_MIC),
                  int(CfgTLV.PAD), int(CfgTLV.END_OF_DATA)}

DEFAULT_SHARED_SECRET = b"docsislab"


# --------------------------------------------------------------------------
# MIC computation
# --------------------------------------------------------------------------

def cm_mic(settings: list[TLV]) -> bytes:
    """MD5 over the encoded settings, in file order, minus the MIC settings."""
    body = b"".join(t.encode() for t in settings if t.type not in CM_MIC_EXCLUDE)
    return hashlib.md5(body).digest()


def cmts_mic(settings: list[TLV], shared_secret: bytes,
             cm_mic_value: bytes | None = None) -> bytes:
    """MD5 over an ordered subset of the settings plus the shared secret."""
    by_type: dict[int, list[TLV]] = {}
    for t in settings:
        by_type.setdefault(t.type, []).append(t)
    if cm_mic_value is not None:
        by_type[int(CfgTLV.CM_MIC)] = [TLV(int(CfgTLV.CM_MIC), cm_mic_value)]
    body = b""
    for type_ in CMTS_MIC_ORDER:
        for t in by_type.get(int(type_), []):
            body += t.encode()
    return hashlib.md5(body + shared_secret).digest()


# --------------------------------------------------------------------------
# encode / decode
# --------------------------------------------------------------------------

def encode(settings: list[TLV], shared_secret: bytes = DEFAULT_SHARED_SECRET,
           pad_to_multiple: int = 4) -> bytes:
    """Serialise a config file, appending both MICs and the end marker."""
    core = [t for t in settings
            if t.type not in (int(CfgTLV.CM_MIC), int(CfgTLV.CMTS_MIC),
                              int(CfgTLV.END_OF_DATA))]
    cm = cm_mic(core)
    cmts = cmts_mic(core, shared_secret, cm)
    out = b"".join(t.encode() for t in core)
    out += TLV(int(CfgTLV.CM_MIC), cm).encode()
    out += TLV(int(CfgTLV.CMTS_MIC), cmts).encode()
    out += bytes([int(CfgTLV.END_OF_DATA)])
    if pad_to_multiple:
        out += b"\x00" * (-len(out) % pad_to_multiple)
    return out


def decode(data: bytes) -> list[TLV]:
    """Parse a configuration file into settings, expanding compound TLVs."""
    return tlv.decode(data, CFG_COMPOUND, strict=False)


@dataclass
class Verification:
    """The result of checking a configuration file's two MICs."""
    cm_mic_ok: bool
    cmts_mic_ok: bool
    cm_mic_found: bytes | None
    cmts_mic_found: bytes | None
    cm_mic_expected: bytes
    cmts_mic_expected: bytes

    @property
    def ok(self) -> bool:
        return self.cm_mic_ok and self.cmts_mic_ok

    def explain(self) -> str:
        if self.ok:
            return "CM MIC and CMTS MIC both verify"
        bits = []
        if not self.cm_mic_ok:
            bits.append(f"CM MIC mismatch (file {(self.cm_mic_found or b'').hex()}, "
                        f"computed {self.cm_mic_expected.hex()})")
        if not self.cmts_mic_ok:
            bits.append(f"CMTS MIC mismatch (file {(self.cmts_mic_found or b'').hex()}, "
                        f"computed {self.cmts_mic_expected.hex()}) -- "
                        f"wrong shared secret or altered settings")
        return "; ".join(bits)


def verify(settings: list[TLV], shared_secret: bytes = DEFAULT_SHARED_SECRET) -> Verification:
    """Check both MICs over a decoded settings list (from a file or REG-REQ)."""
    found_cm = tlv.find(settings, int(CfgTLV.CM_MIC))
    found_cmts = tlv.find(settings, int(CfgTLV.CMTS_MIC))
    core = [t for t in settings
            if t.type not in (int(CfgTLV.CM_MIC), int(CfgTLV.CMTS_MIC),
                              int(CfgTLV.END_OF_DATA), int(CfgTLV.MODEM_CAPABILITIES))]
    want_cm = cm_mic(core)
    want_cmts = cmts_mic(core, shared_secret,
                         found_cm.value if found_cm else want_cm)
    return Verification(
        cm_mic_ok=bool(found_cm) and found_cm.value == want_cm,
        cmts_mic_ok=bool(found_cmts) and found_cmts.value == want_cmts,
        cm_mic_found=found_cm.value if found_cm else None,
        cmts_mic_found=found_cmts.value if found_cmts else None,
        cm_mic_expected=want_cm, cmts_mic_expected=want_cmts)


# --------------------------------------------------------------------------
# a friendly source format
# --------------------------------------------------------------------------

def build(spec: dict) -> list[TLV]:
    """Compile a readable dict into configuration setting TLVs.

    Keeps the same field names an operator would recognise from a config file
    editor, so `provisioning/configs/*.json` stays legible.
    """
    out: list[TLV] = []
    if "downstream_frequency_hz" in spec:
        out.append(tlv.u32(CfgTLV.DOWNSTREAM_FREQUENCY, spec["downstream_frequency_hz"]))
    if "upstream_channel_id" in spec:
        out.append(tlv.u8(CfgTLV.UPSTREAM_CHANNEL_ID, spec["upstream_channel_id"]))
    out.append(tlv.u8(CfgTLV.NETWORK_ACCESS_CONTROL,
                      1 if spec.get("network_access", True) else 0))

    for cos in spec.get("class_of_service", []):
        subs = [tlv.u8(ClassOfServiceTLV.CLASS_ID, cos.get("class_id", 1))]
        if "max_downstream_bps" in cos:
            subs.append(tlv.u32(ClassOfServiceTLV.MAX_DOWNSTREAM_RATE, cos["max_downstream_bps"]))
        if "max_upstream_bps" in cos:
            subs.append(tlv.u32(ClassOfServiceTLV.MAX_UPSTREAM_RATE, cos["max_upstream_bps"]))
        subs.append(tlv.u8(ClassOfServiceTLV.UPSTREAM_PRIORITY, cos.get("upstream_priority", 0)))
        if "guaranteed_min_upstream_bps" in cos:
            subs.append(tlv.u32(ClassOfServiceTLV.GUARANTEED_MIN_UPSTREAM_RATE,
                                cos["guaranteed_min_upstream_bps"]))
        if "max_upstream_burst" in cos:
            subs.append(tlv.u16(ClassOfServiceTLV.MAX_UPSTREAM_BURST, cos["max_upstream_burst"]))
        subs.append(tlv.u8(ClassOfServiceTLV.PRIVACY_ENABLE,
                           1 if cos.get("privacy", False) else 0))
        out.append(tlv.compound(CfgTLV.CLASS_OF_SERVICE, subs))

    def service_flow(sf: dict, upstream: bool) -> TLV:
        subs = [tlv.u16(SFTLV.SERVICE_FLOW_REFERENCE, sf["ref"])]
        if "service_class_name" in sf:
            subs.append(tlv.raw(SFTLV.SERVICE_CLASS_NAME,
                                sf["service_class_name"].encode() + b"\x00"))
        subs.append(tlv.u8(SFTLV.QOS_PARAM_SET_TYPE, sf.get("qos_param_set", QoSParamSet.ALL)))
        if "traffic_priority" in sf:
            subs.append(tlv.u8(SFTLV.TRAFFIC_PRIORITY, sf["traffic_priority"]))
        if "max_sustained_bps" in sf:
            subs.append(tlv.u32(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE, sf["max_sustained_bps"]))
        if "max_burst_bytes" in sf:
            subs.append(tlv.u32(SFTLV.MAX_TRAFFIC_BURST, sf["max_burst_bytes"]))
        if "min_reserved_bps" in sf:
            subs.append(tlv.u32(SFTLV.MIN_RESERVED_TRAFFIC_RATE, sf["min_reserved_bps"]))
        if upstream:
            if "max_concatenated_burst" in sf:
                subs.append(tlv.u16(SFTLV.MAX_CONCATENATED_BURST, sf["max_concatenated_burst"]))
            subs.append(tlv.u8(SFTLV.SCHEDULING_TYPE,
                               sf.get("scheduling_type", SchedulingType.BEST_EFFORT)))
            if "request_transmission_policy" in sf:
                subs.append(tlv.u32(SFTLV.REQUEST_TRANSMISSION_POLICY,
                                    sf["request_transmission_policy"]))
        return tlv.compound(CfgTLV.UPSTREAM_SERVICE_FLOW if upstream
                            else CfgTLV.DOWNSTREAM_SERVICE_FLOW, subs)

    for sf in spec.get("upstream_service_flows", []):
        out.append(service_flow(sf, True))
    for sf in spec.get("downstream_service_flows", []):
        out.append(service_flow(sf, False))

    if "max_cpe" in spec:
        out.append(tlv.u8(CfgTLV.MAX_CPE, spec["max_cpe"]))
    if "max_classifiers" in spec:
        out.append(tlv.u16(CfgTLV.MAX_CLASSIFIERS, spec["max_classifiers"]))
    out.append(tlv.u8(CfgTLV.PRIVACY_ENABLE, 1 if spec.get("privacy_enable", False) else 0))
    if spec.get("snmp_write_access"):
        for oid in spec["snmp_write_access"]:
            out.append(tlv.raw(CfgTLV.SNMP_WRITE_ACCESS, bytes.fromhex(oid)))
    for vs in spec.get("vendor_specific", []):
        out.append(tlv.raw(CfgTLV.VENDOR_SPECIFIC, bytes.fromhex(vs)))
    return out


def modem_capabilities(docsis_version: int = DocsisVersion.V20,
                       concatenation: bool = True, fragmentation: bool = True,
                       phs: bool = True, igmp: bool = True,
                       privacy: bool = True, downstream_saids: int = 4,
                       upstream_sids: int = 8) -> TLV:
    """TLV 5, which the modem adds to REG-REQ (it is never in the config file).

    Two sub-TLVs decide whether the modem gets DOCSIS 2.0 treatment:

      * **DOCSIS Version** (5.2) tells the CMTS which spec revision it is
        talking to, and therefore whether advanced-PHY grants (IUC 9/10) are
        legal for this modem at all.
      * **Upstream Symbol Rates** (5.21) is a bitmask saying which rates the
        transmitter can actually produce.  Bit 5 -- 5120 ksps -- exists only
        on a 2.0 modem, and it is what makes a 6.4 MHz A-TDMA channel usable.
    """
    is_20 = docsis_version >= DocsisVersion.V20
    subs = [
        tlv.u8(CapTLV.CONCATENATION, int(concatenation)),
        tlv.u8(CapTLV.DOCSIS_VERSION, docsis_version),
        tlv.u8(CapTLV.FRAGMENTATION, int(fragmentation)),
        tlv.u8(CapTLV.PHS_SUPPORT, int(phs)),
        tlv.u8(CapTLV.IGMP_SUPPORT, int(igmp)),
        tlv.u8(CapTLV.PRIVACY_SUPPORT, int(privacy)),
        tlv.u8(CapTLV.DOWNSTREAM_SAID_SUPPORT, downstream_saids),
        tlv.u8(CapTLV.UPSTREAM_SID_SUPPORT, upstream_sids),
        tlv.u8(CapTLV.TRANSMIT_EQ_TAPS_PER_SYMBOL, 1),
        tlv.u8(CapTLV.TRANSMIT_EQ_TAPS, 8),
        tlv.u8(CapTLV.DCC_SUPPORT, 1),
    ]
    if is_20:
        subs += [
            tlv.u8(CapTLV.UPSTREAM_FREQUENCY_RANGE, 0),      # standard 5-42 MHz
            tlv.u8(CapTLV.UPSTREAM_SYMBOL_RATES, SYMBOL_RATES_DOCSIS_20),
        ]
    else:
        subs.append(tlv.u8(CapTLV.UPSTREAM_SYMBOL_RATES, SYMBOL_RATES_DOCSIS_1X))
    return tlv.compound(CfgTLV.MODEM_CAPABILITIES, subs)


def vendor_class_identifier(docsis_version: int = DocsisVersion.V20,
                            **kwargs) -> bytes:
    """DHCP option 60 as a DOCSIS modem sends it.

    The value is the string "docsisX.Y:" followed by the modem capability
    TLVs rendered as ASCII hex -- so a provisioning system can tell a 2.0
    modem from a 1.1 one, and see what it can do, before it has registered.
    """
    version = {0: "1.0", 1: "1.1", 2: "2.0", 3: "3.0"}.get(docsis_version, "2.0")
    caps = modem_capabilities(docsis_version=docsis_version, **kwargs)
    return f"docsis{version}:".encode() + tlv.encode(caps.sub).hex().upper().encode()


# --------------------------------------------------------------------------
# pretty printer
# --------------------------------------------------------------------------

_CFG_NAMES = {int(v): v.name for v in CfgTLV}
_SF_NAMES = {int(v): v.name for v in SFTLV}
_COS_NAMES = {int(v): v.name for v in ClassOfServiceTLV}
_CAP_NAMES = {int(v): v.name for v in CapTLV}

_SUB_NAMES = {
    int(CfgTLV.UPSTREAM_SERVICE_FLOW): _SF_NAMES,
    int(CfgTLV.DOWNSTREAM_SERVICE_FLOW): _SF_NAMES,
    int(CfgTLV.CLASS_OF_SERVICE): _COS_NAMES,
    int(CfgTLV.MODEM_CAPABILITIES): _CAP_NAMES,
}


def dump(settings: list[TLV] | bytes, indent: str = "") -> str:
    """Render config settings the way a config-file editor would show them."""
    if isinstance(settings, (bytes, bytearray)):
        settings = decode(bytes(settings))
    lines = []
    for t in settings:
        name = _CFG_NAMES.get(t.type, f"TLV-{t.type}")
        if t.sub:
            lines.append(f"{indent}{t.type:>3}  {name}")
            names = _SUB_NAMES.get(t.type, {})
            for s in t.sub:
                sname = names.get(s.type, f"sub-{s.type}")
                lines.append(f"{indent}       .{s.type:<2} {sname:38} "
                             f"{_render(s.value)}")
        else:
            lines.append(f"{indent}{t.type:>3}  {name:42} {_render(t.value)}")
    return "\n".join(lines)


def _render(value: bytes) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return f"{int.from_bytes(value, 'big')} (0x{value.hex()})"
    if all(32 <= b < 127 or b == 0 for b in value):
        return value.rstrip(b"\x00").decode(errors="replace")
    return "0x" + value.hex()
