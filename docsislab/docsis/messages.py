"""Encoders and decoders for the DOCSIS 2.0 MAC management messages.

Every class here is a faithful representation of a message body as it appears
on the wire, i.e. the bytes that follow the 20-byte MAC management header.
`encode()` produces those bytes; `decode()` parses them back.  Field layouts
follow CM-SP-RFIv2.0 section 8.3.

The messages implemented are the ones needed to take a modem from cold start
to `online`, plus the dynamic-service and channel-change messages that a CMTS
of this era would emit:

    SYNC     8.3.1   downstream timestamp, the modem's clock reference
    UCD      8.3.3   upstream channel description (type 2 = 1.x, type 29 = 2.0)
    MAP      8.3.4   mini-slot allocation
    RNG-REQ  8.3.5   ranging request
    RNG-RSP  8.3.6   timing/power/frequency correction
    REG-REQ  8.3.7   registration request, echoes the config file
    REG-RSP  8.3.8   registration response, assigns SIDs
    REG-ACK  8.3.14  registration acknowledgement
    UCC-REQ/RSP, DSA/DSC/DSD-REQ/RSP/ACK
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..util import tlv
from ..util.tlv import TLV
from .consts import (IUC, IUC_NAMES, MgmtType, Modulation, MODULATION_NAMES,
                     RangingStatus, RngRspTLV, UCDTLV, BurstTLV, CfgTLV,
                     ConfirmationCode, RegRspCode)


class MessageError(ValueError):
    """A MAC management message body that cannot be parsed."""
    pass


# ==========================================================================
# SYNC -- RFIv2.0 8.3.1
# ==========================================================================

@dataclass
class Sync:
    """Downstream timestamp.  The CMTS latches its 32-bit 10.24 MHz master
    clock into this field; every modem on the downstream slaves its own clock
    to the arriving value, which is what makes upstream mini-slot timing
    possible in the first place."""
    timestamp: int

    TYPE = MgmtType.SYNC

    def encode(self) -> bytes:
        return (self.timestamp & 0xFFFFFFFF).to_bytes(4, "big")

    @classmethod
    def decode(cls, data: bytes) -> "Sync":
        if len(data) < 4:
            raise MessageError("SYNC must carry a 4-byte timestamp")
        return cls(int.from_bytes(data[0:4], "big"))

    def summary(self) -> str:
        return f"SYNC ts={self.timestamp}"


# ==========================================================================
# UCD -- RFIv2.0 8.3.3
# ==========================================================================

@dataclass
class BurstDescriptor:
    """Per-IUC burst profile.  The IUC is the first byte of the descriptor
    value, followed by sub-TLVs.  A type-4 descriptor is DOCSIS 1.x; a type-5
    descriptor is DOCSIS 2.0 and may carry the interleaver, preamble-type and
    S-CDMA parameters that 1.x has no way to express."""
    iuc: int
    modulation: int = Modulation.QPSK
    differential_encoding: int = 2       # 2 = off
    preamble_length: int = 64            # bits
    preamble_value_offset: int = 0
    fec_t: int = 5                       # correctable bytes per codeword
    fec_k: int = 75                      # information bytes per codeword
    scrambler_seed: int = 0x152
    max_burst: int = 0                   # mini-slots, 0 = unlimited
    guard_time: int = 8                  # symbols
    last_codeword_shortened: bool = True
    scrambler_on: bool = True
    # DOCSIS 2.0 only
    rs_interleaver_depth: int | None = None
    rs_interleaver_block_size: int | None = None
    preamble_type: int | None = None     # 1 = QPSK0, 2 = QPSK1
    scdma_spreader_on: int | None = None
    tcm_encoding: int | None = None

    def encode(self, advanced: bool) -> bytes:
        subs = [
            tlv.u8(BurstTLV.MODULATION_TYPE, self.modulation),
            tlv.u8(BurstTLV.DIFFERENTIAL_ENCODING, self.differential_encoding),
            tlv.u16(BurstTLV.PREAMBLE_LENGTH, self.preamble_length),
            tlv.u16(BurstTLV.PREAMBLE_VALUE_OFFSET, self.preamble_value_offset),
            tlv.u8(BurstTLV.FEC_ERROR_CORRECTION, self.fec_t),
            tlv.u8(BurstTLV.FEC_CODEWORD_LENGTH, self.fec_k),
            tlv.u16(BurstTLV.SCRAMBLER_SEED, self.scrambler_seed),
            tlv.u8(BurstTLV.MAX_BURST_SIZE, self.max_burst),
            tlv.u8(BurstTLV.GUARD_TIME_SIZE, self.guard_time),
            tlv.u8(BurstTLV.LAST_CODEWORD_LENGTH, 2 if self.last_codeword_shortened else 1),
            tlv.u8(BurstTLV.SCRAMBLER_ONOFF, 1 if self.scrambler_on else 2),
        ]
        if advanced:
            if self.rs_interleaver_depth is not None:
                subs.append(tlv.u8(BurstTLV.RS_INTERLEAVER_DEPTH, self.rs_interleaver_depth))
            if self.rs_interleaver_block_size is not None:
                subs.append(tlv.u16(BurstTLV.RS_INTERLEAVER_BLOCK_SIZE,
                                    self.rs_interleaver_block_size))
            if self.preamble_type is not None:
                subs.append(tlv.u8(BurstTLV.PREAMBLE_TYPE, self.preamble_type))
            if self.scdma_spreader_on is not None:
                subs.append(tlv.u8(BurstTLV.SCDMA_SPREADER_ONOFF, self.scdma_spreader_on))
            if self.tcm_encoding is not None:
                subs.append(tlv.u8(BurstTLV.TCM_ENCODING, self.tcm_encoding))
        body = bytes([self.iuc & 0xFF]) + tlv.encode(subs)
        type_ = UCDTLV.BURST_DESCRIPTOR_20 if advanced else UCDTLV.BURST_DESCRIPTOR_1X
        return TLV(type_, body).encode()

    @classmethod
    def decode(cls, value: bytes) -> "BurstDescriptor":
        if not value:
            raise MessageError("empty burst descriptor")
        bd = cls(iuc=value[0])
        subs = {t.type: t for t in tlv.decode(value[1:], strict=False)}
        def geti(k, default):
            t = subs.get(k)
            return t.as_int if t is not None else default
        bd.modulation = geti(BurstTLV.MODULATION_TYPE, bd.modulation)
        bd.differential_encoding = geti(BurstTLV.DIFFERENTIAL_ENCODING, 2)
        bd.preamble_length = geti(BurstTLV.PREAMBLE_LENGTH, bd.preamble_length)
        bd.preamble_value_offset = geti(BurstTLV.PREAMBLE_VALUE_OFFSET, 0)
        bd.fec_t = geti(BurstTLV.FEC_ERROR_CORRECTION, bd.fec_t)
        bd.fec_k = geti(BurstTLV.FEC_CODEWORD_LENGTH, bd.fec_k)
        bd.scrambler_seed = geti(BurstTLV.SCRAMBLER_SEED, bd.scrambler_seed)
        bd.max_burst = geti(BurstTLV.MAX_BURST_SIZE, 0)
        bd.guard_time = geti(BurstTLV.GUARD_TIME_SIZE, bd.guard_time)
        bd.last_codeword_shortened = geti(BurstTLV.LAST_CODEWORD_LENGTH, 2) == 2
        bd.scrambler_on = geti(BurstTLV.SCRAMBLER_ONOFF, 1) == 1
        bd.rs_interleaver_depth = subs[BurstTLV.RS_INTERLEAVER_DEPTH].as_int \
            if BurstTLV.RS_INTERLEAVER_DEPTH in subs else None
        bd.rs_interleaver_block_size = subs[BurstTLV.RS_INTERLEAVER_BLOCK_SIZE].as_int \
            if BurstTLV.RS_INTERLEAVER_BLOCK_SIZE in subs else None
        bd.preamble_type = subs[BurstTLV.PREAMBLE_TYPE].as_int \
            if BurstTLV.PREAMBLE_TYPE in subs else None
        bd.scdma_spreader_on = subs[BurstTLV.SCDMA_SPREADER_ONOFF].as_int \
            if BurstTLV.SCDMA_SPREADER_ONOFF in subs else None
        return bd

    def label(self) -> str:
        name = IUC_NAMES.get(self.iuc, f"IUC{self.iuc}")
        mod = MODULATION_NAMES.get(self.modulation, str(self.modulation))
        return f"IUC {self.iuc} ({name}): {mod} FEC T={self.fec_t} k={self.fec_k}"


@dataclass
class Ucd:
    """Upstream Channel Descriptor.

    A DOCSIS 2.0 CMTS running an A-TDMA upstream in mixed mode describes the
    same physical channel twice: once as a type-2 UCD carrying type-4 burst
    descriptors for IUCs 1..6 (which is all a DOCSIS 1.x modem understands),
    and once as a type-29 UCD carrying type-5 burst descriptors that add the
    advanced-PHY IUCs 9..11.  A 2.0 modem prefers the type-29 UCD.
    """
    upstream_channel_id: int
    config_change_count: int
    minislot_size: int          # in 6.25 us timebase ticks, a power of two
    downstream_channel_id: int
    symbol_rate_ksym: int = 2560
    frequency_hz: int = 30_000_000
    preamble_pattern: bytes = b""
    burst_descriptors: list[BurstDescriptor] = field(default_factory=list)
    scdma_mode: int = 0                     # 0 = off (A-TDMA/TDMA)
    maintain_psd: int | None = None
    ranging_required: int | None = None     # 1 = initial, 2 = broadcast, 3 = unicast
    #: message type -- 2 for the DOCSIS 1.x view, 29 for the DOCSIS 2.0 view
    msg_type: int = MgmtType.UCD2

    @property
    def advanced(self) -> bool:
        return self.msg_type in (MgmtType.UCD2, MgmtType.UCD3)

    @property
    def TYPE(self) -> int:
        return self.msg_type

    def encode(self) -> bytes:
        head = bytes([self.upstream_channel_id & 0xFF,
                      self.config_change_count & 0xFF,
                      self.minislot_size & 0xFF,
                      self.downstream_channel_id & 0xFF])
        body = b""
        # RFIv2.0 requires symbol rate, frequency and preamble pattern before
        # the burst descriptors.
        body += tlv.u8(UCDTLV.SYMBOL_RATE, self.symbol_rate_ksym // 160).encode()
        body += tlv.u32(UCDTLV.FREQUENCY, self.frequency_hz).encode()
        if self.preamble_pattern:
            body += TLV(UCDTLV.PREAMBLE_PATTERN, self.preamble_pattern).encode()
        if self.advanced:
            body += tlv.u8(UCDTLV.SCDMA_MODE_ENABLE, self.scdma_mode).encode()
        if self.maintain_psd is not None:
            body += tlv.u8(UCDTLV.MAINTAIN_POWER_SPECTRAL_DENSITY, self.maintain_psd).encode()
        if self.ranging_required is not None:
            body += tlv.u8(UCDTLV.RANGING_REQUIRED, self.ranging_required).encode()
        for bd in self.burst_descriptors:
            body += bd.encode(self.advanced)
        return head + body

    @classmethod
    def decode(cls, data: bytes, msg_type: int = MgmtType.UCD2) -> "Ucd":
        if len(data) < 4:
            raise MessageError("UCD header truncated")
        ucd = cls(upstream_channel_id=data[0], config_change_count=data[1],
                  minislot_size=data[2], downstream_channel_id=data[3],
                  msg_type=msg_type)
        for t in tlv.decode(data[4:], strict=False):
            if t.type == UCDTLV.SYMBOL_RATE:
                ucd.symbol_rate_ksym = t.as_int * 160
            elif t.type == UCDTLV.FREQUENCY:
                ucd.frequency_hz = t.as_int
            elif t.type == UCDTLV.PREAMBLE_PATTERN:
                ucd.preamble_pattern = t.value
            elif t.type == UCDTLV.SCDMA_MODE_ENABLE:
                ucd.scdma_mode = t.as_int
            elif t.type == UCDTLV.MAINTAIN_POWER_SPECTRAL_DENSITY:
                ucd.maintain_psd = t.as_int
            elif t.type == UCDTLV.RANGING_REQUIRED:
                ucd.ranging_required = t.as_int
            elif t.type in (UCDTLV.BURST_DESCRIPTOR_1X, UCDTLV.BURST_DESCRIPTOR_20):
                ucd.burst_descriptors.append(BurstDescriptor.decode(t.value))
        return ucd

    def burst(self, iuc: int) -> BurstDescriptor | None:
        for bd in self.burst_descriptors:
            if bd.iuc == iuc:
                return bd
        return None

    def summary(self) -> str:
        kind = "type 29 (2.0)" if self.advanced else "type 2 (1.x)"
        return (f"UCD {kind} us={self.upstream_channel_id} ccc={self.config_change_count} "
                f"{self.frequency_hz/1e6:.2f} MHz {self.symbol_rate_ksym} ksym/s "
                f"minislot={self.minislot_size} ticks "
                f"IUCs={[bd.iuc for bd in self.burst_descriptors]}")


# ==========================================================================
# MAP -- RFIv2.0 8.3.4
# ==========================================================================

@dataclass
class MapIE:
    """One 32-bit MAP information element: SID(14) | IUC(4) | offset(14).

    The offset is a mini-slot offset from the MAP's Alloc Start Time.  A grant
    runs from its own offset up to the offset of the *next* IE, so a MAP
    always ends with a Null IE to close the last grant.
    """
    sid: int
    iuc: int
    offset: int

    def encode(self) -> int:
        return (((self.sid & 0x3FFF) << 18)
                | ((self.iuc & 0x0F) << 14)
                | (self.offset & 0x3FFF))

    @classmethod
    def from_word(cls, word: int) -> "MapIE":
        return cls(sid=(word >> 18) & 0x3FFF,
                   iuc=(word >> 14) & 0x0F,
                   offset=word & 0x3FFF)

    def label(self) -> str:
        return f"sid={self.sid} {IUC_NAMES.get(self.iuc, self.iuc)}@{self.offset}"


@dataclass
class Map:
    """Upstream Bandwidth Allocation: who may transmit in which mini-slots."""
    upstream_channel_id: int
    ucd_count: int
    alloc_start_time: int       # mini-slot number this MAP starts at
    ack_time: int               # mini-slot up to which requests are acknowledged
    ranging_backoff_start: int = 0
    ranging_backoff_end: int = 4
    data_backoff_start: int = 0
    data_backoff_end: int = 4
    ies: list[MapIE] = field(default_factory=list)

    TYPE = MgmtType.MAP

    def encode(self) -> bytes:
        head = struct.pack(">BBBBIIBBBB",
                           self.upstream_channel_id & 0xFF,
                           self.ucd_count & 0xFF,
                           len(self.ies) & 0xFF,
                           0,
                           self.alloc_start_time & 0xFFFFFFFF,
                           self.ack_time & 0xFFFFFFFF,
                           self.ranging_backoff_start & 0xFF,
                           self.ranging_backoff_end & 0xFF,
                           self.data_backoff_start & 0xFF,
                           self.data_backoff_end & 0xFF)
        return head + b"".join(ie.encode().to_bytes(4, "big") for ie in self.ies)

    @classmethod
    def decode(cls, data: bytes) -> "Map":
        if len(data) < 16:
            raise MessageError("MAP header truncated")
        (uchid, ucd_count, n_elem, _rsvd, alloc_start, ack_time,
         rbs, rbe, dbs, dbe) = struct.unpack(">BBBBIIBBBB", data[:16])
        m = cls(upstream_channel_id=uchid, ucd_count=ucd_count,
                alloc_start_time=alloc_start, ack_time=ack_time,
                ranging_backoff_start=rbs, ranging_backoff_end=rbe,
                data_backoff_start=dbs, data_backoff_end=dbe)
        body = data[16:16 + 4 * n_elem]
        for i in range(0, len(body), 4):
            m.ies.append(MapIE.from_word(int.from_bytes(body[i:i + 4], "big")))
        return m

    def grant_span(self, index: int) -> tuple[int, int]:
        """Absolute (first, last_exclusive) mini-slot of IE `index`."""
        start = self.alloc_start_time + self.ies[index].offset
        if index + 1 < len(self.ies):
            end = self.alloc_start_time + self.ies[index + 1].offset
        else:
            end = start
        return start, end

    def summary(self) -> str:
        return (f"MAP us={self.upstream_channel_id} start={self.alloc_start_time} "
                f"ack={self.ack_time} n={len(self.ies)} "
                f"rng-backoff={self.ranging_backoff_start}..{self.ranging_backoff_end} "
                f"[{', '.join(ie.label() for ie in self.ies)}]")


# ==========================================================================
# Ranging -- RFIv2.0 8.3.5 / 8.3.6
# ==========================================================================

@dataclass
class RngReq:
    """Ranging Request: SID 0 for initial ranging, the assigned SID after."""
    sid: int
    downstream_channel_id: int
    pending_till_complete: int = 0

    TYPE = MgmtType.RNG_REQ

    def encode(self) -> bytes:
        return ((self.sid & 0x3FFF).to_bytes(2, "big")
                + bytes([self.downstream_channel_id & 0xFF,
                         self.pending_till_complete & 0xFF]))

    @classmethod
    def decode(cls, data: bytes) -> "RngReq":
        if len(data) < 4:
            raise MessageError("RNG-REQ must be 4 bytes")
        return cls(sid=int.from_bytes(data[0:2], "big") & 0x3FFF,
                   downstream_channel_id=data[2], pending_till_complete=data[3])

    def summary(self) -> str:
        who = "initial (SID 0)" if self.sid == 0 else f"sid={self.sid}"
        return f"RNG-REQ {who} ds={self.downstream_channel_id}"


@dataclass
class RngRsp:
    """Ranging Response: timing, power and frequency corrections, plus status."""
    sid: int
    upstream_channel_id: int
    timing_adjust: int | None = None       # 1/64 tick units
    power_adjust: int | None = None        # 0.25 dB units
    frequency_adjust: int | None = None    # Hz
    ranging_status: int = RangingStatus.CONTINUE
    extra: list[TLV] = field(default_factory=list)

    TYPE = MgmtType.RNG_RSP

    def encode(self) -> bytes:
        tlvs: list[TLV] = []
        if self.timing_adjust is not None:
            tlvs.append(tlv.s32(RngRspTLV.TIMING_ADJUST, self.timing_adjust))
        if self.power_adjust is not None:
            tlvs.append(tlv.s8(RngRspTLV.POWER_ADJUST, self.power_adjust))
        if self.frequency_adjust is not None:
            tlvs.append(tlv.s16(RngRspTLV.FREQUENCY_ADJUST, self.frequency_adjust))
        tlvs.append(tlv.u8(RngRspTLV.RANGING_STATUS, self.ranging_status))
        tlvs.extend(self.extra)
        return ((self.sid & 0x3FFF).to_bytes(2, "big")
                + bytes([self.upstream_channel_id & 0xFF])
                + tlv.encode(tlvs))

    @classmethod
    def decode(cls, data: bytes) -> "RngRsp":
        if len(data) < 3:
            raise MessageError("RNG-RSP header truncated")
        r = cls(sid=int.from_bytes(data[0:2], "big") & 0x3FFF,
                upstream_channel_id=data[2])
        for t in tlv.decode(data[3:], strict=False):
            if t.type == RngRspTLV.TIMING_ADJUST:
                r.timing_adjust = t.as_sint
            elif t.type == RngRspTLV.POWER_ADJUST:
                r.power_adjust = t.as_sint
            elif t.type == RngRspTLV.FREQUENCY_ADJUST:
                r.frequency_adjust = t.as_sint
            elif t.type == RngRspTLV.RANGING_STATUS:
                r.ranging_status = t.as_int
            else:
                r.extra.append(t)
        return r

    def summary(self) -> str:
        bits = [f"sid={self.sid}", f"us={self.upstream_channel_id}",
                RangingStatus(self.ranging_status).name
                if self.ranging_status in set(RangingStatus) else str(self.ranging_status)]
        if self.timing_adjust is not None:
            bits.append(f"timing{self.timing_adjust:+d}")
        if self.power_adjust is not None:
            bits.append(f"power{self.power_adjust/4:+.2f}dB")
        if self.frequency_adjust is not None:
            bits.append(f"freq{self.frequency_adjust:+d}Hz")
        return "RNG-RSP " + " ".join(bits)


# ==========================================================================
# Registration -- RFIv2.0 8.3.7 / 8.3.8 / 8.3.14
# ==========================================================================

#: Config-file / REG-REQ TLV types whose values are themselves TLV streams.
CFG_COMPOUND = {
    int(CfgTLV.CLASS_OF_SERVICE), int(CfgTLV.MODEM_CAPABILITIES),
    int(CfgTLV.BASELINE_PRIVACY_CFG), int(CfgTLV.UPSTREAM_CLASSIFIER),
    int(CfgTLV.DOWNSTREAM_CLASSIFIER), int(CfgTLV.UPSTREAM_SERVICE_FLOW),
    int(CfgTLV.DOWNSTREAM_SERVICE_FLOW), int(CfgTLV.PAYLOAD_HEADER_SUPPRESSION),
}


@dataclass
class RegReq:
    """Registration Request: the config file settings echoed back, plus capabilities."""
    sid: int
    settings: list[TLV] = field(default_factory=list)

    TYPE = MgmtType.REG_REQ

    def encode(self) -> bytes:
        return (self.sid & 0x3FFF).to_bytes(2, "big") + tlv.encode(self.settings)

    @classmethod
    def decode(cls, data: bytes) -> "RegReq":
        if len(data) < 2:
            raise MessageError("REG-REQ header truncated")
        return cls(sid=int.from_bytes(data[0:2], "big") & 0x3FFF,
                   settings=tlv.decode(data[2:], CFG_COMPOUND, strict=False))

    def summary(self) -> str:
        return f"REG-REQ sid={self.sid} tlvs={[t.type for t in self.settings]}"


@dataclass
class RegRsp:
    """Registration Response: accept or refuse, and the assigned SFIDs and SIDs."""
    sid: int
    response: int = RegRspCode.OK
    settings: list[TLV] = field(default_factory=list)

    TYPE = MgmtType.REG_RSP

    def encode(self) -> bytes:
        return ((self.sid & 0x3FFF).to_bytes(2, "big")
                + bytes([self.response & 0xFF]) + tlv.encode(self.settings))

    @classmethod
    def decode(cls, data: bytes) -> "RegRsp":
        if len(data) < 3:
            raise MessageError("REG-RSP header truncated")
        return cls(sid=int.from_bytes(data[0:2], "big") & 0x3FFF,
                   response=data[2],
                   settings=tlv.decode(data[3:], CFG_COMPOUND, strict=False))

    def summary(self) -> str:
        name = RegRspCode(self.response).name if self.response in set(RegRspCode) \
            else str(self.response)
        return f"REG-RSP sid={self.sid} {name}"


@dataclass
class RegAck:
    """Registration Acknowledge: the modem confirms, and is then in service."""
    sid: int
    confirmation_code: int = ConfirmationCode.OKAY

    TYPE = MgmtType.REG_ACK

    def encode(self) -> bytes:
        return (self.sid & 0x3FFF).to_bytes(2, "big") + bytes([self.confirmation_code & 0xFF])

    @classmethod
    def decode(cls, data: bytes) -> "RegAck":
        if len(data) < 3:
            raise MessageError("REG-ACK must be 3 bytes")
        return cls(sid=int.from_bytes(data[0:2], "big") & 0x3FFF,
                   confirmation_code=data[2])

    def summary(self) -> str:
        name = ConfirmationCode(self.confirmation_code).name \
            if self.confirmation_code in set(ConfirmationCode) else str(self.confirmation_code)
        return f"REG-ACK sid={self.sid} {name}"


# ==========================================================================
# Upstream Channel Change -- RFIv2.0 8.3.9 / 8.3.10
# ==========================================================================

@dataclass
class UccReq:
    """Upstream Channel Change Request: move to another upstream."""
    upstream_channel_id: int
    settings: list[TLV] = field(default_factory=list)

    TYPE = MgmtType.UCC_REQ

    def encode(self) -> bytes:
        return bytes([self.upstream_channel_id & 0xFF]) + tlv.encode(self.settings)

    @classmethod
    def decode(cls, data: bytes) -> "UccReq":
        return cls(upstream_channel_id=data[0],
                   settings=tlv.decode(data[1:], strict=False))

    def summary(self) -> str:
        return f"UCC-REQ -> us={self.upstream_channel_id}"


@dataclass
class UccRsp:
    """Upstream Channel Change Response, sent on the channel being left."""
    upstream_channel_id: int

    TYPE = MgmtType.UCC_RSP

    def encode(self) -> bytes:
        return bytes([self.upstream_channel_id & 0xFF])

    @classmethod
    def decode(cls, data: bytes) -> "UccRsp":
        return cls(upstream_channel_id=data[0])

    def summary(self) -> str:
        return f"UCC-RSP us={self.upstream_channel_id}"


# ==========================================================================
# Dynamic service messages -- RFIv2.0 8.3.15 onward
# ==========================================================================

@dataclass
class DsxReq:
    """DSA-REQ / DSC-REQ / DSD-REQ share a transaction-ID + TLV shape."""
    transaction_id: int
    settings: list[TLV] = field(default_factory=list)
    msg_type: int = MgmtType.DSA_REQ

    @property
    def TYPE(self) -> int:
        return self.msg_type

    def encode(self) -> bytes:
        return (self.transaction_id & 0xFFFF).to_bytes(2, "big") + tlv.encode(self.settings)

    @classmethod
    def decode(cls, data: bytes, msg_type: int = MgmtType.DSA_REQ) -> "DsxReq":
        return cls(transaction_id=int.from_bytes(data[0:2], "big"),
                   settings=tlv.decode(data[2:], CFG_COMPOUND, strict=False),
                   msg_type=msg_type)

    def summary(self) -> str:
        return f"{MgmtType(self.msg_type).name} tid={self.transaction_id}"


@dataclass
class DsxRsp:
    """DSA/DSC/DSD response and acknowledge: transaction ID plus a confirmation code."""
    transaction_id: int
    confirmation_code: int = ConfirmationCode.OKAY
    settings: list[TLV] = field(default_factory=list)
    msg_type: int = MgmtType.DSA_RSP

    @property
    def TYPE(self) -> int:
        return self.msg_type

    def encode(self) -> bytes:
        return ((self.transaction_id & 0xFFFF).to_bytes(2, "big")
                + bytes([self.confirmation_code & 0xFF]) + tlv.encode(self.settings))

    @classmethod
    def decode(cls, data: bytes, msg_type: int = MgmtType.DSA_RSP) -> "DsxRsp":
        return cls(transaction_id=int.from_bytes(data[0:2], "big"),
                   confirmation_code=data[2],
                   settings=tlv.decode(data[3:], CFG_COMPOUND, strict=False),
                   msg_type=msg_type)

    def summary(self) -> str:
        return f"{MgmtType(self.msg_type).name} tid={self.transaction_id} cc={self.confirmation_code}"


DsxAck = DsxRsp


# ==========================================================================
# dispatch
# ==========================================================================

def decode_body(msg_type: int, payload: bytes):
    """Decode a MAC management payload according to its type byte."""
    if msg_type == MgmtType.SYNC:
        return Sync.decode(payload)
    if msg_type in (MgmtType.UCD, MgmtType.UCD2, MgmtType.UCD3):
        return Ucd.decode(payload, msg_type)
    if msg_type == MgmtType.MAP:
        return Map.decode(payload)
    if msg_type == MgmtType.RNG_REQ:
        return RngReq.decode(payload)
    if msg_type == MgmtType.RNG_RSP:
        return RngRsp.decode(payload)
    if msg_type == MgmtType.REG_REQ:
        return RegReq.decode(payload)
    if msg_type == MgmtType.REG_RSP:
        return RegRsp.decode(payload)
    if msg_type == MgmtType.REG_ACK:
        return RegAck.decode(payload)
    if msg_type == MgmtType.UCC_REQ:
        return UccReq.decode(payload)
    if msg_type == MgmtType.UCC_RSP:
        return UccRsp.decode(payload)
    if msg_type in (MgmtType.DSA_REQ, MgmtType.DSC_REQ, MgmtType.DSD_REQ):
        return DsxReq.decode(payload, msg_type)
    if msg_type in (MgmtType.DSA_RSP, MgmtType.DSC_RSP, MgmtType.DSD_RSP,
                    MgmtType.DSA_ACK, MgmtType.DSC_ACK):
        return DsxRsp.decode(payload, msg_type)
    return None
