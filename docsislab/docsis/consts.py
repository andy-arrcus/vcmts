"""DOCSIS 2.0 constants: frame control, message types, IUCs, TLVs, timers.

Section references are to CM-SP-RFIv2.0 (the DOCSIS 2.0 Radio Frequency
Interface specification).  Where DOCSIS 1.1 and 2.0 differ, the 2.0 value is
the one used by this simulation and the 1.x value is kept for the mixed-mode
messages the CMTS also emits.
"""

from __future__ import annotations

from enum import IntEnum

# ==========================================================================
# MAC frame header -- RFIv2.0 section 6.2.1
# ==========================================================================

class FCType(IntEnum):
    """The two high bits of FC: which kind of frame this is."""
    PACKET = 0      # Packet PDU (an Ethernet frame)
    ATM = 1         # ATM cells (never used in practice)
    ISOLATION = 2   # Isolation Packet PDU (DOCSIS 2.0, upstream isolation)
    MAC_SPECIFIC = 3


class FCParm(IntEnum):
    """FC_PARM values when FC_TYPE == MAC_SPECIFIC."""
    TIMING = 0x00           # Timing header -- carries the SYNC message
    MAC_MGMT = 0x01         # MAC management header
    REQUEST = 0x02          # Request frame (bandwidth request, header only)
    FRAGMENTATION = 0x03    # Fragmentation header
    QUEUE_DEPTH_REQ = 0x04  # Queue-depth-based request (DOCSIS 2.0)
    CONCATENATION = 0x1C    # Concatenation header


class EHdrType(IntEnum):
    """Extended header element types -- RFIv2.0 Table 6-8."""
    NULL = 0
    REQUEST = 1          # piggybacked bandwidth request
    ACK_REQUEST = 2
    BP_UP = 3            # upstream privacy
    BP_DOWN = 4          # downstream privacy
    SFLOW_UP = 5         # upstream service flow (PHS / request)
    SFLOW_DOWN = 6       # downstream service flow (PHS)
    PAYLOAD_HDR_SUP = 7
    UNSOLICITED_GRANT = 8
    EXTENDED = 15


# ==========================================================================
# MAC management messages -- RFIv2.0 Table 6-15
# ==========================================================================

class MgmtType(IntEnum):
    """MAC management message type codes (Table 6-15)."""
    SYNC = 1
    UCD = 2             # Upstream Channel Descriptor, DOCSIS 1.x (TDMA)
    MAP = 3             # Upstream Bandwidth Allocation
    RNG_REQ = 4
    RNG_RSP = 5
    REG_REQ = 6
    REG_RSP = 7
    UCC_REQ = 8         # Upstream Channel Change
    UCC_RSP = 9
    TRI_TCD = 10
    TRI_TSI = 11
    BPKM_REQ = 12       # Baseline Privacy Key Management
    BPKM_RSP = 13
    REG_ACK = 14
    DSA_REQ = 15        # Dynamic Service Addition
    DSA_RSP = 16
    DSA_ACK = 17
    DSC_REQ = 18        # Dynamic Service Change
    DSC_RSP = 19
    DSC_ACK = 20
    DSD_REQ = 21        # Dynamic Service Deletion
    DSD_RSP = 22
    DCC_REQ = 23        # Dynamic Channel Change
    DCC_RSP = 24
    DCC_ACK = 25
    DCI_REQ = 26        # Device Class Identification
    DCI_RSP = 27
    UP_DIS = 28         # Upstream Transmitter Disable
    UCD2 = 29           # Type 29 UCD -- DOCSIS 2.0 (A-TDMA / S-CDMA)
    INIT_RNG_REQ = 30
    TST_REQ = 31
    DCD = 32            # DSG Downstream Channel Descriptor
    MDD = 33            # DOCSIS 3.0
    B_INIT_RNG_REQ = 34
    UCD3 = 35


#: The `version` byte in the MAC management header.  RFIv2.0 section 6.4.1:
#: version 1 for messages defined in DOCSIS 1.0, 2 for those added in 1.1,
#: 3/4 for 2.0.  A DOCSIS 2.0 CMTS marks type 29 UCD and MAPs describing an
#: A-TDMA channel with version 4.
MGMT_VERSION_10 = 1
MGMT_VERSION_11 = 2
MGMT_VERSION_20 = 3
MGMT_VERSION_20_EXT = 4

#: Well-known multicast destination for MAC management messages sent to all
#: modems on the downstream (RFIv2.0 Annex A).
DOCSIS_MGMT_MULTICAST = bytes.fromhex("01e02f000001")


# ==========================================================================
# Interval Usage Codes -- RFIv2.0 Table 8-4
# ==========================================================================

class IUC(IntEnum):
    """Interval Usage Codes: the kinds of upstream region a MAP allocates."""
    REQUEST = 1                 # contention or unicast request region
    REQ_DATA = 2                # request/data (contention data)
    INITIAL_MAINT = 3           # initial ranging, broadcast/contention
    STATION_MAINT = 4           # periodic ranging, unicast
    SHORT_DATA_GRANT = 5        # DOCSIS 1.x
    LONG_DATA_GRANT = 6         # DOCSIS 1.x
    NULL_IE = 7                 # terminates the MAP / marks end of a grant
    DATA_ACK = 8
    ADV_PHY_SHORT_DATA = 9      # DOCSIS 2.0 A-TDMA short grant
    ADV_PHY_LONG_DATA = 10      # DOCSIS 2.0 A-TDMA long grant
    ADV_PHY_UGS = 11            # DOCSIS 2.0 unsolicited grant
    EXPANSION = 14
    RESERVED_15 = 15


IUC_NAMES = {
    IUC.REQUEST: "Request",
    IUC.REQ_DATA: "REQ/Data",
    IUC.INITIAL_MAINT: "Initial Maintenance",
    IUC.STATION_MAINT: "Station Maintenance",
    IUC.SHORT_DATA_GRANT: "Short Data Grant",
    IUC.LONG_DATA_GRANT: "Long Data Grant",
    IUC.NULL_IE: "Null IE",
    IUC.DATA_ACK: "Data Ack",
    IUC.ADV_PHY_SHORT_DATA: "Adv PHY Short Data Grant",
    IUC.ADV_PHY_LONG_DATA: "Adv PHY Long Data Grant",
    IUC.ADV_PHY_UGS: "Adv PHY UGS",
    IUC.EXPANSION: "Expansion",
}


# ==========================================================================
# Service Identifiers -- RFIv2.0 section 8.2.2
# ==========================================================================
SID_BROADCAST = 0x3FFF   # all modems (used for broadcast Initial Maintenance)
SID_INITIAL_RANGING = 0  # a modem that has not yet been given a SID
SID_MAX_UNICAST = 0x1FFF
SID_NULL = 0x3FFF


# ==========================================================================
# Upstream Channel Descriptor -- RFIv2.0 Table 8-2 / 8-3
# ==========================================================================

class UCDTLV(IntEnum):
    """Top-level TLVs inside an Upstream Channel Descriptor."""
    SYMBOL_RATE = 1              # multiples of 160 ksym/s
    FREQUENCY = 2                # Hz, centre of the upstream channel
    PREAMBLE_PATTERN = 3
    BURST_DESCRIPTOR_1X = 4      # DOCSIS 1.x burst descriptor
    BURST_DESCRIPTOR_20 = 5      # DOCSIS 2.0 burst descriptor
    EXT_PREAMBLE = 6
    SCDMA_MODE_ENABLE = 7
    SCDMA_SPREADING_INTERVAL = 8
    SCDMA_CODES_PER_MINISLOT = 9
    SCDMA_ACTIVE_CODES = 10
    SCDMA_CODE_HOPPING_SEED = 11
    SCDMA_US_RATIO_NUM = 12
    SCDMA_US_RATIO_DENOM = 13
    SCDMA_TIMESTAMP_SNAPSHOT = 14
    MAINTAIN_POWER_SPECTRAL_DENSITY = 15
    RANGING_REQUIRED = 16
    SCDMA_MAX_SCHEDULED_CODES = 17
    RANGING_HOLD_OFF_PRIORITY = 18
    CHANNEL_CLASS_ID = 19


class BurstTLV(IntEnum):
    """Sub-TLVs inside a UCD burst descriptor (RFIv2.0 Table 8-3)."""
    MODULATION_TYPE = 1
    DIFFERENTIAL_ENCODING = 2
    PREAMBLE_LENGTH = 3          # bits
    PREAMBLE_VALUE_OFFSET = 4    # bits into the preamble pattern
    FEC_ERROR_CORRECTION = 5     # T, 0..16 (0 = FEC off)
    FEC_CODEWORD_LENGTH = 6      # k, information bytes
    SCRAMBLER_SEED = 7
    MAX_BURST_SIZE = 8           # mini-slots, 0 = unlimited
    GUARD_TIME_SIZE = 9          # symbols
    LAST_CODEWORD_LENGTH = 10    # 1 = fixed, 2 = shortened
    SCRAMBLER_ONOFF = 11         # 1 = on, 2 = off
    # DOCSIS 2.0 additions (only legal in a type-5 burst descriptor)
    RS_INTERLEAVER_DEPTH = 12
    RS_INTERLEAVER_BLOCK_SIZE = 13
    PREAMBLE_TYPE = 14           # 1 = QPSK0, 2 = QPSK1
    SCDMA_SPREADER_ONOFF = 15
    SCDMA_CODES_PER_SUBFRAME = 16
    SCDMA_FRAMER_INT_STEP_SIZE = 17
    TCM_ENCODING = 18


class Modulation(IntEnum):
    """UCD burst-descriptor modulation codes (RFIv2.0 Table 8-3)."""
    QPSK = 1
    QAM16 = 2
    QAM8 = 3
    QAM32 = 4
    QAM64 = 5
    QAM128 = 6   # S-CDMA only
    QAM256 = 7   # downstream only


#: Bits carried per modulation symbol.
BITS_PER_SYMBOL = {
    Modulation.QPSK: 2,
    Modulation.QAM8: 3,
    Modulation.QAM16: 4,
    Modulation.QAM32: 5,
    Modulation.QAM64: 6,
    Modulation.QAM128: 7,
    Modulation.QAM256: 8,
}

MODULATION_NAMES = {
    Modulation.QPSK: "QPSK",
    Modulation.QAM8: "8-QAM",
    Modulation.QAM16: "16-QAM",
    Modulation.QAM32: "32-QAM",
    Modulation.QAM64: "64-QAM",
    Modulation.QAM128: "128-QAM",
    Modulation.QAM256: "256-QAM",
}


# ==========================================================================
# Ranging Response -- RFIv2.0 Table 8-6
# ==========================================================================

class RngRspTLV(IntEnum):
    """TLVs inside a Ranging Response: the corrections the CMTS sends."""
    TIMING_ADJUST = 1        # signed 32-bit, units of 1/64 of a 6.25us tick
    POWER_ADJUST = 2         # signed 8-bit, 0.25 dB steps
    FREQUENCY_ADJUST = 3     # signed 16-bit, Hz
    TRANSMIT_EQ_ADJUST = 4
    RANGING_STATUS = 5
    DS_FREQ_OVERRIDE = 6
    US_CHANNEL_ID_OVERRIDE = 7
    TRANSMIT_EQ_SET = 9
    T4_TIMEOUT_MULTIPLIER = 13


class RangingStatus(IntEnum):
    """What the CMTS thinks of a modem's ranging so far."""
    CONTINUE = 1   # keep ranging, more adjustment needed
    ABORT = 2      # give up, re-initialise the MAC
    SUCCESS = 3    # ranging complete


#: One unit of RNG-RSP Timing Adjust: 1/64 of a 6.25 us timebase tick.
TIMING_ADJUST_UNIT_S = 6.25e-6 / 64.0   # 97.65625 ns


# ==========================================================================
# Registration -- RFIv2.0 Table 8-8 / 8-9
# ==========================================================================

class RegRspCode(IntEnum):
    """Why the CMTS accepted or refused a registration."""
    OK = 0
    AUTH_FAILURE = 1
    CLASS_OF_SERVICE_FAILURE = 2
    UNSPECIFIED_REJECT = 3


class ConfirmationCode(IntEnum):
    """RFIv2.0 Annex C.4 -- also used by DSA/DSC."""
    OKAY = 0
    REJECT_OTHER = 1
    REJECT_UNRECOGNIZED_CONFIGURATION = 2
    REJECT_TEMPORARY = 3
    REJECT_PERMANENT = 4
    REJECT_DUPLICATE_REF_ID = 5
    REJECT_CLASS_OF_SERVICE = 8
    REJECT_MAJOR_SERVICE_FLOW_ERROR = 9
    REJECT_AUTHENTICATION_FAILURE = 13


# ==========================================================================
# Configuration file / REG-REQ TLVs -- RFIv2.0 Annex C.1
# ==========================================================================

class CfgTLV(IntEnum):
    """Configuration settings: the config file's contents, echoed in REG-REQ."""
    PAD = 0
    DOWNSTREAM_FREQUENCY = 1
    UPSTREAM_CHANNEL_ID = 2
    NETWORK_ACCESS_CONTROL = 3
    CLASS_OF_SERVICE = 4            # DOCSIS 1.0 class of service (compound)
    MODEM_CAPABILITIES = 5          # compound
    CM_MIC = 6
    CMTS_MIC = 7
    VENDOR_ID = 8
    SW_UPGRADE_FILENAME = 9
    SNMP_WRITE_ACCESS = 10
    SNMP_MIB_OBJECT = 11
    MODEM_IP_ADDRESS = 12
    SERVICE_UNAVAILABLE = 13
    CPE_ETHERNET_MAC = 14
    BASELINE_PRIVACY_CFG = 17
    MAX_CPE = 18
    TFTP_SERVER_TIMESTAMP = 19
    TFTP_SERVER_ADDRESS = 20
    SW_UPGRADE_TFTP_SERVER = 21
    UPSTREAM_CLASSIFIER = 22        # compound
    DOWNSTREAM_CLASSIFIER = 23      # compound
    UPSTREAM_SERVICE_FLOW = 24      # compound
    DOWNSTREAM_SERVICE_FLOW = 25    # compound
    PAYLOAD_HEADER_SUPPRESSION = 26 # compound
    MAX_CLASSIFIERS = 28
    PRIVACY_ENABLE = 29
    AUTH_BLOCK = 30
    KEY_SEQUENCE_NUMBER = 31
    SUBSCRIBER_MGMT_CONTROL = 35
    SUBSCRIBER_MGMT_CPE_TABLE = 36
    SUBSCRIBER_MGMT_FILTER_GROUPS = 37
    SNMPV3_KICKSTART = 38
    SUBSCRIBER_MGMT_ENABLE = 39
    SNMPV3_NOTIFY_RECEIVER = 38
    ENABLE_20_MODE = 39
    TEST_MODE = 40
    DS_CHANNEL_LIST = 41
    MCAST_MAC_ADDRESS = 42
    VENDOR_SPECIFIC = 43
    SERVICE_FLOW_SID_CLUSTER = 44
    END_OF_DATA = 255


class ClassOfServiceTLV(IntEnum):
    """Sub-TLVs of CfgTLV.CLASS_OF_SERVICE (Annex C.1.1.4)."""
    CLASS_ID = 1
    MAX_DOWNSTREAM_RATE = 2         # bits/s
    MAX_UPSTREAM_RATE = 3           # bits/s
    UPSTREAM_PRIORITY = 4
    GUARANTEED_MIN_UPSTREAM_RATE = 5
    MAX_UPSTREAM_BURST = 6          # bytes
    PRIVACY_ENABLE = 7


class CapTLV(IntEnum):
    """Sub-TLVs of CfgTLV.MODEM_CAPABILITIES (Annex C.1.3.1).

    The numbering runs contiguously from 1; there is no gap at 9.  Getting
    this wrong shifts everything after it, which is exactly the sort of
    mistake that produces a modem the CMTS quietly mis-provisions.
    """
    CONCATENATION = 1
    DOCSIS_VERSION = 2
    FRAGMENTATION = 3
    PHS_SUPPORT = 4
    IGMP_SUPPORT = 5
    PRIVACY_SUPPORT = 6
    DOWNSTREAM_SAID_SUPPORT = 7
    UPSTREAM_SID_SUPPORT = 8
    OPTIONAL_FILTERING = 9              # 802.1P/802.1Q filtering
    TRANSMIT_EQ_TAPS_PER_SYMBOL = 10
    TRANSMIT_EQ_TAPS = 11
    DCC_SUPPORT = 12
    IP_FILTERS = 13
    LLC_FILTERS = 14
    EXPANDED_UNICAST_SID_SPACE = 15
    RANGING_HOLD_OFF_SUPPORT = 16
    L2VPN_CAPABILITY = 17
    L2VPN_ESAFE = 18
    DUT_FILTERING = 19
    #: DOCSIS 2.0 additions: how the CMTS learns the modem can actually use
    #: an A-TDMA channel wider than DOCSIS 1.x allows.
    UPSTREAM_FREQUENCY_RANGE = 20
    UPSTREAM_SYMBOL_RATES = 21          # bitmask, bit 5 == 5120 ksps
    SELECTABLE_ACTIVE_CODE_MODE_2 = 22


class UpstreamSymbolRate(IntEnum):
    """Bit positions in CapTLV.UPSTREAM_SYMBOL_RATES."""
    KSPS_160 = 0x01
    KSPS_320 = 0x02
    KSPS_640 = 0x04
    KSPS_1280 = 0x08
    KSPS_2560 = 0x10
    KSPS_5120 = 0x20     # DOCSIS 2.0 only

#: A DOCSIS 2.0 modem supports every rate up to and including 5120 ksps.
SYMBOL_RATES_DOCSIS_20 = 0x3F
#: DOCSIS 1.x tops out at 2560 ksps.
SYMBOL_RATES_DOCSIS_1X = 0x1F


class DocsisVersion(IntEnum):
    """Spec revision a modem claims in its Modem Capabilities."""
    V10 = 0
    V11 = 1
    V20 = 2
    V30 = 3


class SFTLV(IntEnum):
    """Service flow encodings, sub-TLVs of type 24/25 (Annex C.2.2)."""
    SERVICE_FLOW_REFERENCE = 1
    SERVICE_FLOW_IDENTIFIER = 2
    SERVICE_IDENTIFIER = 3            # upstream only
    SERVICE_CLASS_NAME = 4
    ERROR_ENCODINGS = 5
    QOS_PARAM_SET_TYPE = 6
    TRAFFIC_PRIORITY = 7
    MAX_SUSTAINED_TRAFFIC_RATE = 8    # bits/s
    MAX_TRAFFIC_BURST = 9             # bytes
    MIN_RESERVED_TRAFFIC_RATE = 10    # bits/s
    MIN_RESERVED_PACKET_SIZE = 11
    ACTIVE_QOS_TIMEOUT = 12
    ADMITTED_QOS_TIMEOUT = 13
    MAX_CONCATENATED_BURST = 14
    SCHEDULING_TYPE = 15
    REQUEST_TRANSMISSION_POLICY = 16
    NOMINAL_POLLING_INTERVAL = 17
    TOLERATED_POLL_JITTER = 18
    UNSOLICITED_GRANT_SIZE = 19
    NOMINAL_GRANT_INTERVAL = 20
    TOLERATED_GRANT_JITTER = 21
    GRANTS_PER_INTERVAL = 22
    IP_TOS_OVERWRITE = 23
    UNSOLICITED_GRANT_TIME_REFERENCE = 24
    TARGET_SAID = 25


class QoSParamSet(IntEnum):
    """Which QoS parameter sets a service flow encoding applies to."""
    PROVISIONED = 1
    ADMITTED = 2
    ACTIVE = 4
    ALL = 7


class SchedulingType(IntEnum):
    """Upstream scheduling discipline for a service flow."""
    UNDEFINED = 0
    BEST_EFFORT = 2
    NON_REALTIME_POLLING = 3
    REALTIME_POLLING = 4
    UGS_AD = 5
    UGS = 6


# ==========================================================================
# Timers -- RFIv2.0 Annex B
# ==========================================================================
#: Wait for a UCD after acquiring the downstream.
T1_UCD_WAIT = 5 * 2.0
#: Wait for a broadcast Initial Maintenance opportunity.
T2_INITIAL_MAINT_WAIT = 5 * 2.0
#: Wait for a RNG-RSP after transmitting a RNG-REQ.
T3_RNG_RSP_WAIT = 0.200
#: Wait for a unicast Station Maintenance opportunity before re-initialising.
T4_STATION_MAINT_WAIT = 30.0
#: Wait for a UCC-RSP.
T5_UCC_RSP_WAIT = 2.0
#: Wait for a REG-RSP after sending REG-REQ.
T6_REG_RSP_WAIT = 3.0
#: Wait for a DSA/DSC response.
T7_DSX_RSP_WAIT = 1.0
#: Wait for a DSA/DSC acknowledgement.
T8_DSX_ACK_WAIT = 0.300
#: Loss of downstream SYNC.
LOST_SYNC_TIMEOUT = 0.600

#: Maximum interval between SYNC messages (RFIv2.0 section 6.4.2).
SYNC_INTERVAL_MAX = 0.200
#: Maximum interval between UCD messages.
UCD_INTERVAL_MAX = 2.0
#: Number of consecutive T3 timeouts after which the modem gives up on a
#: channel and rescans (RFIv2.0 section 11.2.4).
RNG_RETRIES = 16
#: Number of Contention Ranging attempts before declaring the upstream unusable.
CONTENTION_RANGING_RETRIES = 16


# ==========================================================================
# MAC management message version numbers -- RFIv2.0 Table 6-17
# ==========================================================================
#: The `version` byte says which revision of the spec a reader needs in order
#: to parse the message: 1 for messages defined in DOCSIS 1.0, 2 for those
#: introduced in 1.1/2.0.  Getting this wrong is not harmless -- Wireshark
#: (and real equipment) will refuse to parse a MAP that is not version 1,
#: because DOCSIS 3.1 reused version 5 for a MAP with a different layout.
MGMT_MSG_VERSION: dict[int, int] = {
    MgmtType.SYNC: MGMT_VERSION_10,
    MgmtType.UCD: MGMT_VERSION_10,          # type 2 UCD: DOCSIS 1.x TDMA
    MgmtType.MAP: MGMT_VERSION_10,          # MAP stayed at version 1 until 3.1
    MgmtType.RNG_REQ: MGMT_VERSION_10,
    MgmtType.RNG_RSP: MGMT_VERSION_10,
    MgmtType.REG_REQ: MGMT_VERSION_11,      # carries 1.1+ service flow TLVs
    MgmtType.REG_RSP: MGMT_VERSION_11,
    MgmtType.REG_ACK: MGMT_VERSION_11,
    MgmtType.UCC_REQ: MGMT_VERSION_10,
    MgmtType.UCC_RSP: MGMT_VERSION_10,
    MgmtType.UCD2: MGMT_VERSION_11,         # type 29 UCD: introduced by 2.0
    MgmtType.INIT_RNG_REQ: MGMT_VERSION_11,
    MgmtType.UP_DIS: MGMT_VERSION_11,
    MgmtType.DSA_REQ: MGMT_VERSION_11,
    MgmtType.DSA_RSP: MGMT_VERSION_11,
    MgmtType.DSA_ACK: MGMT_VERSION_11,
    MgmtType.DSC_REQ: MGMT_VERSION_11,
    MgmtType.DSC_RSP: MGMT_VERSION_11,
    MgmtType.DSC_ACK: MGMT_VERSION_11,
    MgmtType.DSD_REQ: MGMT_VERSION_11,
    MgmtType.DSD_RSP: MGMT_VERSION_11,
    MgmtType.DCC_REQ: MGMT_VERSION_11,
    MgmtType.DCC_RSP: MGMT_VERSION_11,
    MgmtType.DCC_ACK: MGMT_VERSION_11,
    MgmtType.DCI_REQ: MGMT_VERSION_11,
    MgmtType.DCI_RSP: MGMT_VERSION_11,
    MgmtType.BPKM_REQ: MGMT_VERSION_10,
    MgmtType.BPKM_RSP: MGMT_VERSION_10,
}

#: Upstream and downstream channel IDs are numbered from 1.  Channel ID 0 in
#: an upstream context means "telephony return" in the pre-DOCSIS-1.1 world,
#: so using it makes decoders report something misleading.
FIRST_CHANNEL_ID = 1
