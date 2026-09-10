# Verifying the wire format against Wireshark

Wireshark's DOCSIS dissector is an independently written implementation of the
same specification — 1291 fields across 40-odd DOCSIS protocols. That makes it
the best available check that the bytes in this repository are actually DOCSIS
and not merely self-consistent with themselves.

`tools/probe_wireshark.py` writes one frame per candidate encoding and reports
what the dissector made of each. `tests/test_wireshark.py` keeps it honest,
asserting on every run that the capture still dissects with no complaints.

```sh
python3 tools/probe_wireshark.py            # the probe
python3 -m pytest tests/test_wireshark.py   # the regression test
./docsis pcap                                # summarise any capture
```

The dissector found two real bugs in this code, recorded below alongside the
questions it settled.

---

## Q1: which CRC-16 is the MAC header HCS?

CM-SP-RFIv2.0 §6.2.1.6 says the HCS uses "the CRC-CCITT polynomial
x¹⁶ + x¹² + x⁵ + 1" with an all-ones preset. That names a *family*: reflected
or not, complemented or not, and either byte order on the wire — eight
plausible algorithms, all matching the prose.

The probe emitted a SYNC frame under each of six named variants. Wireshark
rejected all six, but its expert info said what it wanted:

```
1  hcs:ccitt-false  BAD  !! Bad header check sequence [should be 0xce5b]
2  hcs:genibus      BAD  !! Bad header check sequence [should be 0xce5b]
3  hcs:x25          BAD  !! Bad header check sequence [should be 0xce5b]
...
```

Five (header, expected) pairs harvested that way were enough to brute-force
the full parameter space — every polynomial, both initial values, both
reflection settings, both final XORs, both byte orders — in three seconds. One
combination fits all five:

```
poly=0x1021 init=0xffff refin=True refout=True xorout=0xffff byteswap=True
```

That is **CRC-16/X-25**: the FCS-16 that HDLC and PPP use, transmitted
**least-significant byte first**. The polynomial had been right all along; the
byte order was wrong. It is the detail that catches people out, because the
algorithm can be correct and the frame still fails validation.

`docsislab/util/crc.py` keeps all six variants so the probe still works, and
`tests/test_lowlevel.py` pins the five expected values.

## Q2: does a Packet PDU's LEN include the Ethernet FCS?

Yes. RFIv2.0 Table 6-3 defines LEN as the extended header length plus the
number of bytes after the HCS, and a Packet PDU carries the complete Ethernet
frame — destination, source, type, data and CRC.

Wireshark hands the payload to `eth_withoutfcs`, so those four bytes appear as
`Trailer: b42aae15` rather than as an FCS:

```
Ethernet II, Src: Commscope_11:22:33, Dst: Broadcast
    Trailer: b42aae15
```

Worth knowing, because it means a real DOCSIS capture looks the same way. The
simulation keeps the FCS — spec fidelity wins over cosmetics — and computes it
for real, so `eth_fcs(payload[:-4])` matches the trailer.

## Q3: what version byte does each management message need?

Wireshark accepted a type-2 UCD, a type-29 UCD, RNG-REQ/RSP and REG-REQ/RSP
under every version from 1 to 5. MAPs were different:

| MAP version | Dissection |
| --- | --- |
| 1 | `Map Message: Version: 1, Channel ID = 1, UCD Count = 1, # IE's...` |
| 2, 3, 4 | `Data (32 bytes)` — body not parsed |
| 5 | parsed, as a DOCSIS 3.1 MAP |

DOCSIS 3.1 reused version 5 for a MAP with a different layout, and Wireshark
registers dissectors only for 1 and 5. **A DOCSIS 2.0 MAP must say version 1.**

`MGMT_MSG_VERSION` in `docsislab/docsis/consts.py` now holds the whole table so
no call site has to remember it, and `frames.encode_mgmt()` is the only place
that stamps the byte.

## Q4: upstream channel ID 0

Legal, but Wireshark renders channel 0 as `Channel ID = 0 (Telephony Return)` —
a pre-DOCSIS-1.1 special case. Real channel IDs start at 1, so the simulation
numbers from 1 and the label goes away.

## Bug 1 — modem capability sub-TLV numbering

The dissector flagged a REG-REQ:

```
5 Modem Capabilities Type (Length = 33)
    .11 # Xmit Equalizer Taps: 1
    .12 DCC Support: On
    [Expert Info (Error/Malformed): Wrong TLV length: 1]
```

The values were landing in the wrong fields. Wireshark's table shows why:

| Sub-TLV | Correct meaning | What this code had |
| --- | --- | --- |
| 9 | 802.1P/802.1Q Filtering Support | *(gap)* |
| 10 | Transmit Equalizer Taps per Symbol | Optional Filtering |
| 11 | Number of Transmit Equalizer Taps | Taps per Symbol |
| 12 | DCC Support | Number of Taps |
| 13 | IP Filters Support | DCC Support |

`CapTLV` had left a gap at 9, shifting every field after it by one. The
capability numbering runs contiguously from 1. Fixed, and
`test_modem_capabilities_numbering` pins it.

Two DOCSIS 2.0 capabilities that the dissector's table also revealed are now
sent: **20 Upstream Frequency Range** and **21 Upstream Symbol Rates**, a
bitmask whose bit 5 (5120 ksym/s) exists only on a 2.0 transmitter. Note that
21 is a **single byte** — encoding it as 16-bit made Wireshark read only the
high half and report every rate unsupported.

## Bug 2 — the DHCP vendor class identifier

Every DHCPDISCOVER and DHCPREQUEST from the modem was malformed:

```
Option: (60) Vendor class identifier
    Length: 13
    Vendor class identifier: docsis2.0:vcm
[Malformed Packet: DHCP/BOOTP]
```

Bisecting the options showed option 60 alone was responsible, and that
`docsis1.0:` was fine while `docsis2.0:` was not. Wireshark's DHCP dissector
special-cases a `docsis` vendor class from 2.0 onwards and tries to parse
**modem capability TLVs, ASCII-hex encoded, after the colon** — which is what a
real DOCSIS 2.0 modem actually sends, and what lets a provisioning system
identify a modem before it has registered.

Trying the plausible framings settled the encoding:

| Option 60 value | Result |
| --- | --- |
| `docsis2.0:` | malformed |
| `docsis2.0:vcm` | malformed |
| `docsis2.0:` + hex(TLVs) | **parses; capabilities decoded** |
| `docsis2.0:` + hex(len + TLVs) | malformed |

So the value is the version string, a colon, and the capability TLVs as ASCII
hex with nothing in between. `cfgfile.vendor_class_identifier()` builds it, and
Wireshark now decodes it:

```
Vendor class identifier: docsis2.0:010101020102030101...
    0x03: Fragmentation Support = Supported
    0x06: Privacy Support = BPI Plus Support
    0x07: Downstream SAID Support = 4
    0x0c: DCC Support = Supported
    0x15: Upstream Symbol Rate Support
        ..1. .... = 5120 ksps symbol rate: Supported
```

Fixing it also made the CMTS more realistic: it now learns the modem's DOCSIS
version from the relayed option 60, which is how it decides whether
advanced-PHY grants are allowed — earlier than REG-REQ, and visible in the log.

---

## Reading a capture

Every run writes `captures/docsis.pcapng` with four interfaces, all on one
timeline. DLT 143 carries no direction bit, so the interface name is what
distinguishes a CMTS transmission from a modem's burst.

| Interface | Link type | Carries |
| --- | --- | --- |
| `docsis-ds` | 143 DOCSIS | CMTS transmit |
| `docsis-us` | 143 DOCSIS | cable modem transmit |
| `cmts-nsi` | 1 Ethernet | CMTS network side |
| `cpe` | 1 Ethernet | CPE LAN behind the modem |

Every packet carries an `opt_comment` describing what the simulation was doing.
Wireshark shows them in the packet detail and the comment column; `tshark`
reads them as `frame.comment`.

### Filters

```
docsis_mgmt.type not in {1,3}     everything except SYNC and MAP chatter
docsis_mgmt.type in {4,5}        ranging only
docsis_mgmt.type in {6,7,14}     registration only
docsis_mgmt.type in {2,29}       both UCD views of the same channel
docsis.fcparm == 2               bandwidth Request frames
docsis_map.ie                    MAP information elements
docsis_rngrsp.timingadj          every timing correction the CMTS issued
docsis_tlv.map.docsver           the DOCSIS version in REG-REQ
dhcp || tftp || time             the provisioning exchange
docsis && dhcp                   DHCP seen inside the DOCSIS MAC layer
frame.interface_name == "docsis-us"
docsis.hcs.status != 1           any bad header check sequence (should be none)
_ws.expert.severity > 1048576    any dissector complaint (should be none)
```

The last two are what `tests/test_wireshark.py` asserts on. `1048576` is the
severity of a pcapng comment, so anything above it is a real complaint.

### Useful one-liners

```sh
# the whole management exchange as a timeline
tshark -r captures/docsis.pcapng -Y 'docsis_mgmt && docsis_mgmt.type not in {1,3}' \
       -T fields -e frame.time_relative -e frame.interface_name -e _ws.col.info

# ranging converging, correction by correction
tshark -r captures/docsis.pcapng -Y docsis_rngrsp.timingadj \
       -T fields -e frame.time_relative -e docsis_rngrsp.sid \
       -e docsis_rngrsp.timingadj -e docsis_rngrsp.rng_stat

# what the simulation was thinking, per frame
tshark -r captures/docsis.pcapng -Y 'frame.comment' \
       -T fields -e frame.number -e frame.comment
```
