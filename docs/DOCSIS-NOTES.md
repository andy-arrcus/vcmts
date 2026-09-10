# How DOCSIS 2.0 brings a modem online

A guide to what this simulation implements and why each step exists. Section
references are to CM-SP-RFIv2.0, the DOCSIS 2.0 Radio Frequency Interface
specification. Everything below is observable in a run: the log line, CLI
command or Wireshark filter that shows it is given alongside.

---

## The shape of the problem

A cable plant is one wire shared by every subscriber. Downstream is easy: the
CMTS is the only transmitter, so it broadcasts a continuous 256-QAM stream and
each modem picks out the frames addressed to it. Upstream is the hard
direction, because hundreds of modems must share one channel without talking
over each other, and each of them is a different, unknown distance away.

DOCSIS solves it by making upstream time explicit. The CMTS divides the
upstream into **mini-slots** and publishes, in advance, exactly who may
transmit in which ones. A modem transmits only when granted, and only if it
has first learned how far away it is — because at 25 µs per mini-slot, a
38 µs propagation delay is more than a whole slot of error.

Three mechanisms follow from that, and they are the three worth watching:

1. **The timebase.** Every modem slaves its clock to a timestamp the CMTS
   broadcasts. That timestamp is always stale by one propagation delay.
2. **Ranging.** The CMTS measures how late a modem's burst actually arrives
   and tells it how much earlier to transmit next time.
3. **Contention resolution.** Before a modem has a grant it must contend, and
   collisions are resolved by randomised exponential back-off.

---

## Step 1 — Find a downstream

The modem sweeps the downstream spectrum looking for a DOCSIS carrier, locks
QAM and FEC, and starts reading MAC frames.

```
./docsis cli show cm            # "downstream 555.000 MHz locked"
```

The lab plant has one 6 MHz downstream at 555 MHz, 256-QAM, ITU-T J.83 Annex
B. That gives 38.81 Mbit/s of MPEG transport stream, and after the 4-byte
header in each 188-byte TS packet, **37.98 Mbit/s** of DOCSIS payload. The
plant uses that rate to work out how long each downstream frame occupies the
channel, which is why frames queue behind each other rather than arriving
instantaneously.

## Step 2 — Acquire SYNC and the timebase (§6.4.2, §8.3.1)

The CMTS transmits a **SYNC** message carrying a snapshot of its 32-bit
10.24 MHz master clock. That counter is the shared time reference for the
whole MAC domain:

| Unit | Value |
| --- | --- |
| master clock | 10.24 MHz, 32-bit, wraps every 419.43 s |
| timebase tick | 6.25 µs = 64 master clock counts |
| mini-slot | M ticks, M a power of two — here 4 ticks = 25 µs |
| ranging resolution | 1/64 tick = 97.65625 ns = one master clock count |

SYNC rides in a **Timing header** (FC_TYPE 3, FC_PARM 0) rather than the
ordinary MAC management header — the only message that does.

Here is the part that matters. The CMTS latches the timestamp as the first
symbol leaves. The modem knows the frame length and the downstream rate, so it
can subtract the serialisation time — but it has no way to know the
propagation delay. Its idea of "CMTS time now" is therefore permanently behind
by the one-way delay:

```
 0.080045 cm0 sync  first SYNC: timestamp 819200 -> timebase acquired, local
                    clock offset -38.341 us (the residual error is the one-way
                    propagation delay, still unknown to the modem)
```

−38.341 µs is exactly 10 km at 0.87c. Everything the modem transmits will
therefore arrive one *round* trip late, and removing that is ranging's whole
job.

If SYNC stops arriving for 600 ms the modem declares loss of sync and
re-initialises its MAC. `./docsis cli test cable loss 0 60` makes that happen.

## Step 3 — Obtain upstream parameters (§8.3.3)

The **UCD** describes an upstream channel: frequency, symbol rate, mini-slot
size, and a **burst descriptor** for each Interval Usage Code saying how a
burst in that kind of region is modulated and coded.

DOCSIS 2.0 has two UCD messages, and a 2.0 CMTS running a channel narrow
enough for both sends *both* for the same physical channel:

| Message | Type | Burst descriptors | Read by |
| --- | --- | --- | --- |
| UCD | 2 | type 4 — IUCs 1–6 | DOCSIS 1.x and 2.0 modems |
| Type 29 UCD | 29 | type 5 — adds IUCs 9–11, interleaver, preamble type, S-CDMA | DOCSIS 2.0 only |

```
./docsis cli show cable ucd
./docsis pcap --filter 'docsis_mgmt.type in {2,29}'
```

A DOCSIS 1.1 modem cannot parse a type-29 UCD, so it uses the type-2 one and
never learns the advanced-PHY IUCs exist. A 2.0 modem holds out for the
type-29 UCD so it can use them. `--scenario mixed` runs both modems on one
channel and shows each taking the view it understands.

A 6.4 MHz channel runs at 5120 ksym/s, above the DOCSIS 1.x maximum of
2560 ksym/s, so no type-2 UCD can describe it at all — such a channel is
invisible to a 1.x modem. `--scenario two-upstream` adds one.

**Interval Usage Codes** name the kinds of upstream region:

| IUC | Usage | Notes |
| --- | --- | --- |
| 1 | Request | contention region for bandwidth requests |
| 3 | Initial Maintenance | broadcast; where unranged modems range |
| 4 | Station Maintenance | unicast; periodic ranging |
| 5 / 6 | Short / Long Data Grant | DOCSIS 1.x data |
| 9 / 10 | Advanced PHY Short / Long Data Grant | DOCSIS 2.0 A-TDMA data |
| 11 | Advanced PHY Unsolicited Grant | 2.0 UGS |
| 7 | Null IE | terminates the last grant in a MAP |

The lab's modulation profile keeps the maintenance and request IUCs at QPSK,
because they have to work for a modem that has not been equalised yet, and
puts the data grants at 16-QAM (1.x) or 64-QAM (2.0):

```
./docsis cli show cable modulation-profile
```

A mini-slot is a slice of *time*, so its byte capacity depends entirely on
which profile the grant was issued under — 16 bytes at QPSK, 32 at 16-QAM,
48 at 64-QAM, for the same 25 µs.

If no usable UCD arrives within **T1** (10 s) the modem re-initialises.

## Step 4 — Ranging (§8.3.5, §8.3.6, §11.2.4)

### Initial ranging

The modem waits for a broadcast **Initial Maintenance** region in a MAP. That
region is sized to hold one ranging burst *plus the worst-case round trip of
the plant*, because a modem that has never ranged transmits with no correction
at all and its burst can land anywhere in that window. Which is why the whole
region counts as a **single transmit opportunity**, however many mini-slots
long it is:

```
./docsis cli show cable timing
  Initial Maintenance : every 200 ms, 13 mini-slots (8 of that is round-trip
                        headroom for a 25 km plant)
```

Before transmitting, the modem draws a random number from the ranging back-off
window the MAP advertises and defers that many opportunities (§8.2.6). Then it
sends **RNG-REQ** with **SID 0** — it has no identity yet — and starts **T3**
(200 ms).

### The measurement

The CMTS knows which mini-slot it granted, so it knows when the burst's first
symbol should have arrived. Anything later is uncorrected round trip:

```
 0.612208 cmts ranging  initial ranging from 00:1d:cf:11:22:33 in the broadcast
                        Initial Maintenance region -- assigned temporary SID 1
 0.612208 cmts ranging  RNG-RSP sid=1: burst arrived +76.859 us from its
                        mini-slot boundary (+787 x 97.66 ns units), rx power
                        +31.00 dBmV vs target +0.00 (-31.00 dB), status CONTINUE
```

**RNG-RSP** carries a temporary SID and three corrections as TLVs: **Timing
Adjust** (signed 32-bit, in 1/64-tick units), **Power Level Adjust** (signed
8-bit, 0.25 dB steps) and **Offset Frequency Adjust** (signed 16-bit, Hz). The
modem adds the timing adjust to its ranging offset and transmits that much
earlier from then on:

```
 0.612256 cm0 ranging  RNG-RSP: timing adjust +787 units -> ranging offset
                        0 -> 787 (76.86 us, i.e. transmit this much earlier)
```

### Convergence

The CMTS then polls the modem with **unicast Station Maintenance** regions —
fast (every 20 ms) while it is still ranging, slowly (every 5 s) once it is
online — and repeats the measurement until the burst lands on its boundary.
Then it sends ranging status **SUCCESS**:

```
 0.616115 cmts ranging  RNG-RSP sid=1: burst arrived -0.290 us from its
                        mini-slot boundary (-3 units), status SUCCESS
 0.616115 cmts ranging  ranging complete: total timing offset 784 units
                        (76.56 us round trip)
```

784 units × 97.65625 ns = 76.56 µs, which is a 10 km round trip at 0.87c. The
number the modem ends up with *is* the distance to the CMTS:

| Distance | Round trip | Ranging offset |
| --- | --- | --- |
| 1 km | 7.67 µs | 79 units |
| 10 km | 76.68 µs | 785 units |
| 25 km | 191.70 µs | 1963 units |
| 80 km | 613.45 µs | 6282 units |

Ranging completes on *timing*. Receive level only has to be inside the window
the receiver can demodulate; trimming it to the exact target carries on for the
modem's whole life through station maintenance, which is why even a successful
RNG-RSP still carries a power adjustment. A modem on a short drop can be pinned
at its +8 dBmV floor (the real DOCSIS minimum) and still come online a few dB
hot — `show cable modem phy` reports it.

### When it fails

Two failure modes are worth running:

- `--scenario far` puts a modem 60 km out on a plant engineered for 25 km. Its
  ranging burst arrives after the end of the Initial Maintenance region, runs
  outside the mini-slots the receiver was listening in, and is simply not
  received. The modem sees only T3 timeouts. This is the real reason DOCSIS has
  a maximum plant reach.
- `--scenario long-haul` sizes the plant for 100 km and the same distance
  works fine, with a much larger maintenance region and a 6279-unit offset.

Sixteen consecutive T3 timeouts and the modem abandons the channel. If a
**Station Maintenance** opportunity does not arrive for **T4** (30 s), an
online modem re-initialises its MAC — that is how a modem notices the CMTS has
forgotten it.

## Step 5 — MAPs, requests and grants (§8.3.4, §8.2.5, §8.2.6)

A **MAP** describes a contiguous span of mini-slots as a list of 32-bit
information elements, each packing **SID (14 bits) | IUC (4) | offset (14)**.
A grant runs from its own offset to the offset of the *next* element, which is
why a MAP always ends with a Null IE:

```
./docsis cli show cable map

  Alloc Start Time 459201 (t=11.480025s), Ack Time 459119, span 160 mini-slots
SID        IUC  Usage    Offset  Mini-slot  Length  Capacity
broadcast  1    Request  0       459201     6       86 bytes
0          7    Null IE  6       459207     -
```

Each MAP is transmitted ahead of the time it describes — 2 ms here — because
the modem has to receive it, apply its ranging offset, and still hit the first
mini-slot.

To send anything, a modem must first ask. It transmits a **Request frame**: a
bare six-byte MAC header (FC_TYPE 3, FC_PARM 2) where MAC_PARM is a mini-slot
count and the LEN/SID field holds a SID instead of a length. That request goes
in the contention **Request** region, where it can collide with other modems'
requests.

```
./docsis pcap --filter 'docsis.fcparm == 2'
```

**Contention resolution** (§8.2.6) is how collisions get sorted out. The modem
draws a random number from a back-off window, counts that many transmit
opportunities going past, and only then transmits. A request counts as lost
once the MAP's **Ack Time** has passed the mini-slot it went out in and no
grant has appeared — at which point the window doubles:

```
 1.062049 cm0 bandwidth  request sent in mini-slot 42401 was not acknowledged
                         by ack-time 42480 and this MAP holds no grant for
                         sid 1: assuming collision, back-off window 1 -> 2
```

`--scenario crowd` starts eight modems at once and produces around thirty
collisions on the way to getting all eight online.

A request the CMTS cannot satisfy yet gets a **zero-length grant**, which means
"heard you, wait" and stops the modem re-requesting or timing out.

One subtlety the simulation reproduces: a request is denominated in mini-slots,
but how many bytes a mini-slot holds depends on the profile the CMTS grants
under — and the modem cannot know that choice in advance. So it sizes against
the least efficient profile it might be handed, and narrows once it sees what
the CMTS actually grants:

```
 1.054050 cm0 bandwidth  CMTS switched our data grants from IUC 6 to IUC 10
                         (32 -> 48 bytes per mini-slot)
```

Which raises the question of how the CMTS decided.

## Step 6 — Establish IP connectivity (DHCP)

The modem's first data transmission is a DHCPDISCOVER, and it has to go
through the full request/grant cycle to get out.

The CMTS is a **DHCP relay**. It stamps `giaddr` with the address of the cable
interface the request came in on, and *that* is what selects the address pool:

```
 0.624263 cmts dhcp  relaying DISCOVER from cable modem 00:1d:cf:11:22:33
                     (sid 1) to helper 10.30.0.2, giaddr=10.10.0.1 (giaddr is
                     what selects the address pool)
```

A cable modem's DHCP gets `giaddr` 10.10.0.1 and an address from the modem
pool; a CPE behind the same modem gets `giaddr` 10.20.0.1 and an address from
the subscriber pool. One server, two populations, neither aware of the other.

```
./docsis cli show cable dhcp
```

DOCSIS leans on three DHCP fields ordinary clients ignore: `siaddr` is the TFTP
server, `file` is the configuration file name, and option 4 is the
Time-of-Day server.

And **option 60**, the vendor class identifier, is the answer to how the CMTS
knew the modem was DOCSIS 2.0. A cable modem sends `"docsis2.0:"` followed by
its capability TLVs as ASCII hex. The relay sees it go past:

```
 0.624396 cmts dhcp  00:1d:cf:11:22:33 identifies as DOCSIS 2.0 in its DHCP
                     vendor class; advanced-PHY grants (IUC 9/10) enabled
```

Before that point the CMTS has no evidence about the modem's capabilities, so
it grants the 1.x-compatible IUC 5/6 that any modem on the channel can
demodulate. Afterwards it switches to IUC 9/10. Registration later confirms it
from the Modem Capabilities in REG-REQ.

## Step 7 — Time of day (RFC 868)

A single UDP datagram to port 37; the reply is a 32-bit count of seconds since
1900. A DOCSIS modem must have time of day before it registers — it needs it to
timestamp its own event log, and BPI+ needs it to check certificate validity.
The reply comes back to the source port the request went out from, not to
port 37.

## Step 8 — Transfer operational parameters (TFTP)

The modem fetches the file DHCP named, over ordinary TFTP in 512-byte blocks.
The file is a stream of configuration setting TLVs ending with two MD5 digests
and an end-of-data marker:

```
./docsis cfg decode configs/cm-default.cfg
```

| TLV | Setting |
| --- | --- |
| 3 | Network Access Control — 0 means registers but forwards nothing |
| 24 / 25 | Upstream / Downstream Service Flow (nested: rate, priority, scheduling) |
| 18 | Maximum Number of CPEs |
| 29 | Privacy Enable — 0 skips BPI+ entirely |
| 6 | **CM MIC** |
| 7 | **CMTS MIC** |
| 255 | End of Data |

The **CM MIC** is an unkeyed MD5 over every setting except the two MIC
settings. It detects a corrupted download, and the modem checks it before
going any further.

The **CMTS MIC** is an MD5 over a *specific ordered subset* of the settings
with a **shared secret** appended — a secret known only to the provisioning
system and the CMTS. This is the whole security model of DOCSIS 1.x/2.0
provisioning: a modem cannot hand itself a better service tier, because it
cannot recompute a digest salted with a secret it has never seen.

```
./docsis cfg forge configs/cm-default.cfg   # rewrite the rate and watch it fail
./docsis run --scenario bad-secret          # watch a CMTS reject it
```

The ordering of that subset is normative. Two implementations that disagree
about it fail to authenticate each other even with the same shared secret.

## Step 9 — Register (§8.3.7, §8.3.8, §8.3.14)

The modem sends **REG-REQ** containing every configuration setting it received,
verbatim and in order, both MICs included, plus one thing that was never in the
file: **Modem Capabilities** (TLV 5). None of the TLVs the modem adds are in
the CMTS MIC's ordered subset, which is what lets the CMTS recompute the digest
over what it received and get the same answer.

Two capability sub-TLVs decide whether the modem gets DOCSIS 2.0 treatment:

- **5.2 DOCSIS Version** — 2 means 2.0, and therefore that advanced-PHY grants
  are legal for this modem.
- **5.21 Upstream Symbol Rates** — a bitmask of what the transmitter can
  actually produce. Bit 5, 5120 ksym/s, exists only on a 2.0 modem, and it is
  what makes a 6.4 MHz A-TDMA channel usable.

The sub-TLV numbering runs contiguously from 1 with no gap at 9. Getting that
wrong shifts every field after it — see [WIRESHARK.md](WIRESHARK.md), where it
did.

The CMTS then:

1. verifies both MICs — failure is `reject(m)` and REG-RSP authentication
   failure;
2. admits or refuses the requested service flows — refusal is `reject(c)`
   (`--scenario over-rate`);
3. assigns the **SFIDs**, and a **SID** for each upstream flow. The config file
   carries only *references*, which is what lets one file be handed to every
   modem;
4. answers **REG-RSP** with those assignments.

The modem replies **REG-ACK** — and is not in service until that
acknowledgement has actually been transmitted, since it still needs a grant to
send it and on a noisy upstream that burst can be lost like any other.

```
./docsis cli show cable qos service-flow
```

## Step 10 — Operational

With Privacy Enable 0 there is no BPI+ exchange, so the modem goes straight to
forwarding. It bridges its CPEs' traffic upstream inside Packet PDUs, keeps
answering Station Maintenance every 5 s, and stays online until something
breaks.

## Moving a modem: Upstream Channel Change (§8.3.9)

With more than one upstream configured, the CMTS can move a modem with a
**UCC-REQ**. The modem acknowledges with **UCC-RSP** on the *old* channel
before leaving it, then waits for the new channel's UCD and ranges there from
scratch — timing is a property of the channel, so the ranging offset does not
carry over.

What does carry over is everything above the MAC: the SID, the service flows
and the IP address all survive, and the modem does not go near DHCP again.

```sh
./docsis up --scenario two-upstream
# in another terminal:
./docsis cli show cable modem          # both modems settle on US1
./docsis cli test cable ucc cm20 2     # move the 2.0 modem to the 6.4 MHz channel
./docsis cli show cable modem          # cm20 is now C1/0/U2, still online
```

```
 9.592117 cm20 ranging  ranging complete: SID 2, offset 787 units
 9.592117 cm20 ucc      back in service on US2 with the same SID and service
                        flows -- a channel change re-ranges, it does not
                        re-register
```

With several usable upstreams a modem takes the lowest-numbered one and stays
there; only a UCC-REQ or a MAC re-initialisation moves it. The 1.1 modem in
that scenario has no choice at all — US2 runs at 5120 ksym/s, so it gets no
type-2 UCD and the channel does not exist as far as that modem is concerned.

---

## The state names

The CMTS cannot see inside a modem, so it infers how far the modem got from
what it has seen go past. That is what makes these states the most useful
diagnostic in DOCSIS — each one says which *step* failed, and `init(t)` versus
`init(o)` even says which provisioning server to go and look at.

| CMTS state | Means | If it is stuck here |
| --- | --- | --- |
| `offline` | never heard from | wrong downstream, or out of plant reach |
| `init(r1)` | first RNG-REQ received, temporary SID assigned | — |
| `init(r2)` | ranging, corrections still being applied | level or timing will not converge |
| `init(rc)` | ranging complete | — |
| `init(d)` | DHCP DISCOVER seen | DHCP server or relay |
| `init(i)` | IP address assigned | — |
| `init(t)` | asking for time of day | Time-of-Day server |
| `init(o)` | fetching the config file | TFTP server, or a missing file |
| `reject(m)` | MIC check failed | wrong shared secret, or a tampered file |
| `reject(c)` | service flow not admitted | config file asks for too much |
| `online(d)` | registered, network access disabled | TLV 3 is 0 in the config file |
| `online` | registered and forwarding | — |

```
./docsis cli show cable modem states
./docsis cli show cable modem <mac>     # includes the full state history
```

## The timers

| Timer | Value | Waiting for |
| --- | --- | --- |
| lost sync | 600 ms | a SYNC message |
| T1 | 10 s | a usable UCD |
| T2 | 10 s | a broadcast Initial Maintenance opportunity |
| T3 | 200 ms | a RNG-RSP |
| T4 | 30 s | a unicast Station Maintenance opportunity |
| T6 | 3 s | a REG-RSP |

Every one of them can be made to fire: `test cable loss`, `test cable noise`,
`clear cable modem <mac> reset`, or the `far` and `noisy` scenarios.

## The MAC frame

```
+----+----------+-----------+----------+-----+---------+
| FC | MAC_PARM |  LEN/SID  |   EHDR   | HCS | payload |
+----+----------+-----------+----------+-----+---------+
  1       1           2       0..240      2

FC:  bits 7..6  FC_TYPE   0 packet PDU, 1 ATM, 2 isolation, 3 MAC-specific
     bits 5..1  FC_PARM   for MAC-specific: 0 timing, 1 management,
                          2 request, 3 fragmentation, 4 queue-depth request,
                          0x1C concatenation
     bit  0     EHDR_ON
```

Two details are easy to get wrong and both are tested:

- **LEN counts the extended header as well as the payload** (Table 6-3), so
  when an EHDR is present it is counted twice over — once via MAC_PARM and
  again inside LEN.
- **A Packet PDU carries the whole Ethernet frame including its FCS**, so LEN
  is four bytes longer than the Ethernet header plus data. Wireshark shows
  those four bytes as a trailer, which is exactly what a real DOCSIS capture
  looks like.

The **HCS** is a CRC-16 over the header bytes preceding it. The spec names the
CRC-CCITT polynomial with an all-ones preset, which describes a family rather
than one algorithm; the concrete answer is CRC-16/X-25 — the HDLC FCS-16 —
transmitted least-significant byte first. How that was pinned down is in
[WIRESHARK.md](WIRESHARK.md).

A MAC management message adds a 20-byte header inside the frame: destination
and source MAC, an 802.2 LLC length counting from DSAP to the end of the
payload, DSAP and SSAP both zero, control 0x03, then version, type and a
reserved byte. The **version** byte says which spec revision a reader needs:
1 for DOCSIS 1.0 messages, 2 for those added in 1.1/2.0. A MAP must say
version 1 — DOCSIS 3.1 reused version 5 for a differently shaped MAP, so
anything else stops decoders parsing the body at all.
