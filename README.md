# docsislab — a virtual DOCSIS 2.0 CMTS and cable modem

A CMTS and a cable modem that talk to each other in real DOCSIS 2.0 bytes over
a simulated HFC plant, built so you can watch a modem come online and take
apart every step of how it got there.

```
$ ./docsis run
 0.050000 cm0   state    ds-scan: scanning the downstream spectrum for a DOCSIS carrier
 0.070000 cm0   scan     downstream lock on 555.000 MHz: DS1 555.000 MHz 256-QAM Annex B
 0.080045 cm0   sync     first SYNC: timestamp 819200 -> timebase acquired, local clock
                         offset -38.341 us (the residual error is the one-way propagation
                         delay, still unknown to the modem)
 0.501119 cm0   ucd      upstream parameters from type 29 (DOCSIS 2.0) UCD: US1 30.000 MHz
                         2560 ksym/s, mini-slot 4 ticks (25.00 us), IUCs [1,3,4,5,6,9,10]
 0.610050 cm0   ranging  transmitting initial RNG-REQ with SID 0 in the Initial Maintenance
                         region at mini-slot 24481
 0.612208 cmts  ranging  RNG-RSP sid=1: burst arrived +76.859 us from its mini-slot boundary
                         (+787 x 97.66 ns units), rx power +31.00 dBmV vs target +0.00
 0.616115 cmts  ranging  00:1d:cf:11:22:33 sid=1 ranging complete: total timing offset
                         784 units (76.56 us round trip)
 0.632480 cm0   dhcp     DHCPACK: ip 10.10.0.10/255.255.255.0 gw 10.10.0.1, tftp 10.30.0.2,
                         config file 'cm-default.cfg'
 0.648271 cm0   config   CM MIC verifies; 9 settings
 0.660212 cm0   online   cm0 is ONLINE: ip 10.10.0.10, sid 1, ranging offset 784 units
```

## What is real and what is modelled

**Real, byte for byte.** Every frame that crosses the plant is an actual DOCSIS
MAC frame: FC/MAC_PARM/LEN-SID/EHDR/HCS header, MAC management messages with
their 802.2 LLC framing, UCD burst descriptors, MAP information elements
bit-packed as SID(14)/IUC(4)/offset(14), RNG-REQ/RSP TLVs, REG-REQ echoing the
configuration file, the binary config file with its two MD5 MICs, and real
DHCP, RFC 868 Time-of-Day and TFTP inside DOCSIS Packet PDUs. The wire format
is checked against Wireshark's independently written DOCSIS dissector — see
[docs/WIRESHARK.md](docs/WIRESHARK.md), which also records the two bugs that
found in this code.

**Real timing.** A 10.24 MHz master clock, 6.25 µs timebase ticks, mini-slots,
MAPs transmitted ahead of the time they describe, per-modem propagation delay,
and the T1/T2/T3/T4/T6 protocol timers. The simulation runs on a discrete-event
clock, so a 25 µs mini-slot boundary and a 97.65625 ns ranging correction are
exact rather than approximated by OS timers.

**Modelled, not implemented.** The PHY. There are no QAM symbols, no
Reed-Solomon codewords and no I/Q samples. Instead the plant models everything
the MAC layer can observe about the PHY: how long a burst occupies the channel
(from symbol rate, modulation order, FEC overhead, preamble and guard time),
when it arrives, at what level, and whether it collided with another burst.
That is enough to make ranging, contention resolution and the request/grant
loop behave for real.

## Getting started

Python 3.11+ and nothing else. Wireshark is optional but strongly recommended.

```sh
./docsis doctor                 # check the environment, run a self-test
./docsis run                    # headless: bring a modem online and report
./docsis up                     # run in real time, with a control socket
```

With a lab running, attach to it from other terminals:

```sh
./docsis cli                    # a CMTS-style shell
./docsis dash                   # a live dashboard
```

The dashboard shows the modem stepping through DOCSIS initialisation on the
left, the CMTS's view on the right, and a live event log below; `1`–`4` change
the time scale, `space` pauses, `q` quits.

## Looking at the capture

Every run writes `captures/docsis.pcapng` with four interfaces, so one file
holds the DOCSIS downstream, the modem's upstream bursts, the CMTS network side
and the CPE LAN on a single timeline:

```sh
open captures/docsis.pcapng     # Wireshark dissects it natively (DLT 143)
./docsis pcap                   # summary, message list, filter recipes
```

Each packet carries a comment saying what the simulation was doing at that
moment — "initial RNG-REQ (SID 0), attempt 1, ranging offset 0 units — the
burst will arrive late by the round trip" — which turns the capture from
correct into readable. Wireshark shows them in the packet detail and in the
comment column.

Filters worth knowing:

| Filter | Shows |
| --- | --- |
| `docsis_mgmt.type not in {1,3}` | everything except the SYNC and MAP chatter |
| `docsis_mgmt.type in {4,5}` | ranging only |
| `docsis_mgmt.type in {2,29}` | both UCD flavours for the same channel |
| `docsis.fcparm == 2` | bandwidth Request frames |
| `dhcp \|\| tftp \|\| time` | the provisioning exchange |
| `frame.interface_name == "docsis-us"` | upstream only |

## Scenarios

The interesting parts of DOCSIS are mostly contention and failure, which one
healthy modem never shows you.

```sh
./docsis scenarios
./docsis up --scenario crowd
```

| Scenario | What it demonstrates |
| --- | --- |
| `default` | one 2.0 modem; ranging converging, then grants moving to advanced PHY |
| `mixed` | a 1.1 and a 2.0 modem on one channel, each reading its own UCD |
| `two-upstream` | a 6.4 MHz A-TDMA channel that DOCSIS 1.x cannot describe at all |
| `crowd` | eight modems powering up together: collisions and back-off |
| `noisy` | 25% upstream burst loss: T3 timeouts, retries, level creep |
| `far` | a modem past the plant's engineered reach — ranging bursts miss their region |
| `long-haul` | a 100 km plant: a 6279-unit ranging offset, and a bigger maintenance region |
| `bad-secret` | config files signed with the wrong secret: `reject(m)` |
| `no-access` | network access disabled: registers, forwards nothing, `online(d)` |
| `over-rate` | a service flow the CMTS will not admit: `reject(c)` |

Things worth doing to a running lab:

```sh
./docsis cli test cable ucc cm0 2        # move a modem to another upstream
./docsis cli test cable noise 300        # a 300 ms ingress burst
./docsis cli test cable loss 25          # 25% upstream burst loss
./docsis cli clear cable modem cm0 reset # force a full re-initialisation
./docsis cli debug cable mac-messages on # log every SYNC and MAP
```

## The data plane

Once the modem is online it forwards traffic. By default a simulated CPE DHCPs
through the modem — landing in a different address pool from the modem itself,
because the CMTS relays with a different `giaddr` — and can ping:

```
cmts# ping 10.30.0.2
cpe0: 17 bytes from 10.30.0.2: seq=1 time=6.248 ms (through the DOCSIS upstream and back)
```

The 6 ms is not propagation — it is the request/grant round trip, which is what
dominates DOCSIS upstream latency.

To carry your Mac's own traffic through the virtual plant, `--cpe utun` creates
a real `utun` interface and routes the simulated networks down it. That needs
root:

```sh
sudo ./docsis up --cpe utun
# then, from another terminal:
ping 10.20.0.1        # the CMTS cable interface, via the virtual modem
ping 10.30.0.2        # the provisioning host, across the CMTS network side
```

## Configuration files

```sh
./docsis cfg encode --out configs/cm-default.cfg    # compile a JSON spec
./docsis cfg decode configs/cm-default.cfg          # dump it, check the MICs
./docsis cfg forge  configs/cm-default.cfg          # try to give yourself 100 Mbit/s
```

`forge` rewrites the rate, recomputes the CM MIC (which anyone can do — it is an
unkeyed digest) and shows the CMTS MIC failing, because that one is salted with
a shared secret the modem never sees. That is the entire security model of
DOCSIS 1.x/2.0 provisioning, and `--scenario bad-secret` shows a CMTS rejecting
it.

## Layout

```
docsislab/
  util/      TLVs, the two CRCs, pcapng writer, DOCSIS timebase, logging
  docsis/    MAC header, MAC management framing, every message codec,
             the configuration file and its MICs, protocol constants
  phy/       channel parameters and byte/mini-slot arithmetic; the HFC plant
             (delay, attenuation, serialisation, collisions, impairments)
  cmts/      the CMTS: MAP scheduler, modem database, ranging, registration,
             forwarding and DHCP relay, and the operator CLI
  cm/        the cable modem: the full initialisation state machine; a CPE
  net/       Ethernet/ARP/IPv4/UDP/ICMP, DHCP, TFTP, ToD, a small IP stack,
             and the macOS utun bridge
  provisioning/  the DHCP, Time-of-Day and TFTP host behind the CMTS
  lab/       discrete-event scheduler, topology, scenarios, control socket,
             dashboard
configs/     configuration-file specs, and the compiled binary
tools/       probe_wireshark.py — the script that pinned down the wire format
             gen_docs.py        — generates the reference documentation
tests/       139 tests, including a check that Wireshark still likes the bytes
             and one that the generated docs still match the code
docs/        see below
```

## Documentation

[docs/README.md](docs/README.md) is the index. Three documents are written and
three are generated from the code:

| Document | | Contents |
| --- | --- | --- |
| [docs/DOCSIS-NOTES.md](docs/DOCSIS-NOTES.md) | written | how a modem comes online, step by step, with the log line or filter that shows each one |
| [docs/WIRESHARK.md](docs/WIRESHARK.md) | written | how the wire format was verified, and the two bugs that found |
| [docs/REFERENCE.md](docs/REFERENCE.md) | generated | message types, IUCs, every TLV namespace, timers, channel and plant arithmetic |
| [docs/CLI.md](docs/CLI.md) | generated | every `docsis` subcommand and every CMTS shell command |
| [docs/API.md](docs/API.md) | generated | module map |

```sh
./docsis docs           # regenerate the generated three
./docsis docs --check   # fail if they are stale (this is also a test)
```

Generating them from the constant tables, the argparse tree, the CLI command
table and the modules' own docstrings means they describe what the code does
rather than what it was once meant to do.

## Not implemented

Called out so nothing here looks more complete than it is:

- **BPI+.** Privacy is disabled in the config file, so the modem goes straight
  from registration to operational with no key exchange. `PRIVACY_ENABLE` and
  the modem's `PRIVACY_SUPPORT` capability are carried and reported, but there
  is no BPKM exchange, no TEK and no DES.
- **S-CDMA.** The type-29 UCD carries the S-CDMA parameters and the code can
  describe an S-CDMA channel, but only TDMA and A-TDMA are scheduled.
- **Fragmentation and payload header suppression.** Advertised as capabilities,
  not implemented. Concatenation *is* implemented.
- **SNMP.** No agent, no MIBs.
- **Dynamic service flows.** DSA/DSC/DSD messages encode and decode, but the
  CMTS only creates flows at registration.
- **TCP through `--cpe utun`.** ICMP and UDP reach the simulated network;
  there is no NAT to the real internet.

See [docs/DOCSIS-NOTES.md](docs/DOCSIS-NOTES.md) for how the parts that *are*
implemented work, and where in the spec each piece comes from.
