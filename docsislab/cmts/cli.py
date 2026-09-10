"""A CMTS-style command line.

Deliberately shaped like the CLI on real cable equipment, because that is the
vocabulary the information is usually described in: `show cable modem`,
`show cable modulation-profile`, `show cable flap-list`.  Commands accept
unambiguous abbreviations, so `sh ca mo` works.

Everything here runs inside the simulation's event loop (the control server
hands commands over and waits), so a command can read live state without
locking.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Callable

from ..docsis.cfgfile import decode as decode_cfg
from ..docsis.cfgfile import dump as dump_cfg
from ..docsis.cfgfile import verify as verify_cfg
from ..docsis.consts import (IUC, IUC_NAMES, MODULATION_NAMES, TIMING_ADJUST_UNIT_S)
from ..net.packet import mac_str
from .modemdb import STATE_MEANING


def _table(headers: list[str], rows: list[list[str]], gap: str = "  ") -> str:
    if not rows:
        widths = [len(h) for h in headers]
    else:
        widths = [max(len(h), *(len(str(r[i])) for r in rows))
                  for i, h in enumerate(headers)]
    out = [gap.join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    out.append(gap.join("-" * w for w in widths))
    for r in rows:
        out.append(gap.join(str(c).ljust(widths[i]) for i, c in enumerate(r)))
    return "\n".join(out)


@dataclass
class Command:
    """One CLI command: its words, handler and help text."""
    words: tuple[str, ...]
    handler: Callable
    help: str
    args: str = ""


class Cli:
    """Command tree for one running lab."""

    def __init__(self, lab):
        self.lab = lab
        self.cmts = lab.cmts
        self.context = "cmts"          # or a modem name
        self.commands: list[Command] = []
        self._register()

    # ------------------------------------------------------------------
    def _add(self, words: str, handler, help: str, args: str = "") -> None:
        self.commands.append(Command(tuple(words.split()), handler, help, args))

    def _register(self) -> None:
        a = self._add
        a("show version", self.show_version, "software and topology summary")
        a("show topology", self.show_topology, "what the plant is made of")
        a("show cable modem", self.show_cable_modem,
          "one line per modem, or details for one", "[<mac|sid|ip>] [verbose]")
        a("show cable modem summary", self.show_modem_summary,
          "count of modems by state")
        a("show cable modem phy", self.show_modem_phy,
          "per-modem PHY measurements")
        a("show cable modem states", self.show_modem_states,
          "what each initialisation state means")
        a("show cable flap-list", self.show_flap_list,
          "modems that have lost and regained service")
        a("show cable qos service-flow", self.show_service_flows,
          "admitted service flows")
        a("show interface cable", self.show_interface,
          "cable interface counters", "[upstream|downstream [<id>]]")
        a("show cable modulation-profile", self.show_modulation_profile,
          "burst profile per interval usage code", "[<upstream-id>]")
        a("show cable ucd", self.show_ucd, "upstream channel descriptors",
          "[<upstream-id>]")
        a("show cable map", self.show_map, "the most recent MAP, decoded",
          "[<upstream-id>]")
        a("show cable timing", self.show_timing, "DOCSIS timebase and mini-slots")
        a("show cable scheduler", self.show_scheduler, "upstream scheduler state")
        a("show cable dhcp", self.show_dhcp, "provisioning leases and services")
        a("show cable config", self.show_config,
          "decode a configuration file", "[<filename>]")
        a("show cable plant", self.show_plant, "HFC plant counters and impairments")
        a("show logging", self.show_logging, "event log tail",
          "[<lines>] [<source>]")
        a("show cm", self.show_cm, "cable-modem side view", "[<name>] [verbose]")
        a("show cpe", self.show_cpe, "customer equipment behind the modems")
        a("clear cable modem", self.clear_cable_modem,
          "force a modem to re-initialise", "<mac|sid|name|all> reset")
        a("test cable noise", self.test_noise,
          "destroy upstream bursts for a while", "<milliseconds> [<upstream-id>]")
        a("test cable loss", self.test_loss,
          "set random upstream/downstream loss", "<us-percent> [<ds-percent>]")
        a("test cable ucc", self.test_ucc,
          "move a modem to another upstream", "<mac|sid|name> <upstream-id>")
        a("ping", self.do_ping, "ping from a CPE", "<address> [<cpe>] [count <n>]")
        a("debug cable mac-messages", self.debug_mac_messages,
          "echo the per-MAP and per-SYNC chatter", "{on|off}")
        a("help", self.do_help, "this list")
        a("?", self.do_help, "this list")

    # ------------------------------------------------------------------
    def execute(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        try:
            words = shlex.split(line)
        except ValueError:
            words = line.split()
        best: Command | None = None
        best_len = 0
        ambiguous: list[Command] = []
        for cmd in self.commands:
            n = len(cmd.words)
            if len(words) < n:
                continue
            if all(cmd.words[i].startswith(words[i].lower()) for i in range(n)):
                if n > best_len:
                    best, best_len, ambiguous = cmd, n, [cmd]
                elif n == best_len and cmd is not best:
                    ambiguous.append(cmd)
        if best is None:
            return (f"% Unrecognised command: {line!r}\n"
                    f"  Try 'help'.")
        if len(ambiguous) > 1:
            names = ", ".join(" ".join(c.words) for c in ambiguous)
            return f"% Ambiguous command: {line!r} could be {names}"
        try:
            return best.handler(words[best_len:]) or ""
        except Exception as exc:  # a CLI should never take the sim down
            import traceback
            return f"% Command failed: {exc}\n{traceback.format_exc(limit=3)}"

    # ==================================================================
    # show
    # ==================================================================
    def show_version(self, args: list[str]) -> str:
        snap = self.lab.snapshot()
        c = snap["cmts"]
        return "\n".join([
            "docsislab -- virtual DOCSIS 2.0 CMTS and cable modem",
            f"hostname {c['hostname']}, uptime {c['uptime']:.3f} s of "
            f"simulated time ({snap['events']} scheduler events)",
            f"time scale {snap['speed']}x, capture "
            f"{snap['capture']['path'] or 'disabled'} "
            f"({snap['capture']['packets']} packets)",
            f"{len(c['downstreams'])} downstream, {len(c['upstreams'])} upstream, "
            f"{len(c['modems'])} modem(s) known",
            "",
            "DOCSIS 2.0 MAC layer is byte-accurate; the PHY is modelled as "
            "timing, power and collisions rather than modulated symbols.",
        ])

    def show_topology(self, args: list[str]) -> str:
        lines = ["HFC plant:"]
        lines += ["  " + l for l in self.lab.plant.describe()]
        lines.append("")
        lines.append("Addressing:")
        cfg = self.cmts.cfg
        lines.append(f"  cable interface  {cfg.cm_gateway}/{cfg.cm_netmask} "
                     f"(cable modems), {cfg.cpe_gateway}/{cfg.cpe_netmask} "
                     f"secondary (subscribers)")
        lines.append(f"  network side     {cfg.nsi_ip}/{cfg.nsi_netmask}")
        lines.append(f"  dhcp helper      {cfg.dhcp_helper}")
        lines.append(f"  shared secret    {cfg.shared_secret.decode(errors='replace')!r} "
                     f"(checked against the CMTS MIC in every REG-REQ)")
        return "\n".join(lines)

    def show_cable_modem(self, args: list[str]) -> str:
        verbose = any(a.startswith("v") for a in args)
        selector = next((a for a in args if not a.startswith("v")), None)
        if selector:
            rec = self.cmts.modems.find(selector)
            if rec is None:
                return f"% No modem matching {selector!r}"
            return self._modem_detail(rec)
        if verbose:
            return "\n\n".join(self._modem_detail(r)
                               for r in self.cmts.modems.modems) or "% No modems"
        rows = []
        now = self.lab.sched.now()
        for r in self.cmts.modems.modems:
            rows.append([
                r.mac_text, r.ip or "-",
                f"C1/0/U{r.upstream_channel}",
                r.state, str(r.sid),
                f"{r.rx_power_dbmv:+.2f}",
                str(r.timing_offset), str(len(r.cpe_macs)),
                "N" if not r.privacy_enabled else "Y",
                f"{r.uptime(now):.1f}s" if r.online_since else "-",
            ])
        if not rows:
            return "% No cable modems have been heard from yet"
        return _table(["MAC Address", "IP Address", "I/F", "MAC State",
                       "Prim Sid", "RxPwr", "Timing", "CPE", "BPI", "Online"], rows)

    def _modem_detail(self, r) -> str:
        now = self.lab.sched.now()
        caps = ", ".join(f"{k}={v}" for k, v in sorted(r.capabilities.items()))
        lines = [
            f"MAC Address             : {r.mac_text}",
            f"IP Address              : {r.ip or '-'}",
            f"Primary SID             : {r.sid}",
            f"MAC State               : {r.state}  ({STATE_MEANING.get(r.state, '')})",
            f"Interface               : C1/0 upstream {r.upstream_channel}, "
            f"downstream {r.downstream_channel}",
            f"DOCSIS Version          : {r.docsis_version}",
            f"Config File             : {r.config_file or '-'}",
            f"Network Access          : {'enabled' if r.network_access else 'disabled'}",
            f"Privacy (BPI+)          : {'enabled' if r.privacy_enabled else 'disabled'}",
            f"Max CPE                 : {r.max_cpe} "
            f"({len(r.cpe_macs)} learned: "
            f"{', '.join(mac_str(m) for m in r.cpe_macs) or 'none'})",
            "",
            f"Timing Offset           : {r.timing_offset} units "
            f"({r.timing_offset * TIMING_ADJUST_UNIT_S * 1e6:.2f} us round trip)",
            f"Residual Timing Error   : {r.residual_timing_error:+d} units",
            f"Received Power           : {r.rx_power_dbmv:+.2f} dBmV",
            f"Frequency Offset        : {r.freq_offset_hz:+d} Hz",
            f"SNR                     : {r.snr_db:.1f} dB",
            "",
            f"Ranging Exchanges       : {r.ranging_attempts} "
            f"({r.rng_rsp_sent} RNG-RSP sent)",
            f"Bandwidth Requests      : {r.requests_received}",
            f"Upstream Bursts         : {r.us_bursts} "
            f"({r.us_collisions} collided)",
            f"Flaps                   : {r.flaps}",
            f"First Seen              : {r.first_seen:.6f} s",
            f"Online Since            : "
            + (f"{r.online_since:.6f} s ({r.uptime(now):.3f} s ago)"
               if r.online_since else "-"),
            f"Capabilities            : {caps or '-'}",
        ]
        if r.service_flows:
            lines.append("")
            lines.append("Service Flows:")
            for sf in r.service_flows:
                lines.append(f"  {sf.describe()}  "
                             f"{sf.packets} packets / {sf.bytes} bytes")
        lines.append("")
        lines.append("State history:")
        for t, st in r.state_history:
            lines.append(f"  {t:9.6f}  {st}")
        return "\n".join(lines)

    def show_modem_summary(self, args: list[str]) -> str:
        counts = self.cmts.modems.count_by_state()
        if not counts:
            return "% No cable modems"
        rows = [[state, str(counts[state]),
                 STATE_MEANING.get(state, "")] for state in
                sorted(counts, key=lambda s: list(STATE_MEANING).index(s)
                       if s in STATE_MEANING else 99)]
        return _table(["State", "Count", "Meaning"], rows)

    def show_modem_states(self, args: list[str]) -> str:
        rows = [[k, v] for k, v in STATE_MEANING.items()]
        return ("CMTS-side modem states, in the order a modem passes through them:\n\n"
                + _table(["State", "Meaning"], rows))

    def show_modem_phy(self, args: list[str]) -> str:
        rows = []
        for r in self.cmts.modems.modems:
            rows.append([r.mac_text, str(r.sid),
                         f"{r.rx_power_dbmv:+.2f}", f"{r.snr_db:.1f}",
                         str(r.timing_offset),
                         f"{r.timing_offset * TIMING_ADJUST_UNIT_S * 1e6:.2f}",
                         f"{r.residual_timing_error:+d}",
                         f"{r.freq_offset_hz:+d}"])
        if not rows:
            return "% No cable modems"
        return _table(["MAC Address", "Sid", "RxPwr(dBmV)", "SNR(dB)",
                       "Timing(units)", "Timing(us)", "Residual", "Freq(Hz)"], rows)

    def show_flap_list(self, args: list[str]) -> str:
        rows = []
        for r in self.cmts.modems.modems:
            if r.flaps == 0 and r.us_collisions == 0 and r.ranging_attempts <= 3:
                continue
            rows.append([r.mac_text, f"C1/0/U{r.upstream_channel}",
                         str(r.ranging_attempts), str(r.flaps),
                         str(r.us_collisions), f"{r.last_heard:.3f}"])
        if not rows:
            return "% Flap list is empty (no modem has lost service or collided)"
        return _table(["MAC Address", "I/F", "Ins", "Flap", "Collisions",
                       "Last Heard"], rows)

    def show_service_flows(self, args: list[str]) -> str:
        rows = []
        for r in self.cmts.modems.modems:
            for sf in r.service_flows:
                rows.append([str(sf.sfid), r.mac_text,
                             "US" if sf.direction == "us" else "DS",
                             str(sf.sid) if sf.sid else "-",
                             "primary" if sf.primary else "secondary",
                             {2: "BE", 3: "nrtPS", 4: "rtPS", 5: "UGS-AD",
                              6: "UGS"}.get(sf.scheduling, str(sf.scheduling)),
                             f"{sf.max_sustained_bps / 1e6:.2f}" if sf.max_sustained_bps else "-",
                             str(sf.priority), str(sf.packets), str(sf.bytes)])
        if not rows:
            return "% No service flows admitted yet"
        return _table(["Sfid", "MAC Address", "Dir", "Sid", "Type", "Sched",
                       "MaxRate(Mb/s)", "Pri", "Packets", "Bytes"], rows)

    def show_interface(self, args: list[str]) -> str:
        want = args[0].lower() if args else ""
        lines = []
        if not want or "downstream".startswith(want):
            for ds in self.cmts.downstreams:
                lines.append(f"Cable1/0 downstream {ds.channel_id} is up")
                lines.append(f"  {ds.describe()}")
                lines.append(f"  Annex {ds.annex}, MPEG-TS rate "
                             f"{ds.ts_bps / 1e6:.4f} Mbit/s, DOCSIS payload "
                             f"{ds.payload_bps / 1e6:.3f} Mbit/s")
                lines.append(f"  {self.cmts.stats['sync']} SYNC, "
                             f"{self.cmts.stats['ucd']} UCD, "
                             f"{self.cmts.stats['maps']} MAP, "
                             f"{self.cmts.stats['ds_pdus']} data PDUs sent")
                lines.append(f"  {self.lab.plant.stats['ds_frames']} frames / "
                             f"{self.lab.plant.stats['ds_bytes']} bytes total, "
                             f"{self.lab.plant.stats['ds_dropped']} dropped")
                lines.append("")
        if not want or "upstream".startswith(want):
            for us in self.cmts.upstreams:
                sch = self.cmts.schedulers[us.channel_id]
                lines.append(f"Cable1/0 upstream {us.channel_id} is up")
                lines.append(f"  {us.describe()}")
                lines.append(f"  describable by a DOCSIS 1.x type-2 UCD: "
                             f"{'yes' if us.describable_by_docsis_1x else 'no '
                                '(5120 ksps exceeds the 1.x maximum)'}")
                lines.append(f"  mini-slot {us.minislot_ticks} ticks = "
                             f"{us.minislot_s * 1e6:.2f} us = "
                             f"{us.symbols_per_minislot:.0f} symbols")
                for iuc in (IUC.REQUEST, IUC.INITIAL_MAINT, IUC.STATION_MAINT,
                            us.data_iuc(False), us.data_iuc(True)):
                    prof = us.profile(iuc)
                    if prof:
                        lines.append(f"    IUC {int(iuc):2d} "
                                     f"{IUC_NAMES.get(iuc, ''):26} "
                                     f"{us.bytes_per_minislot(iuc):3d} bytes/mini-slot")
                lines.append(f"  {sch.maps_sent} MAPs, "
                             f"{sch.granted_minislots} mini-slots granted, "
                             f"{sch.contention_minislots} offered for contention, "
                             f"{len(sch.pending)} requests pending")
                lines.append(f"  {self.lab.plant.stats['us_bursts']} bursts / "
                             f"{self.lab.plant.stats['us_bytes']} bytes received, "
                             f"{self.lab.plant.stats['us_collisions']} collisions, "
                             f"{self.lab.plant.stats['us_dropped']} discarded")
                lines.append("")
        return "\n".join(lines).rstrip()

    def show_modulation_profile(self, args: list[str]) -> str:
        out = []
        for us in self.cmts.upstreams:
            if args and str(us.channel_id) != args[0]:
                continue
            out.append(f"Upstream {us.channel_id} modulation profile "
                       f"({us.phy_mode.upper()}):")
            rows = []
            for p in us.burst_profiles:
                rows.append([
                    str(p.iuc), IUC_NAMES.get(p.iuc, "?"),
                    MODULATION_NAMES.get(p.modulation, "?"),
                    f"{p.fec_t}", f"{p.fec_k}",
                    f"{p.preamble_length}", f"{p.guard_time}",
                    str(p.max_burst or "-"),
                    "shortened" if p.last_codeword_shortened else "fixed",
                    "on" if p.scrambler_on else "off",
                    str(us.bytes_per_minislot(p.iuc)),
                    "2.0" if p.iuc in (IUC.ADV_PHY_SHORT_DATA,
                                       IUC.ADV_PHY_LONG_DATA,
                                       IUC.ADV_PHY_UGS) else "1.x",
                ])
            out.append(_table(["IUC", "Usage", "Mod", "FEC-T", "FEC-k",
                               "Preamble", "Guard", "MaxBurst", "LastCW",
                               "Scram", "B/slot", "Needs"], rows))
            out.append("")
        return "\n".join(out).rstrip() or "% No such upstream"

    def show_ucd(self, args: list[str]) -> str:
        out = []
        for us in self.cmts.upstreams:
            if args and str(us.channel_id) != args[0]:
                continue
            ccc = self.cmts.ucd_change_count[us.channel_id]
            out.append(f"Upstream {us.channel_id}: configuration change count {ccc}")
            out.append(f"  type 29 UCD (DOCSIS 2.0): sent, describes IUCs "
                       f"{[int(b.iuc) for b in us.burst_profiles]}")
            if self.cmts.cfg.mixed_mode_ucd and us.describable_by_docsis_1x:
                legacy = [int(b.iuc) for b in us.burst_profiles
                          if b.iuc < IUC.ADV_PHY_SHORT_DATA]
                out.append(f"  type  2 UCD (DOCSIS 1.x): also sent, describes "
                           f"IUCs {legacy}")
                out.append("  -> mixed mode: 1.x and 2.0 modems share this channel, "
                           "each reading the UCD it understands")
            else:
                out.append("  type  2 UCD (DOCSIS 1.x): not sent"
                           + ("" if us.describable_by_docsis_1x else
                              " -- this channel is too wide for DOCSIS 1.x"))
            out.append(f"  frequency {us.center_freq_hz / 1e6:.3f} MHz, "
                       f"{us.symbol_rate_ksym} ksym/s, "
                       f"mini-slot {us.minislot_ticks} ticks")
            out.append("")
        return "\n".join(out).rstrip() or "% No such upstream"

    def show_map(self, args: list[str]) -> str:
        out = []
        for us in self.cmts.upstreams:
            if args and str(us.channel_id) != args[0]:
                continue
            sch = self.cmts.schedulers[us.channel_id]
            rec = sch.last_map
            if rec is None:
                out.append(f"Upstream {us.channel_id}: no MAP built yet")
                continue
            out.append(f"Upstream {us.channel_id}: most recent MAP")
            out.append(f"  Alloc Start Time {rec.alloc_start} "
                       f"(t={us.clock.start_of(rec.alloc_start):.6f}s), "
                       f"Ack Time {rec.ack_time}, span {rec.span} mini-slots "
                       f"({rec.span * us.minislot_s * 1e3:.2f} ms)")
            rows = []
            for i, ie in enumerate(rec.ies):
                start = rec.alloc_start + ie.offset
                nxt = (rec.alloc_start + rec.ies[i + 1].offset
                       if i + 1 < len(rec.ies) else start)
                length = nxt - start
                rows.append([str(ie.sid) if ie.sid != 0x3FFF else "broadcast",
                             str(int(ie.iuc)), IUC_NAMES.get(ie.iuc, "?"),
                             str(ie.offset), str(start),
                             str(length) if ie.iuc != IUC.NULL_IE else "-",
                             (f"{us.payload_capacity(length, int(ie.iuc))} bytes"
                              if length and ie.iuc not in (IUC.NULL_IE,) else "")])
            out.append(_table(["SID", "IUC", "Usage", "Offset", "Mini-slot",
                               "Length", "Capacity"], rows))
            out.append("")
            out.append("  A grant runs from its own offset to the offset of the "
                       "next element, which is why the MAP ends with a Null IE.")
            out.append("")
        return "\n".join(out).rstrip() or "% No such upstream"

    def show_timing(self, args: list[str]) -> str:
        from ..util.clock import (COUNTS_PER_TICK, MASTER_CLOCK_HZ, TICK_S,
                                  TIMESTAMP_WRAP_S, timestamp_at)
        now = self.lab.sched.now()
        lines = [
            f"Master clock            : {MASTER_CLOCK_HZ / 1e6:.2f} MHz, "
            f"32-bit counter wrapping every {TIMESTAMP_WRAP_S:.2f} s",
            f"Timebase tick           : {TICK_S * 1e6:.2f} us "
            f"({COUNTS_PER_TICK} master clock counts)",
            f"Current SYNC timestamp  : "
            f"{timestamp_at(now - self.cmts.started_at)}",
            f"Simulated time          : {now:.6f} s",
            "",
        ]
        for us in self.cmts.upstreams:
            sch = self.cmts.schedulers[us.channel_id]
            lines += [
                f"Upstream {us.channel_id}:",
                f"  mini-slot           : {us.minislot_ticks} ticks = "
                f"{us.minislot_s * 1e6:.2f} us = {us.clock.counts} counts",
                f"  current mini-slot   : {us.clock.number_at(now)}",
                f"  allocated through   : {sch.next_minislot}",
                f"  MAP interval        : {sch.cfg.map_interval * 1e3:.2f} ms "
                f"({sch.span} mini-slots), transmitted "
                f"{sch.cfg.map_advance * 1e3:.2f} ms in advance",
                f"  Initial Maintenance : every "
                f"{sch.cfg.initial_maint_interval * 1e3:.0f} ms, "
                f"{sch.initial_maint_minislots()} mini-slots "
                f"({sch.round_trip_minislots} of that is round-trip headroom "
                f"for a {sch.cfg.max_reach_km:.0f} km plant)",
                f"  Station Maintenance : every "
                f"{sch.cfg.station_maint_interval_ranging * 1e3:.0f} ms while "
                f"ranging, {sch.cfg.station_maint_interval:.0f} s once online",
                "",
            ]
        lines.append(f"One RNG-RSP timing adjust unit = "
                     f"{TIMING_ADJUST_UNIT_S * 1e9:.5f} ns (1/64 of a tick)")
        return "\n".join(lines)

    def show_scheduler(self, args: list[str]) -> str:
        out = []
        for us in self.cmts.upstreams:
            sch = self.cmts.schedulers[us.channel_id]
            out.append(f"Upstream {us.channel_id} scheduler:")
            out.append(f"  MAPs built            : {sch.maps_sent}")
            out.append(f"  mini-slots granted    : {sch.granted_minislots}")
            out.append(f"  contention offered    : {sch.contention_minislots}")
            out.append(f"  pending requests      : "
                       + (", ".join(f"sid {s}={r.minislots} minislots"
                                    for s, r in sch.pending.items()) or "none"))
            out.append(f"  station maintenance   : "
                       + (", ".join(f"sid {s} due at {t:.3f}"
                                    for s, t in sorted(sch.station_maint_due.items()))
                          or "none"))
            out.append(f"  still ranging         : "
                       + (", ".join(str(s) for s in sorted(sch.ranging_sids)) or "none"))
            out.append(f"  back-off advertised   : ranging "
                       f"[{sch.cfg.ranging_backoff_start},"
                       f"{sch.cfg.ranging_backoff_end}], data "
                       f"[{sch.cfg.data_backoff_start},"
                       f"{sch.cfg.data_backoff_end}] (exponents)")
            out.append("")
        return "\n".join(out).rstrip()

    def show_dhcp(self, args: list[str]) -> str:
        snap = self.lab.provisioning.snapshot()
        lines = [f"Provisioning host {snap['ip']}: "
                 + ", ".join(f"{k}={v}" for k, v in snap["stats"].items()), ""]
        for pool in snap["pools"]:
            lines.append(f"Pool {pool['name']} (selected by giaddr {pool['relay']}), "
                         f"subnet {pool['subnet']}:")
            if pool["leases"]:
                lines.append(_table(["MAC Address", "IP Address"],
                                    [[m, a] for m, a in pool["leases"].items()]))
            else:
                lines.append("  no leases")
            lines.append("")
        lines.append("Config files served: "
                     + ", ".join(f"{n} ({s} bytes)"
                                 for n, s in snap["files"].items()))
        return "\n".join(lines)

    def show_config(self, args: list[str]) -> str:
        files = self.lab.provisioning.files
        name = args[0] if args else next(iter(files), None)
        if name is None:
            return "% No config files"
        blob = files.get(name)
        if blob is None:
            return f"% No such config file {name!r} (have: {', '.join(files)})"
        settings = decode_cfg(blob)
        result = verify_cfg(settings, self.cmts.cfg.shared_secret)
        return "\n".join([
            f"Configuration file {name!r}: {len(blob)} bytes, "
            f"{len(settings)} settings",
            "",
            dump_cfg(settings),
            "",
            f"MIC verification: {result.explain()}",
            "",
            "The CM MIC covers every setting above except the two MIC settings.",
            "The CMTS MIC covers an ordered subset plus the shared secret, so a",
            "modem cannot rewrite its own service tier and still register.",
        ])

    def show_plant(self, args: list[str]) -> str:
        p = self.lab.plant
        lines = ["HFC plant:"] + ["  " + l for l in p.describe()]
        lines.append("")
        lines.append("Counters: " + ", ".join(f"{k}={v}" for k, v in p.stats.items()))
        lines.append(f"Impairments: upstream loss {p.us_loss_prob * 100:.1f}%, "
                     f"downstream loss {p.ds_loss_prob * 100:.1f}%, "
                     f"{len(p.noise_windows)} noise window(s)")
        for start, end, cid in p.noise_windows:
            lines.append(f"  noise {start:.6f}..{end:.6f} s on "
                         f"{'all upstreams' if cid is None else f'US{cid}'}")
        return "\n".join(lines)

    def show_logging(self, args: list[str]) -> str:
        count = 40
        source = None
        for a in args:
            if a.isdigit():
                count = int(a)
            else:
                source = a
        events = self.lab.log.tail(count, source=source)
        if not events:
            return "% No matching log events"
        return "\n".join(e.format(False) for e in events)

    def show_cm(self, args: list[str]) -> str:
        verbose = any(a.startswith("v") for a in args)
        names = [a for a in args if not a.startswith("v")]
        targets = ([self.lab.modems[n] for n in names if n in self.lab.modems]
                   or list(self.lab.modems.values()))
        if names and not targets:
            return f"% No such modem {names[0]!r} (have: {', '.join(self.lab.modems)})"
        out = []
        for m in targets:
            s = m.snapshot()
            out.append(f"{s['name']} ({s['mac']}) -- modem's own view")
            out.append(f"  state              : {s['state']}")
            out.append(f"                       {s['state_meaning']}")
            out.append(f"  downstream         : "
                       + (f"{s['ds_freq'] / 1e6:.3f} MHz locked, "
                          f"{s['sync_count']} SYNC received"
                          if s['ds_freq'] else "not locked"))
            out.append(f"  clock offset       : "
                       + (f"{s['clock_offset_us']:+.3f} us "
                          f"(its estimate of CMTS time lags by the one-way delay)"
                          if s['clock_offset_us'] is not None else "no timebase"))
            out.append(f"  upstream           : "
                       + (f"US{s['us_channel']} from a {s['ucd_type']} UCD"
                          if s['us_channel'] else "no UCD yet"))
            out.append(f"  SID                : {s['sid'] or '-'}")
            out.append(f"  ranging offset     : {s['ranging_offset']} units "
                       f"({s['ranging_offset_us']:.2f} us of advance)")
            out.append(f"  transmit power     : {s['tx_power']:.2f} dBmV")
            out.append(f"  IP address         : {s['ip'] or '-'}")
            out.append(f"  config file        : {s['config_file'] or '-'}")
            out.append(f"  upstream queue     : {s['queue']} frame(s), "
                       f"{s['outstanding_request']} mini-slots requested")
            out.append(f"  back-off windows   : ranging {s['ranging_backoff']}, "
                       f"request {s['request_backoff']}")
            out.append(f"  CPEs on LAN side   : "
                       + (", ".join(s['cpes']) or "none"))
            if verbose:
                out.append("  counters:")
                for k, v in s["counters"].items():
                    out.append(f"    {k:20} {v}")
                out.append("  state history:")
                for t, st in m.state_history:
                    out.append(f"    {t:9.6f}  {st}")
            out.append("")
        return "\n".join(out).rstrip()

    def show_cpe(self, args: list[str]) -> str:
        rows = []
        for name, cpe in self.lab.cpes.items():
            s = cpe.snapshot()
            rows.append([name, s["mac"], s["ip"] or "-", s["gateway"] or "-",
                         cpe.modem.cfg.name, str(s["pings_ok"]),
                         str(s["pings_lost"])])
        if not rows:
            return "% No CPEs configured"
        return _table(["Name", "MAC Address", "IP Address", "Gateway",
                       "Behind", "Pings OK", "Lost"], rows)

    # ==================================================================
    # actions
    # ==================================================================
    def clear_cable_modem(self, args: list[str]) -> str:
        if not args:
            return "% Usage: clear cable modem <mac|sid|name|all> reset"
        target = args[0]
        if target == "all":
            for m in self.lab.modems.values():
                m.reinitialize("operator issued 'clear cable modem all reset'")
            return f"% Reset {len(self.lab.modems)} modem(s)"
        modem = self.lab.modems.get(target)
        if modem is None:
            rec = self.cmts.modems.find(target)
            if rec is not None:
                modem = next((m for m in self.lab.modems.values()
                              if m.cfg.mac == rec.mac), None)
        if modem is None:
            return f"% No modem matching {target!r}"
        modem.reinitialize("operator issued 'clear cable modem reset'")
        return (f"% {modem.cfg.name} re-initialising -- watch it rescan the "
                f"downstream, re-range and re-register")

    def test_noise(self, args: list[str]) -> str:
        if not args:
            return "% Usage: test cable noise <milliseconds> [<upstream-id>]"
        ms = float(args[0])
        cid = int(args[1]) if len(args) > 1 else None
        start, end = self.lab.plant.inject_noise(ms / 1000.0, cid)
        return (f"% Injecting an ingress burst from {start:.6f} to {end:.6f} s "
                f"on {'all upstreams' if cid is None else f'US{cid}'}.\n"
                f"% Upstream bursts overlapping that window are destroyed; "
                f"expect T3 timeouts and back-off growth.")

    def test_loss(self, args: list[str]) -> str:
        if not args:
            return (f"% Usage: test cable loss <us-percent> [<ds-percent>]\n"
                    f"% Currently upstream {self.lab.plant.us_loss_prob * 100:.1f}%, "
                    f"downstream {self.lab.plant.ds_loss_prob * 100:.1f}%")
        self.lab.plant.us_loss_prob = float(args[0]) / 100.0
        if len(args) > 1:
            self.lab.plant.ds_loss_prob = float(args[1]) / 100.0
        return (f"% Upstream loss {self.lab.plant.us_loss_prob * 100:.1f}%, "
                f"downstream loss {self.lab.plant.ds_loss_prob * 100:.1f}%")

    def test_ucc(self, args: list[str]) -> str:
        if len(args) < 2:
            return "% Usage: test cable ucc <mac|sid|name> <upstream-id>"
        rec = self.cmts.modems.find(args[0])
        if rec is None:
            modem = self.lab.modems.get(args[0])
            rec = self.cmts.modems.get(modem.cfg.mac) if modem else None
        if rec is None:
            return f"% No modem matching {args[0]!r}"
        target = int(args[1])
        if target not in self.cmts.plant.upstreams:
            return (f"% No upstream {target} "
                    f"(have {sorted(self.cmts.plant.upstreams)})")
        from ..docsis import messages as M
        req = M.UccReq(upstream_channel_id=target)
        self.cmts._send_mgmt(req, f"UCC-REQ move {rec.mac_text} to US{target}",
                             dst=rec.mac)
        return (f"% Sent UCC-REQ moving {rec.mac_text} to upstream {target}; "
                f"the modem will re-range there")

    def do_ping(self, args: list[str]) -> str:
        if not args:
            return "% Usage: ping <address> [<cpe-name>] [count <n>]"
        dst = args[0]
        count = 3
        cpe_name = None
        i = 1
        while i < len(args):
            if args[i] == "count" and i + 1 < len(args):
                count = int(args[i + 1])
                i += 2
                continue
            cpe_name = args[i]
            i += 1
        cpe = (self.lab.cpes.get(cpe_name) if cpe_name
               else next(iter(self.lab.cpes.values()), None))
        if cpe is None:
            return "% No CPE to ping from"
        if cpe.ip is None:
            return f"% {cpe.cfg.name} has no IP address yet"
        cpe.ping(dst, count=count)
        return (f"% Sending {count} echo requests from {cpe.cfg.name} "
                f"({cpe.ip}) to {dst}; replies appear in the log")

    def debug_mac_messages(self, args: list[str]) -> str:
        on = bool(args) and args[0].lower() in ("on", "enable", "true", "1")
        if on:
            self.lab.log.mute.discard("map")
            self.lab.log.mute.discard("sync")
            return "% MAP and SYNC logging enabled (this is a lot of output)"
        self.lab.log.mute.update({"map", "sync"})
        return "% MAP and SYNC logging suppressed"

    def do_help(self, args: list[str]) -> str:
        rows = [[" ".join(c.words) + (" " + c.args if c.args else ""), c.help]
                for c in self.commands if c.words != ("?",)]
        return ("Commands (unambiguous abbreviations work, e.g. 'sh ca mo'):\n\n"
                + _table(["Command", "Description"], rows))
