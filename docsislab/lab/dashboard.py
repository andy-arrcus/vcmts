"""Full-screen live view of the simulation.

Plain ANSI rather than curses, so it behaves the same over ssh and in every
terminal, and so the layout code stays readable.  Three regions:

    left    the modem's own state machine, stepping through DOCSIS
            initialisation, with its PHY and provisioning values
    right   the CMTS's view: the modem table, upstream scheduler, counters
    bottom  a live tail of the event log
"""

from __future__ import annotations

import select
import shutil
import sys
import termios
import time
import tty

from ..cm.cm import CmState
from .control import ControlClient

CSI = "\x1b["
ALT_ON, ALT_OFF = CSI + "?1049h", CSI + "?1049l"
HIDE, SHOW = CSI + "?25l", CSI + "?25h"
CLEAR = CSI + "2J" + CSI + "H"
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"

GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
CYAN = "\x1b[36m"
MAGENTA = "\x1b[35m"
BLUE = "\x1b[34m"
GREY = "\x1b[90m"
WHITE = "\x1b[97m"

#: The DOCSIS 2.0 initialisation sequence, in order, as the dashboard shows it.
STEPS = [
    (CmState.DS_SCAN, "scan downstream"),
    (CmState.DS_LOCK, "downstream lock"),
    (CmState.SYNC_WAIT, "acquire SYNC / timebase"),
    (CmState.UCD_WAIT, "obtain upstream params (UCD)"),
    (CmState.RANGING_WAIT, "wait Initial Maintenance"),
    (CmState.RANGING_INITIAL, "initial ranging (SID 0)"),
    (CmState.RANGING_STATION, "station maintenance ranging"),
    (CmState.RANGING_COMPLETE, "ranging complete"),
    (CmState.DHCP, "establish IP (DHCP)"),
    (CmState.TOD, "time of day"),
    (CmState.TFTP, "config file (TFTP)"),
    (CmState.REGISTERING, "register (REG-REQ/RSP/ACK)"),
    (CmState.OPERATIONAL, "operational"),
]
STEP_INDEX = {s: i for i, (s, _) in enumerate(STEPS)}

LEVEL_COLOR = {"debug": GREY, "info": "", "notice": CYAN,
               "warn": YELLOW, "error": RED}
SOURCE_COLOR = {"cmts": MAGENTA, "prov": BLUE, "lab": WHITE, "plant": GREY}


def _visible_len(text: str) -> int:
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\x1b":
            j = text.find("m", i)
            i = len(text) if j < 0 else j + 1
            continue
        out += 1
        i += 1
    return out


def _fit(text: str, width: int) -> str:
    """Truncate to `width` visible columns, keeping escape sequences intact."""
    if _visible_len(text) <= width:
        return text + " " * (width - _visible_len(text))
    out, shown, i = [], 0, 0
    while i < len(text) and shown < width:
        if text[i] == "\x1b":
            j = text.find("m", i)
            if j < 0:
                break
            out.append(text[i:j + 1])
            i = j + 1
            continue
        out.append(text[i])
        shown += 1
        i += 1
    out.append(RESET)
    return "".join(out)


class Dashboard:
    """Full-screen live view of a running lab."""
    def __init__(self, client: ControlClient, interval: float = 0.25):
        self.client = client
        self.interval = interval
        self.seq = 0
        self.log_lines: list[str] = []
        self.paused = False
        self.status = ""

    # ------------------------------------------------------------------
    def run(self) -> None:
        old = None
        try:
            if sys.stdin.isatty():
                old = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
            sys.stdout.write(ALT_ON + HIDE)
            while True:
                if not self.paused:
                    self._refresh()
                self._draw()
                if self._read_key():
                    break
        except (ConnectionError, OSError) as exc:
            sys.stdout.write(ALT_OFF + SHOW)
            print(f"dashboard disconnected: {exc}")
            return
        finally:
            sys.stdout.write(ALT_OFF + SHOW + RESET)
            sys.stdout.flush()
            if old is not None:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)

    def _read_key(self) -> bool:
        deadline = time.monotonic() + self.interval
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if not sys.stdin.isatty():
                time.sleep(remaining)
                return False
            r, _, _ = select.select([sys.stdin], [], [], remaining)
            if not r:
                return False
            ch = sys.stdin.read(1)
            if ch in ("q", "Q", "\x03", "\x04"):
                return True
            if ch == " ":
                self.paused = not self.paused
                self.status = "paused" if self.paused else ""
            elif ch in "1234":
                speed = {"1": 0.25, "2": 1.0, "3": 4.0, "4": 0.0}[ch]
                r = self.client.request(cmd="speed", value=speed)
                self.status = (f"time scale {'max' if speed == 0 else str(speed) + 'x'}"
                               if r.get("ok") else "speed change failed")
            elif ch in ("r", "R"):
                self.log_lines.clear()

    # ------------------------------------------------------------------
    def _refresh(self) -> None:
        self.snap = self.client.snapshot()
        r = self.client.request(cmd="log", since=self.seq, limit=300)
        if r.get("ok"):
            self.seq = r.get("seq", self.seq)
            for e in r.get("events", []):
                lc = LEVEL_COLOR.get(e["level"], "")
                sc = SOURCE_COLOR.get(e["source"], GREEN)
                self.log_lines.append(
                    f"{GREY}{e['time']:9.6f}{RESET} {sc}{e['source']:<7}{RESET} "
                    f"{GREY}{e['category']:<10}{RESET} {lc}{e['message']}{RESET}")
            if len(self.log_lines) > 2000:
                del self.log_lines[:-2000]

    # ------------------------------------------------------------------
    def _draw(self) -> None:
        snap = getattr(self, "snap", None)
        if not snap:
            return
        cols, rows = shutil.get_terminal_size((120, 40))
        left_w = max(38, min(52, cols // 3))
        right_w = cols - left_w - 3

        left = self._left_panel(snap, left_w)
        right = self._right_panel(snap, right_w)
        # Give the panels the room their content needs before handing the
        # rest to the log, so the modem's state machine never gets clipped.
        wanted = max(len(left), len(right))
        body_h = max(1, min(wanted, rows - 10))
        log_h = max(4, rows - body_h - 4)
        out = [CLEAR]
        out.append(self._header(snap, cols))
        for i in range(body_h):
            l = left[i] if i < len(left) else ""
            r = right[i] if i < len(right) else ""
            out.append(_fit(l, left_w) + f" {GREY}│{RESET} " + _fit(r, right_w))
        out.append(GREY + "─" * cols + RESET)
        tail = self.log_lines[-log_h:]
        for i in range(log_h):
            out.append(_fit(tail[i] if i < len(tail) else "", cols))
        out.append(self._footer(snap, cols))
        sys.stdout.write("\n".join(out))
        sys.stdout.flush()

    def _header(self, snap: dict, cols: int) -> str:
        c = snap["cmts"]
        speed = snap["speed"]
        title = (f"{BOLD}{WHITE} docsislab {RESET}{GREY}│{RESET} "
                 f"{MAGENTA}{c['hostname']}{RESET} "
                 f"t={snap['now']:.3f}s  "
                 f"scale={'max' if speed == 0 else f'{speed}x'}  "
                 f"pcap={snap['capture']['packets']}")
        states = c["states"]
        online = states.get("online", 0) + states.get("online(d)", 0)
        right = (f"{GREEN if online else YELLOW}{online}/{len(c['modems'])} online"
                 f"{RESET}  {self.status}")
        pad = cols - _visible_len(title) - _visible_len(right)
        return title + " " * max(1, pad) + right + "\n" + GREY + "─" * cols + RESET

    def _left_panel(self, snap: dict, w: int) -> list[str]:
        lines: list[str] = []
        for name, m in snap["modems"].items():
            cur = m["state"]
            idx = STEP_INDEX.get(CmState(cur), -1) if cur in [s.value for s, _ in STEPS] else -1
            lines.append(f"{BOLD}{name}{RESET} {GREY}{m['mac']}{RESET}")
            lines.append("")
            for i, (state, label) in enumerate(STEPS):
                if cur == CmState.REJECTED.value:
                    mark, color = "x", RED
                elif idx < 0:
                    mark, color = " ", GREY
                elif i < idx:
                    mark, color = "✓", GREEN
                elif i == idx:
                    mark, color = "▶", (GREEN if state == CmState.OPERATIONAL
                                             else YELLOW)
                else:
                    mark, color = "·", GREY
                lines.append(f" {color}{mark}{RESET} {color}{label}{RESET}")
            lines.append("")
            if cur == CmState.REJECTED.value:
                lines.append(f" {RED}registration rejected{RESET}")
            lines.append(f"{GREY}─ PHY ─{RESET}")
            lines.append(f" downstream   {m['ds_freq'] / 1e6:.3f} MHz"
                         if m["ds_freq"] else " downstream   not locked")
            lines.append(f" SYNC seen    {m['sync_count']}")
            if m["clock_offset_us"] is not None:
                lines.append(f" clock offset {m['clock_offset_us']:+.3f} us")
            lines.append(f" upstream     "
                         + (f"US{m['us_channel']} {m['ucd_type']}"
                            if m["us_channel"] else "no UCD"))
            lines.append(f" ranging      {m['ranging_offset']} units "
                         f"= {m['ranging_offset_us']:.2f} us")
            lines.append(f" tx power     {m['tx_power']:.2f} dBmV")
            lines.append(f" backoff      rng={m['ranging_backoff']} "
                         f"req={m['request_backoff']}")
            lines.append("")
            lines.append(f"{GREY}─ MAC / IP ─{RESET}")
            lines.append(f" SID          {m['sid'] or '-'}")
            lines.append(f" IP address   {m['ip'] or '-'}")
            lines.append(f" config file  {m['config_file'] or '-'}")
            lines.append(f" us queue     {m['queue']} frame(s), "
                         f"req {m['outstanding_request']}")
            cnt = m["counters"]
            lines.append(f" bursts       {cnt['us_bursts']} up, "
                         f"{cnt['grants']} grants, {cnt['requests']} reqs")
            if cnt["t3_timeouts"] or cnt["collisions_assumed"]:
                lines.append(f" {YELLOW}retries      T3={cnt['t3_timeouts']} "
                             f"assumed-collisions={cnt['collisions_assumed']}{RESET}")
            lines.append("")
        for name, cpe in snap["cpes"].items():
            lines.append(f"{GREY}─ CPE {name} ─{RESET}")
            lines.append(f" {cpe['ip'] or 'no address'}  gw {cpe['gateway'] or '-'}")
            if cpe["pings_ok"] or cpe["pings_lost"]:
                lines.append(f" pings ok {cpe['pings_ok']} lost {cpe['pings_lost']}")
        return lines

    def _right_panel(self, snap: dict, w: int) -> list[str]:
        c = snap["cmts"]
        lines = [f"{BOLD}CMTS view{RESET}  {GREY}show cable modem{RESET}", ""]
        header = (f" {'MAC Address':17} {'IP':15} {'State':10} {'Sid':>4} "
                  f"{'RxPwr':>7} {'Timing':>7} {'CPE':>3}")
        lines.append(f"{GREY}{header}{RESET}")
        for m in c["modems"]:
            color = (GREEN if m["state"] == "online" else
                     RED if m["state"].startswith("reject") else YELLOW)
            lines.append(f" {m['mac']:17} {(m['ip'] or '-'):15} "
                         f"{color}{m['state']:10}{RESET} {m['sid']:>4} "
                         f"{m['rx_power']:>+7.2f} {m['timing']:>7} {m['cpes']:>3}")
        lines.append("")
        lines.append(f"{GREY}─ channels ─{RESET}")
        for ds in c["downstreams"]:
            lines.append(f" {ds['describe']}")
        for us in c["upstreams"]:
            lines.append(f" {us['describe']}")
            lines.append(f"   MAPs {us['maps']}  granted {us['granted']} minislots  "
                         f"contention {us['contention']}  pending {us['pending']}")
        lines.append("")
        lines.append(f"{GREY}─ CMTS counters ─{RESET}")
        st = c["stats"]
        order = [("sync", "SYNC"), ("ucd", "UCD"), ("maps", "MAP"),
                 ("rng_req", "RNG-REQ"), ("rng_rsp", "RNG-RSP"),
                 ("reg_req", "REG-REQ"), ("reg_rsp", "REG-RSP"),
                 ("reg_ack", "REG-ACK"), ("requests", "REQ"),
                 ("us_pdus", "US PDU"), ("ds_pdus", "DS PDU"),
                 ("relayed_dhcp", "DHCP relayed"), ("collisions", "collisions"),
                 ("bad_hcs", "bad HCS"), ("rejected", "rejected")]
        row = ""
        for key, label in order:
            cell = f" {label}={st.get(key, 0)}"
            if _visible_len(row + cell) > w - 1:
                lines.append(row)
                row = ""
            row += cell
        if row:
            lines.append(row)
        lines.append("")
        lines.append(f"{GREY}─ plant ─{RESET}")
        p = c["plant"]
        lines.append(f" downstream {p['ds_frames']} frames / {p['ds_bytes']} bytes"
                     + (f", {p['ds_dropped']} dropped" if p["ds_dropped"] else ""))
        lines.append(f" upstream   {p['us_bursts']} bursts / {p['us_bytes']} bytes, "
                     f"{p['us_collisions']} collisions, {p['us_dropped']} discarded")
        lines.append("")
        prov = snap["provisioning"]
        lines.append(f"{GREY}─ provisioning {prov['ip']} ─{RESET}")
        ps = prov["stats"]
        lines.append(f" DHCP discover={ps['discover']} offer={ps['offer']} "
                     f"request={ps['request']} ack={ps['ack']}  "
                     f"ToD={ps['tod']}  TFTP rrq={ps['rrq']} blocks={ps['blocks']}")
        for pool in prov["pools"]:
            leases = ", ".join(f"{m}={a}" for m, a in pool["leases"].items())
            lines.append(f" pool {pool['name']:14} giaddr {pool['relay']:11} "
                         f"{leases or 'no leases'}")
        return lines

    def _footer(self, snap: dict, cols: int) -> str:
        keys = (f"{GREY}q{RESET} quit  {GREY}space{RESET} pause  "
                f"{GREY}1{RESET} 0.25x  {GREY}2{RESET} 1x  {GREY}3{RESET} 4x  "
                f"{GREY}4{RESET} max  {GREY}r{RESET} clear log")
        return GREY + "─" * cols + RESET + "\n" + _fit(keys, cols)
