"""docsislab command line.

    docsis up [--scenario NAME]      run the lab
    docsis cli                       attach a CMTS-style shell
    docsis dash                      attach the live dashboard
    docsis run                        run headless until online, print a report
    docsis cfg encode|decode|forge   work with DOCSIS configuration files
    docsis pcap                      summarise a capture through tshark
    docsis scenarios                 list what there is to look at
    docsis docs                      regenerate the reference documentation
    docsis doctor                    check the environment
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

from .cm.cm import CmState
from .lab.control import DEFAULT_SOCKET, ControlClient, ControlServer
from .lab.runner import Lab, LabOptions
from .lab.scenarios import SCENARIOS, apply_runtime
from .lab.topology import Topology

DEFAULT_CAPTURE = "captures/docsis.pcapng"


# ==========================================================================
# up
# ==========================================================================

def cmd_up(args) -> int:
    scenario = SCENARIOS.get(args.scenario)
    if scenario is None:
        print(f"unknown scenario {args.scenario!r}; "
              f"try: {', '.join(SCENARIOS)}", file=sys.stderr)
        return 2
    topo: Topology = scenario.build()
    if args.upstreams == 2 and len(topo.upstreams) == 1:
        from .lab.topology import second_upstream
        topo.upstreams = list(topo.upstreams) + [second_upstream()]
    if args.distance is not None:
        for m in topo.modems:
            m.distance_km = args.distance
    if args.modems is not None and args.scenario == "crowd":
        from .lab.scenarios import _crowd
        topo = _crowd(args.modems)

    opts = LabOptions(
        speed=args.speed,
        capture_path=None if args.no_capture else args.capture,
        capture_comments=not args.no_comments,
        echo=not args.quiet,
        echo_level=args.log_level,
        mute=tuple(args.mute.split(",")) if args.mute else (),
        cpe_autostart=args.cpe != "none",
    )
    lab = Lab(topo, opts)
    apply_runtime(args.scenario, lab)
    if args.us_loss:
        lab.plant.us_loss_prob = args.us_loss / 100.0
    if args.ds_loss:
        lab.plant.ds_loss_prob = args.ds_loss / 100.0

    utun = None
    if args.cpe == "utun":
        from .net.utun import UtunConfig, UtunCpe, UtunError
        modem = next(iter(lab.modems.values()))
        # Replace the simulated CPE with the host's own stack.
        lab.cpes.clear()
        try:
            utun = UtunCpe(lab.sched, modem, lab.cmts,
                           UtunConfig(local_ip=args.cpe_ip,
                                      peer_ip=topo.cmts.cpe_gateway),
                           lab.log.logger("utun"), lab.capture)
        except Exception as exc:
            print(f"utun setup failed: {exc}", file=sys.stderr)
            return 1

    control = ControlServer(lab, args.socket)
    lab.start()
    control.start()

    if utun is not None:
        from .net.utun import UtunError
        try:
            utun.start()
            lab.cpes["utun"] = utun
        except UtunError as exc:
            print(f"\n{exc}\n", file=sys.stderr)
            control.stop()
            lab.close()
            return 1

    banner(lab, scenario, args)

    stopping = {"flag": False}

    def on_signal(signum, frame):
        if stopping["flag"]:
            os._exit(1)
        stopping["flag"] = True
        lab.sched.stop()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        lab.run(until=args.duration if args.duration else None)
    finally:
        control.stop()
        if utun is not None:
            utun.stop()
        lab.close()
        print()
        report(lab)
    return 0


def banner(lab, scenario, args) -> None:
    print()
    print(f"  scenario   {scenario.name}: {scenario.description}")
    if scenario.watch:
        print(f"  watch for  {scenario.watch}")
    print(f"  capture    {lab.opts.capture_path or 'disabled'}")
    print(f"  attach     docsis cli   (CMTS-style shell)")
    print(f"             docsis dash  (live dashboard)")
    if lab.opts.capture_path:
        print(f"  wireshark  open {lab.opts.capture_path}")
    print()


def report(lab) -> None:
    snap = lab.snapshot()
    print("=" * 72)
    online = [n for n, m in lab.modems.items()
              if m.state == CmState.OPERATIONAL]
    print(f"{len(online)}/{len(lab.modems)} modem(s) reached operational state"
          + (f": {', '.join(online)}" if online else ""))
    cmts_state = {m["mac"]: m["state"] for m in snap["cmts"]["modems"]}
    for name, m in snap["modems"].items():
        at = snap["online_at"].get(name)
        print(f"  {name:9} modem says {m['state']:16} "
              f"CMTS says {cmts_state.get(m['mac'], 'offline'):10} "
              f"sid={str(m['sid'] or '-'):<4} ip={m['ip'] or '-':<15} "
              f"ranging={m['ranging_offset']} units "
              f"({m['ranging_offset_us']:.2f} us)"
              + (f"  online t={at:.3f}s" if at else ""))
    c = snap["cmts"]
    print(f"CMTS: " + ", ".join(f"{k}={v}" for k, v in c["stats"].items() if v))
    print(f"Plant: " + ", ".join(f"{k}={v}" for k, v in c["plant"].items() if v))
    if lab.opts.capture_path:
        print(f"Capture: {snap['capture']['packets']} packets -> "
              f"{lab.opts.capture_path}")
        print(f"  tshark -r {lab.opts.capture_path} -Y docsis_mgmt")
    print("=" * 72)


# ==========================================================================
# run (headless)
# ==========================================================================

def cmd_run(args) -> int:
    scenario = SCENARIOS.get(args.scenario)
    if scenario is None:
        print(f"unknown scenario {args.scenario!r}", file=sys.stderr)
        return 2
    topo = scenario.build()
    opts = LabOptions(speed=0.0,
                      capture_path=None if args.no_capture else args.capture,
                      echo=not args.quiet, echo_level=args.log_level,
                      mute=tuple(args.mute.split(",")) if args.mute else ())
    lab = Lab(topo, opts)
    apply_runtime(args.scenario, lab)
    lab.start()
    ok = lab.run_until_online(timeout=args.timeout)
    if args.settle:
        lab.sched.drain(args.settle)
    print()
    report(lab)
    lab.close()
    return 0 if ok else 1


# ==========================================================================
# cli
# ==========================================================================

BANNER_CLI = """docsislab CMTS shell -- 'help' for commands, 'exit' to leave.
Abbreviations work: 'sh ca mo' == 'show cable modem'.
"""


def cmd_cli(args) -> int:
    try:
        client = ControlClient(args.socket)
    except (FileNotFoundError, ConnectionRefusedError):
        print(f"no lab listening on {args.socket}. Start one with 'docsis up'.",
              file=sys.stderr)
        return 1
    if args.command:
        print(client.exec(" ".join(args.command)))
        client.close()
        return 0

    try:
        import readline  # noqa: F401  (enables line editing and history)
        histfile = os.path.expanduser("~/.docsislab_history")
        try:
            readline.read_history_file(histfile)
        except OSError:
            pass
    except ImportError:
        histfile = None

    snap = client.snapshot()
    prompt = f"{snap.get('cmts', {}).get('hostname', 'cmts')}# "
    print(BANNER_CLI)
    try:
        while True:
            try:
                line = input(prompt)
            except EOFError:
                print()
                break
            if line.strip() in ("exit", "quit", "logout"):
                break
            if not line.strip():
                continue
            try:
                out = client.exec(line)
            except (ConnectionError, OSError):
                print("% lab disconnected")
                break
            if out:
                print(out)
    except KeyboardInterrupt:
        print()
    finally:
        if histfile:
            try:
                import readline
                readline.write_history_file(histfile)
            except Exception:
                pass
        client.close()
    return 0


# ==========================================================================
# dash
# ==========================================================================

def cmd_dash(args) -> int:
    from .lab.dashboard import Dashboard
    try:
        client = ControlClient(args.socket)
    except (FileNotFoundError, ConnectionRefusedError):
        print(f"no lab listening on {args.socket}. Start one with 'docsis up'.",
              file=sys.stderr)
        return 1
    Dashboard(client, interval=args.interval).run()
    client.close()
    return 0


# ==========================================================================
# cfg
# ==========================================================================

def cmd_cfg(args) -> int:
    import json

    from .docsis import cfgfile
    from .lab.topology import DEFAULT_CM_CONFIG

    if args.action == "encode":
        spec = (json.load(open(args.source)) if args.source
                else dict(DEFAULT_CM_CONFIG))
        settings = cfgfile.build(spec)
        blob = cfgfile.encode(settings, args.secret.encode())
        if args.out:
            with open(args.out, "wb") as fh:
                fh.write(blob)
            print(f"wrote {args.out}: {len(blob)} bytes")
        else:
            sys.stdout.buffer.write(blob)
            return 0
        print()
        print(cfgfile.dump(blob))
        return 0

    if args.action == "decode":
        blob = open(args.source, "rb").read()
        settings = cfgfile.decode(blob)
        print(f"{args.source}: {len(blob)} bytes, {len(settings)} settings\n")
        print(cfgfile.dump(settings))
        result = cfgfile.verify(settings, args.secret.encode())
        print()
        print(f"MIC check with shared secret {args.secret!r}: {result.explain()}")
        return 0 if result.ok else 1

    if args.action == "forge":
        # Demonstrate why the CMTS MIC exists: rewrite the rate in a signed
        # config file and show that it stops verifying.
        blob = open(args.source, "rb").read()
        settings = cfgfile.decode(blob)
        from .docsis.consts import CfgTLV, SFTLV
        from .util import tlv
        changed = False
        for t in settings:
            if t.type == int(CfgTLV.UPSTREAM_SERVICE_FLOW):
                for sub in t.sub:
                    if sub.type == int(SFTLV.MAX_SUSTAINED_TRAFFIC_RATE):
                        old = sub.as_int
                        sub.value = (args.rate).to_bytes(4, "big")
                        print(f"rewrote upstream max sustained rate "
                              f"{old} -> {args.rate} bps")
                        changed = True
        if not changed:
            print("no upstream service flow rate to rewrite", file=sys.stderr)
            return 1
        # Recompute the CM MIC, which is exactly what an attacker would do:
        # it is an unkeyed digest, so anyone can make it match again.  That
        # leaves the CMTS MIC as the only thing standing in the way.
        core = [t for t in settings
                if t.type not in (int(CfgTLV.CM_MIC), int(CfgTLV.CMTS_MIC),
                                  int(CfgTLV.END_OF_DATA))]
        rebuilt = list(core)
        rebuilt.append(tlv.TLV(int(CfgTLV.CM_MIC), cfgfile.cm_mic(core)))
        rebuilt += [t for t in settings if t.type == int(CfgTLV.CMTS_MIC)]
        rebuilt += [t for t in settings if t.type == int(CfgTLV.END_OF_DATA)]
        print("recomputed the CM MIC so it matches the altered contents")
        settings = rebuilt
        forged = b"".join(t.encode() for t in settings)
        out = args.out or (args.source + ".forged")
        with open(out, "wb") as fh:
            fh.write(forged)
        print(f"wrote {out}: {len(forged)} bytes")
        result = cfgfile.verify(cfgfile.decode(forged), args.secret.encode())
        print()
        print(cfgfile.dump(forged))
        print()
        print(f"MIC check: {result.explain()}")
        print()
        print("The CM MIC now verifies: it is an unkeyed MD5 over the settings,")
        print("so anyone who edits the file can make it match again. It only ever")
        print("detected a corrupted download.")
        print()
        print("The CMTS MIC does not verify, and cannot be made to: it is salted")
        print("with a shared secret the modem never sees. A CMTS handed this file")
        print("recomputes the digest, gets a different answer, and replies REG-RSP")
        print("authentication failure -- the modem lands in reject(m).")
        print()
        print("  ./docsis run --scenario bad-secret   # watch that happen")
        return 0
    return 2


# ==========================================================================
# pcap
# ==========================================================================

TSHARK_CANDIDATES = [
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
    "tshark",
]


def find_tshark() -> str | None:
    import shutil
    for cand in TSHARK_CANDIDATES:
        if os.path.isabs(cand) and os.path.exists(cand):
            return cand
        found = shutil.which(cand)
        if found:
            return found
    return None


def cmd_pcap(args) -> int:
    import subprocess
    tshark = find_tshark()
    if tshark is None:
        print("tshark not found; install Wireshark to use this command",
              file=sys.stderr)
        return 1
    path = args.file
    if not os.path.exists(path):
        print(f"no such capture {path}", file=sys.stderr)
        return 1
    if args.filter:
        cmd = [tshark, "-r", path, "-Y", args.filter]
        if args.verbose:
            cmd.append("-V")
        return subprocess.run(cmd).returncode

    print(f"== {path} ==\n")
    subprocess.run([tshark, "-r", path, "-q", "-z", "io,phs"])

    counts = subprocess.run(
        [tshark, "-r", path, "-Y", "docsis_mgmt", "-T", "fields",
         "-e", "docsis_mgmt.type"], capture_output=True, text=True).stdout
    tally: dict[str, int] = {}
    for line in counts.splitlines():
        for value in line.split(","):
            if value.strip():
                tally[value.strip()] = tally.get(value.strip(), 0) + 1
    names = {"1": "SYNC", "2": "UCD (type 2, DOCSIS 1.x)", "3": "MAP",
             "4": "RNG-REQ", "5": "RNG-RSP", "6": "REG-REQ", "7": "REG-RSP",
             "8": "UCC-REQ", "9": "UCC-RSP", "14": "REG-ACK",
             "29": "UCD (type 29, DOCSIS 2.0)"}
    print("\n== MAC management messages by type ==")
    for key in sorted(tally, key=lambda k: int(k)):
        print(f"  {int(key):>3}  {names.get(key, 'type ' + key):28} {tally[key]:>6}")

    # SYNC and MAP are most of the frames and none of the story, so the
    # timeline leaves them out; `--filter docsis_mgmt` shows everything.
    print("\n== the exchange, without the SYNC and MAP chatter ==")
    res = subprocess.run(
        [tshark, "-r", path, "-Y", "docsis_mgmt.type not in {1,3}",
         "-T", "fields", "-E", "separator=\t",
         "-e", "frame.time_relative", "-e", "frame.interface_name",
         "-e", "_ws.col.info"], capture_output=True, text=True)
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            print(f"  {float(parts[0]):9.6f}  {parts[1]:<10} {parts[2]}")

    print("\n== dissector complaints (should be none) ==")
    res = subprocess.run([tshark, "-r", path, "-T", "fields",
                          "-e", "frame.number", "-e", "_ws.expert.message",
                          "-Y", "_ws.expert.severity > 1048576"],
                         capture_output=True, text=True)
    print(res.stdout.strip() or "  none -- every frame dissects cleanly")
    print("\n== useful display filters ==")
    for f, why in [
        ("docsis_mgmt.type == 1", "SYNC: the downstream timebase"),
        ("docsis_mgmt.type in {2,29}",
         "UCDs: type 2 is the DOCSIS 1.x view, type 29 the 2.0 one"),
        ("docsis_mgmt.type == 3", "MAPs: every mini-slot allocation"),
        ("docsis_mgmt.type in {4,5,6,7,14}",
         "ranging and registration only"),
        ("docsis.fcparm == 2", "Request frames (bandwidth requests)"),
        ("dhcp || tftp || time", "the provisioning exchange"),
        ("frame.interface_name == \"docsis-us\"", "upstream only"),
        # A plain !(...) would also match every frame where the field is
        # absent; "not in" only considers frames that have it.
        ("docsis_mgmt.type not in {1,3}",
         "everything except the SYNC/MAP chatter"),
        ("docsis_rngrsp.timingadj", "every timing correction the CMTS issued"),
        ("docsis.hcs.status != 1", "any bad header check sequence"),
        ("_ws.expert.severity > 1048576", "any dissector complaint"),
    ]:
        print(f"  {f:52} {why}")
    return 0


# ==========================================================================
# misc
# ==========================================================================

def cmd_scenarios(args) -> int:
    for name, s in SCENARIOS.items():
        print(f"{name}")
        print(f"    {s.description}")
        if s.watch:
            print(f"    watch for: {s.watch}")
    print("\nRun one with:  docsis up --scenario <name>")
    return 0


def cmd_docs(args) -> int:
    """Regenerate docs/REFERENCE.md, CLI.md, API.md and docs/README.md.

    They are derived from the code -- the constant tables, the argparse tree,
    the CLI command table and the modules' own docstrings -- so they cannot
    drift from the implementation.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(here, "tools"))
    import gen_docs
    argv = ["--check"] if args.check else []
    if args.out:
        argv += ["--out", args.out]
    return gen_docs.main(argv)


def cmd_doctor(args) -> int:
    import platform
    ok = True
    print(f"python      {sys.version.split()[0]} ({platform.machine()})")
    print(f"platform    {platform.platform()}")
    tshark = find_tshark()
    print(f"tshark      {tshark or 'NOT FOUND -- pcap inspection unavailable'}")
    if tshark:
        import subprocess
        v = subprocess.run([tshark, "-v"], capture_output=True, text=True)
        print(f"            {v.stdout.splitlines()[0]}")
    print(f"root        {'yes' if os.geteuid() == 0 else 'no -- utun CPE mode needs sudo'}")
    from .util.crc import HCS_VARIANT, hcs_bytes
    probe = hcs_bytes(bytes.fromhex("c0000018"))
    good = probe.hex() == "ce5b"
    ok &= good
    print(f"HCS         {HCS_VARIANT}, little-endian -> {probe.hex()} "
          f"{'(matches Wireshark)' if good else '(MISMATCH)'}")
    try:
        lab = Lab(Topology(), LabOptions(speed=0, capture_path=None, echo=False))
        lab.start()
        got = lab.run_until_online(timeout=20.0)
        print(f"self test   modem reached operational: {got} "
              f"(t={lab.sched.now():.3f}s simulated)")
        ok &= got
        lab.close()
    except Exception as exc:
        print(f"self test   FAILED: {type(exc).__name__}: {exc}")
        ok = False
    print()
    print("ready" if ok else "problems found")
    return 0 if ok else 1


# ==========================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="docsis", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--scenario", default="default",
                        help="which situation to run (see 'docsis scenarios')")
        sp.add_argument("--capture", default=DEFAULT_CAPTURE,
                        help="pcapng output path")
        sp.add_argument("--no-capture", action="store_true")
        sp.add_argument("--quiet", action="store_true",
                        help="do not echo the event log to stdout")
        sp.add_argument("--log-level", default="info",
                        choices=["debug", "info", "notice", "warn", "error"])
        sp.add_argument("--mute", default="map,sync",
                        help="comma-separated log categories to suppress "
                             "(default: map,sync -- the per-MAP chatter)")

    up = sub.add_parser("up", help="run the lab")
    add_common(up)
    up.add_argument("--speed", type=float, default=1.0,
                    help="time scale; 1.0 is real time, 0 runs as fast as possible")
    up.add_argument("--duration", type=float, default=0.0,
                    help="stop after this many simulated seconds")
    up.add_argument("--socket", default=DEFAULT_SOCKET)
    up.add_argument("--no-comments", action="store_true",
                    help="omit the explanatory pcapng packet comments")
    up.add_argument("--upstreams", type=int, default=1, choices=[1, 2])
    up.add_argument("--modems", type=int, default=None)
    up.add_argument("--distance", type=float, default=None,
                    help="override every modem's distance from the CMTS, km")
    up.add_argument("--us-loss", type=float, default=0.0,
                    help="upstream burst loss, percent")
    up.add_argument("--ds-loss", type=float, default=0.0)
    up.add_argument("--cpe", default="sim", choices=["sim", "utun", "none"],
                    help="sim: a simulated host (no privileges). "
                         "utun: a real macOS interface, needs sudo")
    up.add_argument("--cpe-ip", default="10.20.0.10")
    up.set_defaults(func=cmd_up)

    run = sub.add_parser("run", help="run headless until online, then report")
    add_common(run)
    run.add_argument("--timeout", type=float, default=30.0)
    run.add_argument("--settle", type=float, default=0.0,
                     help="keep running this long after everything is online")
    run.set_defaults(func=cmd_run)

    cli = sub.add_parser("cli", help="attach a CMTS-style shell")
    cli.add_argument("--socket", default=DEFAULT_SOCKET)
    cli.add_argument("command", nargs="*",
                     help="run one command and exit")
    cli.set_defaults(func=cmd_cli)

    dash = sub.add_parser("dash", help="attach the live dashboard")
    dash.add_argument("--socket", default=DEFAULT_SOCKET)
    dash.add_argument("--interval", type=float, default=0.25)
    dash.set_defaults(func=cmd_dash)

    cfg = sub.add_parser("cfg", help="DOCSIS configuration file tool")
    cfg.add_argument("action", choices=["encode", "decode", "forge"])
    cfg.add_argument("source", nargs="?",
                     help="JSON spec (encode) or binary config file "
                          "(decode/forge)")
    cfg.add_argument("--out")
    cfg.add_argument("--secret", default="docsislab")
    cfg.add_argument("--rate", type=int, default=100_000_000,
                     help="for 'forge': the upstream rate to substitute")
    cfg.set_defaults(func=cmd_cfg)

    pcap = sub.add_parser("pcap", help="summarise a capture through tshark")
    pcap.add_argument("file", nargs="?", default=DEFAULT_CAPTURE)
    pcap.add_argument("--filter", "-Y", dest="filter")
    pcap.add_argument("--verbose", "-V", action="store_true")
    pcap.set_defaults(func=cmd_pcap)

    sc = sub.add_parser("scenarios", help="list the built-in scenarios")
    sc.set_defaults(func=cmd_scenarios)

    docs = sub.add_parser("docs", help="regenerate the reference documentation")
    docs.add_argument("--check", action="store_true",
                      help="exit non-zero if the docs on disk are stale")
    docs.add_argument("--out", default=None,
                      help="write somewhere other than docs/")
    docs.set_defaults(func=cmd_docs)

    doc = sub.add_parser("doctor", help="check the environment and self-test")
    doc.set_defaults(func=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
