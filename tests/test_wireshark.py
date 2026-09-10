"""Validate the wire format against Wireshark's DOCSIS dissector.

Wireshark's dissector is an independently maintained implementation of the
same specification, which makes it the best available check that these bytes
are actually DOCSIS and not merely self-consistent.  Every field name asserted
here was chosen because getting it wrong is both easy and silent.

Skipped when tshark is not installed.
"""

import os
import subprocess
import tempfile

import pytest

from docsislab.lab.runner import Lab, LabOptions
from docsislab.lab.topology import Topology

TSHARK = None
for candidate in ("/Applications/Wireshark.app/Contents/MacOS/tshark",
                  "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"):
    if os.path.exists(candidate):
        TSHARK = candidate
        break
if TSHARK is None:
    import shutil
    TSHARK = shutil.which("tshark")

pytestmark = pytest.mark.skipif(TSHARK is None, reason="tshark not installed")

#: Severity of a pcapng packet comment, which tshark reports as expert info.
COMMENT_SEVERITY = 1048576


@pytest.fixture(scope="module")
def capture():
    path = os.path.join(tempfile.mkdtemp(), "docsis-test.pcapng")
    lab = Lab(Topology(), LabOptions(speed=0.0, capture_path=path, echo=False))
    lab.start()
    assert lab.run_until_online(timeout=20.0)
    lab.sched.drain(1.5)
    cpe = lab.cpes["cpe0"]
    if cpe.ip:
        cpe.ping("10.30.0.2", count=2, interval=0.05)
        lab.sched.drain(1.0)
    lab.close()
    return path


def fields(capture, *names, display_filter=None):
    cmd = [TSHARK, "-r", capture, "-T", "fields", "-E", "separator=\t"]
    for name in names:
        cmd += ["-e", name]
    if display_filter:
        cmd += ["-Y", display_filter]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    rows = [line.split("\t") for line in res.stdout.splitlines()]
    # Keep rows where at least one requested field produced a value.
    return [r for r in rows if any(cell.strip() for cell in r)]


# --------------------------------------------------------------------------

def test_the_capture_dissects_as_docsis(capture):
    rows = fields(capture, "frame.number", display_filter="docsis")
    assert len(rows) > 100, "DLT 143 should be dissected as DOCSIS"


def test_every_header_check_sequence_is_good(capture):
    bad = fields(capture, "frame.number", "docsis.hcs",
                 display_filter="docsis.hcs.status != 1")
    assert bad == [], f"frames with a bad HCS: {bad}"


def test_no_dissector_complaints(capture):
    """Anything above comment severity means Wireshark thinks a frame is
    malformed or a length is wrong."""
    rows = fields(capture, "frame.number", "_ws.expert.message",
                  display_filter=f"_ws.expert.severity > {COMMENT_SEVERITY}")
    assert rows == [], f"dissector complaints: {rows}"


def test_the_expected_management_messages_are_all_present(capture):
    rows = fields(capture, "docsis_mgmt.type", display_filter="docsis_mgmt")
    seen = {int(r[0].split(",")[0]) for r in rows if r[0]}
    for msg_type, name in [(1, "SYNC"), (2, "type 2 UCD"), (3, "MAP"),
                           (4, "RNG-REQ"), (5, "RNG-RSP"), (6, "REG-REQ"),
                           (7, "REG-RSP"), (14, "REG-ACK"),
                           (29, "type 29 UCD")]:
        assert msg_type in seen, f"{name} (type {msg_type}) missing"


def test_both_ucd_flavours_describe_the_same_upstream(capture):
    """Mixed mode: the type-2 UCD is the DOCSIS 1.x view of the channel and
    the type-29 UCD the 2.0 view, and both must name the same channel."""
    legacy = fields(capture, "docsis_mgmt.upchid", "docsis_ucd.confcngcnt",
                    display_filter="docsis_mgmt.type == 2")
    modern = fields(capture, "docsis_mgmt.upchid", "docsis_ucd.confcngcnt",
                    display_filter="docsis_mgmt.type == 29")
    assert legacy and modern
    assert legacy[0][0] == modern[0][0]
    assert legacy[0][1] == modern[0][1]


def test_map_is_version_1(capture):
    """DOCSIS 3.1 reused version 5 for a different MAP layout, so anything
    other than 1 here stops decoders parsing the body at all."""
    rows = fields(capture, "docsis_mgmt.version",
                  display_filter="docsis_mgmt.type == 3")
    assert rows
    assert {r[0] for r in rows} == {"1"}


def test_map_carries_the_expected_interval_usage_codes(capture):
    from docsislab.docsis.consts import IUC
    rows = fields(capture, "docsis_map.ie",
                  display_filter="docsis_map.ie")
    words = []
    for row in rows:
        for value in row[0].split(","):
            if value:
                words.append(int(value, 0))
    iucs = {(w >> 14) & 0x0F for w in words}
    for iuc in (IUC.REQUEST, IUC.INITIAL_MAINT, IUC.STATION_MAINT, IUC.NULL_IE):
        assert int(iuc) in iucs, f"IUC {int(iuc)} never appeared in a MAP"
    assert (int(IUC.ADV_PHY_SHORT_DATA) in iucs
            or int(IUC.ADV_PHY_LONG_DATA) in iucs), \
        "no DOCSIS 2.0 advanced-PHY grant was ever issued"


def test_ranging_response_timing_adjust_is_decoded(capture):
    rows = fields(capture, "docsis_rngrsp.timingadj",
                  display_filter="docsis_rngrsp.timingadj")
    assert rows, "no RNG-RSP timing adjustment found"
    values = [int(r[0].split(",")[0]) for r in rows if r[0]]
    # The first correction is the whole round trip for a 10 km plant.
    assert max(abs(v) for v in values) > 700


def test_reg_req_reports_docsis_version_20(capture):
    rows = fields(capture, "docsis_tlv.map.docsver",
                  display_filter="docsis_mgmt.type == 6")
    assert rows, "REG-REQ carried no Modem Capabilities / DOCSIS Version"
    assert "2" in rows[0][0]


def test_request_frames_are_dissected(capture):
    """FC_TYPE 3 / FC_PARM 2: a bare six-byte bandwidth request, where
    MAC_PARM is a mini-slot count and LEN/SID is a SID rather than a length."""
    rows = fields(capture, "docsis.ehdr.sid", "docsis.ehdr.minislots",
                  display_filter="docsis.fcparm == 2")
    assert rows, "no Request frames in the capture"
    assert all(int(r[1]) > 0 for r in rows), "a request must ask for mini-slots"
    assert all(int(r[0]) > 0 for r in rows), "a request must name its SID"
    lengths = fields(capture, "frame.len", display_filter="docsis.fcparm == 2")
    assert {r[0] for r in lengths} == {"6"}, "a Request frame is exactly 6 bytes"


def test_provisioning_rides_inside_docsis_packet_pdus(capture):
    """The point of the capture: DHCP, ToD and TFTP visible *through* the
    DOCSIS MAC layer, not just on the network side."""
    for proto in ("dhcp", "tftp", "time"):
        rows = fields(capture, "frame.number",
                      display_filter=f"docsis && {proto}")
        assert rows, f"{proto} never appeared inside a DOCSIS Packet PDU"


def test_upstream_and_downstream_are_separate_interfaces(capture):
    """DLT 143 has no direction bit, so the pcapng interface is what tells a
    CMTS transmission from a modem transmission."""
    names = {r[0] for r in fields(capture, "frame.interface_name")}
    assert {"docsis-ds", "docsis-us"} <= names


def test_packet_comments_explain_what_the_simulation_was_doing(capture):
    rows = fields(capture, "frame.comment",
                  display_filter="frame.comment contains \"RNG-REQ\"")
    assert rows, "ranging frames should carry an explanatory comment"


#: Every display filter the README, the docs and `docsis pcap` suggest.
#: Wireshark's set syntax needs commas -- `{1 3}` parses but matches the wrong
#: thing -- so these are worth checking rather than trusting.
DOCUMENTED_FILTERS = [
    "docsis",
    "docsis_mgmt",
    "docsis_mgmt.type not in {1,3}",
    "docsis_mgmt.type in {2,29}",
    "docsis_mgmt.type in {4,5}",
    "docsis_mgmt.type in {6,7,14}",
    "docsis_mgmt.type == 1",
    "docsis_mgmt.type == 3",
    "docsis.fcparm == 2",
    "docsis_map.ie",
    "docsis_rngrsp.timingadj",
    "docsis_tlv.map.docsver",
    "dhcp || tftp || time",
    "docsis && dhcp",
    'frame.interface_name == "docsis-us"',
    'frame.interface_name == "docsis-ds"',
    "frame.comment",
    "docsis.hcs.status != 1",
    f"_ws.expert.severity > {COMMENT_SEVERITY}",
]


@pytest.mark.parametrize("display_filter", DOCUMENTED_FILTERS)
def test_documented_filter_is_valid(capture, display_filter):
    res = subprocess.run([TSHARK, "-r", capture, "-Y", display_filter],
                         capture_output=True, text=True)
    assert res.returncode == 0, f"{display_filter!r}: {res.stderr.strip()}"


@pytest.mark.parametrize("display_filter,least", [
    ("docsis_mgmt.type not in {1,3}", 8),   # ranging + registration + UCDs
    ("docsis_mgmt.type in {4,5}", 4),       # at least two ranging exchanges
    ("docsis_mgmt.type in {6,7,14}", 3),    # REG-REQ, REG-RSP, REG-ACK
    ("docsis_mgmt.type in {2,29}", 2),      # both UCD flavours
    ("docsis.fcparm == 2", 3),              # bandwidth requests
    ("docsis && dhcp", 2),                  # DHCP inside the DOCSIS MAC layer
])
def test_documented_filter_actually_matches(capture, display_filter, least):
    """A filter that parses but matches nothing is no more useful than a
    broken one."""
    rows = fields(capture, "frame.number", display_filter=display_filter)
    assert len(rows) >= least, f"{display_filter!r} matched only {len(rows)}"
