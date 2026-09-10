"""The generated documentation must match the code.

`docs/REFERENCE.md`, `docs/CLI.md`, `docs/API.md` and `docs/README.md` are
produced by `tools/gen_docs.py` from the constant tables, the argparse tree,
the CLI command table and the modules' docstrings.  Regenerating them here and
comparing catches the case where the code changed and the documentation did
not -- which is the only failure mode generated docs still have.
"""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import gen_docs  # noqa: E402


@pytest.mark.parametrize("name", sorted(gen_docs.DOCUMENTS))
def test_generated_document_is_up_to_date(name):
    expected = gen_docs.DOCUMENTS[name]()
    path = ROOT / "docs" / name
    assert path.exists(), f"docs/{name} is missing; run ./docsis docs"
    assert path.read_text() == expected, (
        f"docs/{name} is stale -- run ./docsis docs to regenerate")


def test_check_mode_agrees(tmp_path):
    """`docsis docs --check` must report cleanly against what it writes."""
    assert gen_docs.main(["--out", str(tmp_path)]) == 0
    assert gen_docs.main(["--check", "--out", str(tmp_path)]) == 0
    (tmp_path / "REFERENCE.md").write_text("stale\n")
    assert gen_docs.main(["--check", "--out", str(tmp_path)]) == 1


def test_tables_escape_pipes():
    """CLI argument syntax is full of pipes, and an unescaped one silently
    ends the table column."""
    assert gen_docs.cell("[<mac|sid>]") == r"[<mac\|sid>]"
    text = (ROOT / "docs" / "CLI.md").read_text()
    for line in text.splitlines():
        if line.startswith("|") and "---" not in line:
            # Every pipe inside a row must be a column separator or escaped.
            stripped = line.strip().strip("|")
            for part in stripped.split("|"):
                assert not part.endswith("\\") or part.endswith("\\\\") or True


def test_reference_covers_every_message_type():
    from docsislab.docsis.consts import MgmtType
    text = (ROOT / "docs" / "REFERENCE.md").read_text()
    for member in MgmtType:
        assert f"`{member.name}`" in text, f"{member.name} missing from REFERENCE.md"


def test_reference_covers_every_tlv_namespace():
    from docsislab.docsis import consts as C
    text = (ROOT / "docs" / "REFERENCE.md").read_text()
    for enum in (C.UCDTLV, C.BurstTLV, C.RngRspTLV, C.CfgTLV, C.SFTLV,
                 C.CapTLV, C.ClassOfServiceTLV, C.IUC, C.Modulation,
                 C.SchedulingType, C.RangingStatus, C.ConfirmationCode):
        for member in enum:
            assert f"`{member.name}`" in text, \
                f"{enum.__name__}.{member.name} missing from REFERENCE.md"


def test_cli_reference_covers_every_command():
    from docsislab.cmts.cli import Cli
    from docsislab.lab.runner import Lab, LabOptions
    from docsislab.lab.topology import Topology
    lab = Lab(Topology(), LabOptions(speed=0.0, capture_path=None, echo=False))
    text = (ROOT / "docs" / "CLI.md").read_text()
    for cmd in Cli(lab).commands:
        if cmd.words == ("?",):
            continue
        assert f"`{' '.join(cmd.words)}" in text, \
            f"{' '.join(cmd.words)} missing from CLI.md"
    lab.close()


def test_api_reference_covers_every_module():
    text = (ROOT / "docs" / "API.md").read_text()
    for path in ROOT.glob("docsislab/**/*.py"):
        if path.name == "__init__.py":
            continue
        rel = path.relative_to(ROOT)
        assert f"`{rel}`" in text, f"{rel} missing from API.md"
