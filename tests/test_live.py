"""Live mode: follow a growing file and print events as they happen."""

import pytest

from log_engine.ingestion import follow_lines
from main import main


def test_follow_waits_for_the_end_of_a_line(tmp_path):
    log = tmp_path / "live.log"
    log.write_text("a\nb")  # "b" is still being written
    lines = follow_lines(log, poll=0.01)
    assert next(lines) == "a"
    with open(log, "a") as f:
        f.write("c\nd\n")
    assert next(lines) == "bc"
    assert next(lines) == "d"


def test_live_simulation_prints_lines_findings_and_report(tmp_path, capsys):
    audit = str(tmp_path / "audit.json")
    argv = ["--simulate", "300", "--rate", "100000", "--audit", audit]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "[LOG]" in out and "[FIND]" in out and "[AUDIT]" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["a.log", "b.log", "--follow"],
        ["--simulate", "10", "--follow"],
        ["a.log", "--rate", "5"],
        ["--simulate", "10", "--rate", "0"],
    ],
)
def test_bad_live_options_are_rejected(argv):
    with pytest.raises(SystemExit):
        main(argv)
