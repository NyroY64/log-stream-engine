"""Module 1: lazy reading and parsing of log lines."""

import types

import pytest

from log_engine.ingestion import parse_line, read_lines, read_sources
from main import main

MIB = 1 << 20
TS = "2026-11-04T10:15:32Z"
EVENT = (
    "2026-11-04T10:15:32Z error 192.168.1.10 user=Alice code=401 port=22/TCP"
    ' {"msg": "Failed password"}'
)


def test_read_sources_is_lazy_and_chains_files(tmp_path):
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text("a1\na2\n")
    b.write_text("b1\n")
    gen = read_sources(a, b)
    assert isinstance(gen, types.GeneratorType)
    assert list(gen) == ["a1", "a2", "b1"]


def test_parse_line_shapes():
    assert parse_line(EVENT)["meta"] == ("192.168.1.10", 22, "TCP")
    assert parse_line(EVENT)["payload"] == {"msg": "Failed password"}
    assert parse_line("CONN 203.0.113.7 22 tcp") == ("203.0.113.7", 22, "TCP")
    assert parse_line("kernel: eth0 link up") == "kernel: eth0 link up"
    assert parse_line("###corrupted###") is None
    assert parse_line("{not json") is None


def test_a_line_never_exceeds_one_mib(tmp_path):
    log = tmp_path / "flat.log"
    log.write_text("a" * (3 * MIB))
    lengths = [len(line) for line in read_lines(log)]
    assert max(lengths) <= MIB
    assert sum(lengths) == 3 * MIB


def test_deeply_nested_json_line_is_rejected_not_a_crash():
    assert parse_line('{"a":' + "[" * 200_000) is None


def test_deeply_nested_payload_stays_text():
    payload = "[" * 200_000
    assert parse_line(f"{TS} INFO 10.0.0.9 {payload}")["payload"] == payload


def test_a_5000_digit_code_is_not_a_code():
    assert parse_line(f"{TS} INFO 10.0.0.9 code={'9' * 5000}")["code"] is None


@pytest.mark.parametrize(
    "line",
    [
        "CONN 1.1.1.1 ²² TCP",
        "CONN 1.1.1.1 65536 TCP",
        f"CONN 1.1.1.1 {'9' * 5000} TCP",
    ],
)
def test_bad_ports_are_not_connections(line):
    assert not isinstance(parse_line(line), tuple)


def test_port_limits_are_inclusive():
    assert parse_line("CONN 1.1.1.1 0 TCP") == ("1.1.1.1", 0, "TCP")
    assert parse_line("CONN 1.1.1.1 65535 tcp") == ("1.1.1.1", 65535, "TCP")


def test_a_hostile_file_runs_to_the_end(tmp_path):
    log = tmp_path / "hostile.log"
    lines = [
        '{"a":' + "[" * 200_000,
        f"{TS} INFO 10.0.0.9 code={'9' * 5000}",
        "CONN 1.1.1.1 ²² TCP",
        f"{TS} INFO 10.0.0.9",
    ]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main([str(log), "--audit", str(tmp_path / "audit.json")]) == 0


def test_a_5000_digit_json_number_is_rejected_not_a_crash():
    assert parse_line('{"level": "INFO", "code": ' + "9" * 5000 + "}") is None
    assert (
        parse_line(f"{TS} INFO 10.0.0.9 [{'9' * 5000}]")["payload"]
        == f"[{'9' * 5000}]"
    )


def test_an_unwritable_audit_path_is_a_clean_error(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text(f"{TS} INFO 10.0.0.9\n")
    blocker = tmp_path / "file"
    blocker.write_text("")
    assert main([str(log), "--audit", str(blocker / "audit.json")]) == 1
    assert capsys.readouterr().err.startswith("error:")
