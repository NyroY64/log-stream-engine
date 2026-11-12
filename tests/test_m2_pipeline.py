"""Module 2: filter/map pipeline, match-case routing and normalising."""

import json

from log_engine.ingestion import parse_line
from log_engine.pipeline import build_pipeline, is_ip, normalise, route
from main import main

EVENT = (
    "2026-11-04T10:15:32Z error 192.168.1.10 user=Alice code=401 port=22/TCP"
    ' {"msg": "Failed password"}'
)
ESC_LINE = (
    "2026-11-04T10:15:32Z CRITICAL 10.0.0.1 user=root\x1b]0;hacked\x07"
    " code=401"
)


def test_blank_lines_are_counted_apart_from_rejects(tmp_path, capsys):
    log = tmp_path / "blank.log"
    log.write_text(
        "\n   \n###corrupted###\n2026-11-04T10:15:32Z INFO 10.0.0.9\n"
    )
    assert main([str(log), "--audit", str(tmp_path / "audit.json")]) == 0
    assert "read 4, accepted 1, rejected 1, blank 2" in capsys.readouterr().out


def test_record_text_is_printable():
    record = normalise(route(parse_line(ESC_LINE)))
    assert record["line"].isprintable()
    assert record["user_id"].isprintable()


def test_no_control_code_reaches_the_terminal(tmp_path, capsys):
    log = tmp_path / "esc.log"
    log.write_text(ESC_LINE + "\n", encoding="utf-8")
    assert main([str(log), "--audit", str(tmp_path / "audit.json")]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out


def test_is_ip_is_cached():
    is_ip.cache_clear()
    is_ip("10.0.0.1")
    is_ip("10.0.0.1")
    assert is_ip.cache_info().hits == 1


def test_json_meta_becomes_a_safe_tuple(tmp_path, capsys):
    line = json.dumps(
        {
            "level": "INFO",
            "src_ip": "1.2.3.4",
            "meta": ["\x1b]0;x\x07", 4444, "tcp"],
        }
    )
    record = normalise(route(parse_line(line)))
    assert isinstance(record["meta"], tuple)
    assert all(map(str.isprintable, record["meta"][::2]))
    log = tmp_path / "meta.log"
    log.write_text(line + "\n", encoding="utf-8")
    assert main([str(log), "--live", "--audit", str(tmp_path / "a.json")]) == 0
    out = capsys.readouterr().out
    assert "suspicious_port" in out and "\x1b" not in out and "\x07" not in out


def test_route_and_pipeline_normalise_and_reject():
    assert route(parse_line(EVENT))["kind"] == "auth_failure"
    assert route(("1.2.3.4", 80, "TCP"))["kind"] == "connection"
    lines = [
        EVENT,
        "",
        "###corrupted###",
        "2026-11-04T10:15:32Z LOUD 1.2.3.4",
        "2026-11-04T10:15:32Z INFO 999.1.1.1",
        json.dumps({"level": " warning "}),
    ]
    out = list(build_pipeline(lines))
    assert [r["level"] for r in out] == ["ERROR", "WARNING"]
    assert out[0]["user_id"] == "alice"
