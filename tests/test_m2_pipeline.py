"""Acceptance tests for issue #2 (Module 2: pipeline)."""

from log_engine.ingestion import parse_line
from log_engine.pipeline import is_ip, normalise, route
from main import main

ESC_LINE = "2026-11-04T10:15:32Z CRITICAL 10.0.0.1 user=root\x1b]0;hacked\x07 code=401"


def test_blank_lines_are_counted_apart_from_rejects(tmp_path, capsys):
    log = tmp_path / "blank.log"
    log.write_text("\n   \n###corrupted###\n2026-11-04T10:15:32Z INFO 10.0.0.9\n")
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
