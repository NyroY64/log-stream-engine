import json
import types
from collections import defaultdict

from log_engine.aggregation import Stats, blacklist_report, detect_brute_force
from log_engine.ingestion import parse_line, read_sources
from log_engine.pipeline import build_pipeline, route
from log_engine.rules import (
    apply_security_rules,
    audit_scope,
    blacklisted_ip,
    critical_level,
)

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


def rec(ip, kind, level="ERROR"):
    return {
        "src_ip": ip,
        "kind": kind,
        "level": level,
        "user_id": None,
        "meta": None,
        "line": "",
    }


def test_brute_force_break_reset_and_else():
    events = (
        [rec("x", "auth_failure")] * 2
        + [rec("x", "auth_success")]
        + [rec("x", "raw")]
        + [rec("x", "auth_failure")] * 3
        + [rec("y", "auth_failure")]
    )
    cycles: list[bool] = []
    assert list(detect_brute_force(events, 3, cycles)) == [("x", 3)]
    assert cycles == [False, True]


def test_sets_and_counters():
    stats = Stats()
    list(stats.tally([rec("a", "event"), rec("b", "event", "INFO")]))
    assert stats.error_ips == {"a"} and stats.by_level["WARNING"] == 0
    ops = blacklist_report(frozenset({"a", "z"}), stats.active_ips)
    assert ops["intersection"] == {"a"} and ops["symmetric_difference"] == {
        "b",
        "z",
    }


def test_rule_engine_and_audit():
    r = rec("bad", "event", "CRITICAL")
    hits = apply_security_rules(
        blacklisted_ip, critical_level, record=r, blacklist=frozenset({"bad"})
    )
    assert set(hits) == {"blacklisted_ip", "critical_level"}
    audit = audit_scope(
        {"api_key": "s3cr3t", "counts": defaultdict(int), "__name__": "x"}
    )
    assert audit["api_key"]["repr"] == "***" and "__name__" not in audit
