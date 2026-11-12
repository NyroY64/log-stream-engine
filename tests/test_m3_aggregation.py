"""Module 3: sets, counters and brute-force detection."""

from log_engine.aggregation import Stats, blacklist_report, detect_brute_force


def test_brute_force_break_reset_and_else(rec):
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


def test_sets_and_counters(rec):
    stats = Stats()
    list(stats.tally([rec("a", "event"), rec("b", "event", "INFO")]))
    assert stats.error_ips == {"a"} and stats.by_level["WARNING"] == 0
    ops = blacklist_report(frozenset({"a", "z"}), stats.active_ips)
    assert ops["intersection"] == {"a"} and ops["symmetric_difference"] == {
        "b",
        "z",
    }
