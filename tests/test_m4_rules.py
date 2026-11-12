"""Module 4: rule engine and globals()/locals() audit."""

from collections import defaultdict

from log_engine.rules import (
    apply_security_rules,
    audit_scope,
    blacklisted_ip,
    critical_level,
)


def test_rule_engine_and_audit(rec):
    r = rec("bad", "event", "CRITICAL")
    hits = apply_security_rules(
        blacklisted_ip, critical_level, record=r, blacklist=frozenset({"bad"})
    )
    assert set(hits) == {"blacklisted_ip", "critical_level"}
    audit = audit_scope(
        {"api_key": "s3cr3t", "counts": defaultdict(int), "__name__": "x"}
    )
    assert audit["api_key"]["repr"] == "***" and "__name__" not in audit
