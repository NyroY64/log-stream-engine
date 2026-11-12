"""Module 4: flexible rule engine and scope audit."""

import inspect
import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from types import FunctionType, ModuleType

Rule = Callable[..., str | None]
RULES: list[Rule] = []
SENSITIVE = ("password", "secret", "token", "key")
SUSPICIOUS_PORTS = frozenset({23, 445, 3389, 4444})


def security_rule(func: Rule) -> Rule:
    """Register a rule so main can pass every rule with *RULES."""
    RULES.append(func)
    return func


@security_rule
def blacklisted_ip(
    record: dict, blacklist: frozenset[str] = frozenset(), **_: object
) -> str | None:
    if record["src_ip"] in blacklist:
        return f"blacklisted IP {record['src_ip']}"
    return None


@security_rule
def critical_level(record: dict, **_: object) -> str | None:
    return (
        f"critical event: {record['line']}"
        if record["level"] == "CRITICAL"
        else None
    )


@security_rule
def suspicious_port(
    record: dict, ports: frozenset[int] = SUSPICIOUS_PORTS, **_: object
) -> str | None:
    match record["meta"]:
        case (ip, int(port), proto) if port in ports:
            return f"{ip} used port {port}/{proto}"
    return None


@security_rule
def privileged_failure(
    record: dict, privileged: tuple[str, ...] = ("root", "admin"), **_: object
) -> str | None:
    if record["kind"] == "auth_failure" and record["user_id"] in privileged:
        return f"failed login for {record['user_id']} from {record['src_ip']}"
    return None


def apply_security_rules(*args: Rule, **kwargs: object) -> dict[str, str]:
    """Run every rule in args with the settings in kwargs; keep the hits."""
    return {rule.__name__: msg for rule in args if (msg := rule(**kwargs))}


def describe_rules(rules: Iterable[Rule]) -> dict[str, str]:
    """Map each rule name to its parameters, read with inspect."""
    return {r.__name__: str(inspect.signature(r)) for r in rules}


def check_rules(
    records: Iterable[dict],
    rules: Iterable[Rule],
    findings: defaultdict[str, list[str]],
    hits: defaultdict[str, int],
    max_samples: int = 20,
    on_hit: Callable[[str, str], None] | None = None,
    **config: object,
) -> Iterator[dict]:
    """Apply the rules to each record, count hits, keep a few samples."""
    rules = tuple(rules)
    for rec in records:
        for name, msg in apply_security_rules(
            *rules, record=rec, **config
        ).items():
            hits[name] += 1
            if on_hit:
                on_hit(name, msg)
            # bounded: memory must not grow with the number of hits
            if len(findings[name]) < max_samples:
                findings[name].append(msg)
        yield rec


def _describe(value: object) -> dict:
    info: dict = {"type": type(value).__name__}
    try:
        info["size"] = len(value)  # type: ignore[arg-type]
    except TypeError:
        pass
    info["repr"] = repr(value)[:80]
    return info


def audit_scope(scope: dict[str, object]) -> dict[str, dict]:
    """Describe a scope's variables; skip modules and dunders, mask secrets."""
    report = {}
    for name, value in scope.items():
        if name.startswith("__") or isinstance(value, ModuleType):
            continue
        info = _describe(value)
        if any(word in name.lower() for word in SENSITIVE):
            info["repr"] = "***"
        if isinstance(value, FunctionType):
            info["repr"] = f"function {value.__module__}.{value.__qualname__}"
        report[name] = info
    return report


def export_audit(
    globals_: dict[str, object], locals_: dict[str, object], path: str | Path
) -> Path:
    """Write the globals() and locals() audit as JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"globals": audit_scope(globals_), "locals": audit_scope(locals_)}
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
