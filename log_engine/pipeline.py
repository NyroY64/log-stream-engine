"""Module 2: lazy transformation chain of filter, map and match-case."""

import ipaddress
from collections.abc import Iterable, Iterator
from datetime import datetime
from functools import lru_cache
from typing import cast

from log_engine.ingestion import Parsed, parse_line

LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")
DEFAULTS: dict = {
    "timestamp": None,
    "level": "INFO",
    "src_ip": None,
    "user_id": None,
    "code": None,
    "payload": None,
    "meta": None,
}


def route(item: Parsed) -> dict | None:
    """Turn every parsed shape into one record dict via match-case."""
    # cast: mypy does not narrow mapping patterns,
    # the case already proved rec is a dict
    match item:
        case str() as raw:
            return {**DEFAULTS, "payload": raw, "kind": "raw"}
        case (str() as ip, int() as port, str() as proto):
            return {
                **DEFAULTS,
                "src_ip": ip,
                "meta": (ip, port, proto),
                "payload": f"{proto} connection on port {port}",
                "kind": "connection",
            }
        case {"code": 401 | 403} as rec:
            return {**DEFAULTS, **cast(dict, rec), "kind": "auth_failure"}
        case {"code": 200, "user_id": str()} as rec:
            return {**DEFAULTS, **cast(dict, rec), "kind": "auth_success"}
        case {"level": str()} as rec:
            return {**DEFAULTS, **cast(dict, rec), "kind": "event"}
        case _:
            return None


def printable(text: str) -> str:
    """Escape control characters (ESC as \\x1b) so logs cannot drive a tty."""
    return text if text.isprintable() else repr(text)[1:-1]


def normalise(record: dict) -> dict:
    """Clean strings, fix case, and add a display line."""
    level = str(record["level"]).strip().upper()
    user = (
        printable(record["user_id"].strip().lower())
        if record["user_id"]
        else None
    )
    ip = record["src_ip"].strip() if record["src_ip"] else None
    ts = record["timestamp"]
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    when = ts.strftime("%H:%M:%S") if ts else "--:--:--"
    ip_text, code = ip or "-", record["code"] or ""
    return {
        **record,
        "timestamp": ts,
        "level": level,
        "user_id": user,
        "src_ip": ip,
        "line": printable(
            f"[{when}] {level:<8} {ip_text:<15} {user or '-'} {code}".rstrip()
        ),
    }


@lru_cache(maxsize=65536)  # the same IPs repeat on most lines
def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def safe_normalise(record: dict) -> dict | None:
    try:
        return normalise(record)
    except (
        ValueError,
        AttributeError,
    ):  # bad timestamp string or non-str field
        return None


def build_pipeline(lines: Iterable[str]) -> Iterator[dict]:
    """Chain lazy stages; nothing runs until the result is iterated."""
    non_empty = filter(None, map(str.strip, lines))
    records = filter(None, map(route, map(parse_line, non_empty)))
    cleaned = filter(None, map(safe_normalise, records))
    return filter(
        lambda r: r["level"] in LEVELS
        and (r["src_ip"] is None or is_ip(r["src_ip"])),
        cleaned,
    )
