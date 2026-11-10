"""Module 1: lazy ingestion and parsing of log lines."""

import json
import re
from collections.abc import Iterator
from datetime import datetime
from functools import partial
from pathlib import Path

# Line formats (see data/auth.log):
#   2026-11-04T10:15:32Z ERROR 192.168.1.10 user=alice code=401 port=22/TCP \
#       {"msg": "Failed password"}
#   {"timestamp": "...", "level": "WARNING", "src_ip": "...", "user_id": "...", "code": 200}
#   CONN 203.0.113.7 22 TCP
#   kernel: eth0 link up
EVENT_RE = re.compile(
    r"(?P<ts>\S+)\s+(?P<level>\w+)\s+(?P<ip>\S+)"
    r"(?:\s+user=(?P<user>\S+))?"
    r"(?:\s+code=(?P<code>[0-9]{1,5}))?"
    r"(?:\s+port=(?P<port>[0-9]{1,5})/(?P<proto>\w+))?"
    r"(?:\s+(?P<payload>.*))?"
)
RAW_RE = re.compile(r"[\w.\-\[\]]+: .+")
MAX_LINE = 1 << 20  # 1 MiB: a file without newlines must not load whole

Parsed = dict | tuple | str | None


def read_lines(path: str | Path) -> Iterator[str]:
    """Yield the lines of one file, one at a time, each at most MAX_LINE chars."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in iter(partial(f.readline, MAX_LINE), ""):
            yield line.rstrip("\n")


def read_sources(*paths: str | Path) -> Iterator[str]:
    """Yield the lines of several files, one file after the other."""
    for path in paths:
        yield from read_lines(path)


def load_blacklist(path: str | Path) -> frozenset[str]:
    """Read one IP per line; '#' starts a comment."""
    return frozenset(ip for line in read_lines(path) if (ip := line.split("#")[0].strip()))


def parse_timestamp(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_payload(text: str | None) -> dict | str | None:
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError):  # deep nesting overflows the parser
        return text


def is_port(text: str) -> bool:
    """ASCII digits only (no "²²"), at most 5, within 0-65535."""
    return text.isascii() and text.isdigit() and len(text) <= 5 and int(text) <= 65535


def parse_line(line: str) -> Parsed:
    """Turn a raw line into a dict, a connection tuple, a raw str, or None."""
    line = line.strip()
    if line.startswith("{"):
        payload = parse_payload(line)
        return payload if isinstance(payload, dict) else None
    match line.split():
        case ["CONN", ip, port, proto] if is_port(port):
            return (ip, int(port), proto.upper())
    if (m := EVENT_RE.fullmatch(line)) and (ts := parse_timestamp(m["ts"])):
        port_num = int(m["port"]) if m["port"] else None
        return {
            "timestamp": ts,
            "level": m["level"],
            "src_ip": m["ip"],
            "user_id": m["user"],
            "code": int(m["code"]) if m["code"] else None,
            "payload": parse_payload(m["payload"]),
            "meta": (m["ip"], port_num, m["proto"]),
        }
    return line if RAW_RE.fullmatch(line) else None
