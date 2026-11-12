"""Module 3: sets, counters and brute-force detection over the stream."""

from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field


@dataclass
class Stats:
    """Aggregates grow with distinct IPs and users, never with line count."""

    accepted: int = 0
    by_level: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    by_kind: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    by_user: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    active_ips: set[str] = field(default_factory=set)
    error_ips: set[str] = field(default_factory=set)

    def tally(self, records: Iterable[dict]) -> Iterator[dict]:
        """Count each record, then pass it on unchanged."""
        for rec in records:
            self.accepted += 1
            self.by_level[rec["level"]] += 1
            self.by_kind[rec["kind"]] += 1
            if rec["user_id"]:
                self.by_user[rec["user_id"]] += 1
            if rec["src_ip"]:
                self.active_ips.add(rec["src_ip"])
                if rec["level"] in ("ERROR", "CRITICAL"):
                    self.error_ips.add(rec["src_ip"])
            yield rec


def count_items(items: Iterable[str], counter: list[int]) -> Iterator[str]:
    """Count items in counter[0] and blank ones in counter[1] as they pass."""
    for item in items:
        counter[0] += 1
        if not item.strip():
            counter[1] += 1
        yield item


def blacklist_report(
    blacklist: frozenset[str], active: set[str]
) -> dict[str, frozenset[str] | set[str]]:
    return {
        "union": blacklist | active,
        "intersection": blacklist & active,
        "active_not_listed": active - blacklist,
        "listed_dormant": blacklist - active,
        "symmetric_difference": blacklist ^ active,
    }


def detect_brute_force(
    records: Iterable[dict],
    threshold: int = 5,
    cycles: list[bool] | None = None,
) -> Iterator[tuple[str, int]]:
    """Yield (ip, failures) when an IP fails `threshold` logins in a row.

    A success from the same IP resets its count. Each alert ends one detection
    cycle; the next cycle resumes the same iterator where the last one stopped.
    """
    stream = iter(records)
    fails: defaultdict[str, int] = defaultdict(int)
    while True:
        for rec in stream:
            if (
                rec["kind"] not in ("auth_failure", "auth_success")
                or not rec["src_ip"]
            ):
                continue
            ip = rec["src_ip"]
            if rec["kind"] == "auth_success":
                fails[ip] = 0
                continue
            fails[ip] += 1
            if fails[ip] >= threshold:
                break
        else:
            # stream ended without a pending alert: cycle validated
            if cycles is not None:
                cycles.append(True)
            return
        if cycles is not None:
            cycles.append(False)
        yield ip, fails[ip]
        fails[ip] = 0
