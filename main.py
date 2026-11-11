"""Entry point: stream logs through the whole pipeline and print a report."""

import argparse
import sys
import time
import tracemalloc
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

from log_engine.aggregation import (
    Stats,
    blacklist_report,
    count_items,
    detect_brute_force,
)
from log_engine.ingestion import follow_lines, load_blacklist, read_sources
from log_engine.pipeline import build_pipeline, printable
from log_engine.rules import RULES, check_rules, describe_rules, export_audit
from log_engine.simulator import paced, simulate


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Secure streaming log analysis engine."
    )
    parser.add_argument(
        "logs",
        nargs="*",
        type=Path,
        help="log files, read one after the other",
    )
    parser.add_argument(
        "--simulate",
        type=int,
        metavar="N",
        help="analyse N simulated lines instead of files",
    )
    parser.add_argument(
        "--blacklist", type=Path, default=Path("data/blacklist.txt")
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="consecutive failures that raise a brute-force alert",
    )
    parser.add_argument(
        "--audit", type=Path, default=Path("reports/audit_report.json")
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="keep reading one growing log file, like tail -f (Ctrl+C stops)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        help="with --simulate: lines per second, to watch it live",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="print each line, finding and alert as it happens",
    )
    parser.add_argument(
        "--trace-memory",
        action="store_true",
        help="report peak Python memory (slower)",
    )
    args = parser.parse_args(argv)
    if not args.logs and args.simulate is None:
        parser.error("give log files or --simulate N")
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.follow and (len(args.logs) != 1 or args.simulate is not None):
        parser.error("--follow reads exactly one log file")
    if args.rate is not None and (args.simulate is None or args.rate <= 0):
        parser.error("--rate needs --simulate and a positive value")
    args.live = args.live or args.follow or args.rate is not None
    return args


def echo(lines: Iterable[str]) -> Iterator[str]:
    """Show each incoming line before it enters the pipeline."""
    for line in lines:
        print(f"[LOG]    {printable(line)}")
        yield line


def status(
    records: Iterable[dict], read: list[int], stats: Stats, hits: dict
) -> Iterator[dict]:
    """Print a progress line at most once per second."""
    last = time.monotonic()
    for rec in records:
        if time.monotonic() - last >= 1:
            last = time.monotonic()
            print(
                f"[LIVE]   read {read[0]}, accepted {stats.accepted}, "
                f"findings {sum(hits.values())}"
            )
        yield rec


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.trace_memory:
        tracemalloc.start()
    try:
        blacklist = (
            load_blacklist(args.blacklist)
            if args.blacklist.exists()
            else frozenset()
        )
        if args.simulate is not None:
            lines = simulate(args.simulate)
            if args.rate:
                lines = paced(lines, args.rate)
        elif args.follow:
            lines = follow_lines(args.logs[0])
        else:
            lines = read_sources(*args.logs)
        if args.live:
            lines = echo(lines)
        read = [0, 0]  # lines read, blank lines
        stats = Stats()
        findings: defaultdict[str, list[str]] = defaultdict(list)
        hits: defaultdict[str, int] = defaultdict(int)
        cycles: list[bool] = []
        records = stats.tally(build_pipeline(count_items(lines, read)))
        if args.live:
            records = status(records, read, stats, hits)
        records = check_rules(
            records,
            RULES,
            findings,
            hits,
            on_hit=live_hit if args.live else None,
            blacklist=blacklist,
        )
        alerts: list[tuple[str, int]] = []
        # this loop pulls every record through all stages; only alerts stay
        try:
            for ip, count in detect_brute_force(
                records, args.threshold, cycles
            ):
                alerts.append((ip, count))
                if args.live:
                    print(f"[ALERT]  brute force from {ip}: {count} failures")
        except KeyboardInterrupt:
            print("[LIVE]   stopped by Ctrl+C, final report:")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sets = blacklist_report(blacklist, stats.active_ips)
    levels = "  ".join(
        f"{lvl} {stats.by_level[lvl]}"
        for lvl in ("INFO", "WARNING", "ERROR", "CRITICAL")
    )
    top_users = sorted(
        stats.by_user.items(), key=lambda kv: kv[1], reverse=True
    )[:5]
    rejected = read[0] - read[1] - stats.accepted
    print(
        f"[INGEST] read {read[0]}, accepted {stats.accepted}, "
        f"rejected {rejected}, blank {read[1]}"
    )
    print(f"[LEVELS] {levels}")
    print(f"[KINDS]  {dict(stats.by_kind)}")
    print(f"[USERS]  top 5: {top_users}")
    print(f"[SETS]   {len(stats.error_ips)} IPs produced errors")
    print(f"[SETS]   blacklist & active = {sorted(sets['intersection'])}")
    print(f"[SETS]   listed but dormant = {sorted(sets['listed_dormant'])}")
    print(
        f"[SETS]   active not listed = {len(sets['active_not_listed'])}, "
        f"symmetric diff = {len(sets['symmetric_difference'])}"
    )
    print(
        f"[BRUTE]  {len(alerts)} alerts over {len(cycles)} cycles, "
        f"last cycle validated: {cycles[-1] if cycles else 'stopped'}"
    )
    for ip, count in alerts[:5]:
        print(f"         {ip}: {count} consecutive failures")
    print(
        f"[RULES]  {len(RULES)} rules {list(describe_rules(RULES))}, "
        f"{sum(hits.values())} findings {dict(hits)}"
    )
    for name, samples in findings.items():
        print(f"         {name}: {samples[0]}")
    if args.trace_memory:
        _, peak = tracemalloc.get_traced_memory()
        print(f"[MEMORY] peak {peak / 1024:.0f} KiB")
    try:
        audit_path = export_audit(globals(), locals(), args.audit)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"[AUDIT]  written to {audit_path}")
    return 0


def live_hit(rule: str, msg: str) -> None:
    print(f"[FIND]   {rule}: {printable(msg)}")


if __name__ == "__main__":
    sys.exit(main())
