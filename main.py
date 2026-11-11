"""Entry point: stream logs through the whole pipeline and print a report."""

import argparse
import sys
import tracemalloc
from collections import defaultdict
from pathlib import Path

from log_engine.aggregation import Stats, blacklist_report, count_items, detect_brute_force
from log_engine.ingestion import load_blacklist, read_sources
from log_engine.pipeline import build_pipeline
from log_engine.rules import RULES, check_rules, describe_rules, export_audit
from log_engine.simulator import simulate


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure streaming log analysis engine.")
    parser.add_argument("logs", nargs="*", type=Path, help="log files, read one after the other")
    parser.add_argument(
        "--simulate", type=int, metavar="N", help="analyse N simulated lines instead of files"
    )
    parser.add_argument("--blacklist", type=Path, default=Path("data/blacklist.txt"))
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="consecutive failures that raise a brute-force alert",
    )
    parser.add_argument("--audit", type=Path, default=Path("reports/audit_report.json"))
    parser.add_argument(
        "--trace-memory", action="store_true", help="report peak Python memory (slower)"
    )
    args = parser.parse_args(argv)
    if not args.logs and args.simulate is None:
        parser.error("give log files or --simulate N")
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.trace_memory:
        tracemalloc.start()
    try:
        blacklist = load_blacklist(args.blacklist) if args.blacklist.exists() else frozenset()
        lines = simulate(args.simulate) if args.simulate is not None else read_sources(*args.logs)
        read = [0, 0]  # lines read, blank lines
        stats = Stats()
        findings: defaultdict[str, list[str]] = defaultdict(list)
        hits: defaultdict[str, int] = defaultdict(int)
        cycles: list[bool] = []
        records = check_rules(
            stats.tally(build_pipeline(count_items(lines, read))),
            RULES,
            findings,
            hits,
            blacklist=blacklist,
        )
        # list() pulls every record through all stages; only alerts are kept
        alerts = list(detect_brute_force(records, args.threshold, cycles))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sets = blacklist_report(blacklist, stats.active_ips)
    levels = "  ".join(
        f"{lvl} {stats.by_level[lvl]}" for lvl in ("INFO", "WARNING", "ERROR", "CRITICAL")
    )
    top_users = sorted(stats.by_user.items(), key=lambda kv: kv[1], reverse=True)[:5]
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
        f"last cycle validated: {cycles[-1]}"
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
    print(f"[AUDIT]  written to {export_audit(globals(), locals(), args.audit)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
