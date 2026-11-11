"""Simulated log stream in every supported format, plus sample-file writer."""

import argparse
import json
import random
import time
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone

from log_engine.pipeline import printable

USERS = ("alice", "bob", "carol", "dave", "root", "admin")
IPS = tuple(f"10.0.0.{i}" for i in range(1, 30)) + (
    "203.0.113.7",
    "198.51.100.23",
    "192.168.1.10",
)
ATTACKER = "203.0.113.7"
FAILED = '{"msg": "Failed password"}'


def simulate(
    n: int, seed: int = 42, attack_every: int = 2000
) -> Iterator[str]:
    """Yield n log lines; every attack_every lines, 7 attacker failures."""
    rng = random.Random(seed)
    ts = datetime(2026, 11, 4, 8, 0, tzinfo=timezone.utc)
    for i in range(n):
        ts += timedelta(seconds=rng.randint(0, 3))
        stamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        if i >= attack_every and i % attack_every < 7:
            yield (
                f"{stamp} ERROR {ATTACKER} user=root code=401 port=22/TCP"
                f" {FAILED}"
            )
            continue
        ip, user = rng.choice(IPS), rng.choice(USERS)
        roll = rng.random()
        if roll < 0.45:
            yield (
                f"{stamp} INFO {ip} user={user} code=200 port=22/TCP"
                " Accepted password"
            )
        elif roll < 0.60:
            yield (
                f"{stamp} ERROR {ip} user={user} code=401 port=22/TCP"
                f" {FAILED}"
            )
        elif roll < 0.72:
            yield json.dumps(
                {
                    "timestamp": stamp,
                    "level": "warning",
                    "src_ip": ip,
                    "user_id": user,
                    "payload": "disk 91%",
                }
            )
        elif roll < 0.82:
            yield f"CONN {ip} {rng.choice((22, 80, 443, 3389, 4444))} tcp"
        elif roll < 0.90:
            eth = rng.randint(0, 2)
            yield f"kernel: eth{eth} link {rng.choice(('up', 'down'))}"
        elif roll < 0.93:
            yield f"{stamp} CRITICAL {ip} user={user} code=500 service crashed"
        elif roll < 0.96:
            yield ""
        else:
            yield rng.choice(
                (
                    "###corrupted###",
                    f"{stamp} INFO 999.1.1.1 user=x",
                    "{not json",
                    f"{stamp} LOUD {ip}",
                )
            )


def paced(lines: Iterable[str], rate: float) -> Iterator[str]:
    """Yield at most `rate` lines per second, like a live source."""
    for line in lines:
        yield line
        time.sleep(1 / rate)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Write simulated logs to a file."
    )
    parser.add_argument("output")
    parser.add_argument("--lines", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--rate",
        type=float,
        help="lines per second; also prints each line (live demo)",
    )
    args = parser.parse_args()
    if args.rate is not None and args.rate <= 0:
        parser.error("--rate must be positive")
    lines = simulate(args.lines, args.seed)
    # line buffering so a reader using --follow sees each line at once
    with open(
        args.output, "w", encoding="utf-8", buffering=1 if args.rate else -1
    ) as f:
        try:
            for line in paced(lines, args.rate) if args.rate else lines:
                f.write(line + "\n")
                if args.rate:
                    print(f"[GEN]  {printable(line)}")
        except KeyboardInterrupt:
            print("[GEN]  stopped")


if __name__ == "__main__":
    main()
