# Log stream engine

Command-line engine that streams large log files, parses each line, detects attacks
and writes an audit report. No stage ever loads a whole file into memory
(peak about 200 KiB for 1 000 000 lines).

## Setup

Python 3.10 to 3.13. `requirements.txt` is a `pip freeze` of a Python 3.10 venv;
its pinned numpy/contourpy have no wheels for 3.14.

```bash
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python main.py data/auth.log data/net.log --blacklist data/blacklist.txt
python main.py --simulate 1000000 --trace-memory   # simulated stream, memory peak
python -m log_engine.simulator data/new.log --lines 50000   # write more test data
python -m pytest -q
```

Options: `--threshold N` (failed logins in a row that raise a brute-force alert, default 5),
`--audit PATH` (default `reports/audit_report.json`).

## Layout

| Path | Module | Content |
|---|---|---|
| `log_engine/ingestion.py` | M1 | `read_lines` (`yield`), `read_sources` (`yield from`), `parse_line` to dict, tuple or str |
| `log_engine/pipeline.py` | M2 | `filter(None)`, `map`, `match-case` routing, `normalise`, `filter(lambda)` |
| `log_engine/aggregation.py` | M3 | `set`/`frozenset` operations, `defaultdict` counters, brute-force detector (`while`, `for`, `break`, `continue`, `for ... else`) |
| `log_engine/rules.py` | M4 | `apply_security_rules(*args, **kwargs)`, rule registry, `globals()`/`locals()` audit |
| `log_engine/simulator.py` | test data | simulated log stream in every format |
| `main.py` | entry point | wires the stages into one lazy pass, prints the summary |
| `notebooks/report.ipynb` | report | charts of the results and memory use |

## Log formats

```text
2026-11-04T10:15:32Z ERROR 192.168.1.10 user=alice code=401 port=22/TCP {"msg": "Failed password"}
{"timestamp": "2026-11-04T10:15:33Z", "level": "warning", "src_ip": "10.0.0.4", "user_id": "bob"}
CONN 203.0.113.7 22 tcp
kernel: eth0 link up
```

Code 401 or 403 is a failed login and code 200 is a successful one. Other lines are rejected and counted.
