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

### Live demo

Two terminals. The first writes simulated logs as they happen, the second
analyses them as they arrive and prints each line (`[LOG]`), rule finding
(`[FIND]`), brute-force alert (`[ALERT]`) and a progress line (`[LIVE]`).
Ctrl+C stops the engine and prints the final report.

```bash
python -m log_engine.simulator data/live.log --lines 100000 --rate 20   # terminal 1
python main.py data/live.log --follow                                   # terminal 2
```

One terminal: `python main.py --simulate 5000 --rate 20` (generation and
analysis in the same window). `--live` shows events without slowing a normal run.

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

## Team

| Member | GitHub | Work |
|---|---|---|
| Youcef Meradi | [@NyroY64](https://github.com/NyroY64) | project setup, M1 ingestion, `main.py` |
| Hivda Armagan | [@ARM-Hivda](https://github.com/ARM-Hivda) | M2 pipeline, unit tests |
| asma-abc | [@asma-abc](https://github.com/asma-abc) | M3 aggregation, report notebook |
| khadijaferouat | [@khadijaferouat](https://github.com/khadijaferouat) | M4 rule engine, log simulator |
