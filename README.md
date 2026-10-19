# Sentinel — Mini SOC Log Analyzer

A beginner-friendly Python tool that reads simulated authentication logs,
detects repeated failed login attempts per IP address, and generates security alerts.

**No third-party dependencies.** Python 3.10+ standard library only.

---

## What It Does

1. Reads a static `.log` file line by line
2. Parses each line into a structured record (timestamp, status, IP, username)
3. Counts failed login attempts per IP address
4. Flags any IP that meets or exceeds the configured threshold (default: **5**)
5. Prints a security report to **stdout** and writes it to **`output/alerts.txt`**

---

## Requirements

- Python 3.10 or later (uses `dict | None` union type hint)
- No `pip install` needed

---

## Project Structure

```
sentinel/
├── sentinel/
│   ├── __init__.py
│   ├── parser.py       # Log line → structured dict
│   ├── detector.py     # Count failures, flag offenders
│   └── reporter.py     # Format and output alerts
├── data/
│   └── auth.log        # Simulated authentication log (input)
├── output/
│   └── alerts.txt      # Generated alerts (output, created on first run)
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_reporter.py
│   └── test_integration.py
├── main.py             # Entry point
└── README.md
```

---

## Log File Format

Each line must follow this exact format:

```
YYYY-MM-DD HH:MM:SS STATUS login from IP user=USERNAME
```

**Examples:**
```
2024-06-01 08:00:15 FAILED login from 192.168.1.105 user=admin
2024-06-01 08:02:21 SUCCESS login from 10.0.0.1 user=alice
```

- `STATUS` must be either `FAILED` or `SUCCESS`
- `IP` must be a valid IPv4 address (e.g. `192.168.1.105`)
- Lines that do not match this format are silently skipped

---

## Usage

### Run with defaults

```bash
python main.py
```

Reads `data/auth.log`, detects threats using a threshold of 5, writes results to
`output/alerts.txt`.

### Custom options

```bash
python main.py --log path/to/custom.log --threshold 3 --output path/to/output.txt
```

| Flag | Default | Description |
|---|---|---|
| `--log` | `data/auth.log` | Path to the input log file |
| `--threshold` | `5` | Minimum failed logins to trigger an alert |
| `--output` | `output/alerts.txt` | Path for the alerts output file |

### Example output

```
=== Sentinel Security Report | 2024-06-01 08:10:00 ===
[ALERT] 192.168.1.105 — 7 failed login attempts (threshold: 5)
[ALERT] 203.0.113.47 — 6 failed login attempts (threshold: 5)
[ALERT] 172.16.0.200 — 7 failed login attempts (threshold: 5)

Alerts written to: output/alerts.txt
```

---

## Running the Tests

```bash
python -m unittest discover tests
```

To run a single test file:

```bash
python -m unittest tests.test_parser
python -m unittest tests.test_detector
python -m unittest tests.test_reporter
python -m unittest tests.test_integration
```

---

## Limitations

The following are known, intentional constraints of this beginner-scoped tool:

1. **No real-time monitoring** — Sentinel is a batch tool. It reads a static file once and exits.
   It does not watch the log for new entries.
2. **Single log format** — Only lines matching the documented format are processed.
   Syslog, JSON, or other formats are not supported.
3. **No time-windowing** — Five failures over one second and five failures over one year are
   treated identically. Only total counts matter.
4. **No IP allow-listing** — Trusted or internal IPs are not excluded from analysis.
5. **No log rotation support** — Only a single, already-existing file is read at a time.
6. **In-memory only** — No state is persisted between runs. Each execution starts fresh.
7. **stdout + file only** — Alerts are not sent over the network (no email, webhooks, or SIEM).
