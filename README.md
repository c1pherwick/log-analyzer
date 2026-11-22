# Log Analyzer

A small Python command-line tool that parses Linux system and authentication
logs to flag repeated failed logins, suspicious IPs and unusual access
patterns.

## What it does

- Reads a log file (default: `/var/log/auth.log`)
- Finds failed SSH login attempts with regex and groups them by source IP
- Flags any IP with 5 or more failed attempts (adjustable with `--threshold`)
- Summarises successful logins and the most-targeted usernames
- Handles a missing or unreadable file with a clear error instead of a crash

## How to run it

Try it on the included sample log (no root access needed):

```bash
python3 log_analyzer.py sample_auth.log
```

Analyse your own system's auth log:

```bash
python3 log_analyzer.py /var/log/auth.log
```

Flag IPs after just 3 failed attempts instead of 5:

```bash
python3 log_analyzer.py /var/log/auth.log --threshold 3
```

See all options:

```bash
python3 log_analyzer.py --help
```

## Example output

```
=======================================================
Log Analyzer Report
=======================================================
Lines scanned:        14
Failed logins:        10
Successful logins:    3

Failed logins by IP (threshold: 5 to flag):
  203.0.113.7      7 failed  <-- FLAGGED: possible brute force
  198.51.100.23    3 failed

Successful logins by IP:
  192.0.2.15       3 successful

Most-targeted usernames:
  admin            5 failed attempts
  root             2 failed attempts
  test             1 failed attempts
  ubuntu           1 failed attempts
  guest            1 failed attempts

[!] 1 IP(s) flagged for review: 203.0.113.7
```

## About this project

A learning project built while studying Python and Linux logs. It is a
starting point for understanding how authentication logs work and how simple
pattern matching can surface brute-force attempts — not a production security
tool.
