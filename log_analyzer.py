#!/usr/bin/env python3
"""Log Analyzer - parse Linux auth logs and flag suspicious login activity.

Reads a system log file (default: /var/log/auth.log), finds failed SSH
login attempts, counts them per source IP, and prints a short report.

Usage:
    python3 log_analyzer.py [logfile] [--threshold N]

Examples:
    python3 log_analyzer.py sample_auth.log
    python3 log_analyzer.py /var/log/auth.log --threshold 3

Learning project built while studying Python and Linux logs.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict

DEFAULT_LOG = "/var/log/auth.log"
DEFAULT_THRESHOLD = 5

# Lines like: "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)
# Lines like: "Accepted password for bishnu from 192.168.1.10 port 22 ssh2"
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)
# Lines like: "Invalid user admin from 203.0.113.7 port 22"
INVALID_USER_RE = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")


def parse_log(path):
    """Parse a log file and return (failures_by_ip, successes_by_ip, failures_by_user)."""
    failures_by_ip = Counter()
    successes_by_ip = Counter()
    failures_by_user = Counter()
    total_lines = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            m = FAILED_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                failures_by_ip[ip] += 1
                failures_by_user[user] += 1
                continue
            m = ACCEPTED_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                successes_by_ip[ip] += 1
                continue
            m = INVALID_USER_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                failures_by_user[user] += 1

    return total_lines, failures_by_ip, successes_by_ip, failures_by_user


def print_report(total_lines, failures_by_ip, successes_by_ip,
                 failures_by_user, threshold):
    """Print a human-readable summary of the parsed log."""
    total_failed = sum(failures_by_ip.values())
    total_success = sum(successes_by_ip.values())

    print("=" * 55)
    print("Log Analyzer Report")
    print("=" * 55)
    print(f"Lines scanned:        {total_lines}")
    print(f"Failed logins:        {total_failed}")
    print(f"Successful logins:    {total_success}")
    print()

    print(f"Failed logins by IP (threshold: {threshold} to flag):")
    if not failures_by_ip:
        print("  none found")
    else:
        for ip, count in failures_by_ip.most_common():
            flag = "  <-- FLAGGED: possible brute force" if count >= threshold else ""
            print(f"  {ip:<16} {count} failed{flag}")
    print()

    print("Successful logins by IP:")
    if not successes_by_ip:
        print("  none found")
    else:
        for ip, count in successes_by_ip.most_common():
            print(f"  {ip:<16} {count} successful")
    print()

    print("Most-targeted usernames:")
    if not failures_by_user:
        print("  none found")
    else:
        for user, count in failures_by_user.most_common(5):
            print(f"  {user:<16} {count} failed attempts")
    print()

    flagged = [ip for ip, c in failures_by_ip.items() if c >= threshold]
    if flagged:
        print(f"[!] {len(flagged)} IP(s) flagged for review: {', '.join(flagged)}")
    else:
        print("[*] No IPs above the failure threshold.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Parse Linux auth logs and flag suspicious login activity."
    )
    parser.add_argument(
        "logfile", nargs="?", default=DEFAULT_LOG,
        help=f"path to the log file (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=f"failed attempts from one IP needed to flag it (default: {DEFAULT_THRESHOLD})",
    )
    args = parser.parse_args(argv)

    try:
        total, failed_ip, success_ip, failed_user = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: log file not found: {args.logfile}", file=sys.stderr)
        print("Tip: try the included sample with: python3 log_analyzer.py sample_auth.log",
              file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: permission denied reading: {args.logfile}", file=sys.stderr)
        print("Tip: run with sudo, or point it at a log you can read.", file=sys.stderr)
        return 1

    print_report(total, failed_ip, success_ip, failed_user, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
