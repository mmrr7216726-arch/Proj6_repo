"""
log_parser.py

Parses raw semi-structured log lines (see backend/data/raw_logs.log) into
structured Python dictionaries that downstream steps (feature engineering,
rule-based detection, model inference) can consume consistently.

Raw line format example:
    [2026-06-01 05:13:00] src=203.0.113.1 dst=10.0.0.1 type=login \
        action=login_failed port=22 user=user3 reason=bad_password

Not every line has every field - "user" and "reason" are optional and only
appear on some events (e.g. login events have "user", port-scan/connection
events don't).
"""

import re
from datetime import datetime
from typing import Optional

# Matches the bracketed timestamp at the start of the line, e.g. "[2026-06-01 05:13:00]"
TIMESTAMP_PATTERN = re.compile(r"\[(.*?)\]")

# Matches every key=value pair in the remainder of the line, e.g. "src=10.0.0.1"
KV_PATTERN = re.compile(r"(\w+)=(\S+)")

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


class LogParseError(ValueError):
    """Raised when a raw log line does not match the expected format."""


def parse_line(raw_line: str) -> dict:
    """
    Parse a single raw log line into a structured record.

    Returns a dict with keys:
        timestamp (datetime), src_ip (str), dst_ip (str), event_type (str),
        action (str), port (int), user (str or None), reason (str or None)

    Raises LogParseError if the line doesn't contain a timestamp or the
    minimum required fields.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        raise LogParseError("Empty line")

    ts_match = TIMESTAMP_PATTERN.search(raw_line)
    if not ts_match:
        raise LogParseError(f"No bracketed timestamp found in line: {raw_line!r}")

    timestamp_str = ts_match.group(1)
    try:
        timestamp = datetime.strptime(timestamp_str, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise LogParseError(f"Could not parse timestamp {timestamp_str!r}") from exc

    # Everything after the closing bracket contains the key=value pairs
    remainder = raw_line[ts_match.end():]
    pairs = KV_PATTERN.findall(remainder)
    fields = dict(pairs)

    required = ("src", "dst", "type", "action", "port")
    missing = [key for key in required if key not in fields]
    if missing:
        raise LogParseError(f"Missing required field(s) {missing} in line: {raw_line!r}")

    try:
        port = int(fields["port"])
    except ValueError as exc:
        raise LogParseError(f"Invalid port value {fields['port']!r}") from exc

    return {
        "timestamp": timestamp,
        "src_ip": fields["src"],
        "dst_ip": fields["dst"],
        "event_type": fields["type"],
        "action": fields["action"],
        "port": port,
        "user": fields.get("user"),      # None if not present
        "reason": fields.get("reason"),  # None if not present
    }


def parse_log_file(path: str, skip_errors: bool = True) -> list[dict]:
    """
    Parse every line in a raw log file into structured records.

    If skip_errors is True (default), malformed lines are skipped and a
    short warning is printed rather than crashing the whole pipeline.
    If skip_errors is False, the first malformed line raises LogParseError.
    """
    records = []
    error_count = 0

    with open(path, "r") as f:
        for line_number, raw_line in enumerate(f, start=1):
            if not raw_line.strip():
                continue
            try:
                records.append(parse_line(raw_line))
            except LogParseError as exc:
                error_count += 1
                if skip_errors:
                    print(f"[log_parser] Skipping line {line_number}: {exc}")
                else:
                    raise

    print(f"[log_parser] Parsed {len(records)} records, "
          f"skipped {error_count} malformed line(s).")
    return records


if __name__ == "__main__":
    import os

    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_path = os.path.join(script_dir, "..", "data", "raw_logs.log")

    parsed_records = parse_log_file(default_log_path)

    print("\nFirst 6 parsed records:")
    for record in parsed_records[:6]:
        print(record)