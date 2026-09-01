"""
generate_logs.py

Generates a simulated network/authentication log dataset containing both
NORMAL behavior and SUSPICIOUS behavior patterns, for Project 6:
Threat Intelligence Dashboard.

This mimics the kind of raw log line a real authentication/network system
might emit. Downstream steps (log parsing, feature engineering) will treat
this as "raw" data even though we generate it in a semi-structured form
here, so students can practice actually parsing it rather than reading a
clean CSV directly.

Output: backend/data/raw_logs.log  (plain text, one event per line)
        backend/data/raw_logs.jsonl (same events, JSON lines - optional
                                      convenience copy for debugging)

Simulated behaviors included:
  NORMAL:
    - Regular users logging in successfully during business hours
    - Occasional single failed login (typo) followed by success
    - Normal browsing/API request rates

  SUSPICIOUS:
    - Brute-force login attempts (many failed logins in a short window
      from the same source IP against the same or multiple accounts)
    - Port scanning (one source IP hitting many distinct destination
      ports in a short time)
    - High-frequency requests / possible DoS-style behavior
    - Login attempts at unusual hours from unfamiliar IPs
"""

import json
import os
import random
from datetime import datetime, timedelta

random.seed(42)

# Directory this script lives in - output files are written here regardless
# of which directory you run "python generate_logs.py" from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

START_TIME = datetime(2026, 6, 1, 0, 0, 0)
TOTAL_DURATION_HOURS = 48

NORMAL_USERS = [f"user{i}" for i in range(1, 21)]
NORMAL_INTERNAL_IPS = [f"10.0.0.{i}" for i in range(2, 30)]
NORMAL_DEST_PORTS = [443, 80, 22, 3389, 8080]

ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 6)]
COMMON_PORTS_FOR_SCAN = list(range(20, 1025))

EVENT_TYPES = ["login", "api_request", "file_access", "connection"]
ACTIONS_LOGIN = ["login_success", "login_failed"]
ACTIONS_OTHER = ["allow", "deny"]

LOG_LINES = []
JSON_EVENTS = []


def fmt_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def add_event(ts, src_ip, dst_ip, event_type, action, port, user=None, extra=""):
    """Format a semi-structured raw log line, similar to a syslog/auth log
    line, and also keep a JSON copy for convenience."""
    user_part = f" user={user}" if user else ""
    line = (
        f"[{fmt_ts(ts)}] src={src_ip} dst={dst_ip} type={event_type} "
        f"action={action} port={port}{user_part} {extra}".rstrip()
    )
    LOG_LINES.append(line)
    JSON_EVENTS.append(
        {
            "timestamp": fmt_ts(ts),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "event_type": event_type,
            "action": action,
            "port": port,
            "user": user,
        }
    )


# ---------------------------------------------------------------------------
# 1. Normal background traffic over the full time window
# ---------------------------------------------------------------------------

current = START_TIME
end_time = START_TIME + timedelta(hours=TOTAL_DURATION_HOURS)

while current < end_time:
    # Business-hours-weighted normal activity: more events during 8am-7pm
    hour = current.hour
    business_hours = 8 <= hour <= 19

    # Number of normal events in this minute-ish slice
    n_events = random.randint(2, 6) if business_hours else random.randint(0, 2)

    for _ in range(n_events):
        user = random.choice(NORMAL_USERS)
        src_ip = random.choice(NORMAL_INTERNAL_IPS)
        dst_ip = "10.0.0.1"  # internal server
        event_type = random.choices(
            EVENT_TYPES, weights=[0.3, 0.4, 0.2, 0.1]
        )[0]

        if event_type == "login":
            # Occasionally a normal user mistypes their password once
            if random.random() < 0.05:
                add_event(
                    current, src_ip, dst_ip, "login", "login_failed",
                    22, user=user, extra="reason=bad_password"
                )
                current += timedelta(seconds=random.randint(2, 8))
            add_event(
                current, src_ip, dst_ip, "login", "login_success",
                22, user=user
            )
        else:
            action = random.choices(ACTIONS_OTHER, weights=[0.95, 0.05])[0]
            port = random.choice(NORMAL_DEST_PORTS)
            add_event(current, src_ip, dst_ip, event_type, action, port, user=user)

    current += timedelta(minutes=1)


# ---------------------------------------------------------------------------
# 2. Injected SUSPICIOUS scenario: brute-force login attempts
# ---------------------------------------------------------------------------

def inject_brute_force(start, attacker_ip, target_user, n_attempts=25):
    ts = start
    for i in range(n_attempts):
        add_event(
            ts, attacker_ip, "10.0.0.1", "login", "login_failed",
            22, user=target_user, extra="reason=bad_password"
        )
        ts += timedelta(seconds=random.uniform(0.5, 2.0))
    # Occasionally the attacker eventually succeeds (credential compromise)
    if random.random() < 0.4:
        add_event(ts, attacker_ip, "10.0.0.1", "login", "login_success", 22, user=target_user)
    return ts


brute_force_start_1 = START_TIME + timedelta(hours=5, minutes=13)
inject_brute_force(brute_force_start_1, ATTACKER_IPS[0], "user3", n_attempts=30)

brute_force_start_2 = START_TIME + timedelta(hours=27, minutes=40)
inject_brute_force(brute_force_start_2, ATTACKER_IPS[1], "admin", n_attempts=40)


# ---------------------------------------------------------------------------
# 3. Injected SUSPICIOUS scenario: port scanning
# ---------------------------------------------------------------------------

def inject_port_scan(start, attacker_ip, n_ports=60):
    ts = start
    ports = random.sample(COMMON_PORTS_FOR_SCAN, n_ports)
    for port in ports:
        add_event(ts, attacker_ip, "10.0.0.1", "connection", "deny", port)
        ts += timedelta(milliseconds=random.randint(50, 300))
    return ts


port_scan_start = START_TIME + timedelta(hours=11, minutes=2)
inject_port_scan(port_scan_start, ATTACKER_IPS[2], n_ports=80)


# ---------------------------------------------------------------------------
# 4. Injected SUSPICIOUS scenario: high-frequency request flood (DoS-ish)
# ---------------------------------------------------------------------------

def inject_request_flood(start, attacker_ip, n_requests=150):
    ts = start
    for _ in range(n_requests):
        add_event(ts, attacker_ip, "10.0.0.1", "api_request", "allow", 443)
        ts += timedelta(milliseconds=random.randint(20, 150))
    return ts


flood_start = START_TIME + timedelta(hours=32, minutes=18)
inject_request_flood(flood_start, ATTACKER_IPS[3], n_requests=200)


# ---------------------------------------------------------------------------
# 5. Injected SUSPICIOUS scenario: unusual-hour login from unfamiliar IP
# ---------------------------------------------------------------------------

odd_hour_time = START_TIME + timedelta(hours=28, minutes=45)  # day 2, 4:45 AM
add_event(odd_hour_time, ATTACKER_IPS[4], "10.0.0.1", "login", "login_success",
          22, user="user7", extra="reason=unusual_hour_unfamiliar_ip")

# ---------------------------------------------------------------------------
# Sort all events chronologically (since we injected scenarios out of order)
# and write output files
# ---------------------------------------------------------------------------

combined = list(zip(LOG_LINES, JSON_EVENTS))
combined.sort(key=lambda pair: pair[1]["timestamp"])
LOG_LINES = [line for line, _ in combined]
JSON_EVENTS = [event for _, event in combined]

log_path = os.path.join(SCRIPT_DIR, "raw_logs.log")
jsonl_path = os.path.join(SCRIPT_DIR, "raw_logs.jsonl")

with open(log_path, "w") as f:
    f.write("\n".join(LOG_LINES) + "\n")

with open(jsonl_path, "w") as f:
    for event in JSON_EVENTS:
        f.write(json.dumps(event) + "\n")

print(f"Generated {len(LOG_LINES)} log events.")
print(f"Wrote raw_logs.log and raw_logs.jsonl to {SCRIPT_DIR}")