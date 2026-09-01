"""
rule_detector.py

A simple, explicit rule-based baseline detector for suspicious behavior.
This is intentionally NOT machine learning - it's a set of manually chosen
thresholds, used as a baseline to compare against the Isolation Forest
model later.

Thresholds here are deliberately strict (favoring fewer false positives)
since the injected attack scenarios in the simulated dataset are extreme
outliers with large margins above normal behavior:
    - normal failed_logins per window tops out around 1
    - normal unique_ports per window tops out around 3
    - normal total_events per window tops out around 6
    - normal off-hours logins come from internal (10.0.0.x) IPs

Each rule, if triggered, contributes a human-readable reason string. A
single row can trigger more than one rule at once.
"""

import os

import pandas as pd

from feature_engineering import engineer_features_from_file

# --- Thresholds (strict, to minimize false positives) ----------------------

FAILED_LOGIN_THRESHOLD = 15       # brute-force login attempts
UNIQUE_PORTS_THRESHOLD = 25       # port scanning
TOTAL_EVENTS_THRESHOLD = 100      # request flood / DoS-style behavior
ODD_HOUR_START = 22               # odd hours: after 22:00 ...
ODD_HOUR_END = 6                  # ... or before 06:00


def _is_external_ip(ip: str) -> bool:
    """Treat anything outside the internal 10.0.0.x range as external."""
    return not ip.startswith("10.0.0.")


def _is_odd_hour(hour: int) -> bool:
    return hour >= ODD_HOUR_START or hour < ODD_HOUR_END


def evaluate_rules(row: pd.Series) -> tuple[bool, list[str]]:
    """
    Evaluate all rules against a single feature row.

    Returns (is_suspicious, reasons) where reasons is a list of
    human-readable strings, one per triggered rule (empty if none triggered).
    """
    reasons = []

    if row["failed_logins"] >= FAILED_LOGIN_THRESHOLD:
        reasons.append(
            f"Brute-force pattern: {row['failed_logins']} failed logins "
            f"in one minute (threshold {FAILED_LOGIN_THRESHOLD})"
        )

    if row["unique_ports"] >= UNIQUE_PORTS_THRESHOLD:
        reasons.append(
            f"Port-scan pattern: {row['unique_ports']} unique ports contacted "
            f"in one minute (threshold {UNIQUE_PORTS_THRESHOLD})"
        )

    if row["total_events"] >= TOTAL_EVENTS_THRESHOLD:
        reasons.append(
            f"Request-flood pattern: {row['total_events']} events "
            f"in one minute (threshold {TOTAL_EVENTS_THRESHOLD})"
        )

    if (
        row["successful_logins"] >= 1
        and _is_odd_hour(row["hour_of_day"])
        and _is_external_ip(row["src_ip"])
    ):
        reasons.append(
            f"Unusual-hour login from external IP {row['src_ip']} "
            f"at hour {row['hour_of_day']}"
        )

    return (len(reasons) > 0, reasons)


def apply_rules(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply the rule-based detector to every row of a feature DataFrame.

    Adds two columns:
        rule_flagged (bool)  - True if any rule triggered
        rule_reasons (str)   - "; "-joined reasons, empty string if none
    """
    results = feature_df.apply(evaluate_rules, axis=1)
    feature_df = feature_df.copy()
    feature_df["rule_flagged"] = results.apply(lambda r: r[0])
    feature_df["rule_reasons"] = results.apply(lambda r: "; ".join(r[1]))
    return feature_df


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_path = os.path.join(script_dir, "..", "data", "raw_logs.log")

    feature_df = engineer_features_from_file(default_log_path)
    flagged_df = apply_rules(feature_df)

    suspicious = flagged_df[flagged_df["rule_flagged"]]

    print(f"\n{len(suspicious)} of {len(flagged_df)} windows flagged as suspicious "
          f"({len(suspicious) / len(flagged_df):.2%} of all windows).\n")

    print("Flagged rows:")
    print(
        suspicious[["src_ip", "window_start", "failed_logins", "unique_ports",
                     "total_events", "hour_of_day", "rule_reasons"]]
        .to_string(index=False)
    )