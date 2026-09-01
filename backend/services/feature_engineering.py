"""
feature_engineering.py

Transforms structured log records (from log_parser.py) into numeric,
behavior-based features suitable for machine learning.

Design decision: features are aggregated PER SOURCE IP, PER 1-MINUTE
WINDOW. A single event tells you almost nothing about whether behavior is
suspicious - 1 failed login is normal, 30 failed logins from the same IP
in the same minute is not. Aggregating over a fixed time window is what
turns raw events into behavioral signal.

Each output row represents: "this source IP, in this 1-minute window,
did the following things."

Features produced per (src_ip, window_start) row:
    total_events        - overall activity volume in the window
    failed_logins        - count of action == "login_failed"
    successful_logins    - count of action == "login_success"
    unique_ports         - number of distinct destination ports contacted
    unique_dst_ips        - number of distinct destination IPs contacted
    unique_users          - number of distinct usernames used
    denied_connections   - count of action == "deny"
    hour_of_day           - hour (0-23) the window falls in
"""

import os

import pandas as pd

from log_parser import parse_log_file


def records_to_dataframe(records: list[dict]) -> pd.DataFrame:
    """Convert a list of parsed log record dicts into a pandas DataFrame."""
    df = pd.DataFrame(records)
    if df.empty:
        raise ValueError("No records to convert - got an empty list.")
    return df


def engineer_features(records: list[dict]) -> pd.DataFrame:
    """
    Aggregate parsed log records into per-(src_ip, 1-minute window)
    behavioral features.

    Returns a DataFrame sorted by window_start, one row per (src_ip,
    window_start) combination that had at least one event.
    """
    df = records_to_dataframe(records)

    # Floor each timestamp down to the start of its 1-minute window.
    # e.g. 05:13:47 -> 05:13:00
    df["window_start"] = df["timestamp"].dt.floor("min")

    grouped = df.groupby(["src_ip", "window_start"])

    features = grouped.agg(
        total_events=("event_type", "count"),
        failed_logins=("action", lambda s: (s == "login_failed").sum()),
        successful_logins=("action", lambda s: (s == "login_success").sum()),
        denied_connections=("action", lambda s: (s == "deny").sum()),
        unique_ports=("port", "nunique"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_users=("user", pd.Series.nunique),  # nunique ignores NaN/None by default
    ).reset_index()

    features["hour_of_day"] = features["window_start"].dt.hour

    features = features.sort_values(["window_start", "src_ip"]).reset_index(drop=True)
    return features


def engineer_features_from_file(log_path: str) -> pd.DataFrame:
    """Convenience wrapper: parse a raw log file and engineer features from it."""
    records = parse_log_file(log_path)
    return engineer_features(records)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_path = os.path.join(script_dir, "..", "data", "raw_logs.log")

    feature_df = engineer_features_from_file(default_log_path)

    print(f"\nEngineered {len(feature_df)} feature rows "
          f"(one per src_ip per active 1-minute window).")
    print("\nColumns:", list(feature_df.columns))

    print("\nTop 10 rows by failed_logins (should surface the brute-force IPs):")
    print(
        feature_df.sort_values("failed_logins", ascending=False)
        .head(10)
        .to_string(index=False)
    )

    print("\nTop 10 rows by unique_ports (should surface the port-scan IP):")
    print(
        feature_df.sort_values("unique_ports", ascending=False)
        .head(10)
        .to_string(index=False)
    )

    print("\nTop 10 rows by total_events (should surface the request-flood IP):")
    print(
        feature_df.sort_values("total_events", ascending=False)
        .head(10)
        .to_string(index=False)
    )