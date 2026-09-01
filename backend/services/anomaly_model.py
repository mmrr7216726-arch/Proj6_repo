"""
anomaly_model.py

Trains an Isolation Forest model on the engineered behavioral features to
detect anomalous (suspicious) network activity in an unsupervised way.

Isolation Forest intuition: it builds many random decision trees, each
splitting the data on random features at random thresholds. Anomalous
points - ones that are far from the bulk of "normal" data - tend to get
isolated into their own leaf node after very few splits, because there's
less "normal" data around them to split through. Normal points, packed
closely together, take many more splits to isolate. The model turns
"average number of splits to isolate a point" into an anomaly score:
short average path length -> more anomalous.

This script:
    1. Loads engineered features (see feature_engineering.py)
    2. Selects numeric columns as model input
    3. Trains Isolation Forest
    4. Produces predictions (1 = normal, -1 = anomaly) and anomaly scores
    5. Serializes the trained model with joblib for reuse in the API
"""

import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from feature_engineering import engineer_features_from_file
from rule_detector import apply_rules

FEATURE_COLUMNS = [
    "total_events",
    "failed_logins",
    "successful_logins",
    "denied_connections",
    "unique_ports",
    "unique_dst_ips",
    "unique_users",
    "hour_of_day",
]

RANDOM_STATE = 42


def prepare_feature_matrix(feature_df: pd.DataFrame) -> pd.DataFrame:
    """Select only the numeric columns Isolation Forest should train on."""
    return feature_df[FEATURE_COLUMNS]


def train_isolation_forest(X: pd.DataFrame, contamination: float) -> IsolationForest:
    """
    Train an Isolation Forest with the given contamination estimate.

    Note on max_samples: scikit-learn's default only samples 256 rows per
    tree, which is meant for very large datasets. For a dataset this size
    (a few thousand rows), that subsampling actually dilutes true global
    outliers - a value like unique_ports=80 (vs a normal max of ~3) isn't
    reliably isolated if any given tree only sees a small, possibly
    unrepresentative slice of the data. Using max_samples=1.0 (the full
    dataset for every tree) fixed this in testing: it took catching 0 of 5
    known attack windows up to 4 of 5, with far fewer false positives.
    """
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples=1.0,
        random_state=RANDOM_STATE,
    )
    model.fit(X)
    return model


def predict_anomalies(model: IsolationForest, X: pd.DataFrame) -> pd.DataFrame:
    """
    Run predictions and anomaly scores for each row.

    Returns a DataFrame with columns:
        prediction     : 1 (normal) or -1 (anomaly)
        anomaly_score  : decision_function output; lower/negative = more anomalous
    """
    predictions = model.predict(X)
    scores = model.decision_function(X)
    return pd.DataFrame({"prediction": predictions, "anomaly_score": scores}, index=X.index)


def save_model(model: IsolationForest, path: str) -> None:
    joblib.dump(model, path)


def load_model(path: str) -> IsolationForest:
    return joblib.load(path)


def _summarize_run(feature_df: pd.DataFrame, contamination: float) -> pd.DataFrame:
    """Train, predict, and attach results to the feature dataframe (for comparison/reporting)."""
    X = prepare_feature_matrix(feature_df)
    model = train_isolation_forest(X, contamination)
    results = predict_anomalies(model, X)
    combined = feature_df.copy()
    combined["prediction"] = results["prediction"]
    combined["anomaly_score"] = results["anomaly_score"]
    return combined, model


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_path = os.path.join(script_dir, "..", "data", "raw_logs.log")
    model_output_path = os.path.join(script_dir, "..", "models", "isolation_forest.joblib")

    feature_df = engineer_features_from_file(default_log_path)

    # Known attacker IPs from the simulated dataset, used only to evaluate
    # results here - the model itself never sees this label.
    ATTACKER_IPS = {"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}

    for contamination in (0.001, 0.01):
        print(f"\n{'=' * 70}")
        print(f"Contamination = {contamination}")
        print(f"{'=' * 70}")

        combined, model = _summarize_run(feature_df, contamination)
        anomalies = combined[combined["prediction"] == -1].sort_values("anomaly_score")

        flagged_attacker_ips = set(anomalies["src_ip"]) & ATTACKER_IPS
        flagged_normal_ips = set(anomalies["src_ip"]) - ATTACKER_IPS

        print(f"Total windows flagged as anomalies: {len(anomalies)} of {len(combined)}")
        print(f"Known attacker IPs caught: {len(flagged_attacker_ips)} of {len(ATTACKER_IPS)} "
              f"-> {sorted(flagged_attacker_ips)}")
        print(f"Missed attacker IPs: {sorted(ATTACKER_IPS - flagged_attacker_ips)}")
        print(f"Normal-IP windows flagged (false positives): {len(flagged_normal_ips)}")

        print("\nMost anomalous rows (lowest score = most anomalous):")
        print(
            anomalies[["src_ip", "window_start", "failed_logins", "unique_ports",
                       "total_events", "hour_of_day", "anomaly_score"]]
            .head(10)
            .to_string(index=False)
        )

    # Compare against the rule-based baseline for discussion purposes
    print(f"\n{'=' * 70}")
    print("Rule-based baseline (for comparison)")
    print(f"{'=' * 70}")
    rule_flagged = apply_rules(feature_df)
    rule_suspicious = rule_flagged[rule_flagged["rule_flagged"]]
    print(f"Rule-based flagged {len(rule_suspicious)} windows: "
          f"{sorted(rule_suspicious['src_ip'].tolist())}")

    # Train and save the final model using contamination=0.001 (matches the
    # true known rate in this simulated dataset - see write-up for why this
    # choice is discussed rather than assumed in a real deployment).
    final_contamination = 0.001
    X_full = prepare_feature_matrix(feature_df)
    final_model = train_isolation_forest(X_full, final_contamination)
    save_model(final_model, model_output_path)
    print(f"\nSaved final model (contamination={final_contamination}) to {model_output_path}")