"""
Train and persist the CloudTrail-ready Isolation Forest model using
data/cloudtrail_training.json (benign-only fitting + train-calibrated threshold)
and evaluate strictly on held-out data/cloudtrail_testing.json.
"""

import json
from pathlib import Path
import joblib

from cloudtrail_pipeline import (
    FEATURES,
    fit_and_evaluate_isolation_forest,
)

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

TRAIN_FILE = DATA_DIR / "cloudtrail_training.json"
TEST_FILE = DATA_DIR / "cloudtrail_testing.json"
MODEL_FILE = DATA_DIR / "isolation_forest_cloudtrail.joblib"
INFO_FILE = DATA_DIR / "cloudtrail_model_info.json"


def main():
    train_records = json.loads(TRAIN_FILE.read_text(encoding="utf-8")).get("Records", [])
    test_records = json.loads(TEST_FILE.read_text(encoding="utf-8")).get("Records", [])

    result = fit_and_evaluate_isolation_forest(
        train_events=train_records,
        test_events=test_records,
        n_estimators=200,
        contamination="auto",
    )

    bundle = {
        "model": result["model"],
        "scaler": result["scaler"],
        "features": FEATURES,
        "threshold": result["threshold"],
        "model_version": "isolation-forest-cloudtrail-v2",
        "trained_on": "data/cloudtrail_training.json",
    }
    joblib.dump(bundle, MODEL_FILE)

    info = {
        "model": "Isolation Forest",
        "model_version": bundle["model_version"],
        "algorithm": "Unsupervised anomaly detection (benign-baseline fitted)",
        "training_file": "data/cloudtrail_training.json",
        "testing_file": "data/cloudtrail_testing.json",
        "train_records": result["train_size"],
        "test_records": result["test_size"],
        "feature_count": len(FEATURES),
        "features": FEATURES,
        "calibrated_threshold": result["threshold"],
        "ground_truth_labels_available": result["has_ground_truth"],
        "held_out_test_metrics": result["metrics"],
        "held_out_confusion_matrix": result["confusion_matrix"],
        "latency_ms": result["latency_ms"],
    }
    INFO_FILE.write_text(json.dumps(info, indent=4), encoding="utf-8")

    print("CloudTrail Isolation Forest training & held-out evaluation completed.")
    print("Model saved:", MODEL_FILE)
    print("Model info saved:", INFO_FILE)
    print("Calibrated threshold:", result["threshold"])
    print("Held-out test metrics:", json.dumps(result["metrics"], indent=2))
    print("Held-out confusion matrix:", json.dumps(result["confusion_matrix"], indent=2))


if __name__ == "__main__":
    main()
