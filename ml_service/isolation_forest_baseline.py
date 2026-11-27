
import csv
import json
from pathlib import Path

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

INPUT_FILE = DATA_DIR / "ml_model_input.csv"
OUTPUT_FILE = DATA_DIR / "isolation_forest_predictions.csv"
MODEL_INFO_FILE = DATA_DIR / "isolation_forest_model_info.json"
MODEL_FILE = DATA_DIR / "isolation_forest_model.joblib"

FEATURES = [
    "is_faas",
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag",
    "time_gap_minutes",
    "time_gap_missing_flag"
]


def main():
    with INPUT_FILE.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    if len(rows) < 2:
        raise ValueError("At least two events are required.")

    X = np.array(
        [[float(row[feature]) for feature in FEATURES] for row in rows],
        dtype=float
    )

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )

    model.fit(X_scaled)

    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "features": FEATURES
        },
        MODEL_FILE
    )

    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)

    output_rows = []

    for row, prediction, score in zip(rows, predictions, scores):
        output_rows.append({
            "event_id": row["event_id"],
            "user_id": row["user_id"],
            "event_source": row["event_source"],
            "anomaly_prediction": (
                "anomaly" if prediction == -1 else "normal"
            ),
            "anomaly_score": round(float(-score), 6)
        })

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=output_rows[0].keys()
        )
        writer.writeheader()
        writer.writerows(output_rows)

    model_info = {
        "model": "Isolation Forest",
        "algorithm": "Unsupervised anomaly detection",
        "input_events": len(rows),
        "feature_count": len(FEATURES),
        "contamination": "auto",
        "random_state": 42,
        "ground_truth_labels_available": False,
        "evaluation_status": "Pipeline experiment only"
    }

    MODEL_INFO_FILE.write_text(
        json.dumps(model_info, indent=4),
        encoding="utf-8"
    )

    anomaly_count = sum(prediction == -1 for prediction in predictions)

    print("Isolation Forest experiment completed.")
    print("Total events:", len(rows))
    print("Features used:", len(FEATURES))
    print("Predicted anomalies:", anomaly_count)
    print("Predicted normal events:", len(rows) - anomaly_count)
    print("Predictions:", OUTPUT_FILE)
    print("Model information:", MODEL_INFO_FILE)
print("Saved model:", MODEL_FILE)

if __name__ == "__main__":
    main()
