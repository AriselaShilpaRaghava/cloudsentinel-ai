
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Literal
from pathlib import Path
from datetime import datetime, timezone
import joblib
import numpy as np

app = FastAPI(
    title="CloudSentinel ML Microservice",
    version="2.0.0"
)

ROOT = Path(__file__).resolve().parent.parent
MODEL_FILE = ROOT / "data" / "isolation_forest_model.joblib"

# Load the saved model and scaler once when the service starts.
if not MODEL_FILE.exists():
    raise FileNotFoundError(f"Saved model not found: {MODEL_FILE}")

bundle = joblib.load(MODEL_FILE)
model = bundle["model"]
scaler = bundle["scaler"]
FEATURES = [
    "is_faas",
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag",
    "time_gap_minutes",
    "time_gap_missing_flag",
]

if bundle.get("features") != FEATURES:
    raise ValueError(
        "Saved model feature order does not match the normalized training pipeline."
    )
if getattr(scaler, "n_features_in_", None) != len(FEATURES):
    raise ValueError("Saved scaler feature count does not match the model feature set.")

SENSITIVE_ACTIONS = {
    "delete_logs",
    "export_keys",
    "download_bulk",
    "assume_role",
    "modify_security_group",
    "spawn_vm"
}

SENSITIVE_RESOURCES = {
    "customer_pii_vault",
    "financial_records_db",
    "kms_keystone",
    "role_cloud_admin",
    "cloud_audit_trail"
}


class NormalizedEvent(BaseModel):
    event_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    event_time: datetime
    cloud_user_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    source_ip: str = Field(min_length=1)
    status: str = Field(min_length=1)
    raw_event: Dict[str, Any] = Field(default_factory=dict)


class PredictPayload(BaseModel):
    events: List[NormalizedEvent]
    model_type: Literal["isolation_forest"] = "isolation_forest"


def parse_time(value):
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None


def is_faas_event(event):
    provider = str(event.get("provider", "")).lower()
    raw_event = event.get("raw_event") or {}
    source = str(
        event.get("event_source")
        or raw_event.get("eventSource")
        or raw_event.get("event_source")
        or ""
    ).lower()
    action = str(event.get("action", "")).lower()
    resource = str(event.get("resource", "")).lower()

    return int(
        "faas" in provider
        or "lambda" in provider
        or "faas" in source
        or action == "invoke_function"
        or resource.startswith("fn_")
    )


def extract_features(events):
    indexed_events = list(enumerate(events))
    indexed_events.sort(
        key=lambda item: (
            str(item[1].get("cloud_user_id", item[1].get("user_id", ""))),
            parse_time(
                item[1].get("event_time", item[1].get("timestamp", ""))
            ) or datetime.min.replace(tzinfo=timezone.utc)
        )
    )

    previous = {}
    features_by_index = {}

    for original_index, event in indexed_events:
        user_id = str(
            event.get("cloud_user_id", event.get("user_id", "unknown"))
        )
        action = str(event.get("action", "")).lower()
        resource = str(event.get("resource", "")).lower()
        status = str(event.get("status", "")).lower()
        ip = str(event.get("source_ip", ""))

        event_time = parse_time(
            event.get("event_time", event.get("timestamp", ""))
        )

        previous_event = previous.get(user_id)

        if previous_event is None:
            time_gap = 0.0
            time_gap_missing = 1.0
            ip_change = 0.0
        else:
            previous_time, previous_ip = previous_event

            time_gap = (
                round(max(0.0, (event_time - previous_time).total_seconds() / 60), 2)
                if event_time and previous_time
                else 0.0
            )
            time_gap_missing = 0.0 if event_time and previous_time else 1.0
            ip_change = float(bool(ip and previous_ip and ip != previous_ip))

        if event_time:
            previous[user_id] = (event_time, ip)

        features_by_index[original_index] = {
            "is_faas": float(is_faas_event(event)),
            "failed_event_flag": float(status in ("failed", "failure", "denied", "error")),
            "sensitive_action_flag": float(action in SENSITIVE_ACTIONS),
            "sensitive_resource_flag": float(resource in SENSITIVE_RESOURCES),
            "off_hours_flag": float(
                event_time is not None
                and (event_time.hour < 6 or event_time.hour >= 22)
            ),
            "ip_change_flag": ip_change,
            "time_gap_minutes": time_gap,
            "time_gap_missing_flag": time_gap_missing
        }

    return [
        [features_by_index[i][name] for name in FEATURES]
        for i in range(len(events))
    ]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "cloudsentinel-ml-microservice",
        "model": "Isolation Forest",
        "model_loaded": True,
        "feature_count": len(FEATURES),
        "features": FEATURES,
    }


@app.post("/predict")
def predict(payload: PredictPayload):
    if not payload.events:
        return {"predictions": []}

    event_ids = [event.event_id for event in payload.events]
    if len(event_ids) != len(set(event_ids)):
        raise HTTPException(status_code=422, detail="event_id values must be unique.")

    try:
        events = [event.model_dump(mode="json") for event in payload.events]
        feature_rows = extract_features(events)
        X = np.asarray(feature_rows, dtype=float)
        X_scaled = scaler.transform(X)

        labels = model.predict(X_scaled)
        raw_scores = -model.decision_function(X_scaled)

        results = []

        for event, label, score in zip(
            events, labels, raw_scores
        ):
            raw_score = float(score)
            if not np.isfinite(raw_score):
                raise ValueError("The saved model returned a non-finite anomaly score.")

            # This bounded signal preserves the existing UI's 0..1 field; it is not a probability.
            anomaly_score = min(1.0, max(0.0, 0.5 + raw_score))
            results.append({
                "event_id": event["event_id"],
                "user_id": event["cloud_user_id"],
                "anomaly_prediction": (
                    "anomaly" if label == -1 else "normal"
                ),
                "anomaly_score": round(anomaly_score, 6),
                "raw_anomaly_score": round(raw_score, 6),
                "model_version": "isolation-forest-saved-v1"
            })

        return {
            "model": "Isolation Forest",
            "model_type": payload.model_type,
            "total_events": len(results),
            "predictions": results
        }

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Prediction input could not be processed: {exc}",
        ) from exc
