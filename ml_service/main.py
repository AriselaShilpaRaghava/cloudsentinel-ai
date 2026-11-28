from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib
import numpy as np

from cloudtrail_pipeline import (
    FEATURES,
    compute_evaluation_curves,
    extract_features,
    extract_ground_truth_labels,
    fit_and_evaluate_isolation_forest,
)
from faas_extractor import FAAS_FEATURES, extract_faas_telemetry
from lstm_pipeline import (
    evaluate_saved_lstm,
    list_saved_lstm_checkpoints,
    train_and_evaluate_lstm,
)

app = FastAPI(
    title="CloudSentinel ML Microservice",
    version="2.1.0",
)

ROOT = Path(__file__).resolve().parent.parent
CLOUDTRAIL_MODEL_FILE = ROOT / "data" / "isolation_forest_cloudtrail.joblib"
LEGACY_MODEL_FILE = ROOT / "data" / "isolation_forest_model.joblib"

MODEL_FILE = CLOUDTRAIL_MODEL_FILE if CLOUDTRAIL_MODEL_FILE.exists() else LEGACY_MODEL_FILE
if not MODEL_FILE.exists():
    raise FileNotFoundError(
        f"Saved Isolation Forest model not found at {CLOUDTRAIL_MODEL_FILE} or {LEGACY_MODEL_FILE}"
    )

bundle = joblib.load(MODEL_FILE)
model = bundle["model"]
scaler = bundle["scaler"]
threshold = float(bundle.get("threshold", 0.0))
model_version = str(bundle.get("model_version", "isolation-forest-saved-v1"))

if bundle.get("features") != FEATURES:
    raise ValueError(
        f"Saved model features {bundle.get('features')} do not match pipeline features {FEATURES}."
    )
if getattr(scaler, "n_features_in_", None) != len(FEATURES):
    raise ValueError("Saved scaler feature count does not match the model feature set.")


class NormalizedEvent(BaseModel):
    event_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    event_time: datetime
    cloud_user_id: str = Field(min_length=1)
    identity_type: Optional[str] = None
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    source_ip: str = Field(min_length=1)
    status: str = Field(min_length=1)
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    ground_truth_label: Optional[int] = None


class PredictPayload(BaseModel):
    events: List[NormalizedEvent]
    model_type: Literal["isolation_forest"] = "isolation_forest"


class TrainPayload(BaseModel):
    train_events: List[NormalizedEvent]
    test_events: Optional[List[NormalizedEvent]] = None
    split_ratio: Optional[Dict[str, float]] = None
    n_estimators: int = Field(default=200, ge=20, le=500)
    contamination: Any = "auto"


class EvaluatePayload(BaseModel):
    test_events: List[NormalizedEvent]
    train_size: int = 0


class FaasTelemetryPayload(BaseModel):
    events: List[NormalizedEvent]
    dataset_id: Optional[str] = None
    dataset_name: Optional[str] = None


class LstmTrainEvaluatePayload(BaseModel):
    train_events: List[NormalizedEvent]
    test_events: Optional[List[NormalizedEvent]] = None
    window_size: Literal[5, 10, 16] = 10
    epochs: int = Field(default=15, ge=5, le=50)
    hidden_dim: int = Field(default=32, ge=16, le=128)
    split_ratio: Optional[Dict[str, float]] = None
    include_if_comparison: bool = True
    save_model: bool = True


class LstmEvaluateSavedPayload(BaseModel):
    test_events: List[NormalizedEvent]
    window_size: Literal[5, 10, 16] = 10
    train_size: int = 0
    include_if_comparison: bool = True


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "cloudsentinel-ml-microservice",
        "model": "Isolation Forest",
        "model_version": model_version,
        "model_loaded": True,
        "feature_count": len(FEATURES),
        "features": FEATURES,
        "threshold": threshold,
        "model_file": MODEL_FILE.name,
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
        X = extract_features(events)
        X_scaled = scaler.transform(X)

        raw_scores = -model.decision_function(X_scaled)
        results = []

        for event, score in zip(events, raw_scores):
            raw_score = float(score)
            if not np.isfinite(raw_score):
                raise ValueError("The saved model returned a non-finite anomaly score.")

            is_anomaly = raw_score >= threshold
            # Scale distance from calibrated threshold into [0.02, 0.99] centered at 0.50.
            anomaly_score = min(0.99, max(0.02, 0.5 + 3.5 * (raw_score - threshold)))
            results.append({
                "event_id": event["event_id"],
                "user_id": event["cloud_user_id"],
                "anomaly_prediction": "anomaly" if is_anomaly else "normal",
                "anomaly_score": round(anomaly_score, 6),
                "raw_anomaly_score": round(raw_score, 6),
                "model_version": model_version,
            })

        return {
            "model": "Isolation Forest",
            "model_type": payload.model_type,
            "model_version": model_version,
            "threshold": threshold,
            "total_events": len(results),
            "predictions": results,
        }
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Prediction input could not be processed: {exc}",
        ) from exc


@app.post("/train")
def train_and_evaluate(payload: TrainPayload):
    if len(payload.train_events) < 5:
        raise HTTPException(
            status_code=422,
            detail="At least 5 events are required for Isolation Forest training and evaluation.",
        )

    try:
        train_dicts = [ev.model_dump(mode="json") for ev in payload.train_events]
        test_dicts = (
            [ev.model_dump(mode="json") for ev in payload.test_events]
            if payload.test_events
            else None
        )

        out = fit_and_evaluate_isolation_forest(
            train_events=train_dicts,
            test_events=test_dicts,
            split_ratio=payload.split_ratio,
            n_estimators=payload.n_estimators,
            contamination=payload.contamination,
        )

        return {
            "model": "Isolation Forest",
            "model_version": f"iforest-sklearn-live-{os.getpid()}",
            "features": out["features"],
            "threshold": out["threshold"],
            "has_ground_truth": out["has_ground_truth"],
            "train_size": out["train_size"],
            "val_size": out["val_size"],
            "test_size": out["test_size"],
            "latency_ms": out["latency_ms"],
            "metrics": out["metrics"],
            "confusion_matrix": out["confusion_matrix"],
            "roc_curve": out["roc_curve"],
            "pr_curve": out["pr_curve"],
        }
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Training/evaluation payload could not be processed: {exc}",
        ) from exc


@app.post("/evaluate")
def evaluate_saved_model(payload: EvaluatePayload):
    """Evaluate the persisted CloudTrail Isolation Forest model on held-out events."""
    if not payload.test_events:
        raise HTTPException(status_code=422, detail="At least 1 test event is required for evaluation.")

    import time
    t_start = time.perf_counter()
    try:
        test_dicts = [ev.model_dump(mode="json") for ev in payload.test_events]
        X_test = extract_features(test_dicts)
        X_scaled = scaler.transform(X_test)
        test_scores = -model.decision_function(X_scaled)
        y_test = extract_ground_truth_labels(test_dicts)

        if y_test is not None and len(np.unique(y_test)) == 2:
            eval_out = compute_evaluation_curves(y_test, test_scores, threshold)
            has_gt = True
        else:
            pred_anom = int(np.sum(test_scores >= threshold))
            eval_out = {
                "metrics": {
                    "accuracy": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                    "false_positive_rate": round(pred_anom / max(1, len(test_scores)), 4),
                    "roc_auc": 0.5,
                },
                "confusion_matrix": {
                    "tp": 0,
                    "fp": pred_anom,
                    "tn": len(test_scores) - pred_anom,
                    "fn": 0,
                },
                "roc_curve": [
                    {"fpr": 0.0, "tpr": 0.0, "threshold": 1.0},
                    {"fpr": 1.0, "tpr": 1.0, "threshold": 0.0},
                ],
                "pr_curve": [],
            }
            has_gt = False

        elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        return {
            "model": "Isolation Forest",
            "model_version": model_version,
            "features": FEATURES,
            "threshold": threshold,
            "has_ground_truth": has_gt,
            "train_size": payload.train_size,
            "val_size": 0,
            "test_size": len(test_dicts),
            "latency_ms": elapsed_ms,
            **eval_out,
        }
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Evaluation payload could not be processed: {exc}",
        ) from exc


@app.post("/faas/telemetry")
def extract_cloudtrail_faas_telemetry(payload: FaasTelemetryPayload):
    """
    Extract leak-free FaaS behavioral features and per-function CloudTrail telemetry
    without touching label fields or altering the saved Isolation Forest contract.
    """
    try:
        events = [ev.model_dump(mode="json") for ev in payload.events]
        result = extract_faas_telemetry(events)
        return {
            "telemetry_source": "cloudtrail",
            "dataset_id": payload.dataset_id,
            "dataset_name": payload.dataset_name,
            **result,
        }
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"FaaS telemetry payload could not be processed: {exc}",
        ) from exc


@app.get("/lstm/status")
def lstm_status():
    """Report persisted PyTorch LSTM Autoencoder checkpoints across allowed window sizes."""
    return {
        "status": "ok",
        "backend": "pytorch-cpu",
        "checkpoints": list_saved_lstm_checkpoints(),
    }


@app.post("/lstm/train-evaluate")
def lstm_train_and_evaluate(payload: LstmTrainEvaluatePayload):
    """
    Chronologically train a real PyTorch LSTM Autoencoder on benign user/session
    sliding windows, calibrate threshold on validation data only, evaluate on held-out
    test data, persist the model artifact, and optionally compare side-by-side against
    the untouched saved Isolation Forest model on identical eligible test events.
    """
    if len(payload.train_events) < payload.window_size:
        raise HTTPException(
            status_code=422,
            detail=f"At least {payload.window_size} training events are required for window_size={payload.window_size}.",
        )

    try:
        train_dicts = [ev.model_dump(mode="json") for ev in payload.train_events]
        test_dicts = (
            [ev.model_dump(mode="json") for ev in payload.test_events]
            if payload.test_events
            else None
        )
        return train_and_evaluate_lstm(
            train_events=train_dicts,
            test_events=test_dicts,
            window_size=payload.window_size,
            hidden_dim=payload.hidden_dim,
            epochs=payload.epochs,
            split_ratio=payload.split_ratio,
            include_if_comparison=payload.include_if_comparison,
            save_model=payload.save_model,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"LSTM training/evaluation payload could not be processed: {exc}",
        ) from exc


@app.post("/lstm/evaluate")
def lstm_evaluate_saved(payload: LstmEvaluateSavedPayload):
    """Evaluate a persisted PyTorch LSTM Autoencoder checkpoint on held-out test events."""
    if not payload.test_events:
        raise HTTPException(status_code=422, detail="At least 1 test event is required for evaluation.")

    try:
        test_dicts = [ev.model_dump(mode="json") for ev in payload.test_events]
        return evaluate_saved_lstm(
            test_events=test_dicts,
            window_size=payload.window_size,
            train_size=payload.train_size,
            include_if_comparison=payload.include_if_comparison,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"LSTM evaluation payload could not be processed: {exc}",
        ) from exc
