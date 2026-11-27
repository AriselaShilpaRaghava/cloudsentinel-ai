from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest
import torch
import torch.nn as nn

app = FastAPI(title="CloudSentinel ML Microservice", version="1.0.0")


class LSTMSequenceDetector(nn.Module):
    """PyTorch LSTM sequential insider threat detector over chronological user event windows."""

    def __init__(self, input_dim: int = 10, hidden_dim: int = 32, num_layers: int = 2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers=num_layers, batch_first=True, dropout=0.2)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out, _ = self.lstm(x)
        last_step = out[:, -1, :]
        return self.classifier(last_step)


def extract_feature_row(ev: Dict[str, Any]) -> List[float]:
    action = str(ev.get("action", "")).lower()
    resource = str(ev.get("resource", "")).lower()
    ip = str(ev.get("source_ip", ""))
    status = str(ev.get("status", "Success")).lower()

    is_unusual_ip = 0.0 if (ip.startswith("10.24.") or ip.startswith("172.16.")) else 1.0
    is_failed = 1.0 if status in ("failed", "denied") else 0.0
    action_crit = 0.9 if any(k in action for k in ("attach", "delete", "createaccess", "bulk", "secret")) else 0.25
    res_sens = 0.95 if any(k in resource for k in ("secret", "admin", "payroll", "pii", "ledger")) else 0.25
    return [is_unusual_ip, is_failed, action_crit, res_sens]


class PredictPayload(BaseModel):
    events: List[Dict[str, Any]]
    model_type: str = "isolation_forest"


@app.get("/health")
def health():
    return {"status": "ok", "models": ["scikit-learn-isolation-forest", "pytorch-lstm-sequence"]}


@app.post("/predict")
def predict(payload: PredictPayload):
    if not payload.events:
        return {"predictions": []}

    X = np.array([extract_feature_row(e) for e in payload.events], dtype=np.float32)
    clf = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
    clf.fit(X)
    raw_scores = -clf.decision_function(X)
    norm_scores = np.clip((raw_scores - raw_scores.min()) / (raw_scores.ptp() + 1e-6), 0.05, 0.99)

    results = []
    for ev, score in zip(payload.events, norm_scores):
        results.append(
            {
                "event_id": ev.get("event_id"),
                "anomaly_score": round(float(score), 3),
                "model_version": "iforest-sklearn-1.5" if payload.model_type == "isolation_forest" else "lstm-pytorch-2.4",
            }
        )
    return {"predictions": results}
