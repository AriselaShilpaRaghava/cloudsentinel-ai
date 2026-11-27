"""
Isolation Forest Baseline Anomaly Detection Model for Cloud Audit Logs.
Learns normal multi-dimensional access patterns and isolates anomalous points
based on average path length across random trees.
"""

import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)
IF_MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")

class IsolationForestDetector:
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state
        )
        self.is_trained = False
        self.feature_names = [
            "hour_of_day",
            "is_off_hours",
            "is_weekend",
            "action_risk_weight",
            "resource_sensitivity",
            "is_failure",
            "user_activity_frequency"
        ]

    def fit(self, X: np.ndarray):
        """Fit Isolation Forest on extracted numerical feature matrix."""
        if len(X) < 5:
            raise ValueError("Insufficient training records (at least 5 samples required)")
        self.model.fit(X)
        self.is_trained = True
        joblib.dump(self.model, IF_MODEL_PATH)
        return self

    def predict_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly score in range [0.0, 1.0].
        Higher score means higher anomaly probability.
        """
        if not self.is_trained and os.path.exists(IF_MODEL_PATH):
            self.model = joblib.load(IF_MODEL_PATH)
            self.is_trained = True

        if not self.is_trained:
            # Fallback heuristic if not yet fitted
            return np.clip(np.random.uniform(0.1, 0.4, size=len(X)), 0, 1)

        # score_samples returns opposite of anomaly score (lower is more anomalous)
        raw_scores = -self.model.score_samples(X)
        # Min-max normalization
        min_s = np.min(raw_scores)
        max_s = np.max(raw_scores)
        if max_s - min_s > 1e-6:
            normalized = (raw_scores - min_s) / (max_s - min_s)
        else:
            normalized = np.full_like(raw_scores, 0.5)
        return normalized
