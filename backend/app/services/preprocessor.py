"""
Data Preprocessing Pipeline for Cloud Audit Logs.
Extracts temporal features, encodes categoricals, removes duplicates,
and builds sliding-window sequential activity matrices for LSTM analysis.
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime
import pandas as pd
import numpy as np

ACTION_RISK_MAP = {
    "delete_logs": 1.0,
    "export_keys": 0.95,
    "download_bulk": 0.90,
    "assume_role": 0.85,
    "modify_security_group": 0.80,
    "spawn_vm": 0.60,
    "scale_cluster": 0.50,
    "restart_service": 0.45,
    "build_artifact": 0.35,
    "deploy": 0.35,
    "commit": 0.25,
    "merge_pr": 0.25,
    "read": 0.20,
    "run_test": 0.15,
    "view_audit_logs": 0.15,
    "login": 0.10,
    "logout": 0.05,
}

RESOURCE_SENSITIVITY_MAP = {
    "kms_keystone": 1.0,
    "customer_pii_vault": 0.95,
    "financial_records_db": 0.95,
    "cloud_audit_trail": 0.90,
    "firewall_neutron": 0.85,
    "object_storage_swift": 0.75,
    "role_cloud_admin": 0.80,
    "compute_nova": 0.60,
    "repo_backend": 0.40,
    "repo_frontend": 0.30,
    "ci_pipeline": 0.30,
    "doc_architecture": 0.20,
    "auth_service": 0.25,
    "audit_store": 0.20,
}

class LogPreprocessor:
    def __init__(self):
        self.action_weights = ACTION_RISK_MAP
        self.resource_weights = RESOURCE_SENSITIVITY_MAP

    def preprocess_dataframe(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, Dict[str, Any]]:
        """
        Takes raw audit log DataFrame, validates columns, handles missing/duplicates,
        extracts numerical features, and returns (cleaned_df, feature_matrix, stats).
        """
        required_cols = {"timestamp", "user_id", "action", "resource", "source_ip", "status"}
        missing_req = required_cols - set(df.columns)
        if missing_req:
            raise ValueError(f"Missing required CSV columns: {missing_req}")

        initial_len = len(df)
        # Handle missing and fill defaults
        cleaned = df.dropna(subset=["timestamp", "user_id", "action"]).copy()
        cleaned["resource"] = cleaned["resource"].fillna("unknown_resource")
        cleaned["source_ip"] = cleaned["source_ip"].fillna("0.0.0.0")
        cleaned["status"] = cleaned["status"].fillna("success")

        # Remove duplicate exact logs
        cleaned = cleaned.drop_duplicates(subset=["timestamp", "user_id", "action", "resource", "source_ip"])
        duplicates_removed = initial_len - len(cleaned)

        # Parse timestamps safely
        cleaned["parsed_time"] = pd.to_datetime(cleaned["timestamp"], errors="coerce")
        # Default to now if parsing failed
        now = pd.Timestamp.now()
        cleaned["parsed_time"] = cleaned["parsed_time"].fillna(now)

        # Extract temporal features
        cleaned["hour_of_day"] = cleaned["parsed_time"].dt.hour
        cleaned["day_of_week"] = cleaned["parsed_time"].dt.dayofweek
        cleaned["is_weekend"] = cleaned["day_of_week"].apply(lambda d: 1.0 if d in [5, 6] else 0.0)
        # Off-hours defined as before 7:00 or after 20:00 local time
        cleaned["is_off_hours"] = cleaned["hour_of_day"].apply(lambda h: 1.0 if (h < 7 or h >= 20) else 0.0)

        # Action risk and resource sensitivity
        cleaned["action_risk_weight"] = cleaned["action"].apply(lambda a: self.action_weights.get(str(a).lower(), 0.3))
        cleaned["resource_sensitivity"] = cleaned["resource"].apply(lambda r: self.resource_weights.get(str(r).lower(), 0.35))
        cleaned["is_failure"] = cleaned["status"].apply(lambda s: 1.0 if str(s).lower() in ["failure", "failed", "denied", "error"] else 0.0)

        # User activity frequency
        user_counts = cleaned["user_id"].value_counts()
        max_user_activity = user_counts.max() if len(user_counts) > 0 else 1
        cleaned["user_activity_frequency"] = cleaned["user_id"].apply(lambda u: user_counts.get(u, 1) / max_user_activity)

        feature_cols = [
            "hour_of_day",
            "is_off_hours",
            "is_weekend",
            "action_risk_weight",
            "resource_sensitivity",
            "is_failure",
            "user_activity_frequency"
        ]

        feature_matrix = cleaned[feature_cols].values.astype(np.float32)

        stats = {
            "initial_records": initial_len,
            "valid_records": len(cleaned),
            "duplicates_removed": duplicates_removed,
            "unique_users": int(cleaned["user_id"].nunique()),
            "unique_actions": int(cleaned["action"].nunique()),
            "off_hours_events": int(cleaned["is_off_hours"].sum()),
            "failure_events": int(cleaned["is_failure"].sum()),
            "extracted_features": feature_cols
        }

        return cleaned, feature_matrix, stats

    def create_lstm_sequences(self, cleaned_df: pd.DataFrame, feature_matrix: np.ndarray, window_size: int = 5) -> np.ndarray:
        """
        Group activities per user chronologically and generate sliding windows (N_samples, window_size, features).
        """
        sequences = []
        df_with_features = cleaned_df.copy()
        df_with_features["feature_vector"] = list(feature_matrix)

        for user_id, group in df_with_features.groupby("user_id"):
            sorted_group = group.sort_values(by="parsed_time")
            feats = np.array(sorted_group["feature_vector"].tolist())
            if len(feats) >= window_size:
                for i in range(len(feats) - window_size + 1):
                    sequences.append(feats[i:i + window_size])
            elif len(feats) > 0:
                # Pad to window_size for users with fewer events
                padding = np.repeat(feats[-1:], window_size - len(feats), axis=0)
                padded_seq = np.vstack([feats, padding])
                sequences.append(padded_seq)

        if not sequences:
            # Fallback singleton window
            return np.zeros((1, window_size, feature_matrix.shape[1]), dtype=np.float32)

        return np.array(sequences, dtype=np.float32)
