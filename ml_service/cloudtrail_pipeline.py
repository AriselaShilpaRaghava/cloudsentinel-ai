"""
Leak-free behavioral feature extraction, training, and evaluation pipeline
for AWS CloudTrail and normalized multi-cloud audit events using Isolation Forest.

Never reads ground-truth labels (`should_sample`, `attack_name`, `ground_truth_label`,
`is_insider`, or `label`) during feature extraction.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
import time
import math

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

FEATURES: List[str] = [
    "is_faas",
    "failed_event_flag",
    "is_iam_user",
    "is_anonymous_or_account",
    "recon_action_flag",
    "sensitive_action_flag",
    "log_s3_burst_1m",
    "log_unique_buckets_5m",
]

RECON_ACTIONS = {
    "listbuckets",
    "listobjects",
    "listobjectsv2",
    "headbucket",
    "getbucketlogging",
    "getbucketencryption",
    "getbucketpolicy",
    "getbucketacl",
    "getbucketcors",
    "getbucketlocation",
    "getbucketversioning",
    "listusers",
    "listroles",
    "listpolicies",
    "listaccesskeys",
}

SENSITIVE_ACTIONS = {
    "delete_logs",
    "export_keys",
    "download_bulk",
    "assume_role",
    "modify_security_group",
    "spawn_vm",
    "attachuserpolicy",
    "putuserpolicy",
    "createaccesskey",
    "createuser",
    "createloginprofile",
    "updateaccesskey",
    "getfederationtoken",
    "deletebucket",
    "novadeleteserver",
    "bulkgetobject",
    "assumerole",
}


def parse_time(value: Any) -> Optional[datetime]:
    """Parse ISO-8601 timestamps safely into UTC-aware datetime objects."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None


def _extract_user_id(event: Dict[str, Any]) -> str:
    direct = event.get("cloud_user_id") or event.get("user_id")
    if direct:
        return str(direct)
    raw = event.get("raw_event") or {}
    ui = event.get("userIdentity") or raw.get("userIdentity") or {}
    if isinstance(ui, dict):
        si = ((ui.get("sessionContext") or {}).get("sessionIssuer")) or {}
        resolved = (
            ui.get("userName")
            or ui.get("arn")
            or (si.get("userName") if isinstance(si, dict) else None)
            or ui.get("invokedBy")
            or ui.get("principalId")
            or (f"aws-account:{ui['accountId']}" if ui.get("accountId") else None)
        )
        if resolved:
            return str(resolved)
    return "anonymous-caller"


def _extract_identity_type(event: Dict[str, Any]) -> str:
    explicit = event.get("identity_type")
    if explicit:
        return str(explicit).lower()
    raw = event.get("raw_event") or {}
    ui = event.get("userIdentity") or raw.get("userIdentity") or {}
    if isinstance(ui, dict):
        if ui.get("type"):
            return str(ui["type"]).lower()
        if ui.get("invokedBy"):
            return "awsservice"
        if ui.get("accountId"):
            return "awsaccount"
    return "anonymous"


def _extract_bucket(event: Dict[str, Any]) -> str:
    raw = event.get("raw_event") or {}
    rp = event.get("requestParameters") or raw.get("requestParameters")
    if isinstance(rp, dict) and rp.get("bucketName"):
        return str(rp["bucketName"])

    resources = event.get("resources") or raw.get("resources")
    if isinstance(resources, list):
        for item in resources:
            if isinstance(item, dict) and item.get("type") == "AWS::S3::Bucket":
                arn = item.get("ARN") or item.get("arn")
                if arn:
                    return str(arn)

    res_str = str(event.get("resource") or "")
    if res_str.startswith("arn:aws:s3:::"):
        return res_str[len("arn:aws:s3:::"):].split("/")[0].split(" | ")[0]
    if res_str.startswith("s3://"):
        return res_str[len("s3://"):].split("/")[0]
    return ""


def _is_faas_event(event: Dict[str, Any], action: str) -> float:
    raw = event.get("raw_event") or {}
    provider = str(event.get("provider") or "").lower()
    source = str(
        event.get("eventSource")
        or event.get("event_source")
        or raw.get("eventSource")
        or raw.get("event_source")
        or ""
    ).lower()
    resource = str(event.get("resource") or "").lower()
    return float(
        "lambda" in provider
        or "faas" in provider
        or "lambda" in source
        or "faas" in source
        or action in ("invokefunction", "invoke_function")
        or resource.startswith("fn_")
        or resource.startswith("fn-")
    )


def _is_failed_event(event: Dict[str, Any]) -> float:
    status = str(event.get("status") or "").lower()
    if status in ("failed", "failure", "denied", "error"):
        return 1.0
    raw = event.get("raw_event") or {}
    if event.get("errorCode") or event.get("errorMessage") or raw.get("errorCode") or raw.get("errorMessage"):
        return 1.0
    return 0.0


def extract_features(events: Sequence[Dict[str, Any]]) -> np.ndarray:
    """
    Extract the 8 behavioral features per event while preserving original order.
    Uses chronological rolling windows per identity without ever touching label fields.
    """
    if not events:
        return np.empty((0, len(FEATURES)), dtype=float)

    indexed = []
    for idx, ev in enumerate(events):
        user_id = _extract_user_id(ev)
        dt = parse_time(ev.get("event_time") or ev.get("eventTime") or ev.get("timestamp"))
        indexed.append((idx, ev, user_id, dt))

    indexed.sort(key=lambda item: (item[2], item[3] or datetime.min.replace(tzinfo=timezone.utc)))

    win_1m: Dict[str, deque] = defaultdict(deque)
    win_5m: Dict[str, deque] = defaultdict(deque)
    rows_by_idx: Dict[int, List[float]] = {}

    for idx, ev, user_id, dt in indexed:
        action = str(ev.get("action") or ev.get("eventName") or "").strip().lower()
        identity_type = _extract_identity_type(ev)
        bucket = _extract_bucket(ev)
        raw = ev.get("raw_event") or {}
        ui = ev.get("userIdentity") or raw.get("userIdentity") or {}
        invoked_by = ui.get("invokedBy") if isinstance(ui, dict) else None

        if dt is not None:
            ts = dt.timestamp()
            q1 = win_1m[user_id]
            q1.append((ts, action))
            while q1 and ts - q1[0][0] > 60.0:
                q1.popleft()

            q5 = win_5m[user_id]
            q5.append((ts, bucket))
            while q5 and ts - q5[0][0] > 300.0:
                q5.popleft()

            s3_burst_1m = sum(1 for _, act in q1 if "object" in act or "bucket" in act)
            unique_buckets_5m = len({b for _, b in q5 if b})
        else:
            s3_burst_1m = 0
            unique_buckets_5m = 0

        is_iam_user = float(identity_type == "iamuser")
        is_anon_or_acct = float(identity_type in ("awsaccount", "anonymous", "missing") and not invoked_by)
        recon_flag = float(action in RECON_ACTIONS)
        # Note: treat GetSecretValue as sensitive only when not executed by Secrets Manager service role?
        # Keep consistent with normalized security actions across CloudTrail & multi-cloud schemas.
        sens_flag = float(action in SENSITIVE_ACTIONS)
        # Support explicit FaaS/burst test payloads if raw_event specifies burst counts
        if isinstance(raw, dict) and raw.get("bytesTransferredMB"):
            try:
                if float(raw["bytesTransferredMB"]) >= 500:
                    sens_flag = 1.0
            except (TypeError, ValueError):
                pass

        rows_by_idx[idx] = [
            _is_faas_event(ev, action),
            _is_failed_event(ev),
            is_iam_user,
            is_anon_or_acct,
            recon_flag,
            sens_flag,
            math.log1p(s3_burst_1m),
            math.log1p(unique_buckets_5m),
        ]

    return np.asarray([rows_by_idx[i] for i in range(len(events))], dtype=float)


def extract_ground_truth_labels(events: Sequence[Dict[str, Any]]) -> Optional[np.ndarray]:
    """Extract ground truth binary labels (0/1) if all events carry valid labels."""
    labels: List[int] = []
    for ev in events:
        raw = ev.get("raw_event") or {}
        gt = ev.get("ground_truth_label")
        if gt is None:
            gt = ev.get("should_sample")
        if gt is None and isinstance(raw, dict):
            gt = raw.get("should_sample")
        if gt is None:
            return None
        if isinstance(gt, bool):
            labels.append(1 if gt else 0)
        elif gt in (0, 1):
            labels.append(int(gt))
        else:
            s = str(gt).strip().lower()
            if s in ("true", "1", "attack", "anomaly"):
                labels.append(1)
            elif s in ("false", "0", "benign", "normal"):
                labels.append(0)
            else:
                return None
    return np.asarray(labels, dtype=int)


def calibrate_threshold(scores: np.ndarray, y_true: Optional[np.ndarray]) -> float:
    """
    Calibrate decision threshold strictly on training/validation data.
    If ground-truth labels exist, pick threshold maximizing F1; otherwise use 0.0 (IF offset).
    """
    if y_true is None or len(np.unique(y_true)) < 2:
        return 0.0

    best_th = 0.0
    best_f1 = -1.0
    s_min, s_max = float(np.min(scores)), float(np.max(scores))
    if s_max - s_min < 1e-9:
        return 0.0

    for th in np.linspace(s_min, s_max, 120):
        preds = (scores >= th).astype(int)
        f1 = f1_score(y_true, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = float(f1)
            best_th = float(th)
    return best_th


def compute_evaluation_curves(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
) -> Dict[str, Any]:
    """Compute real confusion matrix, classification metrics, ROC curve, and PR curve."""
    y_pred = (scores >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr_val = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) == 2 else 0.5

    # Build clean 11-point ROC and PR curves across quantiles/linear thresholds
    s_min, s_max = float(np.min(scores)), float(np.max(scores))
    grid = np.linspace(s_max, s_min, 15) if s_max > s_min else np.array([s_max])
    roc_curve = [{"fpr": 0.0, "tpr": 0.0, "threshold": round(s_max + 1e-4, 4)}]
    pr_curve = []

    for th in grid:
        p = (scores >= th).astype(int)
        c = confusion_matrix(y_true, p, labels=[0, 1])
        c_tn, c_fp, c_fn, c_tp = int(c[0, 0]), int(c[0, 1]), int(c[1, 0]), int(c[1, 1])
        tpr_pt = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 0.0
        fpr_pt = c_fp / (c_fp + c_tn) if (c_fp + c_tn) > 0 else 0.0
        prec_pt = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 1.0
        roc_curve.append({"fpr": round(fpr_pt, 4), "tpr": round(tpr_pt, 4), "threshold": round(float(th), 4)})
        pr_curve.append({"recall": round(tpr_pt, 4), "precision": round(prec_pt, 4), "threshold": round(float(th), 4)})

    roc_curve.append({"fpr": 1.0, "tpr": 1.0, "threshold": round(s_min - 1e-4, 4)})
    roc_curve.sort(key=lambda pt: (pt["fpr"], pt["tpr"]))

    return {
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr_val, 4),
            "roc_auc": round(roc_auc, 4),
        },
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "roc_curve": roc_curve,
        "pr_curve": pr_curve,
    }


def fit_and_evaluate_isolation_forest(
    train_events: Sequence[Dict[str, Any]],
    test_events: Optional[Sequence[Dict[str, Any]]] = None,
    split_ratio: Optional[Dict[str, float]] = None,
    n_estimators: int = 200,
    contamination: Any = "auto",
) -> Dict[str, Any]:
    """
    Fit scikit-learn IsolationForest and evaluate on either an explicit held-out test set
    or a stratified train/val/test split of train_events.
    """
    t_start = time.perf_counter()

    if test_events is not None and len(test_events) > 0:
        y_train = extract_ground_truth_labels(train_events)
        y_test = extract_ground_truth_labels(test_events)

        if y_train is not None:
            fit_events = [ev for ev, lbl in zip(train_events, y_train) if lbl == 0]
            if len(fit_events) < 5:
                fit_events = list(train_events)
        else:
            fit_events = list(train_events)

        X_fit = extract_features(fit_events)
        X_train_all = extract_features(train_events)
        X_test = extract_features(test_events)

        scaler = StandardScaler()
        X_fit_s = scaler.fit_transform(X_fit)
        clf = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_fit_s)

        train_scores = -clf.decision_function(scaler.transform(X_train_all))
        threshold = calibrate_threshold(train_scores, y_train)
        test_scores = -clf.decision_function(scaler.transform(X_test))

        train_size = len(train_events)
        val_size = 0
        test_size = len(test_events)
    else:
        ratio = split_ratio or {"train": 0.6, "val": 0.2, "test": 0.2}
        y_all = extract_ground_truth_labels(train_events)

        def split_indices(indices: List[int]) -> Tuple[List[int], List[int], List[int]]:
            t_end = max(1, int(len(indices) * ratio.get("train", 0.6)))
            v_end = max(t_end, min(len(indices) - 1, t_end + int(len(indices) * ratio.get("val", 0.2))))
            return indices[:t_end], indices[t_end:v_end], indices[v_end:]

        if y_all is not None and len(np.unique(y_all)) == 2:
            pos_idx = [i for i, lbl in enumerate(y_all) if lbl == 1]
            neg_idx = [i for i, lbl in enumerate(y_all) if lbl == 0]
            p_tr, p_val, p_te = split_indices(pos_idx)
            n_tr, n_val, n_te = split_indices(neg_idx)
            tr_idx = p_tr + n_tr
            val_idx = p_val + n_val
            te_idx = p_te + n_te
        else:
            all_idx = list(range(len(train_events)))
            tr_idx, val_idx, te_idx = split_indices(all_idx)

        X_all = extract_features(train_events)
        if y_all is not None:
            fit_idx = [i for i in tr_idx if y_all[i] == 0] or tr_idx
        else:
            fit_idx = tr_idx

        scaler = StandardScaler()
        X_fit_s = scaler.fit_transform(X_all[fit_idx])
        clf = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_fit_s)

        cal_idx = val_idx if val_idx else tr_idx
        cal_scores = -clf.decision_function(scaler.transform(X_all[cal_idx]))
        cal_y = y_all[cal_idx] if y_all is not None else None
        threshold = calibrate_threshold(cal_scores, cal_y)

        test_scores = -clf.decision_function(scaler.transform(X_all[te_idx]))
        y_test = y_all[te_idx] if y_all is not None else None
        train_size = len(tr_idx)
        val_size = len(val_idx)
        test_size = len(te_idx)

    elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

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
            "confusion_matrix": {"tp": 0, "fp": pred_anom, "tn": len(test_scores) - pred_anom, "fn": 0},
            "roc_curve": [{"fpr": 0.0, "tpr": 0.0, "threshold": 1.0}, {"fpr": 1.0, "tpr": 1.0, "threshold": 0.0}],
            "pr_curve": [],
        }
        has_gt = False

    return {
        "model": clf,
        "scaler": scaler,
        "features": FEATURES,
        "threshold": round(threshold, 6),
        "has_ground_truth": has_gt,
        "train_size": train_size,
        "val_size": val_size,
        "test_size": test_size,
        "latency_ms": elapsed_ms,
        **eval_out,
    }
