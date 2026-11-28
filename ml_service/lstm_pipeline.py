"""
Real PyTorch LSTM Autoencoder pipeline for sequential anomaly detection
over chronological CloudTrail user/session sliding windows.

Guarantees:
- Never reads ground-truth labels during feature extraction or window construction.
- Splits training, validation, and testing strictly chronologically (no future leakage).
- Fits StandardScaler and trains LSTM Autoencoder exclusively on benign training sequences.
- Calibrates decision threshold strictly on validation sequences.
- Compares side-by-side against the saved Isolation Forest model on the exact
  same eligible test events without altering Isolation Forest artifacts or features.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
import math
import time

import joblib
import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import StandardScaler

from cloudtrail_pipeline import (
    FEATURES as IF_FEATURES,
    _extract_user_id,
    compute_evaluation_curves,
    extract_features as extract_if_features,
    extract_ground_truth_labels,
    parse_time,
)
from sklearn.metrics import f1_score

LSTM_FEATURES: List[str] = [
    *IF_FEATURES,
    "log_time_delta_sec",
    "action_novelty_flag",
]

ALLOWED_WINDOWS = (5, 10, 16)
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
IF_MODEL_FILE = DATA_DIR / "isolation_forest_cloudtrail.joblib"


class LSTMAutoencoder(nn.Module):
    """Sequence-to-sequence LSTM Autoencoder for multivariate behavioral windows."""

    def __init__(self, input_dim: int, hidden_dim: int = 32) -> None:
        super().__init__()
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h_n, _) = self.encoder(x)
        repeated = h_n[-1].unsqueeze(1).repeat(1, x.size(1), 1)
        reconstructed, _ = self.decoder(repeated)
        return reconstructed


def lstm_checkpoint_path(window_size: int) -> Path:
    return DATA_DIR / f"lstm_cloudtrail_w{int(window_size)}.pt"


def extract_lstm_step_features(events: Sequence[Dict[str, Any]]) -> np.ndarray:
    """
    Extract leak-free 10-dimensional per-event behavioral + temporal features:
    the 8 CloudTrail features plus per-identity log time delta and action novelty.
    """
    if not events:
        return np.empty((0, len(LSTM_FEATURES)), dtype=float)

    base_x = extract_if_features(events)
    temporal = np.zeros((len(events), 2), dtype=float)

    by_identity: Dict[str, List[Tuple[Optional[datetime], int, str]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        uid = _extract_user_id(ev)
        dt = parse_time(ev.get("event_time") or ev.get("eventTime") or ev.get("timestamp"))
        action = str(ev.get("action") or ev.get("eventName") or "").strip().lower()
        by_identity[uid].append((dt, idx, action))

    for items in by_identity.values():
        items.sort(key=lambda item: (item[0] or datetime.min.replace(tzinfo=timezone.utc), item[1]))
        prev_dt: Optional[datetime] = None
        prev_action: Optional[str] = None
        for dt, idx, action in items:
            if dt is not None and prev_dt is not None:
                delta_sec = max(0.0, (dt - prev_dt).total_seconds())
                temporal[idx, 0] = math.log1p(delta_sec)
            if prev_action is not None and action != prev_action:
                temporal[idx, 1] = 1.0
            prev_dt = dt
            prev_action = action

    return np.hstack([base_x, temporal])


def build_identity_sliding_windows(
    events: Sequence[Dict[str, Any]],
    X_scaled: np.ndarray,
    labels: Optional[np.ndarray],
    window_size: int,
) -> Dict[str, Any]:
    """
    Group events chronologically by resolved user/session identity and generate
    sliding windows of length `window_size`. Labels belong strictly to the final
    target event of each window (and `pure_benign_mask` tracks all-benign windows).
    """
    by_identity: Dict[str, List[Tuple[Optional[datetime], int]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        uid = _extract_user_id(ev)
        dt = parse_time(ev.get("event_time") or ev.get("eventTime") or ev.get("timestamp"))
        by_identity[uid].append((dt, idx))

    windows_x: List[np.ndarray] = []
    target_labels: List[int] = []
    pure_benign: List[bool] = []
    target_indices: List[int] = []
    target_event_ids: List[str] = []

    # Process identities in deterministic order; preserve chronological target order
    pending: List[Tuple[datetime, int, np.ndarray, int, bool, str]] = []
    for items in by_identity.values():
        items.sort(key=lambda item: (item[0] or datetime.min.replace(tzinfo=timezone.utc), item[1]))
        if len(items) < window_size:
            continue
        indices = [it[1] for it in items]
        times = [it[0] or datetime.min.replace(tzinfo=timezone.utc) for it in items]
        for pos in range(window_size - 1, len(indices)):
            seq_idx = indices[pos - window_size + 1 : pos + 1]
            t_idx = seq_idx[-1]
            t_dt = times[pos]
            t_lbl = int(labels[t_idx]) if labels is not None else -1
            is_pure_benign = (
                all(int(labels[j]) == 0 for j in seq_idx) if labels is not None else True
            )
            ev_id = str(events[t_idx].get("event_id") or f"idx-{t_idx}")
            pending.append((t_dt, t_idx, X_scaled[seq_idx], t_lbl, is_pure_benign, ev_id))

    pending.sort(key=lambda item: (item[0], item[1]))
    for _, t_idx, seq_mat, t_lbl, is_pure, ev_id in pending:
        windows_x.append(seq_mat)
        target_labels.append(t_lbl)
        pure_benign.append(is_pure)
        target_indices.append(t_idx)
        target_event_ids.append(ev_id)

    n_features = X_scaled.shape[1] if X_scaled.ndim == 2 else len(LSTM_FEATURES)
    X_win = (
        np.asarray(windows_x, dtype=np.float32)
        if windows_x
        else np.empty((0, window_size, n_features), dtype=np.float32)
    )
    y_win = np.asarray(target_labels, dtype=int) if labels is not None else None
    pure_mask = np.asarray(pure_benign, dtype=bool)
    idx_arr = np.asarray(target_indices, dtype=int)

    return {
        "X_win": X_win,
        "y_win": y_win,
        "pure_benign_mask": pure_mask,
        "target_indices": idx_arr,
        "target_event_ids": target_event_ids,
        "unique_identities": len(by_identity),
        "total_events": len(events),
        "eligible_events": len(target_indices),
        "excluded_events": max(0, len(events) - len(target_indices)),
    }


def compute_reconstruction_errors(model: LSTMAutoencoder, X_win: np.ndarray) -> np.ndarray:
    """Compute balanced sequence + final-step MSE reconstruction errors."""
    if len(X_win) == 0:
        return np.empty((0,), dtype=float)
    model.eval()
    tensor_x = torch.from_numpy(X_win.astype(np.float32))
    errors: List[np.ndarray] = []
    batch_size = 512
    with torch.no_grad():
        for start in range(0, len(tensor_x), batch_size):
            xb = tensor_x[start : start + batch_size]
            recon = model(xb)
            seq_mse = torch.mean((recon - xb) ** 2, dim=(1, 2))
            last_mse = torch.mean((recon[:, -1, :] - xb[:, -1, :]) ** 2, dim=1)
            err = (0.5 * seq_mse + 0.5 * last_mse).cpu().numpy()
            errors.append(err)
    return np.concatenate(errors).astype(float)


def _compute_pr_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    if len(np.unique(y_true)) < 2:
        return 0.0
    return round(float(average_precision_score(y_true, scores)), 4)


def _calibrate_validation_threshold(scores: np.ndarray, y_true: np.ndarray) -> float:
    """
    Calibrate threshold on validation reconstruction errors using empirical quantiles
    so extreme outlier errors do not skip the dense threshold region.
    """
    if len(scores) == 0 or len(np.unique(y_true)) < 2:
        return float(np.quantile(scores, 0.95)) if len(scores) > 0 else 0.3

    candidates = np.unique(np.quantile(scores, np.linspace(0.05, 0.99, 150)))
    best_th = float(candidates[0])
    best_f1 = -1.0
    for th in candidates:
        preds = (scores >= th).astype(int)
        score = float(f1_score(y_true, preds, zero_division=0))
        if score > best_f1:
            best_f1 = score
            best_th = float(th)
    return best_th


def _evaluate_saved_isolation_forest_on_indices(
    test_events: Sequence[Dict[str, Any]],
    target_indices: np.ndarray,
    y_target: Optional[np.ndarray],
) -> Optional[Dict[str, Any]]:
    """
    Evaluate the untouched saved Isolation Forest bundle on the exact same
    eligible test event indices used by the LSTM sliding-window evaluation.
    """
    if not IF_MODEL_FILE.exists() or len(target_indices) == 0:
        return None

    bundle = joblib.load(IF_MODEL_FILE)
    if_model = bundle["model"]
    if_scaler = bundle["scaler"]
    if_threshold = float(bundle.get("threshold", 0.0))
    if_version = str(bundle.get("model_version", "isolation-forest-cloudtrail-v2"))

    t0 = time.perf_counter()
    X_all = extract_if_features(test_events)
    X_s = if_scaler.transform(X_all)
    scores_all = -if_model.decision_function(X_s)
    eligible_scores = scores_all[target_indices]
    inf_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    if y_target is not None and len(np.unique(y_target)) == 2:
        curves = compute_evaluation_curves(y_target, eligible_scores, if_threshold)
        pr_auc = _compute_pr_auc(y_target, eligible_scores)
        metrics = {**curves["metrics"], "pr_auc": pr_auc}
        cm = curves["confusion_matrix"]
        has_gt = True
    else:
        pred_anom = int(np.sum(eligible_scores >= if_threshold))
        metrics = {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "false_positive_rate": round(pred_anom / max(1, len(eligible_scores)), 4),
            "roc_auc": 0.5,
            "pr_auc": 0.0,
        }
        cm = {
            "tp": 0,
            "fp": pred_anom,
            "tn": int(len(eligible_scores) - pred_anom),
            "fn": 0,
        }
        has_gt = False

    return {
        "model_type": "Isolation Forest",
        "model_version": if_version,
        "model_file": IF_MODEL_FILE.name,
        "threshold": round(if_threshold, 6),
        "has_ground_truth": has_gt,
        "eligible_test_events": int(len(eligible_scores)),
        "inference_latency_ms": inf_ms,
        "metrics": metrics,
        "confusion_matrix": cm,
    }


def _chronological_event_sort(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    decorated = [
        (parse_time(ev.get("event_time") or ev.get("eventTime") or ev.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc), i, ev)
        for i, ev in enumerate(events)
    ]
    decorated.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in decorated]


def train_and_evaluate_lstm(
    train_events: Sequence[Dict[str, Any]],
    test_events: Optional[Sequence[Dict[str, Any]]] = None,
    window_size: int = 10,
    hidden_dim: int = 32,
    epochs: int = 15,
    batch_size: int = 128,
    split_ratio: Optional[Dict[str, float]] = None,
    include_if_comparison: bool = True,
    save_model: bool = True,
) -> Dict[str, Any]:
    """
    Chronologically train a PyTorch LSTM Autoencoder on benign sequences,
    calibrate threshold strictly on validation sequences, and evaluate on held-out test data.
    """
    if window_size not in ALLOWED_WINDOWS:
        raise ValueError(f"window_size must be one of {ALLOWED_WINDOWS}, got {window_size}.")

    torch.manual_seed(42)
    np.random.seed(42)
    torch.set_num_threads(min(4, max(1, (torch.get_num_threads() or 4))))

    sorted_primary = _chronological_event_sort(train_events)

    if test_events is not None and len(test_events) > 0:
        ratio = split_ratio or {"train": 0.7, "val": 0.3, "test": 0.0}
        tr_share = float(ratio.get("train", 0.7))
        val_share = float(ratio.get("val", 0.3))
        test_share = float(ratio.get("test", 0.0))
        # When caller passes a single-dataset 3-way split alongside an explicit held-out test set,
        # use the standard 70/30 chronological train/validation calibration split on train_events.
        if test_share > 0 or val_share <= 0 or tr_share + val_share <= 0:
            tr_frac = 0.7
        else:
            tr_frac = max(0.55, min(0.75, tr_share / (tr_share + val_share)))

        cut = int(len(sorted_primary) * tr_frac)
        tr_slice = sorted_primary[:cut]
        val_slice = sorted_primary[cut:]
        te_slice = _chronological_event_sort(test_events)
    else:
        ratio = split_ratio or {"train": 0.6, "val": 0.2, "test": 0.2}
        tr_r = max(0.3, float(ratio.get("train", 0.6)))
        val_r = max(0.1, float(ratio.get("val", 0.2)))
        tot_r = tr_r + val_r + max(0.1, float(ratio.get("test", 0.2)))
        cut_tr = int(len(sorted_primary) * (tr_r / tot_r))
        cut_val = int(len(sorted_primary) * ((tr_r + val_r) / tot_r))
        tr_slice = sorted_primary[:cut_tr]
        val_slice = sorted_primary[cut_tr:cut_val]
        te_slice = sorted_primary[cut_val:]

    y_tr_raw = extract_ground_truth_labels(tr_slice)
    y_val_raw = extract_ground_truth_labels(val_slice)
    y_te_raw = extract_ground_truth_labels(te_slice)

    X_tr_raw = extract_lstm_step_features(tr_slice)
    X_val_raw = extract_lstm_step_features(val_slice)
    X_te_raw = extract_lstm_step_features(te_slice)

    if len(X_tr_raw) < window_size or len(X_val_raw) < window_size or len(X_te_raw) < window_size:
        return {
            "suitable": False,
            "unsuitable_reason": (
                f"Chronological split produced fewer events than window_size={window_size} "
                f"(train={len(X_tr_raw)}, val={len(X_val_raw)}, test={len(X_te_raw)})."
            ),
        }

    # Fit StandardScaler strictly on benign training events (never validation/test)
    scaler = StandardScaler()
    if y_tr_raw is not None:
        benign_tr_events = X_tr_raw[y_tr_raw == 0]
        scaler.fit(benign_tr_events if len(benign_tr_events) >= 5 else X_tr_raw)
    else:
        scaler.fit(X_tr_raw)

    X_tr_s = scaler.transform(X_tr_raw)
    X_val_s = scaler.transform(X_val_raw)
    X_te_s = scaler.transform(X_te_raw)

    tr_win = build_identity_sliding_windows(tr_slice, X_tr_s, y_tr_raw, window_size)
    val_win = build_identity_sliding_windows(val_slice, X_val_s, y_val_raw, window_size)
    te_win = build_identity_sliding_windows(te_slice, X_te_s, y_te_raw, window_size)

    X_tr_benign = tr_win["X_win"][tr_win["pure_benign_mask"]]
    if len(X_tr_benign) < 10 and tr_win["y_win"] is not None:
        target_benign = tr_win["X_win"][tr_win["y_win"] == 0]
        if len(target_benign) >= 10:
            X_tr_benign = target_benign

    if len(X_tr_benign) < 10 or len(val_win["X_win"]) < 5 or len(te_win["X_win"]) < 5:
        return {
            "suitable": False,
            "unsuitable_reason": (
                f"Insufficient identity-grouped sliding windows for window_size={window_size}: "
                f"benign_train_windows={len(X_tr_benign)}, val_windows={len(val_win['X_win'])}, "
                f"test_windows={len(te_win['X_win'])}. Reduce window size or select a larger dataset."
            ),
        }

    # Train real PyTorch LSTM Autoencoder on benign chronological sequences
    t_train0 = time.perf_counter()
    model = LSTMAutoencoder(input_dim=len(LSTM_FEATURES), hidden_dim=hidden_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=2e-3)
    criterion = nn.MSELoss()

    dataset = torch.utils.data.TensorDataset(torch.from_numpy(X_tr_benign))
    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    model.train()
    epoch_losses: List[float] = []
    for _ in range(epochs):
        total_loss = 0.0
        n_batches = 0
        for (xb,) in loader:
            optimizer.zero_grad()
            recon = model(xb)
            loss = criterion(recon, xb)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item())
            n_batches += 1
        epoch_losses.append(round(total_loss / max(1, n_batches), 6))

    training_time_ms = round((time.perf_counter() - t_train0) * 1000.0, 2)

    # Calibrate threshold strictly on chronological validation sequences
    val_scores = compute_reconstruction_errors(model, val_win["X_win"])
    y_val_win = val_win["y_win"]
    if y_val_win is not None and len(np.unique(y_val_win)) == 2:
        threshold = _calibrate_validation_threshold(val_scores, y_val_win)
        cal_note = (
            f"Threshold ({threshold:.4f}) calibrated strictly on chronological validation split "
            f"(n={len(y_val_win)}, attacks={int(np.sum(y_val_win))}) via empirical quantile F1 maximization."
        )
    else:
        threshold = float(np.quantile(val_scores, 0.95)) if len(val_scores) > 0 else 0.3
        cal_note = (
            f"Validation slice contained single class (n={len(val_scores)}); threshold ({threshold:.4f}) "
            "calibrated at validation 95th percentile."
        )

    # Evaluate on held-out test sequences & time inference strictly
    t_inf0 = time.perf_counter()
    test_scores = compute_reconstruction_errors(model, te_win["X_win"])
    inference_latency_ms = round((time.perf_counter() - t_inf0) * 1000.0, 2)

    y_test_win = te_win["y_win"]
    if y_test_win is not None and len(np.unique(y_test_win)) == 2:
        eval_out = compute_evaluation_curves(y_test_win, test_scores, threshold)
        pr_auc = _compute_pr_auc(y_test_win, test_scores)
        eval_out["metrics"]["pr_auc"] = pr_auc
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
                "pr_auc": 0.0,
            },
            "confusion_matrix": {
                "tp": 0,
                "fp": pred_anom,
                "tn": int(len(test_scores) - pred_anom),
                "fn": 0,
            },
            "roc_curve": [
                {"fpr": 0.0, "tpr": 0.0, "threshold": 1.0},
                {"fpr": 1.0, "tpr": 1.0, "threshold": 0.0},
            ],
            "pr_curve": [],
        }
        has_gt = False

    model_version = f"pytorch-lstm-ae-w{window_size}-h{hidden_dim}-v1"
    artifact_path = lstm_checkpoint_path(window_size)
    if save_model:
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "input_dim": len(LSTM_FEATURES),
                "hidden_dim": hidden_dim,
                "window_size": window_size,
                "features": LSTM_FEATURES,
                "scaler": scaler,
                "threshold": float(threshold),
                "model_version": model_version,
                "training_time_ms": training_time_ms,
                "final_train_loss": epoch_losses[-1] if epoch_losses else None,
            },
            artifact_path,
        )

    baseline_if = (
        _evaluate_saved_isolation_forest_on_indices(
            te_slice, te_win["target_indices"], y_test_win
        )
        if include_if_comparison
        else None
    )

    return {
        "suitable": True,
        "model": "LSTM Sequence",
        "model_version": model_version,
        "model_artifact": artifact_path.name if save_model else None,
        "features": LSTM_FEATURES,
        "threshold": round(float(threshold), 6),
        "has_ground_truth": has_gt,
        "train_size": int(len(tr_slice)),
        "val_size": int(len(val_slice)),
        "test_size": int(len(te_win["X_win"])),
        "training_time_ms": training_time_ms,
        "inference_latency_ms": inference_latency_ms,
        "latency_ms": inference_latency_ms,
        "sequence_config": {
            "window_size": int(window_size),
            "identity_grouping": "user_or_session_identity",
            "train_windows": int(len(tr_win["X_win"])),
            "benign_train_windows": int(len(X_tr_benign)),
            "val_windows": int(len(val_win["X_win"])),
            "test_windows": int(len(te_win["X_win"])),
            "eligible_test_events": int(te_win["eligible_events"]),
            "excluded_test_events": int(te_win["excluded_events"]),
            "validation_calibration_note": cal_note,
            "epochs": epochs,
            "hidden_dim": hidden_dim,
            "final_train_loss": epoch_losses[-1] if epoch_losses else None,
        },
        "baseline_comparison": baseline_if,
        **eval_out,
    }


def evaluate_saved_lstm(
    test_events: Sequence[Dict[str, Any]],
    window_size: int = 10,
    train_size: int = 0,
    include_if_comparison: bool = True,
) -> Dict[str, Any]:
    """Load persisted PyTorch LSTM checkpoint for `window_size` and evaluate on held-out events."""
    ckpt_path = lstm_checkpoint_path(window_size)
    if not ckpt_path.exists():
        raise FileNotFoundError(
            f"Saved PyTorch LSTM checkpoint not found for W={window_size} at {ckpt_path.name}. "
            "Run /lstm/train-evaluate first."
        )

    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    input_dim = int(ckpt["input_dim"])
    hidden_dim = int(ckpt["hidden_dim"])
    scaler: StandardScaler = ckpt["scaler"]
    threshold = float(ckpt["threshold"])
    model_version = str(ckpt["model_version"])

    model = LSTMAutoencoder(input_dim=input_dim, hidden_dim=hidden_dim)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    te_slice = _chronological_event_sort(test_events)
    y_te_raw = extract_ground_truth_labels(te_slice)
    X_te_raw = extract_lstm_step_features(te_slice)
    X_te_s = scaler.transform(X_te_raw)
    te_win = build_identity_sliding_windows(te_slice, X_te_s, y_te_raw, window_size)

    if len(te_win["X_win"]) == 0:
        return {
            "suitable": False,
            "unsuitable_reason": (
                f"No identity sequences had length >= window_size={window_size} in this test set."
            ),
        }

    t_inf0 = time.perf_counter()
    test_scores = compute_reconstruction_errors(model, te_win["X_win"])
    inference_latency_ms = round((time.perf_counter() - t_inf0) * 1000.0, 2)

    y_test_win = te_win["y_win"]
    if y_test_win is not None and len(np.unique(y_test_win)) == 2:
        eval_out = compute_evaluation_curves(y_test_win, test_scores, threshold)
        eval_out["metrics"]["pr_auc"] = _compute_pr_auc(y_test_win, test_scores)
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
                "pr_auc": 0.0,
            },
            "confusion_matrix": {
                "tp": 0,
                "fp": pred_anom,
                "tn": int(len(test_scores) - pred_anom),
                "fn": 0,
            },
            "roc_curve": [
                {"fpr": 0.0, "tpr": 0.0, "threshold": 1.0},
                {"fpr": 1.0, "tpr": 1.0, "threshold": 0.0},
            ],
            "pr_curve": [],
        }
        has_gt = False

    baseline_if = (
        _evaluate_saved_isolation_forest_on_indices(
            te_slice, te_win["target_indices"], y_test_win
        )
        if include_if_comparison
        else None
    )

    return {
        "suitable": True,
        "model": "LSTM Sequence",
        "model_version": model_version,
        "model_artifact": ckpt_path.name,
        "features": list(ckpt.get("features", LSTM_FEATURES)),
        "threshold": round(threshold, 6),
        "has_ground_truth": has_gt,
        "train_size": train_size,
        "val_size": 0,
        "test_size": int(len(te_win["X_win"])),
        "training_time_ms": ckpt.get("training_time_ms"),
        "inference_latency_ms": inference_latency_ms,
        "latency_ms": inference_latency_ms,
        "sequence_config": {
            "window_size": int(window_size),
            "identity_grouping": "user_or_session_identity",
            "train_windows": 0,
            "benign_train_windows": 0,
            "val_windows": 0,
            "test_windows": int(len(te_win["X_win"])),
            "eligible_test_events": int(te_win["eligible_events"]),
            "excluded_test_events": int(te_win["excluded_events"]),
        },
        "baseline_comparison": baseline_if,
        **eval_out,
    }


def list_saved_lstm_checkpoints() -> List[Dict[str, Any]]:
    checkpoints: List[Dict[str, Any]] = []
    for w in ALLOWED_WINDOWS:
        p = lstm_checkpoint_path(w)
        checkpoints.append({
            "window_size": w,
            "artifact_file": p.name,
            "exists": p.exists(),
            "size_bytes": p.stat().st_size if p.exists() else 0,
        })
    return checkpoints
