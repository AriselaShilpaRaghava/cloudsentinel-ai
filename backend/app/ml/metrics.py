"""
Evaluation metrics computation for anomaly detection models.
Supports ground-truth evaluation: Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrix.
Distinguishes real measured metrics from missing ground truth.
"""

from typing import Dict, Any, List, Optional
import numpy as np

def compute_metrics(
    y_true: Optional[List[int]],
    y_pred_binary: List[int],
    y_scores: List[float]
) -> Dict[str, Any]:
    """
    Computes standard classification & anomaly detection metrics.
    If ground-truth labels y_true are None, returns explicit status without inventing data.
    """
    if y_true is None or len(y_true) == 0:
        return {
            "has_ground_truth": False,
            "message": "Unsupervised mode: Ground-truth audit labels not provided in dataset. Displaying empirical anomaly distribution.",
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1_score": None,
            "roc_auc": None,
            "confusion_matrix": None
        }

    y_t = np.array(y_true)
    y_p = np.array(y_pred_binary)

    tp = int(np.sum((y_t == 1) & (y_p == 1)))
    fp = int(np.sum((y_t == 0) & (y_p == 1)))
    tn = int(np.sum((y_t == 0) & (y_p == 0)))
    fn = int(np.sum((y_t == 1) & (y_p == 0)))

    total = len(y_t)
    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    # Approximate ROC-AUC
    sorted_indices = np.argsort(y_scores)[::-1]
    y_sorted = y_t[sorted_indices]
    n_pos = np.sum(y_t == 1)
    n_neg = np.sum(y_t == 0)

    if n_pos > 0 and n_neg > 0:
        tp_accum = np.cumsum(y_sorted == 1)
        fp_accum = np.cumsum(y_sorted == 0)
        tpr = tp_accum / n_pos
        fpr = fp_accum / n_neg
        roc_auc = round(float(np.trapz(tpr, fpr)), 4)
    else:
        roc_auc = None

    return {
        "has_ground_truth": True,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn
        }
    }
