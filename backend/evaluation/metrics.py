import numpy as np
from sklearn.metrics import precision_recall_curve, auc, roc_auc_score

def calculate_asr(y_true: np.ndarray, y_pred_prob: np.ndarray, threshold: float = 0.5) -> float:
    """
    Attack Success Rate (ASR)
    Percentage of malicious flows (y_true=1) that successfully evade detection (y_pred < threshold).
    """
    malicious_mask = (y_true == 1)
    if not np.any(malicious_mask):
        return 0.0
        
    evaded = (y_pred_prob[malicious_mask] < threshold).sum()
    total_malicious = malicious_mask.sum()
    
    return float(evaded / total_malicious)

def calculate_pr_auc(y_true: np.ndarray, y_pred_prob: np.ndarray) -> float:
    """Precision-Recall Area Under Curve (robust measure for imbalanced data)."""
    precision, recall, _ = precision_recall_curve(y_true, y_pred_prob)
    return float(auc(recall, precision))

def calculate_precision_at_k(y_true: np.ndarray, y_pred_prob: np.ndarray, k: float = 0.01) -> float:
    """
    Precision at Top-K percentile.
    Measures the precision among the top K% most anomalous scores. This is highly relevant for SOC teams.
    """
    n = len(y_true)
    top_k_count = max(1, int(n * k))
    
    # Get indices of the top K largest predicted probabilities
    top_indices = np.argsort(y_pred_prob)[-top_k_count:]
    
    true_anomalies = y_true[top_indices].sum()
    return float(true_anomalies / top_k_count)

def calculate_detection_delay(y_true: np.ndarray, y_pred_prob: np.ndarray, timestamps: np.ndarray, threshold: float = 0.5) -> float:
    """
    Assuming timestamps are ordered. Calculates the time difference between the first
    malicious action and the first time an alert fires above the threshold.
    """
    malicious_idx = np.where(y_true == 1)[0]
    if len(malicious_idx) == 0:
        return 0.0
        
    first_attack_ts = timestamps[malicious_idx[0]]
    
    alert_idx = np.where((y_pred_prob >= threshold) & (y_true == 1))[0]
    if len(alert_idx) == 0:
        return float('inf') # Never detected
        
    first_detect_ts = timestamps[alert_idx[0]]
    return float((first_detect_ts - first_attack_ts).total_seconds())

def generate_report(y_true: np.ndarray, y_pred_prob: np.ndarray) -> dict:
    """Generates a standardized dictionary of metrics."""
    return {
        "roc_auc": float(roc_auc_score(y_true, y_pred_prob)) if len(np.unique(y_true)) > 1 else 0.0,
        "pr_auc": calculate_pr_auc(y_true, y_pred_prob),
        "asr": calculate_asr(y_true, y_pred_prob, threshold=0.5),
        "precision_at_1_pct": calculate_precision_at_k(y_true, y_pred_prob, k=0.01)
    }
