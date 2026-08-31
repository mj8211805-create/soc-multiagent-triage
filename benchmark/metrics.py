"""Metric calculation formulas for SOC triage evaluation."""

from typing import Dict, Any, List
from core.schema import BaselineMetrics


def calculate_baseline_metrics(
    method_name: str,
    total_raw_alerts: int,
    incidents_generated: int,
    tp: int,
    fp: int,
    fn: int,
    tn: int,
    avg_latency_ms: float,
    total_tokens_used: int = 0,
    cost_usd: float = 0.0
) -> BaselineMetrics:
    """Computes standard classification and efficiency metrics for a triage method."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    total_samples = tp + tn + fp + fn
    accuracy = (tp + tn) / total_samples if total_samples > 0 else 0.0

    # Compression: how much the alert volume was reduced into manageable incidents
    alert_compression = ((total_raw_alerts - incidents_generated) / total_raw_alerts * 100.0) if total_raw_alerts > 0 else 0.0
    alert_compression = max(0.0, alert_compression)

    # FP Reduction: percentage of benign noise successfully suppressed
    fp_reduction = (tn / (tn + fp) * 100.0) if (tn + fp) > 0 else 100.0

    return BaselineMetrics(
        method_name=method_name,
        total_alerts_processed=total_raw_alerts,
        incidents_generated=incidents_generated,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        accuracy=round(accuracy, 4),
        alert_compression_ratio=round(alert_compression, 2),
        false_positive_reduction_rate=round(fp_reduction, 2),
        avg_latency_ms=round(avg_latency_ms, 2),
        total_tokens_used=total_tokens_used,
        cost_usd=round(cost_usd, 5)
    )
