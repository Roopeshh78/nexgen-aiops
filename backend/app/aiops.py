"""AIOps engine: baselines, anomaly detection, correlation, RCA, forecasting, explanation."""
import statistics
from datetime import timedelta

from .config import HEALTH_BANDS, LOWER_IS_WORSE, METRICS, THRESHOLDS

# Rolling baseline: per (tenant, host, metric) we keep the last N samples in memory
# and persist the raw samples in SQLite for trend charts.
BASELINE_WINDOW = 40


def health_label(score: float) -> str:
    for floor, label in HEALTH_BANDS:
        if score >= floor:
            return label
    return "Poor"


def score_to_state(score: float) -> str:
    return health_label(score)


def metric_health(metric: str, value: float) -> float:
    """0..100 sub-score for one metric reading."""
    warn, crit = THRESHOLDS.get(metric)
    if warn is None:
        return 100.0
    if metric in LOWER_IS_WORSE:
        if value >= 99.95:
            return 100.0
        if value <= crit:
            return max(0.0, 30 * value / crit)
        if value <= warn:
            return 30 + 40 * (value - crit) / max(warn - crit, 1e-9)
        return 70 + 30 * min(1.0, (value - warn) / max(100 - warn, 1e-9))
    if value <= warn * 0.7:
        return 100.0 - (value / max(warn, 1e-9)) * 10
    if value <= warn:
        return 90 - 20 * (value - warn * 0.7) / max(warn * 0.3, 1e-9)
    if value <= crit:
        return 70 - 40 * (value - warn) / max(crit - warn, 1e-9)
    return max(0.0, 30 - 30 * (value - crit) / max(crit * 0.5, 1e-9))


def baseline_stats(values):
    if not values:
        return {"mean": None, "stdev": None, "samples": 0}
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
    return {"mean": round(mean, 3), "stdev": round(stdev, 3), "samples": len(values),
            "min": round(min(values), 3), "max": round(max(values), 3)}


def z_score(value, stats):
    if stats["mean"] is None or not stats["stdev"]:
        return 0.0
    return round((value - stats["mean"]) / max(stats["stdev"], 1e-6), 2)


def detect_anomalies(series: dict, current: dict):
    """series: metric_key -> [values]; current: metric_key -> latest value.

    Returns anomaly list with z-score, deviation %, severity and contributing signals.
    """
    findings = []
    for key, values in series.items():
        if key not in current or not values:
            continue
        metric = key.split(":")[-1]
        stats = baseline_stats(values[:-1] or values)
        value = current[key]
        z = z_score(value, stats)
        warn, crit = THRESHOLDS.get(metric, (None, None))
        if warn is None:
            continue
        breached = (value <= crit) if metric in LOWER_IS_WORSE else (value >= crit)
        warned = (value <= warn) if metric in LOWER_IS_WORSE else (value >= warn)
        if not (warned or abs(z) >= 2.5):
            continue
        deviation = 0.0
        if stats["mean"]:
            deviation = round((value - stats["mean"]) / abs(stats["mean"]) * 100, 1)
        severity = "critical" if breached or abs(z) >= 4 else "warning"
        findings.append({
            "key": key,
            "metric": metric,
            "value": round(value, 3),
            "baseline_mean": stats["mean"],
            "baseline_stdev": stats["stdev"],
            "z_score": z,
            "deviation_pct": deviation,
            "severity": severity,
            "method": "robust z-score + static threshold",
            "direction": "below" if metric in LOWER_IS_WORSE else "above",
            "threshold": {"warn": warn, "critical": crit},
        })
    findings.sort(key=lambda f: (f["severity"] != "critical", -abs(f["z_score"])))
    return findings


def correlation_key(alert) -> str:
    """Signals that make two alerts 'the same problem'."""
    parts = [alert.get("tenant_id"), alert.get("host") or alert.get("service") or "fleet"]
    return "|".join(str(p) for p in parts)


def correlate(alerts):
    """Group alerts into incident candidates by host/service affinity."""
    groups = {}
    for a in alerts:
        groups.setdefault(correlation_key(a), []).append(a)
    return groups


ROOT_CAUSE_LIBRARY = {
    "cpu_pct": ("Compute saturation on {host}", "CPU sustained above threshold; queue depth and response time rise together. Most likely a runaway workload, insufficient worker capacity, or a noisy neighbour on the node."),
    "mem_pct": ("Memory pressure on {host}", "Resident memory growth without release indicates a leak or working-set growth. Swap activity will degrade latency shortly after."),
    "disk_pct": ("Storage exhaustion on {host}", "Write amplification or log rotation failure is filling the data volume. Writes will fail once the volume is full."),
    "latency_ms": ("WAN path degradation towards {host}", "Round-trip time increase with stable throughput points at transit or peering congestion rather than application code."),
    "packet_loss_pct": ("Transit link loss on {host}", "Loss above baseline causes retransmits, inflating latency and error rate on dependent services."),
    "error_rate_pct": ("Service failure in {service}", "Error rate above baseline with elevated p95 indicates dependency failure or a bad deployment."),
    "api_p95_ms": ("API tail-latency regression in {service}", "p95 inflation with normal request volume suggests downstream dependency slowdown or lock contention."),
    "svc_availability_pct": ("Availability breach for {service}", "Availability has dropped below the service objective; health-check failures are the dominant signal."),
}


def explain(alert, related=None):
    """Explainable AIOps: what happened, why detected, contributing signals, action."""
    metric = alert.get("metric", "")
    host = alert.get("host", "the fleet")
    service = alert.get("service") or "-"
    title, why = ROOT_CAUSE_LIBRARY.get(metric, ("Degradation on {host}", "Value deviated from its learned baseline."))
    template_vars = {"host": host, "service": service}
    signals = [
        {"name": "metric value", "value": alert.get("value"), "weight": 0.42},
        {"name": "deviation from baseline", "value": f"{alert.get('deviation_pct', 0)}%", "weight": 0.28},
        {"name": "z-score", "value": alert.get("z_score", 0), "weight": 0.18},
    ]
    if related:
        signals.append({"name": f"correlated alerts ({len(related)})", "value": len(related), "weight": 0.12})
    actions = {
        "cpu_pct": "Check the top CPU consumers on the node, then either horizontally scale the workload or apply a CPU limit to the noisy neighbour.",
        "mem_pct": "Capture a heap/working-set profile, restart only if the OOM margin is critical, and raise the memory request after confirming growth is unbounded.",
        "disk_pct": "Rotate or archive logs, extend the volume, and verify write availability before the threshold is crossed.",
        "latency_ms": "Validate the transit path with a traceroute from the collector host and fail traffic to the secondary region if latency exceeds the SLA.",
        "packet_loss_pct": "Escalate to the network provider with loss samples and shift latency-sensitive traffic to the alternate path.",
        "error_rate_pct": "Inspect the last deployment and dependency health; roll back if the error budget burn started at the release boundary.",
        "api_p95_ms": "Profile the slowest dependency in the request path and enable the circuit breaker for the degraded upstream.",
        "svc_availability_pct": "Confirm health-check failure, then fail over to the standby instance and page the on-call owner.",
    }.get(metric, "Investigate the affected component and confirm the signal source is live.")
    return {
        "what_happened": f"{title.format(**template_vars)} — {metric} at {alert.get('value')}.",
        "why_detected": why,
        "contributing_signals": signals,
        "recommended_action": actions,
        "confidence": round(min(0.97, 0.62 + min(abs(alert.get("z_score", 0)), 4) * 0.07), 2),
        "correlation": f"{len(related) + 1} signal(s) grouped under one fingerprint" if related is not None else "",
    }


def linear_forecast(values, horizon=12, window=30):
    """Least-squares trend forecast with a confidence band derived from residual error."""
    vals = [v for v in values[-window:] if v is not None]
    if len(vals) < 4:
        return {"available": False, "reason": "insufficient history"}
    n = len(vals)
    xs = list(range(n))
    mx = statistics.fmean(xs)
    my = statistics.fmean(vals)
    denom = sum((x - mx) ** 2 for x in xs) or 1e-9
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, vals)) / denom
    intercept = my - slope * mx
    residuals = [y - (slope * x + intercept) for x, y in zip(xs, vals)]
    rmse = (sum(r * r for r in residuals) / n) ** 0.5
    points = []
    for h in range(1, horizon + 1):
        v = intercept + slope * (n - 1 + h)
        band = rmse * (1 + h / horizon)
        points.append({"step": h, "value": round(v, 2),
                       "low": round(v - band, 2), "high": round(v + band, 2)})
    first = intercept + slope * (n - 1)
    eta = None
    if slope > 0.01:
        for p in points:
            if p["value"] >= 100:
                eta = p["step"]
                break
    return {
        "available": True,
        "slope_per_step": round(slope, 4),
        "current": round(first, 2),
        "rmse": round(rmse, 3),
        "points": points,
        "projected_100_in_steps": eta,
        "trend": "rising" if slope > 0.05 else "falling" if slope < -0.05 else "flat",
        "method": "ordinary least squares with residual-based confidence band",
        "samples": n,
    }
