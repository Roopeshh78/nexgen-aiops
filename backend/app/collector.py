"""Local collector — runs INSIDE the customer boundary.

Pipeline: ingest raw telemetry -> filter -> redact -> aggregate -> local analysis
-> policy check (allow-list) -> approved metadata envelope -> buffer -> transmit with
retry + acknowledgement + dedupe.
"""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

from .config import (ALLOWED_FIELDS, ALLOWED_LABELS, FORBIDDEN_FIELDS, REDACTION_PATTERNS,
                     SCHEMA_VERSION, SENSITIVE_KEY_PATTERN)


def utc_iso(dt=None) -> str:
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _walk_redact(obj, report, path="$"):
    """Deep-walk ANY structure, redacting sensitive keys and value patterns."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            p = f"{path}.{k}"
            if k.lower() in FORBIDDEN_FIELDS or SENSITIVE_KEY_PATTERN.search(k):
                report.append({"path": p, "rule": "sensitive_key", "action": "field_dropped"})
                continue
            if isinstance(v, (dict, list)):
                out[k] = _walk_redact(v, report, p)
            elif isinstance(v, str):
                out[k] = _redact_string(v, report, p)
            else:
                out[k] = v
        return out
    if isinstance(obj, list):
        return [_walk_redact(x, report, f"{path}[{i}]") for i, x in enumerate(obj)]
    if isinstance(obj, str):
        return _redact_string(obj, report, path)
    return obj


def _redact_string(value: str, report, path: str) -> str:
    original = value
    for rule, pattern, replacement in REDACTION_PATTERNS:
        new, n = pattern.subn(replacement, value)
        if n:
            report.append({"path": path, "rule": rule, "action": "value_redacted", "matches": n})
            value = new
    if value != original and len(value) > 240:
        value = value[:240] + "…"
    return value


def filter_events(raw_events):
    """Stage 2 — filter: drop events that carry no approved metric name."""
    kept, rejected = [], []
    for e in raw_events:
        if not e.get("metric") or e.get("value") is None:
            rejected.append({"event_id": e.get("event_id"), "reason": "missing_metric_or_value"})
            continue
        kept.append(e)
    return kept, rejected


def redact_events(events):
    """Stage 3 — redact: strip every sensitive key and value pattern."""
    report = []
    clean = []
    for e in events:
        local_report = []
        clean.append(_walk_redact(e, local_report, f"$.{e.get('event_id', 'event')}"))
        for r in local_report:
            r["event_id"] = e.get("event_id")
        report.extend(local_report)
    return clean, report


def aggregate_events(events, window_s=60):
    """Stage 4 — aggregate: collapse to per-(host, metric) numeric summaries."""
    buckets = {}
    for e in events:
        key = (e.get("host"), e.get("metric"), e.get("service"))
        b = buckets.setdefault(key, {"values": [], "unit": e.get("unit", ""),
                                     "collector_id": e.get("collector_id"),
                                     "region": e.get("region"), "last": e})
        b["values"].append(float(e["value"]))
        b["last"] = e
    out = []
    for (host, metric, service), b in buckets.items():
        vals = b["values"]
        out.append({
            "metric": metric,
            "host": host,
            "service": service,
            "value": round(sum(vals) / len(vals), 4),
            "unit": b["unit"] or "",
            "count": len(vals),
            "min": round(min(vals), 4),
            "max": round(max(vals), 4),
            "aggregation": "avg",
            "window_s": window_s,
            "collector_id": b["last"].get("collector_id"),
            "region": b["last"].get("region"),
            "observed_at": b["last"].get("observed_at"),
        })
    return out


def local_analysis(aggregates):
    """Stage 5 — local analysis: severity + risk scoring happens on-prem."""
    from .config import LOWER_IS_WORSE, THRESHOLDS
    out = []
    for a in aggregates:
        warn, crit = THRESHOLDS.get(a["metric"], (10**9, 10**9))
        v = a["value"]
        if a["metric"] in LOWER_IS_WORSE:
            severity = "critical" if v <= crit else "warning" if v <= warn else "info"
        else:
            severity = "critical" if v >= crit else "warning" if v >= warn else "info"
        headroom = 0.0
        if crit:
            headroom = max(0.0, min(1.0, abs(crit - v) / max(crit, 1e-9)))
        a["severity"] = severity
        a["risk_score"] = round(min(100.0, (1 - headroom) * 100 if severity != "info" else (v / max(crit, 1e-9)) * 45), 1)
        a["event_class"] = "threshold" if severity != "info" else "baseline"
        out.append(a)
    return out


def policy_check(aggregates, tenant_id, collector_id):
    """Stage 6 — policy check / allow-list: construct the ONLY payload allowed to leave.

    Fields not in ALLOWED_FIELDS are structurally impossible to emit because we build a
    fresh dict rather than filtering the source object.
    """
    approved, violations = [], []
    for a in aggregates:
        env = {}
        for field in ALLOWED_FIELDS:
            if field in a and a[field] is not None:
                env[field] = a[field]
        env["schema_version"] = SCHEMA_VERSION
        env["tenant_id"] = tenant_id
        env["collector_id"] = collector_id
        env["event_id"] = str(uuid.uuid4())
        env["sequence"] = a.get("sequence", 0)
        env["observed_at"] = a.get("observed_at") or utc_iso()
        # final guard: assert nothing forbidden slipped in
        for k in env:
            if k.lower() in FORBIDDEN_FIELDS:
                violations.append({"field": k, "action": "blocked"})
                env.pop(k, None)
        approved.append(env)
    return approved, violations


def build_envelope(tenant_id, collector_id, events):
    """Run the full pipeline; return envelope + metrics describing every stage."""
    filtered, rejected = filter_events(events)
    redacted, redaction_report = redact_events(filtered)
    aggregates = aggregate_events(redacted)
    analysed = local_analysis(aggregates)
    approved, violations = policy_check(analysed, tenant_id, collector_id)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "batch_id": str(uuid.uuid4()),
        "collector_id": collector_id,
        "tenant_id": tenant_id,
        "sent_at": utc_iso(),
        "event_count": len(approved),
        "events": approved,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "payload": payload,
        "body": body,
        "checksum": hashlib.sha256(body.encode()).hexdigest(),
        "bytes": len(body.encode()),
        "approved_fields": ALLOWED_FIELDS,
        "redaction_report": redaction_report[:60],
        "redaction_total": len(redaction_report),
        "dropped_fields": violations + rejected,
        "stage_counts": {
            "ingested": len(events),
            "filtered_out": len(rejected),
            "redactions": len(redaction_report),
            "aggregated": len(aggregates),
            "approved": len(approved),
        },
    }


class EventBuffer:
    """Bounded local buffer with retry, ack tracking, dedupe and out-of-order tolerance."""

    def __init__(self, capacity=5000):
        self.capacity = capacity
        self.queue = []          # ordered by (observed_at, sequence)
        self.inflight = {}       # event_id -> payload (awaiting ack)
        self.seen = set()        # dedupe set
        self.acked = 0
        self.duplicates = 0
        self.dropped = 0
        self.attempts = 0

    def enqueue(self, events):
        added = 0
        for e in events:
            eid = e.get("event_id")
            if not eid or eid in self.seen:
                self.duplicates += 1
                continue
            self.seen.add(eid)
            self.queue.append(e)
            added += 1
        # out-of-order handling: stable sort by observation time then sequence
        self.queue.sort(key=lambda x: (x.get("observed_at", ""), x.get("sequence", 0)))
        if len(self.queue) > self.capacity:
            overflow = len(self.queue) - self.capacity
            self.queue = self.queue[overflow:]
            self.dropped += overflow
        return added

    def take(self, n=50):
        batch = self.queue[:n]
        self.queue = self.queue[n:]
        return batch

    def ack(self, event_ids):
        got = 0
        for eid in event_ids:
            if eid in self.inflight:
                self.inflight.pop(eid)
                got += 1
        self.acked += got
        return got

    def depth(self):
        return len(self.queue)

    def stats(self):
        return {
            "buffered": len(self.queue),
            "inflight": len(self.inflight),
            "acked": self.acked,
            "duplicates_suppressed": self.duplicates,
            "dropped": self.dropped,
            "attempts": self.attempts,
            "capacity": self.capacity,
        }


def sanitize_for_prompt(text: str) -> str:
    """Defensive helper for anything surfaced into explanations."""
    return re.sub(r"[\x00-\x1f]", "", str(text))[:500]
