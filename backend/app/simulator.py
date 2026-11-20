"""Telemetry simulator. Every generated sample is flagged simulated=True end-to-end.

Drives: raw telemetry -> local collector pipeline -> envelope -> (persist | buffer)
-> anomaly detection -> correlation -> incidents -> recommendations.
"""
import math
import random
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from . import aiops, collector
from .config import (COL_SPECS, DESTINATION, METRICS, SCENARIOS, STALE_AFTER_S,
                     THRESHOLDS, DEMO_TENANTS, ALLOWED_FIELDS)
from .db import utcnow
from .models import (Alert, Collector, EgressRecord, Incident, MetricSample,
                     Recommendation, Scenario, Tenant, TelemetryEvent, User)

# scenario -> (metric, target value, applies to which host index)
SCENARIO_EFFECT = {
    "high_cpu": ("cpu_pct", 96.4),
    "high_memory": ("mem_pct", 95.1),
    "high_disk": ("disk_pct", 95.8),
    "latency": ("latency_ms", 341.0),
    "packet_loss": ("packet_loss_pct", 4.6),
    "failed_logins": ("failed_logins", 63.0),
    "multi_alert": ("cpu_pct", 94.2),
}

BASE = {
    "cpu_pct": 41.0, "mem_pct": 57.0, "disk_pct": 44.0, "uptime_s": 1_284_000.0,
    "proc_health": 98.0, "svc_availability_pct": 99.98, "latency_ms": 34.0,
    "packet_loss_pct": 0.04, "bandwidth_mbps": 640.0, "throughput_rps": 900.0,
    "api_p95_ms": 235.0, "error_rate_pct": 0.35, "failed_logins": 3.0,
    "auth_anomaly_score": 11.0, "pod_restarts": 0.0, "replication_lag_ms": 48.0,
    "queue_depth": 140.0,
}

TENANT_BUFFERS: dict[str, collector.EventBuffer] = {}
TICK_COUNTER = {"n": 0}


def get_buffer(tenant_id: str) -> collector.EventBuffer:
    return TENANT_BUFFERS.setdefault(tenant_id, collector.EventBuffer())


def active_scenarios(db: Session, tenant_id: str) -> set[str]:
    rows = db.query(Scenario).filter(Scenario.tenant_id == tenant_id, Scenario.active == True).all()  # noqa: E712
    keys = {r.key for r in rows}
    return keys or {"normal"}


def seed_database(db: Session):
    from .security import hash_password
    if db.query(Tenant).count() > 0:
        return {"seeded": False}
    for tid, name, slug, plan, region, quota in DEMO_TENANTS:
        db.add(Tenant(id=tid, name=name, slug=slug, plan=plan, region=region, egress_quota_mb=quota))
    db.commit()
    from .config import DEMO_USERS
    for uid, tid, email, pwd, role, name in DEMO_USERS:
        db.add(User(id=uid, tenant_id=tid, email=email, name=name,
                    password_hash=hash_password(pwd), role=role))
    db.commit()
    for tid, specs in COL_SPECS.items():
        for cid, cname, host, region, services in specs:
            db.add(Collector(id=cid, tenant_id=tid, name=cname, host=host, region=region,
                             services=services, status="online", last_seen=utcnow(),
                             buffer_depth=0, events_sent=0, version="2.4.1"))
    db.commit()
    return {"seeded": True}


def _jitter(base, pct=3.0):
    return max(0.0, base + random.uniform(-pct, pct) * base / 100.0)


def generate_raw_events(db: Session, tenant: Tenant, col: Collector, scenarios: set[str], tick: int) -> list[dict]:
    """Raw telemetry as it exists INSIDE the customer environment (includes sensitive junk)."""
    events = []
    wave = math.sin(tick / 8.0) * 4
    for idx, svc in enumerate(col.services or ["default"]):
        for metric in METRICS:
            if metric in ("uptime_s", "proc_health") and idx > 0:
                continue
            if metric in ("svc_availability_pct",) and idx == 0:
                continue
            value = _jitter(BASE[metric], 4.0)
            if metric in ("cpu_pct", "mem_pct", "latency_ms", "throughput_rps"):
                value += wave
            # scenario overrides apply to the first service of the first collector
            for key in scenarios:
                eff = SCENARIO_EFFECT.get(key)
                if eff and eff[0] == metric and idx == 0 and col.id == _primary_collector(db, tenant.id):
                    value = eff[1] + random.uniform(-1.2, 1.2)
            if "multi_alert" in scenarios and col.id == _primary_collector(db, tenant.id):
                if metric == "latency_ms":
                    value = 298 + random.uniform(-6, 6)
                if metric == "error_rate_pct":
                    value = 7.4
                if metric == "failed_logins":
                    value = 48 + random.uniform(-3, 3)
                if metric == "api_p95_ms":
                    value = 1450.0
            if "saas_failure" in scenarios:
                value = value * 1.02
            events.append({
                "event_id": str(uuid.uuid4()),
                "tenant_id": tenant.id,
                "collector_id": col.id,
                "host": col.host,
                "service": svc,
                "region": col.region,
                # ↓↓↓ everything below never leaves the boundary ↓↓↓
                "raw_log": f"2026-11-20T09:14:0{tick % 10}Z {svc} INFO connected db=10.4.2.{20 + idx} "
                           f"user=ops.{svc}@acme-fg.com token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMifQ.abc123def456 "
                           f"password=Sup3rS3cret! auth=Bearer sk-live-9f2b7e11c4",
                "credentials": {"password": "Sup3rS3cret!", "api_key": "sk-live-9f2b7e11c4"},
                "customer_email": f"oncall.{svc}@acme-fg.com",
                "ip_address": f"10.4.2.{20 + idx}",
                "metric": metric,
                "value": round(max(0.0, value), 3),
                "unit": METRICS[metric][0],
                "observed_at": collector.utc_iso(),
                "sequence": tick * 100 + idx,
                "env": "prod",
                "tier": "tier-1" if idx == 0 else "tier-2",
                "role": "primary" if idx == 0 else "worker",
                "availability_zone": f"{col.region}-a",
            })
    return events


def _primary_collector(db: Session, tenant_id: str) -> str | None:
    c = (db.query(Collector).filter(Collector.tenant_id == tenant_id)
         .order_by(Collector.id.asc()).first())
    return c.id if c else None


def run_tick(db: Session):
    """One full ingestion cycle across every tenant."""
    TICK_COUNTER["n"] += 1
    tick = TICK_COUNTER["n"]
    summary = {"tick": tick, "tenants": 0, "events": 0, "egress": 0, "alerts": 0}
    for tenant in db.query(Tenant).filter(Tenant.status == "active").all():
        summary["tenants"] += 1
        scenarios = active_scenarios(db, tenant.id)
        buffer = get_buffer(tenant.id)
        cols = db.query(Collector).filter(Collector.tenant_id == tenant.id).all()
        for col in cols:
            if "collector_offline" in scenarios and col.id == _primary_collector(db, tenant.id):
                # no telemetry, last_seen frozen -> staleness detector downgrades health
                col.status = "offline"
                db.commit()
                continue
            raw = generate_raw_events(db, tenant, col, scenarios, tick)
            env = collector.build_envelope(tenant.id, col.id, raw)
            approved = env["payload"]["events"]
            buffer.enqueue(approved)
            blocked = "saas_failure" in scenarios and col.id == _primary_collector(db, tenant.id)
            if blocked:
                buffer.attempts += 1
                col.status = "degraded"
                col.buffer_depth = buffer.depth()
                db.add(EgressRecord(
                    tenant_id=tenant.id, collector_id=col.id, destination=DESTINATION,
                    payload={"batch_id": env["payload"]["batch_id"], "event_count": len(approved),
                             "sample": approved[:3], "note": "held locally — upstream 503"},
                    approved_fields=ALLOWED_FIELDS, dropped_fields=env["dropped_fields"][:8],
                    redaction_report=env["redaction_report"][:8], checksum=env["checksum"],
                    status="retrying", bytes=env["bytes"], attempts=3,
                    ack="pending — exponential backoff (2s, 4s, 8s)", ts=utcnow()))
                db.commit()
                summary["egress"] += 1
                continue
            batch = buffer.take(60)
            ids = [e["event_id"] for e in batch]
            buffer.ack(ids)
            for e in batch:
                db.add(TelemetryEvent(event_id=e["event_id"], tenant_id=tenant.id,
                                      collector_id=col.id, metric=e["metric"], value=float(e["value"]),
                                      unit=e.get("unit", ""), sequence=int(e.get("sequence", 0)),
                                      observed_at=utcnow(), received_at=utcnow()))
                db.add(MetricSample(tenant_id=tenant.id, collector_id=col.id, metric=e["metric"],
                                    value=float(e["value"]), ts=utcnow()))
            col.status = "online"
            col.last_seen = utcnow()
            col.events_sent = (col.events_sent or 0) + len(batch)
            col.buffer_depth = buffer.depth()
            db.add(EgressRecord(
                tenant_id=tenant.id, collector_id=col.id, destination=DESTINATION,
                payload={"batch_id": env["payload"]["batch_id"], "schema_version": env["payload"]["schema_version"],
                         "event_count": len(batch), "sample": batch[:4]},
                approved_fields=ALLOWED_FIELDS, dropped_fields=env["dropped_fields"][:8],
                redaction_report=env["redaction_report"][:8], checksum=env["checksum"],
                status="delivered", bytes=env["bytes"], attempts=1,
                ack=f"ack {env['payload']['batch_id'][:8]} · {len(batch)} events accepted", ts=utcnow()))
            summary["events"] += len(batch)
            summary["egress"] += 1
            db.commit()
        evaluate_alerts(db, tenant.id)
        refresh_recommendations(db, tenant.id)
    db.commit()
    return summary


def _recent_series(db: Session, tenant_id: str, host: str, metric: str, limit=40):
    rows = (db.query(MetricSample)
            .filter(MetricSample.tenant_id == tenant_id, MetricSample.metric == metric)
            .order_by(MetricSample.id.desc()).limit(limit * 4).all())
    cols = {c.id: c.host for c in db.query(Collector).filter(Collector.tenant_id == tenant_id).all()}
    vals = [r.value for r in rows if cols.get(r.collector_id) == host]
    return list(reversed(vals[:limit]))


def evaluate_alerts(db: Session, tenant_id: str):
    cols = db.query(Collector).filter(Collector.tenant_id == tenant_id).all()
    open_alerts = {a.fingerprint: a for a in db.query(Alert).filter(
        Alert.tenant_id == tenant_id, Alert.state != "resolved").all()}
    now = utcnow()
    findings = []
    for col in cols:
        stale = (now - col.last_seen).total_seconds() > STALE_AFTER_S if col.last_seen else True
        for metric in METRICS:
            series = _recent_series(db, tenant_id, col.host, metric)
            if not series:
                continue
            key = f"{col.host}:{metric}"
            st = aiops.baseline_stats(series[:-1] or series)
            value = series[-1]
            if metric not in THRESHOLDS:
                continue  # descriptive metric (uptime, bandwidth) — no SLO threshold
            warn, crit = THRESHOLDS[metric]
            from .config import LOWER_IS_WORSE
            breached = value <= crit if metric in LOWER_IS_WORSE else value >= crit
            warned = value <= warn if metric in LOWER_IS_WORSE else value >= warn
            z = aiops.z_score(value, st)
            if not (warned or abs(z) >= 3.0):
                continue
            if stale:
                continue  # never assert health from stale telemetry
            findings.append({
                "key": key, "fingerprint": f"{metric}::{col.id}", "metric": metric, "value": value,
                "z_score": z, "baseline": st, "host": col.host, "service": (col.services or ["-"])[0],
                "collector_id": col.id, "severity": "critical" if (breached or abs(z) >= 4) else "warning",
                "deviation_pct": round((value - st["mean"]) / abs(st["mean"]) * 100, 1) if st["mean"] else 0.0,
                "stale": stale,
            })
    seen_fp = set()
    for f in findings:
        seen_fp.add(f["fingerprint"])
        existing = open_alerts.get(f["fingerprint"])
        expl = aiops.explain(f, related=[a for k, a in open_alerts.items() if k != f["fingerprint"]][:3])
        if existing:
            existing.occurrences = (existing.occurrences or 1) + 1
            existing.suppressed = (existing.suppressed or 0) + 1
            existing.last_seen = now
            existing.severity = f["severity"]
            existing.explanation = expl
        else:
            aid = "alr_" + uuid.uuid4().hex[:10]
            db.add(Alert(id=aid, tenant_id=tenant_id, fingerprint=f["fingerprint"],
                         title=f"{METRICS[f['metric']][1]} {'below' if f['metric'] in ('svc_availability_pct',) else 'above'} threshold on {f['host']}",
                         severity=f["severity"], state="open", metric=f["metric"], host=f["host"],
                         service=f["service"], first_seen=now, last_seen=now, occurrences=1,
                         suppressed=0, explanation=expl))
    # resolve alerts whose signal cleared
    for fp, a in open_alerts.items():
        if fp not in seen_fp and a.state == "open":
            a.state = "resolved"
    db.flush()
    _correlate_incidents(db, tenant_id)


def _correlate_incidents(db: Session, tenant_id: str):
    alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.state == "open").all()
    groups = {}
    for a in alerts:
        groups.setdefault(a.host or a.service or "fleet", []).append(a)
    for host, group in groups.items():
        if len(group) < 2 and not any(a.severity == "critical" for a in group):
            continue
        existing = db.query(Incident).filter(Incident.tenant_id == tenant_id,
                                             Incident.status.in_(["open", "investigating"]),
                                             Incident.title.like(f"%{host}%")).first()
        ids = [a.id for a in group]
        root = aiops.ROOT_CAUSE_LIBRARY.get(group[0].metric, ("Degradation on {host}", "Signal deviation"))[0]
        sev = "critical" if any(a.severity == "critical" for a in group) else "warning"
        summary = (f"{len(group)} correlated signals on {host}: "
                   + ", ".join(sorted({a.metric for a in group})))
        if existing:
            existing.alert_ids = ids
            existing.severity = sev
            existing.summary = summary
            existing.confidence = min(0.96, 0.55 + 0.08 * len(group))
            for a in group:
                a.incident_id = existing.id
        else:
            iid = "inc_" + uuid.uuid4().hex[:10]
            db.add(Incident(id=iid, tenant_id=tenant_id, title=f"Correlated degradation on {host}",
                            severity=sev, status="open", opened_at=utcnow(),
                            root_cause=root.replace("{host}", host).replace("{service}", group[0].service or host),
                            confidence=min(0.96, 0.55 + 0.08 * len(group)),
                            summary=summary, alert_ids=ids, owner="sre-oncall"))
            for a in group:
                a.incident_id = iid
    db.flush()


REC_LIBRARY = [
    ("Right-size CPU requests on saturated nodes", "Nodes breach 90% CPU during peak. Raising requests by 20% and adding one worker reduces saturation risk.", "capacity", "high"),
    ("Enable circuit breaker for payments-api", "Tail-latency inflates when the ledger dependency slows. A circuit breaker caps blast radius.", "reliability", "high"),
    ("Rotate the collector service secret", "Collector mTLS credential is approaching its 90-day rotation window.", "security", "medium"),
    ("Tune packet-loss alert threshold", "Loss above 1% repeats without incident impact; raise to 1.5% to cut noise.", "noise", "low"),
    ("Archive audit logs older than 90 days", "Audit chain is hash-linked; archiving cold segments keeps queries under 200 ms.", "cost", "medium"),
]


def refresh_recommendations(db: Session, tenant_id: str):
    existing = {r.title for r in db.query(Recommendation).filter(
        Recommendation.tenant_id == tenant_id).all()}
    alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.state == "open").all()
    hosts = {a.host for a in alerts}
    for title, detail, cat, impact in REC_LIBRARY:
        if title in existing:
            continue
        if cat == "capacity" and not any(a.metric in ("cpu_pct", "mem_pct", "disk_pct") for a in alerts):
            continue
        if cat == "reliability" and not any(a.metric in ("api_p95_ms", "error_rate_pct", "latency_ms") for a in alerts):
            continue
        db.add(Recommendation(id="rec_" + uuid.uuid4().hex[:8], tenant_id=tenant_id, title=title,
                              detail=detail, category=cat, impact=impact, status="proposed",
                              confidence=round(random.uniform(0.72, 0.94), 2),
                              evidence=[f"active alerts on {', '.join(sorted(hosts)) or 'no hosts'}",
                                        "30-day baseline comparison", "explainability trace available"]))
    db.flush()


def health_for_collector(db: Session, col: Collector) -> dict:
    now = utcnow()
    age = (now - col.last_seen).total_seconds() if col.last_seen else 10**9
    rows = (db.query(MetricSample).filter(MetricSample.collector_id == col.id)
            .order_by(MetricSample.id.desc()).limit(60).all())
    latest = {}
    for r in rows:
        latest.setdefault(r.metric, r.value)
    subs = {m: aiops.metric_health(m, v) for m, v in latest.items() if m in THRESHOLDS}
    if age > STALE_AFTER_S:
        return {"score": 0.0, "state": "Poor", "stale": True, "age_s": round(age, 1),
                "reason": "telemetry stale — last healthy state withheld", "metrics": len(subs)}
    score = round(sum(subs.values()) / len(subs), 1) if subs else 50.0
    # freshness decay: even 20s of silence costs points
    if age > STALE_AFTER_S * 0.5:
        score = min(score, 68.0)
    return {"score": score, "state": aiops.health_label(score), "stale": False,
            "age_s": round(age, 1), "reason": "live telemetry", "metrics": len(subs)}
