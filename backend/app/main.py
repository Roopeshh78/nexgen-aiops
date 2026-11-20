"""NEXGEN AIOPS — SaaS control plane API."""
import asyncio
import hashlib
import json
import os
import random
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import (Body, Depends, FastAPI, HTTPException, Query, WebSocket,
                     WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import aiops, collector, simulator
from .config import (ALLOWED_FIELDS, COL_SPECS, DESTINATION, FORBIDDEN_FIELDS,
                     METRICS, REDACTION_PATTERNS, SCENARIOS, SCHEMA_VERSION,
                     SENSITIVE_KEY_PATTERN, SIM_ENABLED, STALE_AFTER_S, THRESHOLDS,
                     TICK_SECONDS)
from .db import Base, SessionLocal, engine, get_db, iso, utcnow
from .models import (Alert, AuditLog, Collector, EgressRecord, Incident,
                     MetricSample, Recommendation, Scenario, Tenant, User)
from .security import (audit, create_token, current_user, decode_token,
                       hash_password, scope_tenant, verify_chain, verify_password)

Base.metadata.create_all(bind=engine)

_STATE = {"last_tick": None, "tick_count": 0, "started": False}


def _loop():
    db = SessionLocal()
    try:
        simulator.seed_database(db)
    finally:
        db.close()
    while True:
        db = SessionLocal()
        try:
            summary = simulator.run_tick(db)
            _STATE["last_tick"] = iso(utcnow())
            _STATE["tick_count"] = summary["tick"]
        except Exception as exc:  # keep the loop alive, surface the error
            print("[tick error]", exc)
        finally:
            db.close()
        time.sleep(TICK_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if SIM_ENABLED and not _STATE["started"]:
        _STATE["started"] = True
        db = SessionLocal()
        simulator.seed_database(db)
        db.close()
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
    yield


app = FastAPI(title="NEXGEN AIOPS API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"], allow_credentials=False)


# --------------------------------------------------------------------------- auth
@app.post("/api/auth/login")
def login(payload: dict = Body(...), db: Session = Depends(get_db)):
    email = (payload.get("email") or "").lower().strip()
    user = db.query(User).filter(func.lower(User.email) == email).first()
    if not user or not verify_password(payload.get("password") or "", user.password_hash):
        if user:
            audit(db, user.tenant_id, email, "auth.login_failed", "session", {"reason": "bad_password"})
        raise HTTPException(401, "Invalid credentials")
    user.last_login = utcnow()
    audit(db, user.tenant_id, email, "auth.login", "session", {"role": user.role})
    db.commit()
    tenant = db.get(Tenant, user.tenant_id)
    return {"token": create_token(user),
            "user": {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
                     "tenant_id": user.tenant_id, "tenant_name": tenant.name if tenant else ""}}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, user.tenant_id)
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
            "tenant_id": user.tenant_id, "tenant_name": tenant.name if tenant else "",
            "last_login": iso(user.last_login)}


@app.get("/api/auth/demo-accounts")
def demo_accounts(db: Session = Depends(get_db)):
    rows = db.query(User).limit(8).all()
    return [{"email": u.email, "role": u.role, "tenant_id": u.tenant_id, "name": u.name,
             "password_hint": "NexGen#2026"} for u in rows]


# --------------------------------------------------------------------------- helpers
def _series(db: Session, tenant_id: str, metric: str, limit=90, collector_id=None):
    q = db.query(MetricSample).filter(MetricSample.tenant_id == tenant_id,
                                      MetricSample.metric == metric)
    if collector_id:
        q = q.filter(MetricSample.collector_id == collector_id)
    rows = q.order_by(MetricSample.id.desc()).limit(limit * 8).all()
    rows = list(reversed(rows))
    if not rows:
        return []
    if collector_id:
        picked = rows[-limit:]
    else:
        # average across collectors per tick bucket -> one coherent fleet series
        buckets = {}
        for r in rows:
            key = r.ts.strftime("%H:%M:%S")
            buckets.setdefault(key, []).append(r.value)
        picked_keys = list(buckets.keys())[-limit:]
        return [{"t": k, "v": round(sum(buckets[k]) / len(buckets[k]), 2)} for k in picked_keys]
    return [{"t": r.ts.strftime("%H:%M:%S"), "v": round(r.value, 2)} for r in picked]


def _tenant_of(user: User, tenant_id: str | None) -> str:
    return scope_tenant(user, tenant_id)


def _collector_rows(db: Session, tenant_id: str):
    cols = db.query(Collector).filter(Collector.tenant_id == tenant_id).order_by(Collector.id).all()
    out = []
    for c in cols:
        h = simulator.health_for_collector(db, c)
        out.append({"id": c.id, "name": c.name, "host": c.host, "region": c.region,
                    "status": c.status, "version": c.version, "mode": c.mode,
                    "services": c.services, "last_seen": iso(c.last_seen),
                    "buffer_depth": c.buffer_depth, "events_sent": c.events_sent,
                    "health": h})
    return out


# --------------------------------------------------------------------------- overview
@app.get("/api/overview")
def overview(user: User = Depends(current_user), db: Session = Depends(get_db),
             tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    tenant = db.get(Tenant, tid)
    cols = _collector_rows(db, tid)
    states = [c["health"]["state"] for c in cols] or ["Poor"]
    rank = {"Excellent": 4, "Good": 3, "Fair": 2, "Poor": 1}
    worst = min(states, key=lambda s: rank[s])
    overall_score = round(sum(c["health"]["score"] for c in cols) / max(len(cols), 1), 1)
    alerts = db.query(Alert).filter(Alert.tenant_id == tid, Alert.state == "open").all()
    incidents = db.query(Incident).filter(Incident.tenant_id == tid,
                                          Incident.status.in_(["open", "investigating"])).all()
    scenarios = sorted(simulator.active_scenarios(db, tid))
    latest = {}
    for m in METRICS:
        s = _series(db, tid, m, limit=1)
        if s:
            latest[m] = s[-1]["v"]
    total_events = db.query(func.count(MetricSample.id)).filter(MetricSample.tenant_id == tid).scalar() or 0
    suppressed = sum(a.suppressed or 0 for a in db.query(Alert).filter(Alert.tenant_id == tid).all())
    delivered = db.query(func.count(EgressRecord.id)).filter(
        EgressRecord.tenant_id == tid, EgressRecord.status == "delivered").scalar() or 0
    bytes_out = db.query(func.coalesce(func.sum(EgressRecord.bytes), 0)).filter(
        EgressRecord.tenant_id == tid, EgressRecord.status == "delivered").scalar() or 0
    return {
        "tenant": {"id": tid, "name": tenant.name if tenant else tid,
                   "region": tenant.region if tenant else "", "plan": tenant.plan if tenant else ""},
        "overall": {"score": overall_score, "state": aiops.health_label(overall_score),
                    "worst_collector_state": worst,
                    "stale_collectors": sum(1 for c in cols if c["health"]["stale"])},
        "kpis": {
            "collectors_online": sum(1 for c in cols if c["status"] == "online"),
            "collectors_total": len(cols),
            "open_alerts": len(alerts),
            "critical_alerts": sum(1 for a in alerts if a.severity == "critical"),
            "active_incidents": len(incidents),
            "telemetry_events": total_events,
            "alerts_suppressed": suppressed,
            "noise_reduction_pct": round(suppressed / max(suppressed + len(alerts), 1) * 100, 1),
            "egress_batches": delivered,
            "egress_kb": round(bytes_out / 1024, 1),
            "ingest_latency_ms": 42,
        },
        "latest_metrics": latest,
        "series": {m: _series(db, tid, m, limit=48) for m in
                   ["cpu_pct", "mem_pct", "latency_ms", "error_rate_pct", "throughput_rps", "disk_pct"]},
        "health_states": [{"collector": c["name"], "host": c["host"], "state": c["health"]["state"],
                           "score": c["health"]["score"], "stale": c["health"]["stale"],
                           "age_s": c["health"]["age_s"]} for c in cols],
        "scenarios": scenarios,
        "top_alerts": sorted([{"id": a.id, "title": a.title, "severity": a.severity,
                               "host": a.host, "metric": a.metric, "state": a.state,
                               "occurrences": a.occurrences, "last_seen": iso(a.last_seen)}
                              for a in alerts], key=lambda a: a["severity"] != "critical")[:6],
        "simulated": True,
        "last_tick": _STATE["last_tick"],
        "tick_count": _STATE["tick_count"],
    }


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "nexgen-aiops", "utc": iso(utcnow()),
            "ticks": _STATE["tick_count"], "simulated_telemetry": True}


# --------------------------------------------------------------------------- infrastructure
@app.get("/api/infra")
def infra(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    cols = _collector_rows(db, tid)
    servers = []
    for c in cols:
        latest = {}
        for m in ["cpu_pct", "mem_pct", "disk_pct", "uptime_s", "proc_health", "svc_availability_pct"]:
            s = _series(db, tid, m, limit=1, collector_id=c["id"])
            if s:
                latest[m] = s[-1]["v"]
        servers.append({**c, "metrics": latest,
                        "uptime_human": _human_uptime(latest.get("uptime_s", 0)),
                        "process_health": "healthy" if (latest.get("proc_health", 0) or 0) > 90 else "degraded"})
    return {"servers": servers,
            "series": {m: _series(db, tid, m, limit=48) for m in
                       ["cpu_pct", "mem_pct", "disk_pct", "proc_health"]},
            "simulated": True}


def _human_uptime(seconds):
    seconds = int(seconds or 0)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    return f"{d}d {h}h" if d else f"{h}h {rem // 60}m"


# --------------------------------------------------------------------------- network
@app.get("/api/network")
def network(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    lat = _series(db, tid, "latency_ms", 60)
    loss = _series(db, tid, "packet_loss_pct", 60)
    bw = _series(db, tid, "bandwidth_mbps", 60)
    tp = _series(db, tid, "throughput_rps", 60)
    trends = []
    for name, series, unit in [("Latency", lat, "ms"), ("Packet loss", loss, "%"),
                               ("Bandwidth", bw, "Mbps"), ("Throughput", tp, "req/s")]:
        if len(series) >= 4:
            f = aiops.linear_forecast([p["v"] for p in series], horizon=6)
            trends.append({"metric": name, "unit": unit, "trend": f.get("trend"),
                           "slope": f.get("slope_per_step"), "current": series[-1]["v"]})
    anomalies = []
    for m, label in [("latency_ms", "Latency"), ("packet_loss_pct", "Packet loss")]:
        s = _series(db, tid, m, 40)
        if s:
            st = aiops.baseline_stats([p["v"] for p in s][:-1] or [p["v"] for p in s])
            z = aiops.z_score(s[-1]["v"], st)
            if abs(z) >= 2:
                anomalies.append({"metric": label, "value": s[-1]["v"], "z_score": z,
                                  "baseline": st["mean"], "severity": "critical" if abs(z) >= 3.5 else "warning"})
    cols = _collector_rows(db, tid)
    nodes = [{"id": c["id"], "label": c["name"], "region": c["region"], "health": c["health"]["state"]}
             for c in cols]
    edges = []
    for i in range(len(cols) - 1):
        edges.append({"source": cols[i]["id"], "target": cols[i + 1]["id"],
                      "latency": round(random.uniform(8, 40), 1), "loss": round(random.uniform(0, 0.2), 2)})
    return {"latency": lat, "packet_loss": loss, "bandwidth": bw, "throughput": tp,
            "trends": trends, "anomalies": anomalies, "nodes": nodes, "edges": edges,
            "connectivity": [{"link": f"{c['name']} → ingress", "status": "up" if c["status"] == "online" else "down",
                              "region": c["region"]} for c in cols],
            "simulated": True}


# --------------------------------------------------------------------------- application
@app.get("/api/app")
def appobs(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    cols = _collector_rows(db, tid)
    services = []
    for c in cols:
        for i, svc in enumerate(c["services"] or []):
            base = {"payments-api": 0, "ledger-api": 1, "checkout-ui": 2}
            p95 = _series(db, tid, "api_p95_ms", 1, c["id"])
            er = _series(db, tid, "error_rate_pct", 1, c["id"])
            av = _series(db, tid, "svc_availability_pct", 1, c["id"])
            tr = _series(db, tid, "throughput_rps", 1, c["id"])
            p95v = (p95[-1]["v"] if p95 else 0) * (1 + (i * 0.06))
            errv = (er[-1]["v"] if er else 0) * (1 + i * 0.12)
            score = round((aiops.metric_health("api_p95_ms", p95v) * 0.4 +
                           aiops.metric_health("error_rate_pct", errv) * 0.4 +
                           aiops.metric_health("svc_availability_pct", av[-1]["v"] if av else 99.9) * 0.2), 1)
            services.append({"name": svc, "collector": c["name"], "region": c["region"],
                             "p95_ms": round(p95v, 1), "error_rate_pct": round(errv, 2),
                             "availability_pct": round((av[-1]["v"] if av else 0) - i * 0.01, 3),
                             "throughput_rps": round((tr[-1]["v"] if tr else 0) * (1 - i * 0.08), 1),
                             "health": aiops.health_label(score), "score": score})
    return {"services": services,
            "series": {m: _series(db, tid, m, 48) for m in
                       ["api_p95_ms", "error_rate_pct", "throughput_rps", "svc_availability_pct"]},
            "simulated": True}


# --------------------------------------------------------------------------- security
@app.get("/api/security")
def security(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    fails = _series(db, tid, "failed_logins", 48)
    anomaly_score = _series(db, tid, "auth_anomaly_score", 48)
    events = []
    cols = _collector_rows(db, tid)
    for c in cols:
        f = _series(db, tid, "failed_logins", 1, c["id"])
        v = f[-1]["v"] if f else 0
        if v > 18:
            events.append({"class": "credential_stuffing", "severity": "critical" if v > 40 else "warning",
                           "host": c["host"], "count": int(v), "risk_score": min(99, int(v * 1.4)),
                           "detection": "burst of failed authentications from rotating sources",
                           "redaction": "username, source IP and password material redacted locally"})
        if c["status"] == "offline":
            events.append({"class": "collector_silence", "severity": "warning", "host": c["host"],
                           "count": 1, "risk_score": 55,
                           "detection": "collector heartbeat missing beyond staleness window",
                           "redaction": "no payload leaves while offline"})
    egress = db.query(EgressRecord).filter(EgressRecord.tenant_id == tid).order_by(EgressRecord.id.desc()).limit(30).all()
    redactions = 0
    for e in egress:
        redactions += sum(int(r.get("matches", 1)) for r in (e.redaction_report or []))
    return {"failed_logins": fails, "auth_anomaly": anomaly_score, "events": events,
            "risk": {"overall": min(99, 22 + len([e for e in events if e['severity'] == 'critical']) * 24 +
                                    len([e for e in events if e['severity'] == 'warning']) * 8),
                     "factors": ["failed login velocity", "collector silence", "privilege changes"]},
            "redaction": {"total_matches": redactions, "classes": [
                {"class": "credentials", "examples": ["password", "api_key", "bearer token"]},
                {"class": "personal", "examples": ["email", "phone", "ssn", "card number"]},
                {"class": "infrastructure", "examples": ["ip address", "connection string"]}]},
            "simulated": True}


# --------------------------------------------------------------------------- cloud / distributed
@app.get("/api/cloud")
def cloud(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    cols = _collector_rows(db, tid)
    regions = {}
    for c in cols:
        r = regions.setdefault(c["region"], {"region": c["region"], "collectors": 0, "state": "Excellent",
                                             "score": 100, "nodes": 0})
        r["collectors"] += 1
        r["score"] = min(r["score"], c["health"]["score"])
        r["nodes"] += len(c["services"] or [])
    for r in regions.values():
        r["state"] = aiops.health_label(r["score"])
    restarts = _series(db, tid, "pod_restarts", 48)
    return {"regions": list(regions.values()), "pod_restarts": restarts,
            "workloads": [{"name": s, "namespace": "prod", "collector": c["name"],
                           "restarts": random.randint(0, 3), "state": c["health"]["state"]}
                          for c in cols for s in (c["services"] or [])],
            "series": {m: _series(db, tid, m, 48) for m in ["cpu_pct", "mem_pct", "pod_restarts"]},
            "simulated": True}


@app.get("/api/distributed")
def distributed(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    cols = _collector_rows(db, tid)
    svc = []
    for c in cols:
        for s in (c["services"] or [])[:2]:
            lag = _series(db, tid, "replication_lag_ms", 1, c["id"])
            qd = _series(db, tid, "queue_depth", 1, c["id"])
            svc.append({"name": s, "replication_lag_ms": round(lag[-1]["v"] if lag else 0, 1),
                        "queue_depth": int(qd[-1]["v"] if qd else 0), "region": c["region"]})
    return {"services": svc,
            "series": {m: _series(db, tid, m, 48) for m in
                       ["replication_lag_ms", "queue_depth", "api_p95_ms"]},
            "flow": [{"from": "edge", "to": "api-gateway", "rps": 1240},
                     {"from": "api-gateway", "to": "payments-api", "rps": 860},
                     {"from": "payments-api", "to": "ledger-api", "rps": 840},
                     {"from": "ledger-api", "to": "postgres-primary", "rps": 790},
                     {"from": "ledger-api", "to": "event-bus", "rps": 610}],
            "simulated": True}


# --------------------------------------------------------------------------- AIOps
@app.get("/api/aiops/modules")
def aiops_modules(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    alerts = db.query(Alert).filter(Alert.tenant_id == tid).all()
    open_alerts = [a for a in alerts if a.state == "open"]
    suppressed = sum(a.suppressed or 0 for a in alerts)
    incidents = db.query(Incident).filter(Incident.tenant_id == tid).all()
    samples = db.query(func.count(MetricSample.id)).filter(MetricSample.tenant_id == tid).scalar() or 0
    series = _series(db, tid, "cpu_pct", 40)
    f = aiops.linear_forecast([p["v"] for p in series]) if series else {"available": False}
    modules = [
 {"key": "anomaly", "name": "Anomaly detection", "status": "active", "model": "robust z-score + static thresholds",
  "processed": samples, "outputs": len(open_alerts), "detail": "Per-host, per-metric deviation against a 40-sample rolling baseline."},
 {"key": "baseline", "name": "Baseline analysis", "status": "active", "model": "rolling mean/stdev, 40 samples",
  "processed": samples, "outputs": min(samples // 40, 999), "detail": "Learned per (host, metric) baselines with seasonality tolerance."},
 {"key": "predict", "name": "Predictive analytics", "status": "active", "model": "ordinary least squares + residual band",
  "processed": len(series), "outputs": f.get("projected_100_in_steps") or 0,
  "detail": f"Trend is {f.get('trend', 'n/a')} at {f.get('slope_per_step', 0)}/step."},
 {"key": "rca", "name": "Root cause analysis", "status": "active", "model": "signal-affinity root cause library",
  "processed": len(incidents), "outputs": len([i for i in incidents if i.root_cause]), "detail": "Maps metric signatures to probable causes with confidence."},
 {"key": "correlation", "name": "Event correlation", "status": "active", "model": "host/service affinity clustering",
  "processed": len(open_alerts), "outputs": len(incidents), "detail": "Groups alerts that share a failure domain into one incident."},
 {"key": "dedupe", "name": "Alert deduplication", "status": "active", "model": "fingerprint = metric::collector",
  "processed": len(alerts), "outputs": len(alerts) - suppressed if len(alerts) > suppressed else 0,
  "detail": f"{suppressed} duplicate signals folded into existing alerts."},
 {"key": "noise", "name": "Alert noise reduction", "status": "active", "model": "dedupe + suppression + resolution sweep",
  "processed": len(alerts) + suppressed, "outputs": round(suppressed / max(len(alerts) + suppressed, 1) * 100, 1),
  "detail": "Percentage of raw signals that never reached a human."},
 {"key": "risk", "name": "Risk scoring", "status": "active", "model": "severity x blast radius x freshness",
  "processed": len(alerts), "outputs": len([a for a in alerts if a.severity == "critical"]), "detail": "0-100 risk per tenant, incident and finding."},
 {"key": "capacity", "name": "Capacity forecasting", "status": "active", "model": "linear projection to threshold",
  "processed": len(series), "outputs": 1, "detail": "Projects each host to its 100% ceiling and reports headroom."},
 {"key": "explain", "name": "Explainable recommendations", "status": "active", "model": "rule-backed action mapping",
  "processed": len(open_alerts), "outputs": db.query(func.count(Recommendation.id)).filter(Recommendation.tenant_id == tid).scalar() or 0,
  "detail": "Every alert carries what, why, contributing signals and a next action."},
    ]
    return {"modules": modules, "simulated": True}


@app.get("/api/aiops/anomalies")
def anomalies(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    out = []
    for c in _collector_rows(db, tid):
        for metric in ["cpu_pct", "mem_pct", "disk_pct", "latency_ms", "packet_loss_pct", "error_rate_pct", "api_p95_ms"]:
            series = simulator._recent_series(db, tid, c["host"], metric, 40)
            if len(series) < 4:
                continue
            st = aiops.baseline_stats(series[:-1])
            z = aiops.z_score(series[-1], st)
            if metric not in THRESHOLDS:
                continue
            warn, crit = THRESHOLDS[metric]
            if abs(z) < 2.0 and series[-1] < warn:
                continue
            out.append({"host": c["host"], "collector": c["name"], "metric": metric,
                        "label": METRICS[metric][1], "value": round(series[-1], 2),
                        "baseline_mean": st["mean"], "baseline_stdev": st["stdev"], "z_score": z,
                        "deviation_pct": round((series[-1] - st["mean"]) / abs(st["mean"]) * 100, 1) if st["mean"] else 0,
                        "severity": "critical" if (series[-1] >= crit or abs(z) >= 4) else "warning",
                        "method": "z-score vs 40-sample baseline", "threshold": {"warn": warn, "critical": crit},
                        "stale": c["health"]["stale"]})
    out.sort(key=lambda a: (a["severity"] != "critical", -abs(a["z_score"])))
    return {"anomalies": out, "baselines": {
        m: aiops.baseline_stats([p["v"] for p in _series(db, tid, m, 40)]) for m in
        ["cpu_pct", "mem_pct", "disk_pct", "latency_ms", "error_rate_pct"]},
        "method": "Robust z-score on a 40-sample rolling baseline, combined with static SLO thresholds.",
        "simulated": True}


@app.get("/api/aiops/rca/{incident_id}")
def rca(incident_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    scope_tenant(user, inc.tenant_id)
    alerts = db.query(Alert).filter(Alert.id.in_(inc.alert_ids or [])).all()
    signals = []
    for a in alerts:
        expl = a.explanation or {}
        signals.append({"alert_id": a.id, "metric": a.metric, "host": a.host,
                        "value": expl.get("what_happened", ""),
                        "signals": expl.get("contributing_signals", []),
                        "z": (expl.get("contributing_signals") or [{}])[2].get("value")})
    chain = sorted([{"t": iso(a.first_seen), "event": f"{a.metric} breached on {a.host}",
                     "severity": a.severity} for a in alerts], key=lambda x: x["t"] or "")
    return {"incident": {"id": inc.id, "title": inc.title, "severity": inc.severity,
                         "status": inc.status, "root_cause": inc.root_cause,
                         "confidence": inc.confidence, "summary": inc.summary,
                         "opened_at": iso(inc.opened_at), "owner": inc.owner},
            "alerts": signals, "timeline": chain,
            "method": "Alert-affinity correlation, temporal ordering and metric-signature root cause library.",
            "recommended_actions": [
                "Stabilise the first breached signal in the timeline before touching downstream services.",
                "Check whether the alert cluster shares a single host, collector or deployment boundary.",
                "Apply the per-alert recommended action from the explainability panel."],
            "simulated": True}


@app.get("/api/aiops/correlations")
def correlations(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    incs = db.query(Incident).filter(Incident.tenant_id == tid).order_by(Incident.opened_at.desc()).limit(20).all()
    return {"incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status,
                           "alerts": len(i.alert_ids or []), "confidence": i.confidence,
                           "root_cause": i.root_cause, "opened_at": iso(i.opened_at)} for i in incs],
            "engine": "host/service affinity + temporal proximity"}


@app.get("/api/aiops/noise")
def noise(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    alerts = db.query(Alert).filter(Alert.tenant_id == tid).all()
    raw = sum((a.occurrences or 1) for a in alerts)
    surfaced = len(alerts)
    suppressed = sum((a.suppressed or 0) for a in alerts)
    return {"raw_signals": raw, "surfaced_alerts": surfaced, "suppressed": suppressed,
            "reduction_pct": round(suppressed / max(raw, 1) * 100, 1),
            "per_alert": [{"id": a.id, "fingerprint": a.fingerprint, "occurrences": a.occurrences,
                           "suppressed": a.suppressed, "severity": a.severity, "state": a.state}
                          for a in sorted(alerts, key=lambda a: -(a.suppressed or 0))[:15]],
            "simulated": True}


# --------------------------------------------------------------------------- alerts / incidents
@app.get("/api/alerts")
def list_alerts(user: User = Depends(current_user), db: Session = Depends(get_db),
                tenant_id: str | None = None, state: str | None = None, severity: str | None = None):
    tid = _tenant_of(user, tenant_id)
    q = db.query(Alert).filter(Alert.tenant_id == tid)
    if state:
        q = q.filter(Alert.state == state)
    if severity:
        q = q.filter(Alert.severity == severity)
    rows = q.order_by(Alert.last_seen.desc()).limit(200).all()
    return {"alerts": [{"id": a.id, "title": a.title, "severity": a.severity, "state": a.state,
                        "metric": a.metric, "host": a.host, "service": a.service,
                        "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
                        "occurrences": a.occurrences, "suppressed": a.suppressed,
                        "incident_id": a.incident_id, "explanation": a.explanation,
                        "fingerprint": a.fingerprint} for a in rows],
            "counts": {"open": db.query(func.count(Alert.id)).filter(Alert.tenant_id == tid, Alert.state == "open").scalar() or 0,
                       "acknowledged": db.query(func.count(Alert.id)).filter(Alert.tenant_id == tid, Alert.state == "acknowledged").scalar() or 0,
                       "resolved": db.query(func.count(Alert.id)).filter(Alert.tenant_id == tid, Alert.state == "resolved").scalar() or 0}}


@app.post("/api/alerts/{alert_id}/ack")
def ack_alert(alert_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    scope_tenant(user, a.tenant_id)
    a.state = "acknowledged"
    a.acknowledged_by = user.email
    audit(db, a.tenant_id, user.email, "alert.acknowledge", alert_id, {"severity": a.severity})
    db.commit()
    return {"ok": True, "state": a.state, "by": user.email}


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    scope_tenant(user, a.tenant_id)
    a.state = "resolved"
    audit(db, a.tenant_id, user.email, "alert.resolve", alert_id, {})
    db.commit()
    return {"ok": True, "state": a.state}


@app.get("/api/incidents")
def list_incidents(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    rows = db.query(Incident).filter(Incident.tenant_id == tid).order_by(Incident.opened_at.desc()).limit(60).all()
    return {"incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status,
                           "opened_at": iso(i.opened_at), "closed_at": iso(i.closed_at),
                           "root_cause": i.root_cause, "confidence": i.confidence,
                           "summary": i.summary, "alerts": len(i.alert_ids or []), "owner": i.owner}
                          for i in rows],
            "mttr_minutes": 38, "open": sum(1 for i in rows if i.status in ("open", "investigating"))}


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, payload: dict = Body(...), user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    scope_tenant(user, inc.tenant_id)
    new_status = payload.get("status")
    if new_status not in ("open", "investigating", "mitigated", "closed"):
        raise HTTPException(400, "Invalid status")
    inc.status = new_status
    if new_status == "closed":
        inc.closed_at = utcnow()
    if payload.get("owner"):
        inc.owner = payload["owner"]
    audit(db, inc.tenant_id, user.email, "incident.update", incident_id, {"status": new_status})
    db.commit()
    return {"ok": True, "status": inc.status}


# --------------------------------------------------------------------------- predictive / capacity
@app.get("/api/predict")
def predict(user: User = Depends(current_user), db: Session = Depends(get_db),
            metric: str = "cpu_pct", tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    if metric not in METRICS:
        raise HTTPException(400, "Unknown metric")
    s = _series(db, tid, metric, 60)
    f = aiops.linear_forecast([p["v"] for p in s])
    best = None
    for c in _collector_rows(db, tid):
        vals = simulator._recent_series(db, tid, c["host"], metric, 40)
        fc = aiops.linear_forecast(vals)
        if fc.get("available"):
            eta = fc["projected_100_in_steps"]
            if eta and (best is None or eta < best["steps"]):
                best = {"host": c["host"], "steps": eta, "current": fc["current"],
                        "trend": fc["trend"], "slope": fc["slope_per_step"]}
    return {"metric": metric, "label": METRICS[metric][1], "unit": METRICS[metric][0],
            "history": s, "forecast": f, "soonest_threshold_breach": best,
            "horizon_note": f"Each step ≈ {int(TICK_SECONDS)}s of live telemetry.",
            "simulated": True}


@app.get("/api/capacity")
def capacity(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    hosts = []
    for c in _collector_rows(db, tid):
        row = {"host": c["host"], "collector": c["name"], "region": c["region"], "state": c["health"]["state"]}
        for m in ["cpu_pct", "mem_pct", "disk_pct"]:
            vals = simulator._recent_series(db, tid, c["host"], m, 40)
            fc = aiops.linear_forecast(vals, horizon=12)
            current = vals[-1] if vals else 0
            row[m] = {"current": round(current, 1), "headroom_pct": round(max(0, 100 - current), 1),
                      "trend": fc.get("trend"), "steps_to_full": fc.get("projected_100_in_steps"),
                      "forecast": fc.get("points", [])}
        risk = max(row[m]["current"] for m in ["cpu_pct", "mem_pct", "disk_pct"]) if row else 0
        row["risk"] = "critical" if risk > 90 else "warning" if risk > 78 else "ok"
        hosts.append(row)
    return {"hosts": hosts,
            "summary": {"hosts": len(hosts),
                        "at_risk": sum(1 for h in hosts if h["risk"] != "ok"),
                        "avg_headroom_pct": round(sum(h["disk_pct"]["headroom_pct"] for h in hosts) / max(len(hosts), 1), 1)},
            "method": "Per-host linear projection with residual confidence band.",
            "simulated": True}


# --------------------------------------------------------------------------- collectors / privacy / egress
@app.get("/api/collectors")
def collectors(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    buf = simulator.get_buffer(tid)
    return {"collectors": _collector_rows(db, tid), "buffer": buf.stats(),
            "pipeline": ["Ingest", "Filter", "Redact", "Aggregate", "Local analysis",
                         "Policy check", "Approved metadata", "Secure transmit"],
            "stale_after_s": STALE_AFTER_S, "simulated": True}


@app.post("/api/collectors/{collector_id}/state")
def set_collector_state(collector_id: str, payload: dict = Body(...), user: User = Depends(current_user),
                        db: Session = Depends(get_db)):
    c = db.get(Collector, collector_id)
    if not c:
        raise HTTPException(404, "Collector not found")
    scope_tenant(user, c.tenant_id)
    state = payload.get("status")
    if state not in ("online", "degraded", "offline"):
        raise HTTPException(400, "Invalid status")
    c.status = state
    if state == "online":
        c.last_seen = utcnow()
    audit(db, c.tenant_id, user.email, "collector.state", collector_id, {"status": state})
    db.commit()
    return {"ok": True, "status": c.status}


@app.get("/api/privacy/policy")
def privacy_policy(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"schema_version": SCHEMA_VERSION, "destination": DESTINATION,
            "allowed_fields": ALLOWED_FIELDS,
            "forbidden_fields": sorted(FORBIDDEN_FIELDS),
            "sensitive_key_pattern": SENSITIVE_KEY_PATTERN.pattern,
            "redaction_rules": [{"rule": r[0], "pattern": r[1].pattern, "replacement": r[2]}
                                for r in REDACTION_PATTERNS],
            "two_tier": {
                "customer_environment": ["Telemetry sources", "Local collector", "Filter", "Redact",
                                         "Aggregate", "Local analysis", "Policy check", "Approved metadata"],
                "central_saas": ["Secure ingestion API", "Metadata store", "AIOps analytics",
                                 "Incident correlation", "Dashboard", "Recommendations"],
                "never_leaves": ["raw logs", "credentials", "passwords", "tokens", "sensitive payloads",
                                 "IP addresses", "email addresses", "request/response bodies"]},
            "invariant": "Envelope construction is allow-list based: the payload is built from scratch field by field, never filtered from source objects."}


@app.post("/api/privacy/inspect")
def inspect_payload(payload: dict = Body(...), user: User = Depends(current_user)):
    """Live proof: run an arbitrary object through the collector pipeline and show the diff."""
    env = collector.build_envelope(user.tenant_id, "col_inspector",
                                   [payload] if "metric" in payload else [payload])
    return {"input": payload, "output": env["payload"]["events"],
            "redaction_report": env["redaction_report"],
            "stage_counts": env["stage_counts"], "checksum": env["checksum"],
            "bytes_out": env["bytes"]}


@app.get("/api/egress")
def egress(user: User = Depends(current_user), db: Session = Depends(get_db),
           tenant_id: str | None = None, limit: int = 40):
    tid = _tenant_of(user, tenant_id)
    rows = db.query(EgressRecord).filter(EgressRecord.tenant_id == tid).order_by(EgressRecord.id.desc()).limit(limit).all()
    total = db.query(func.count(EgressRecord.id)).filter(EgressRecord.tenant_id == tid).scalar() or 0
    delivered = db.query(func.count(EgressRecord.id)).filter(EgressRecord.tenant_id == tid,
                                                             EgressRecord.status == "delivered").scalar() or 0
    return {"records": [{"id": r.id, "collector_id": r.collector_id, "destination": r.destination,
                         "status": r.status, "bytes": r.bytes, "checksum": r.checksum,
                         "attempts": r.attempts, "ack": r.ack, "ts": iso(r.ts),
                         "payload": r.payload, "approved_fields": r.approved_fields,
                         "dropped_fields": r.dropped_fields, "redaction_report": r.redaction_report}
                        for r in rows],
            "summary": {"total": total, "delivered": delivered,
                        "success_rate": round(delivered / max(total, 1) * 100, 1),
                        "bytes_out": db.query(func.coalesce(func.sum(EgressRecord.bytes), 0)).filter(
                            EgressRecord.tenant_id == tid).scalar() or 0},
            "destination": DESTINATION, "simulated": True}


@app.post("/api/egress/validate")
def validate_egress(payload: dict = Body(...), user: User = Depends(current_user)):
    """Real enforcement test: is this payload allowed to leave the boundary?"""
    body = payload.get("events") or payload.get("payload") or payload
    events = body if isinstance(body, list) else [body]
    violations, approved = [], []
    for e in events:
        bad = [k for k in e if str(k).lower() in FORBIDDEN_FIELDS or SENSITIVE_KEY_PATTERN.search(str(k))]
        extra = [k for k in e if k not in ALLOWED_FIELDS and k not in ("min", "max", "samples")]
        if bad:
            violations.append({"field_violations": bad, "decision": "blocked_at_boundary"})
        if extra:
            violations.append({"non_allowlisted_fields": extra, "decision": "dropped"})
        if not bad:
            approved.append(e)
    ok = not any(v["decision"] == "blocked_at_boundary" for v in violations)
    return {"allowed_to_transmit": ok, "approved_events": len(approved),
            "violations": violations, "policy": "allow-list",
            "verdict": "PASS — nothing sensitive in payload" if ok else "BLOCKED — sensitive field detected"}


# --------------------------------------------------------------------------- tenants / audit
@app.get("/api/tenants")
def tenants(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "platform_admin":
        t = db.get(Tenant, user.tenant_id)
        return {"tenants": [{"id": t.id, "name": t.name, "plan": t.plan, "region": t.region,
                             "quota": t.egress_quota_mb, "users": 1, "collectors": 0}],
                "scoped": True}
    rows = db.query(Tenant).all()
    out = []
    for t in rows:
        out.append({"id": t.id, "name": t.name, "slug": t.slug, "plan": t.plan, "region": t.region,
                    "status": t.status, "quota": t.egress_quota_mb,
                    "users": db.query(func.count(User.id)).filter(User.tenant_id == t.id).scalar() or 0,
                    "collectors": db.query(func.count(Collector.id)).filter(Collector.tenant_id == t.id).scalar() or 0,
                    "alerts": db.query(func.count(Alert.id)).filter(Alert.tenant_id == t.id,
                                                                   Alert.state == "open").scalar() or 0,
                    "created_at": iso(t.created_at)})
    return {"tenants": out, "scoped": False}


@app.post("/api/tenants")
def create_tenant(payload: dict = Body(...), user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "platform_admin":
        raise HTTPException(403, "Platform admin only")
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Name required")
    tid = "t_" + uuid.uuid4().hex[:8]
    db.add(Tenant(id=tid, name=name, slug=name.lower().replace(" ", "-")[:40],
                  plan=payload.get("plan", "Business"), region=payload.get("region", "eu-west-1"),
                  egress_quota_mb=int(payload.get("quota", 100))))
    audit(db, user.tenant_id, user.email, "tenant.create", tid, {"name": name})
    db.commit()
    return {"ok": True, "id": tid}


@app.get("/api/audit")
def audit_logs(user: User = Depends(current_user), db: Session = Depends(get_db),
               tenant_id: str | None = None, limit: int = 100):
    tid = _tenant_of(user, tenant_id)
    rows = db.query(AuditLog).filter(AuditLog.tenant_id == tid).order_by(AuditLog.id.desc()).limit(limit).all()
    return {"logs": [{"id": r.id, "actor": r.actor, "action": r.action, "resource": r.resource,
                      "detail": r.detail, "ts": iso(r.ts), "prev_hash": r.prev_hash, "hash": r.hash}
                     for r in rows],
            "chain": verify_chain(db, tid)}


@app.get("/api/recommendations")
def recommendations(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    rows = db.query(Recommendation).filter(Recommendation.tenant_id == tid).order_by(Recommendation.created_at.desc()).limit(60).all()
    return {"recommendations": [{"id": r.id, "title": r.title, "detail": r.detail, "category": r.category,
                                 "impact": r.impact, "confidence": r.confidence, "status": r.status,
                                 "evidence": r.evidence, "created_at": iso(r.created_at)} for r in rows],
            "autonomy": {"mode": "human-in-the-loop", "executed_24h": sum(1 for r in rows if r.status == "executed"),
                         "approved": sum(1 for r in rows if r.status == "approved"),
                         "proposed": sum(1 for r in rows if r.status == "proposed")}}


@app.post("/api/recommendations/{rec_id}/{action}")
def act_recommendation(rec_id: str, action: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    r = db.get(Recommendation, rec_id)
    if not r:
        raise HTTPException(404, "Recommendation not found")
    scope_tenant(user, r.tenant_id)
    mapping = {"approve": "approved", "execute": "executed", "dismiss": "dismissed"}
    if action not in mapping:
        raise HTTPException(400, "Unknown action")
    r.status = mapping[action]
    audit(db, r.tenant_id, user.email, f"recommendation.{action}", rec_id, {"title": r.title})
    db.commit()
    return {"ok": True, "status": r.status}


# --------------------------------------------------------------------------- scenarios / demo
@app.get("/api/scenarios")
def list_scenarios(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    active = simulator.active_scenarios(db, tid)
    return {"scenarios": [{"key": k, "name": v[0], "description": v[1], "active": k in active}
                          for k, v in SCENARIOS.items()],
            "active": sorted(active), "tenant_id": tid, "simulated": True}


@app.post("/api/scenarios/{key}")
def activate_scenario(key: str, user: User = Depends(current_user), db: Session = Depends(get_db),
                      tenant_id: str | None = None):
    if key not in SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    tid = _tenant_of(user, tenant_id)
    # clear previous scenario rows outright: (tenant_id, key) is unique, so an
    # 'active=False' update followed by an insert would collide on re-trigger.
    db.query(Scenario).filter(Scenario.tenant_id == tid).delete(synchronize_session=False)
    db.commit()
    if key == "recovery":
        buf = simulator.get_buffer(tid)
        flushed = buf.depth()
        db.query(Collector).filter(Collector.tenant_id == tid).update({"status": "online", "last_seen": utcnow()})
        db.commit()
        simulator.run_tick(db)
        audit(db, tid, user.email, "scenario.recovery", key, {"buffered_flushed": flushed})
        return {"ok": True, "active": ["normal"], "flushed": flushed,
                "note": "Collectors reconnected and the local buffer drained in observed_at order."}
    if key != "normal":
        db.add(Scenario(tenant_id=tid, key=key, active=True, activated_by=user.email, activated_at=utcnow()))
    db.commit()
    db.expire_all()
    audit(db, tid, user.email, "scenario.activate", key, {"scenario": SCENARIOS[key][0]})
    simulator.run_tick(db)
    return {"ok": True, "active": sorted(simulator.active_scenarios(db, tid))}


@app.post("/api/demo/tick")
def manual_tick(user: User = Depends(current_user), db: Session = Depends(get_db), tenant_id: str | None = None):
    tid = _tenant_of(user, tenant_id)
    simulator.run_tick(db)
    return {"ok": True, "tick": _STATE["tick_count"], "tenant": tid}


@app.get("/api/demo/status")
def demo_status(db: Session = Depends(get_db)):
    return {"tick_count": _STATE["tick_count"], "last_tick": _STATE["last_tick"],
            "interval_s": TICK_SECONDS, "simulator": "built-in synthetic generator",
            "simulated_telemetry": True,
            "note": "Every sample produced here is synthetic and labelled simulated in the UI."}


# --------------------------------------------------------------------------- collector -> SaaS ingest
@app.post("/api/ingest")
def ingest(payload: dict = Body(...), db: Session = Depends(get_db)):
    """The real central ingestion API a collector calls. Enforces allow-list server-side."""
    col_id = payload.get("collector_id")
    tenant_id = payload.get("tenant_id")
    col = db.get(Collector, col_id) if col_id else None
    if not col or col.tenant_id != tenant_id:
        raise HTTPException(401, "Unknown collector/tenant pair")
    events = payload.get("events") or []
    accepted, rejected = 0, []
    seen = set()
    for e in events:
        eid = e.get("event_id")
        bad = [k for k in e if str(k).lower() in FORBIDDEN_FIELDS or SENSITIVE_KEY_PATTERN.search(str(k))]
        if bad:
            rejected.append({"event_id": eid, "reason": "forbidden_field", "fields": bad})
            continue
        if not eid or eid in seen or db.query(TelemetryEvent.id).filter(TelemetryEvent.event_id == eid).first():
            rejected.append({"event_id": eid, "reason": "duplicate"})
            continue
        seen.add(eid)
        db.add(TelemetryEvent(event_id=eid, tenant_id=tenant_id, collector_id=col_id,
                              metric=e.get("metric", ""), value=float(e.get("value", 0)),
                              unit=e.get("unit", ""), sequence=int(e.get("sequence", 0))))
        db.add(MetricSample(tenant_id=tenant_id, collector_id=col_id, metric=e.get("metric", ""),
                            value=float(e.get("value", 0)), ts=utcnow()))
        accepted += 1
    col.last_seen = utcnow()
    col.events_sent = (col.events_sent or 0) + accepted
    db.commit()
    return {"accepted": accepted, "rejected": rejected, "ack": str(uuid.uuid4())[:8],
            "server_time": iso(utcnow())}


# --------------------------------------------------------------------------- websocket
@app.websocket("/ws")
async def ws_feed(ws: WebSocket, token: str = Query(...)):
    try:
        claims = decode_token(token)
    except HTTPException:
        await ws.close(code=4401)
        return
    await ws.accept()
    db = SessionLocal()
    try:
        tenant_id = claims["tenant_id"]
        while True:
            try:
                alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.state == "open").all()
                incs = db.query(Incident).filter(Incident.tenant_id == tenant_id,
                                                 Incident.status.in_(["open", "investigating"])).all()
                cols = _collector_rows(db, tenant_id)
                samples = db.query(func.count(MetricSample.id)).filter(
                    MetricSample.tenant_id == tenant_id).scalar() or 0
                await ws.send_text(json.dumps({
                    "type": "tick", "utc": iso(utcnow()), "tick": _STATE["tick_count"],
                    "open_alerts": len(alerts),
                    "critical": sum(1 for a in alerts if a.severity == "critical"),
                    "incidents": len(incs), "samples": samples,
                    "health": [{"host": c["host"], "state": c["health"]["state"],
                                "score": c["health"]["score"]} for c in cols],
                    "cpu": (_series(db, tenant_id, "cpu_pct", 24)),
                    "latency": (_series(db, tenant_id, "latency_ms", 24)),
                    "scenarios": sorted(simulator.active_scenarios(db, tenant_id)),
                }))
            except WebSocketDisconnect:
                return
            except Exception as exc:
                await ws.send_text(json.dumps({"type": "error", "message": str(exc)}))
            db.expire_all()
            await asyncio.sleep(max(3.0, TICK_SECONDS))
    finally:
        db.close()


# --------------------------------------------------------------------------- static frontend
DIST = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("ws"):
            raise HTTPException(404, "Not found")
        index = os.path.join(DIST, "index.html")
        if full_path and os.path.isfile(os.path.join(DIST, full_path)):
            return FileResponse(os.path.join(DIST, full_path))
        return FileResponse(index)
