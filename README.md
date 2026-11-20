# NEXGEN AIOPS — Privacy-First Two-Tier AIOps Observability

A working, full-stack AIOps observability application: FastAPI + SQLite backend, local collector
pipeline with allow-listed egress, WebSocket live feed, and a 20-page React/TypeScript/Tailwind/Recharts
console.

> **Telemetry provenance.** Every metric in this build is synthetic, produced by the in-process
> simulator and labelled `SIMULATED TELEMETRY` in the UI. The organiser's shared stream has **not**
> been connected or tested — no connection details or schema were available in this environment.
> No accuracy, uptime or performance figures are claimed anywhere they were not measured.

---

## 1. What exists and runs

| Layer | Implementation | Verified how |
|---|---|---|
| API | FastAPI 0.165, ~40 REST endpoints + 1 WebSocket | pytest, 51 assertions |
| DB | SQLite via SQLAlchemy 2 (PostgreSQL-ready URL switch) | tables created, queried in tests |
| Auth | JWT (HS256, 12 h), PBKDF2-SHA256 passwords (120k iters) | login / 401 / 403 tests |
| Tenancy | scope derived from token claim only | cross-tenant 403 test |
| Collector | filter → redact → aggregate → local analysis → policy check → allow-list envelope | pipeline unit tests |
| Buffering | bounded queue, dedupe by `event_id`, out-of-order sort, ack tracking, retry | 4 buffer tests |
| AIOps | baselines, z-score, correlation, RCA, forecast, risk, explanation | 6 engine tests |
| Frontend | React 18 + TS + Tailwind + Recharts, 20 routed pages | `vite build` clean |
| Real time | WS `/ws?token=…` pushing ticks every 5 s | websocket test |

### Run it

```bash
# backend
cd backend && pip install fastapi uvicorn sqlalchemy pyjwt httpx pytest
uvicorn app.main:app --reload --port 8000

# frontend (dev, proxies /api and /ws to :8000)
cd frontend && npm install && npm run dev

# production single origin: build the SPA, FastAPI serves it from frontend/dist
cd frontend && npm run build
cd ../backend && uvicorn app.main:app --port 8000   # http://localhost:8000

# tests
cd backend && python3 -m pytest tests/ -v
```

Demo accounts (password `NexGen#2026`):

| Email | Role | Tenant |
|---|---|---|
| admin@acme.io | platform_admin | Acme Financial Group |
| analyst@acme.io | analyst | Acme Financial Group |
| soc@acme.io | security_analyst | Acme Financial Group |
| ops@northwind.io | analyst | Northwind Logistics |
| sre@orbit.io | analyst | Orbit Media Labs |

---

## 2. Judging photographs

**Not received.** The message referenced two judging photographs but contained no image attachments
that were readable. Every requirement below therefore comes from the user's written brief (four phases,
sections 1–15) and not from a marks distribution. Nothing in this repository claims to match a
specific scoring table.

---

## 3. Requirements checklist

### Phase 1 — Problem understanding and ideation
- [x] Problem statement encoded in the product: observability value without raw-data exposure.
- [x] Two-tier architecture (customer environment / central SaaS) implemented, not just drawn.
- [x] Explicit "never leaves" list enforced in code (`FORBIDDEN_FIELDS`, `SENSITIVE_KEY_PATTERN`).
- [x] Differentiators surfaced in-product: egress proof panel, live redaction inspector, explainability traces.

### Phase 2 — Architecture and technical design
- [x] Collector pipeline with seven named stages, each a separate function (`app/collector.py`).
- [x] Allow-list envelope construction (built field-by-field, never filtered from source objects).
- [x] Data model: tenants, users, collectors, samples, events, alerts, incidents, egress, audit, recommendations, scenarios.
- [x] REST contract + WebSocket contract + server-side validation on every mutation.
- [x] Architecture rendered in `/privacy` (two-tier panel) and `/aiops` (decision path).

### Phase 3 — Implementation and working prototype
- [x] Real backend with persistence, real frontend consuming it, no mock JSON in the UI.
- [x] 20 pages, all routed, all wired to live endpoints.
- [x] Simulator driving the same pipeline a real collector would.
- [x] Test suite: **51 passed** (see §6 for the exact command output).

### Phase 4 — Final demo, validation and presentation
- [x] 11 demo scenarios with immediate dashboard effect.
- [x] Alert lifecycle (ack / resolve), incident lifecycle (open → investigating → mitigated → closed).
- [x] Audit chain verification endpoint + UI badge.
- [x] Honesty panel in Predictive ("no accuracy metric claimed").

### Mandatory requirements
| Requirement | Where |
|---|---|
| Infrastructure monitoring (CPU, RAM, disk, uptime, process, availability, utilisation) | `/infrastructure` |
| Network monitoring (latency, loss, bandwidth, throughput, connectivity, anomalies, trends) | `/network` |
| Application monitoring (API RT, volume, error rate, availability, failures, distributed health) | `/application` |
| Security intelligence (failed logins, suspicious activity, auth anomalies, classification, risk, redaction) | `/security` |
| AIOps engine, 10 modules | `/aiops` + `/anomalies`, `/rca`, `/predictive`, `/capacity` |
| Two-tier secure architecture | `/privacy`, `app/collector.py` |
| Egress proof panel | `/egress` |
| Reliability (buffer, retry, ack, unique IDs, dedupe, offline detect, reconnect, UTC, out-of-order) | `EventBuffer`, `/collectors` |
| Four health states, stale never healthy | `aiops.health_label`, `health_for_collector` |
| 11 live demo scenarios | demo drawer → `/api/scenarios/{key}` |
| Simulated telemetry labelled | header chip + page tags + `/api/health` |

### Bonus features
- [x] **Privacy-aware processing** — redaction before aggregation; live inspector endpoint.
- [x] **Local buffering** — bounded queue with drop accounting and flush-on-recovery.
- [x] **Explainable AIOps** — every alert carries what / why / signals / action / confidence.
- [x] **Alert noise reduction** — fingerprint dedupe, suppression counter, percentage KPI.
- [x] **Global-ready architecture** — multi-region, multi-tenant, UTC-only timestamps, AZ labels.

### Known gaps (stated, not hidden)
- Organiser telemetry stream: **not integrated, not tested.**
- Autonomous remediation: state transition + audit only; no infrastructure mutation.
- Forecast accuracy: unmeasured (no ground-truth history).
- Deployment: runs locally; no cloud host was provisioned for this build.

---

## 4. Two-tier data path (implemented)

```
CUSTOMER ENVIRONMENT
 telemetry sources
   → local collector        app/collector.py: filter_events()
   → filter                 drop events without metric/value
   → redact                 _walk_redact(): 12 pattern classes + sensitive-key blocklist
   → aggregate              aggregate_events(): per (host, metric) window summary
   → local analysis         local_analysis(): severity + risk score computed on-prem
   → policy check           policy_check(): envelope rebuilt from ALLOWED_FIELDS only
   → approved metadata      schema 1.4 envelope, sha256 checksum
   → buffer / transmit      EventBuffer: dedupe, order, retry, ack
────────────────────────── boundary ──────────────────────────
CENTRAL SAAS
   → POST /api/ingest       re-validates forbidden fields server-side, rejects duplicates
   → metadata store         telemetry_events / metric_samples
   → AIOps analytics        baselines, z-score, forecast, risk
   → incident correlation   affinity clustering + RCA signature match
   → dashboard              React console (REST + WS)
   → recommendations        human-in-the-loop approval
```

Raw logs, credentials, tokens, IPs, emails, request bodies and stack traces are dropped inside the
customer environment. The egress envelope cannot contain them because it is **constructed** from an
allow-list, not filtered down from a source object — that distinction is the core privacy claim and it
is covered by `test_allow_list_is_enforced_structurally`.

---

## 5. Health-state contract

| Score | State | Rule |
|---|---|---|
| ≥ 85 | Excellent | all monitored SLOs comfortably met |
| 70–84 | Good | within SLO, minor pressure |
| 50–69 | Fair | degraded dimension, watch |
| < 50 | Poor | SLO breach, or **stale telemetry** |

Staleness: if `now − last_seen > 45 s` the collector is forced to `Poor` with `stale: true` and the
reason string `telemetry stale — last healthy state withheld`. Even at 22 s the score is capped at 68.
Verified by `test_stale_collector_is_poor_not_healthy`.

---

## 6. Test evidence (actual run output)

```
$ cd backend && python3 -m pytest tests/ -q
...................................................                      [100%]
51 passed in 4.78s
```

Coverage highlights: auth 401/403, cross-tenant denial, redaction of credentials/PII/IPs, structural
allow-list enforcement, ingest-side forbidden-field rejection, boundary validator verdicts both ways,
buffer dedupe + ordering + capacity drop, aggregation collapse (10 events → 1), four-state health
mapping, forecast trend/insufficiency, explanation completeness, stale→Poor, scenario→dashboard
change, multi-alert→incident, recovery→all collectors online, ack→audit entry, chain verification,
23 endpoint smoke checks, incident status validation, WebSocket frame.

Bugs found and fixed during the build (recorded honestly):
1. `UNIQUE(tenant_id, key)` collision when re-triggering a scenario — switched to delete-then-insert.
2. `KeyError` on descriptive metrics (`uptime_s`, `bandwidth_mbps`) that have no SLO threshold — added guards in both detection paths.
3. `KeyError: 'service'` in the RCA template for service-level root causes — replaced `str.format` with explicit token replacement.

---

## 7. API surface (selected)

```
POST /api/auth/login                 → JWT + user
GET  /api/overview                   → KPI bundle, series, health matrix
GET  /api/infra | /network | /app    → per-domain telemetry
GET  /api/security                   → events, risk, redaction classes
GET  /api/cloud | /distributed       → regional + dependency health
GET  /api/aiops/modules              → 10 module statuses with metrics
GET  /api/aiops/anomalies            → z-score queue + baselines
GET  /api/aiops/rca/{incident_id}    → timeline, signals, actions
GET  /api/predict?metric=cpu_pct     → history + forecast + band
GET  /api/capacity                   → headroom, steps-to-full
GET/POST /api/alerts…                → list, ack, resolve
GET/PATCH /api/incidents…            → list, validated transitions
GET  /api/collectors                 → fleet, buffer stats, pipeline
GET  /api/privacy/policy             → allow-list, rules, two-tier map
POST /api/privacy/inspect            → run any object through the real pipeline
GET  /api/egress                     → transfer proofs
POST /api/egress/validate            → PASS/BLOCKED verdict
POST /api/ingest                     → collector → SaaS, server-side enforcement
POST /api/scenarios/{key}            → 11 demo scenarios
WS   /ws?token=…                     → 5 s live ticks
```

---

## 8. Project structure

```
nexgen-aiops/
├─ backend/
│  ├─ app/
│  │  ├─ config.py      allow-list, forbidden fields, redaction patterns, thresholds, seeds
│  │  ├─ db.py          engine, session, UTC helper
│  │  ├─ models.py      11 tables
│  │  ├─ security.py    JWT, PBKDF2, tenant scoping, hash-linked audit chain
│  │  ├─ collector.py   pipeline + EventBuffer
│  │  ├─ aiops.py       health, baseline, z-score, correlation, RCA, forecast, explain
│  │  ├─ simulator.py   synthetic generator + alert/incident/recommendation engine
│  │  └─ main.py        ~40 endpoints, WS, SPA hosting
│  └─ tests/test_api.py 51 tests
└─ frontend/
   ├─ src/api.ts, hooks.ts, App.tsx
   ├─ src/components/  Layout (sidebar, demo drawer), ui.tsx (charts, badges, KPI)
   └─ src/pages/       20 pages + Login
```

## 9. Next steps for the final round

1. Connect the organiser stream: implement an adapter that emits the documented schema into
   `simulator.generate_raw_events`' place; keep the pipeline untouched. **Test before claiming.**
2. Swap `NEXGEN_DB_URL` to PostgreSQL; add Alembic migrations.
3. Replace the linear forecaster with seasonal decomposition once labelled history exists; backtest it.
4. Add Playwright end-to-end coverage for the demo scenario flow.
5. Deploy (container + managed Postgres) and re-run the suite against the deployed URL.
