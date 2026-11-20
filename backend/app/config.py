"""Central configuration: egress allow-list, redaction policy, health weights, demo accounts."""
import os
import re

SECRET_KEY = os.environ.get("NEXGEN_SECRET", "nexgen-dev-secret-change-in-prod")
TOKEN_TTL_MIN = int(os.environ.get("NEXGEN_TOKEN_TTL_MIN", "720"))
DB_URL = os.environ.get("NEXGEN_DB_URL", "sqlite:///./nexgen.db")
SIM_ENABLED = os.environ.get("NEXGEN_SIM", "1") == "1"
TICK_SECONDS = float(os.environ.get("NEXGEN_TICK", "5"))
STALE_AFTER_S = float(os.environ.get("NEXGEN_STALE_AFTER_S", "45"))

# ---------------------------------------------------------------------------
# EGRESS ALLOW-LIST — the ONLY fields permitted to leave the customer boundary.
# Anything not listed here is dropped by the collector pipeline and recorded as
# metadata-only in the redaction report.
# ---------------------------------------------------------------------------
ALLOWED_FIELDS = [
    "schema_version",
    "event_id",
    "collector_id",
    "tenant_id",
    "host",
    "service",
    "region",
    "metric",
    "value",
    "unit",
    "observed_at",
    "sequence",
    "aggregation",
    "window_s",
    "severity",
    "risk_score",
    "event_class",
    "count",
]
ALLOWED_LABELS = ["env", "tier", "role", "availability_zone"]

# Field names that must never transit, even if a value looks benign.
FORBIDDEN_FIELDS = {
    "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "authorization", "cookie", "session_id", "private_key",
    "raw_log", "log_line", "message", "body", "payload", "request_body",
    "response_body", "query", "sql", "stack_trace", "card_number", "cvv", "ssn",
    "credit_card", "email", "username", "customer_name", "ip_address",
}

SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|auth|credential|cookie|session|"
    r"private[_-]?key|card|cvv|ssn|email|phone|username|user_name|customer|iban|"
    r"message|raw|body|payload|log|query|sql|stack)",
    re.IGNORECASE,
)

REDACTION_PATTERNS = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED:private_key]"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"), "[REDACTED:jwt]"),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    ("aws_secret", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"), "[REDACTED:aws_secret]"),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [REDACTED:token]"),
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"), "[REDACTED:hash]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED:email]"),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED:card]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:ssn]"),
    ("phone", re.compile(r"\+\d{1,3}[ -]?\d{6,14}\b"), "[REDACTED:phone]"),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED:ip]"),
    ("conn_string", re.compile(r"(?i)(postgres|mysql|mongodb|redis)(\+\w+)?://[^\s\"']+"), "[REDACTED:connection_string]"),
]

DESTINATION = "https://ingest.nexgen-aiops.example/v1/telemetry"
SCHEMA_VERSION = "1.4"

# Metric catalogue: name -> (unit, display, page group)
METRICS = {
    "cpu_pct": ("%", "CPU Utilisation", "infra"),
    "mem_pct": ("%", "Memory Utilisation", "infra"),
    "disk_pct": ("%", "Disk Utilisation", "infra"),
    "uptime_s": ("s", "Uptime", "infra"),
    "proc_health": ("score", "Process Health", "infra"),
    "svc_availability_pct": ("%", "Service Availability", "app"),
    "latency_ms": ("ms", "Network Latency", "network"),
    "packet_loss_pct": ("%", "Packet Loss", "network"),
    "bandwidth_mbps": ("Mbps", "Bandwidth", "network"),
    "throughput_rps": ("req/s", "Throughput", "app"),
    "api_p95_ms": ("ms", "API p95 Latency", "app"),
    "error_rate_pct": ("%", "Error Rate", "app"),
    "failed_logins": ("events/min", "Failed Logins", "security"),
    "auth_anomaly_score": ("score", "Auth Anomaly Score", "security"),
    "pod_restarts": ("count", "Pod Restarts", "cloud"),
    "replication_lag_ms": ("ms", "Replication Lag", "distributed"),
    "queue_depth": ("msgs", "Queue Depth", "distributed"),
}

THRESHOLDS = {  # warn, critical
    "cpu_pct": (75.0, 90.0),
    "mem_pct": (80.0, 92.0),
    "disk_pct": (82.0, 93.0),
    "latency_ms": (120.0, 260.0),
    "packet_loss_pct": (1.0, 3.0),
    "error_rate_pct": (2.0, 6.0),
    "api_p95_ms": (600.0, 1200.0),
    "svc_availability_pct": (99.5, 98.0),
    "failed_logins": (18.0, 40.0),
    "auth_anomaly_score": (55.0, 78.0),
    "pod_restarts": (5.0, 12.0),
    "replication_lag_ms": (1200.0, 4000.0),
    "queue_depth": (5000.0, 12000.0),
}
LOWER_IS_WORSE = {"svc_availability_pct"}

HEALTH_BANDS = [(85, "Excellent"), (70, "Good"), (50, "Fair"), (0, "Poor")]

DEMO_TENANTS = [
    ("t_acme", "Acme Financial Group", "acme-financial", "Enterprise", "eu-west-1", 250),
    ("t_northwind", "Northwind Logistics", "northwind", "Business", "us-east-1", 120),
    ("t_orbit", "Orbit Media Labs", "orbit-media", "Growth", "ap-southeast-2", 60),
]

DEMO_USERS = [
    ("u_admin", "t_acme", "admin@acme.io", "NexGen#2026", "platform_admin", "Priya Raman"),
    ("u_analyst", "t_acme", "analyst@acme.io", "NexGen#2026", "analyst", "Daniel Okoye"),
    ("u_soc", "t_acme", "soc@acme.io", "NexGen#2026", "security_analyst", "Mara Lindqvist"),
    ("u_ops", "t_northwind", "ops@northwind.io", "NexGen#2026", "analyst", "Tomas Berg"),
    ("u_sre", "t_orbit", "sre@orbit.io", "NexGen#2026", "analyst", "Wei Chen"),
]

COL_SPECS = {
    "t_acme": [
        ("col_k8s_prod", "k8s-prod-eu", "k8s-node-04.eu-west-1", "eu-west-1", ["payments-api", "ledger-api", "checkout-ui"]),
        ("col_db_primary", "db-primary-eu", "db01.eu-west-1", "eu-west-1", ["postgres-primary", "pgbouncer"]),
        ("col_edge_gw", "edge-gateway-uk", "edge-lon-01", "eu-west-2", ["api-gateway", "cdn-edge"]),
        ("col_branch_uk", "branch-collector-uk", "branch-lon-hq", "eu-west-2", ["directory", "print-svc"]),
    ],
    "t_northwind": [
        ("col_wh_east", "warehouse-east", "wh-use1-02", "us-east-1", ["routing-api", "fleet-sync"]),
        ("col_wh_west", "warehouse-west", "wh-usw2-01", "us-west-2", ["routing-api", "label-svc"]),
    ],
    "t_orbit": [
        ("col_media_ap", "media-ap-south", "media-apse2-01", "ap-southeast-2", ["transcode-api", "cms"]),
        ("col_media_edge", "media-edge-nz", "edge-akl-01", "ap-southeast-6", ["cdn-edge", "player-api"]),
    ],
}

SCENARIOS = {
    "normal": ("Normal operation", "Steady baseline traffic across every monitored tier."),
    "high_cpu": ("High CPU", "Sustained CPU saturation on the Kubernetes worker pool."),
    "high_memory": ("High memory", "Memory pressure with swap activity on the primary database."),
    "high_disk": ("High disk usage", "Write amplification filling the data volume."),
    "latency": ("Increased network latency", "WAN path degradation towards the edge gateway."),
    "packet_loss": ("Packet loss", "Loss on the transit link causing retransmits."),
    "failed_logins": ("Repeated failed logins", "Credential-stuffing pattern against the admin portal."),
    "collector_offline": ("Collector disconnection", "Branch collector stops reporting; buffer holds events."),
    "saas_failure": ("SaaS connection failure", "Ingestion API returns 503; buffer grows, retries scheduled."),
    "recovery": ("Connection recovery", "Path restored; buffered events flush in order."),
    "multi_alert": ("Multiple related alerts", "Cascading failure across compute, network and identity."),
}
