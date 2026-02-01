from prometheus_client import Counter, Gauge, Histogram, Summary

# NTRIP Caster Metrics
ACTIVE_CONNECTIONS = Gauge(
    "ntrip_active_connections",
    "Number of active NTRIP connections",
    ["type"]  # type can be "client" or "mount"
)

TOTAL_CONNECTIONS = Counter(
    "ntrip_connections_total",
    "Total number of NTRIP connections",
    ["type", "status"] # type: client/mount, status: accepted/rejected
)

DATA_THROUGHPUT = Counter(
    "ntrip_data_throughput_bytes",
    "Total data throughput in bytes",
    ["mount", "direction"] # direction: in/out
)

AUTH_ATTEMPTS = Counter(
    "ntrip_auth_attempts_total",
    "Total number of authentication attempts",
    ["status", "type"] # type: admin/user/mount
)

RTCM_PARSE_ERRORS = Counter(
    "ntrip_rtcm_parse_errors_total",
    "Total number of RTCM parsing errors",
    ["mount"]
)

# Request duration for Web API
REQUEST_DURATION = Histogram(
    "ntrip_web_request_duration_seconds",
    "Duration of web requests in seconds",
    ["method", "endpoint"]
)

SYSTEM_CPU_USAGE = Gauge(
    "ntrip_system_cpu_usage_percent",
    "System CPU usage percentage"
)

SYSTEM_MEMORY_USAGE = Gauge(
    "ntrip_system_memory_usage_bytes",
    "System memory usage in bytes",
    ["type"] # type: used/total
)
