from prometheus_client import Counter

# Counters for monitoring security / reliability events
PDF_PARSER_ERRORS = Counter(
    "pdf_parser_errors_total",
    "Number of PDF parsing / applicability check errors"
)

FILE_UPLOAD_ERRORS = Counter(
    "file_upload_errors_total",
    "Number of file upload related errors (validation, save, write)"
)

FILE_WRITE_ERRORS = Counter(
    "file_write_errors_total",
    "Number of failures writing files to disk"
)

WATERMARK_PROCESSING_ERRORS = Counter(
    "watermark_processing_errors_total",
    "Number of errors during watermark generation / application"
)

WATERMARK_READ_ERRORS = Counter(
    "watermark_read_errors_total",
    "Number of errors when attempting to read watermark from PDFs"
)

RMAP_HANDSHAKE_FAILS = Counter(
    "rmap_handshake_fails_total",
    "Number of RMAP handshake failures or exceptions"
)

DB_EXCEPTIONS = Counter(
    "db_exceptions_total",
    "Number of database exceptions captured in API handlers"
)


# Security-specific metrics
SECURITY_EVENTS = Counter(
    "security_events_total",
    "Total number of security events",
    ["event_type"]
)

AUDIT_EVENTS = Counter(
    "audit_events_total", 
    "Total number of audit events",
    ["event_type"]
)

USER_LOGIN_FAILURES = Counter(
    "user_login_failures_total",
    "Total number of failed login attempts",
    ["client_ip"]
)

API_ERRORS = Counter(
    "api_errors_total",
    "Total number of API errors by endpoint",
    ["endpoint", "method"]
)

FILE_PROCESSING_ERRORS = Counter(
    "file_processing_errors_total",
    "Total number of file processing errors",
    ["operation"]
)

# Rate limiting metrics
RATE_LIMIT_HITS = Counter(
    "rate_limit_hits_total",
    "Total number of rate limit hits",
    ["endpoint", "client_ip"]
)

# Watermark operation metrics
WATERMARK_OPERATIONS = Counter(
    "watermark_operations_total",
    "Total number of watermark operations",
    ["operation", "method"]
)
