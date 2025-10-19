
Monitoring Stack Overview (Prometheus + Grafana Integration)

This section documents the operational monitoring layer for the Tatou platform.
It explains how metrics are exposed, scraped, and visualized, as well as how alerts are triggered.


1. Architecture Overview
[Tatou Flask App]
       │
       │  exposes /metrics
       ▼
[Prometheus]  ← scrapes metrics every 10s
       │
       │  evaluates alerting rules (security_alerts.rules.yml)
       ▼
[Grafana]  ← visualizes data via dashboards


2. Components

|       Component      |                         Description                           |                     Configuration                       |
|----------------------|---------------------------------------------------------------|---------------------------------------------------------|
|      Prometheus      | Time-series database for collecting metrics                   | monitoring/prometheus.yml                               |
|        Grafana       | Dashboard and visualization frontend                          | Docker service grafana                                  |
|   Tatou App Metrics  | Exposed via /metrics endpoint                                 | Instrumented with prometheus_client                     |
|      Alert Rules     | Security-focused alerts (auth, SQLi, upload anomalies, etc.)  | monitoring/prometheus_rules/security_alerts.rules.yml   |


3. Metrics Exposure
The Flask application exposes metrics via /metrics, mounted using DispatcherMiddleware:
http://localhost:5000/metrics
Prometheus scrapes these metrics through the service name server (from docker-compose.yml).


4. Key Metrics Tracked

|             Metric             |          Description            |             Labels             |
|--------------------------------|---------------------------------|--------------------------------|
| http_requests_total            | Total HTTP requests             | method, endpoint, http_status  |
| http_request_duration_seconds  | Request latency                 | method, endpoint               |
| auth_failures_total            | Authentication failures         | client_ip                      |
| sql_errors_total               | SQL-related application errors  | client_ip                      |
| file_upload_errors_total       | File upload failures            | error_type, client_ip          |
| pdf_parser_errors_total        | PDF parser exceptions           | client_ip                      |
| rmap_handshake_failures_total  | RMAP handshake errors           | client_ip                      |
| security_events_total          | High-level security incidents   | event_type, severity           |


5. Alerting Rules
Prometheus applies alerting rules defined in monitoring/prometheus_rules/security_alerts.rules.yml.
Example:
- alert: HighAuthFailureRate
  expr: rate(auth_failures_total[2m]) > 5
  for: 1m
  labels:
    severity: high
  annotations:
    summary: "High authentication failure rate"
    description: "Potential brute-force or credential stuffing attack"
Alerts can later be routed to an Alertmanager (optional) for notification via email, Slack, etc.


6. Running the Stack
docker compose up -d
Services launched:
    • server → Flask app (port 5000)

    • prometheus → Metrics collector (port 9090)

    • grafana → Visualization dashboard (port 3000)

Verify:
curl http://localhost:5000/metrics
curl http://localhost:9090/targets

7. Grafana Dashboards
Default Grafana credentials:
Username: admin
Password: admin
Access Grafana at http://localhost:3000
You can import a Prometheus datasource and create dashboards for Tatou security metrics.
