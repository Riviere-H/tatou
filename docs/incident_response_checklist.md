# Tatou Security Incident Response Checklist

## 1. Purpose
This checklist provides a **step-by-step guide** for handling security incidents in the Tatou PDF watermarking platform.
It complements the executable script `tools/incident_response/quick_response_checklist.sh` by defining the **human procedures** and **documentation requirements**.


## 2. Pre-Incident Preparation

| Step |                        Action                             |   Responsible   |            Verification              |
|------|-----------------------------------------------------------|-----------------|--------------------------------------|
| 2.1  | Ensure monitoring stack (Prometheus + Grafana) is running | Monitoring Lead | `curl http://localhost:9090/-/ready` |
| 2.2  | Validate alert rules in `monitoring/prometheus_rules.yml` | Monitoring Lead | Check rules load successfully        |
| 2.3  | Confirm structured logging is active (`logs/app.log`)     | App Lead        | Inspect recent entries               |
| 2.4  | Ensure all credentials and API keys are stored securely   | Security Lead   | Verify `.env` configuration          |


## 3. Incident Detection & Verification

| Step |                Action                  |    Responsible     |                      Tool/Command                       |
|------|----------------------------------------|--------------------|---------------------------------------------------------|
| 3.1  | Review latest Prometheus alerts        | Monitoring Lead    | Grafana dashboard / AlertManager                        |
| 3.2  | Run automated quick check              | Any responder      | `./tools/incident_response/quick_response_checklist.sh` |
| 3.3  | Inspect `app.log` for anomalies        | Security Analyst   | `grep "ERROR" logs/app.log`                             |
| 3.4  | Verify suspicious IPs or tokens        | Security Analyst   | `docker compose exec server cat /app/logs/app.log`      |
| 3.5  | Document findings in `incident_log.md` | Documentation Lead | Manual entry                                            |


## 4. Containment Procedures

| Step |                    Action                    |   Responsible   |                Verification               |
|------|----------------------------------------------|-----------------|-------------------------------------------|
| 4.1  | Revoke compromised tokens                    | App Lead        | Validate API rejects old tokens           |
| 4.2  | Block malicious IPs at container level       | Network Lead    | `docker network inspect` confirms removal |
| 4.3  | Isolate affected container(s)                | Ops Lead        | `docker compose stop [service]`           |
| 4.4  | Disable suspicious user accounts             | Security Lead   | Database confirmation                     |
| 4.5  | Update Prometheus alert thresholds if needed | Monitoring Lead | Configuration reload successful           |


## 5. Eradication & Recovery

| Step |                  Action                 |   Responsible    |           Verification            |
|------|-----------------------------------------|------------------|-----------------------------------|
| 5.1  | Identify root cause using system logs   | Security Analyst | Cross-reference log timestamps    |
| 5.2  | Remove malicious files or payloads      | Ops Lead         | Confirm checksum integrity        |
| 5.3  | Restore service from clean backup       | App Lead         | Service passes health check       |
| 5.4  | Rotate credentials and regenerate flags | Security Lead    | New values committed to `.env`    |
| 5.5  | Re-enable affected services             | Ops Lead         | Confirm all endpoints operational |


## 6. Post-Incident Documentation

| Step |                       Action                         |    Responsible     |           Output             |
|------|------------------------------------------------------|--------------------|------------------------------|
| 6.1  | Record incident timeline                             | Documentation Lead | `docs/incident_log.md`       |
| 6.2  | Summarize actions taken and lessons learned          | Incident Lead      | Post-mortem section          |
| 6.3  | Update `docs/incident_response.md` with improvements | Security Lead      | New version committed        |
| 6.4  | Archive logs and related evidence                    | Ops Lead           | `logs/incidents/YYYY-MM-DD/` |


## 7. Cross-Reference Tools

|             Tool              |            Description                 |             Path              |
|-------------------------------|----------------------------------------|-------------------------------|
| `quick_response_checklist.sh` | Automated environment check            | `tools/incident_response/`    |
| `generate_test_events.py`     | Simulated incident generator           | `tools/scripts/`              |
| `prometheus_rules.yml`        | Security and service alert definitions | `monitoring/`                 |
| `security_alerts.yml`         | Supplemental detection rules           | `monitoring/detection_rules/` |
| `incident_response.md`        | Main procedural document               | `docs/`                       |


## 8. Verification Log (Example)

|    Timestamp     |             Step              | Status |             Notes               |
|------------------|-------------------------------|--------|---------------------------------|
| 2025-10-09 16:22 | 3.2 Run automated quick check |   ✅   | No anomalies detected           |
| 2025-10-09 16:23 | 3.3 Inspect server.log        |   ⚠️    | Rate limiter errors observed    |
| 2025-10-09 16:26 | 4.1 Revoke compromised tokens |   ✅   | Tokens invalidated successfully |


## 9. Next Steps
After every incident:
1. Conduct a 24–48h post-incident review meeting.
2. Update both this checklist and the main incident response plan.
3. Verify all lessons learned are translated into Prometheus rule improvements or code patches.
 
