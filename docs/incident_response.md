
# Tatou Security Incident Response Plan
## 1. Overview
This document defines the security incident response procedures for the Tatou PDF watermarking platform.
It ensures rapid detection, containment, and recovery from security events affecting system integrity, confidentiality, or availability.

## 2. Incident Classification
###2.1 Severity Levels

| Severity |                         Description                               |                   Example Scenarios                 |
|----------|-------------------------------------------------------------------|-----------------------------------------------------|
| Critical | Direct compromise of sensitive assets or total service disruption | Flag file access, DB leak, container escape         |
|   High   | Authentication or data integrity breach                           | JWT forgery, watermark tampering, RMAP abuse        |
|  Medium  | Detected intrusion attempt or abnormal pattern                    | Brute force trigger, suspicious upload              |
|   Low    | Reconnaissance or minor anomalies                                 | Scan attempts, failed logins, rate-limited requests |

## 3. Response Team

|        Role        |        Responsibility         |  Contact  |
|--------------------|-------------------------------|-----------|
| Incident Lead      | Overall coordination          |  Member A |
| Technical Lead     | Root cause analysis           |  Member B |
| Documentation Lead | Incident reporting & evidence |  Member C |

### Communication Channels:

    • Internal: Group chats

    • Course Teacher: Forum + Email

    • Cross-group: On request basis


## 4. Incident Response Lifecycle
### 4.1 Detection & Analysis

#### Sources:

    • Prometheus alerts

    • Grafana dashboards

    • Application logs

    • Container logs

#### Initial Steps:

    1. Confirm alert validity

    2. Assign severity level

    3. Log event to incident tracker

    4. Notify response team


### 4.2 Containment

#### Immediate Containment:

    • Block offending IPs

    • Revoke tokens

    • Disable compromised accounts

    • Isolate affected containers

#### Long-term Containment:

    • Patch vulnerabilities

    • Rotate keys

    • Update rules (monitoring/prometheus_rules/security_alerts.yml)

    • Harden detection logic

### 4.3 Eradication & Recovery

#### Eradication:

    1. Identify root cause

    2. Remove artifacts

    3. Verify integrity

    4. Document remediation

#### Recovery:

    1. Restore from backups

    2. Restart validated services

    3. Confirm via /healthz

    4. Review Prometheus metrics for anomalies


## 5. Specific Incident Playbooks

### 5.1 Flag Compromise

#### Indicators:

    • Access to /app/flag

    • Container privilege escalation

#### Response:

    • Regenerate flag

    • Audit access logs

    • Apply stricter permission model

### 5.2 Authentication Bypass

#### Indicators:

    • Successful login with invalid creds

    • JWT anomaly

#### Response:

    • Invalidate all sessions

    • Reset credentials

    • Reinforce token validation

### 5.3 Watermark Tampering

#### Indicators:

    • Watermark mismatch or missing

#### Response:

    • Compare hash with reference

    • Document incident

    • Update validation rules


## 6. Communication Plan

|    Phase    |       Internal       |             External               |
|-------------|----------------------|------------------------------------|
| Detection   | Notify response team |              ---                   |
| Containment | Status update        | Course teacher if impact confirmed |
| Resolution  | Final report         | Public disclosure required         |


## 7. Documentation & Evidence

### 7.1 Required Logs

    • Detection timestamp

    • Source alert

    • Severity classification

    • Response actions

    • Recovery validation

### 7.2 Evidence Preservation

    • Application & system logs

    • Prometheus metrics snapshot

    • Suspicious files

    • Container state metadata


## 8. Testing & Drills

|       Type        |            Purpose             |      Frequency       |
|-------------------|--------------------------------|----------------------|
| Tabletop Exercise | Review playbooks               | Each semester        |
| Security Drill    | Validate monitoring & alerting | Monthly              |
| Recovery Test     | Validate service restoration   | After major incident |


## 9. Continuous Improvement

### 9.1 Post-Incident Review

    • Conduct within 48 hours of closure

    • Update procedures and detection rules

### 9.2 Key Metrics

| Metric |       Description         |
|--------|---------------------------|
|  MTTD  | Mean Time to Detect       |
|  MTTR  | Mean Time to Recover      |
|  IRR   | Incident Recurrence Rate  |
|  FPR   | False Positive Rate       |


## Appendix A – Quick Reference

###Critical Commands

#### Monitor logs
```
docker compose logs server -f
```

#### Restart application
```
docker compose restart server
```

#### Check service health
```
curl http://localhost:5000/healthz
```

#### Validate flag file integrity
```
docker exec server cat /app/flag
```

#### Escalation Flow

| Severity |  Responsible   | Escalation Target |    Channel     |
|----------|----------------|-------------------|----------------|
| Critical | Incident Lead  |    Instructor     | Email + Forum  |
|   High   | Technical Lead |    Team Lead      | Group Chat     |
|  Medium  | On-call Member |        —          | Group Chat     |
|   Low    | Any            |        —          | Log entry only |


