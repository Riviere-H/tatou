
# Tatou Monitoring System Guide

## Overview
This document describes the monitoring architecture and operational procedures for Tatou security monitoring.


## Monitoring Architecture

### Components
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboards
- **Tatou App**: Exposes metrics via /metrics endpoint
- **Structured Logging**: JSON-formatted security events

### Key Metrics

#### Authentication & Security Metrics
- `security_events_total`: Security events by type (Phase 1 + Phase 4)
- `user_login_failures_total`: Failed login attempts by IP (Phase 4) 
- `auth_failures_total`: Authentication failures (Phase 1)
- `rate_limit_hits_total`: Rate limit violations by endpoint and IP (Phase 4)

#### API & Application Metrics
- `api_errors_total`: API errors by endpoint and method (Phase 4)
- `http_requests_total`: HTTP request rate (Phase 1)
- `db_exceptions_total`: Database operation exceptions (Phase 1)
- `rmap_handshake_fails_total`: RMAP authentication protocol failures (Phase 1)

#### File Processing Metrics
- `file_upload_errors_total`: File upload validation and processing errors (Phase 1)
- `file_write_errors_total`: File system write operation failures (Phase 1)
- `file_processing_errors_total`: File processing errors (Phase 4)
- `pdf_parser_errors_total`: PDF parsing and applicability check errors (Phase 1)

#### Watermarking Operations Metrics
- `watermark_operations_total`: Watermarking operations by type and method (Phase 4)
- `watermark_processing_errors_total`: Watermark generation and application errors (Phase 1)
- `watermark_read_errors_total`: Watermark extraction and reading errors (Phase 1)

#### System Health Metrics
- `up`: Service health status (Phase 1)


## Alerting Rules

### Critical Alerts
- **HighAuthFailureRate**: > 5 auth failures/sec for 1 minute (Phase 1)
- **SecurityEventsSpike**: > 1 security event/sec for 1 minute (Phase 4)
- **SQLInjectionAttempts**: > 3 SQL errors/sec for 2 minutes (Phase 1)

### Warning Alerts  
- **HighLoginFailureRate**: > 0.1 login failures/sec for 2 minutes (Phase 4)
- **APIErrorsSpike**: > 0.5 API errors/sec for 3 minutes (Phase 4)
- **FileUploadAnomalies**: > 5 upload errors/sec for 2 minutes (Phase 1)
- **PDFParserErrorSpike**: > 5 PDF parsing errors/sec for 2 minutes (Phase 1)
- **WatermarkTamperingDetected**: > 2 watermark errors/sec for 3 minutes (Phase 1)
- **RMAPHandshakeFailures**: > 3 handshake failures/sec for 2 minutes (Phase 1)
- **FileProcessingErrors**: > 0.2 file errors/sec for 2 minutes (Phase 4)
- **WatermarkOperationFailures**: > 0.1 watermark failures/sec for 2 minutes (Phase 4)


## Dashboard Guide

### Security Overview Dashboard (`security_overview.json`)
- **Purpose**: High-level security monitoring at a glance
- **Key Panels**:
  - Security Events by Type: Shows distribution of security events
  - Login Failures by IP: Tracks failed authentication attempts
  - API Error Trends: Monitors API endpoint error patterns
- **Use Case**: Quick daily security status check

### Detailed Security Monitoring Dashboard (`tatou_detailed_security.json`)
- **Purpose**: Comprehensive security analysis and investigation
- **Key Panels**:
  - Security Events Overview: Summary statistics
  - Login Failures by IP Table: Detailed IP-level analysis
  - Security Events by Type Bar Gauge: Visual event distribution
  - API Error Rate Trends: Time-series error monitoring
  - File Processing Errors: Document processing issues
  - Watermark Operations: Watermarking activity tracking
  - Active Alerts Table: Real-time alert status
- **Use Case**: Incident investigation and detailed analysis

### API Monitoring Dashboard (`api_monitor.json`)
- **Purpose**: Focused API performance and reliability monitoring
- **Key Panels**:
  - API Request Rate: Overall API traffic patterns
  - API Error Rate: Error trends across endpoints
  - Endpoint Performance Table: Detailed endpoint metrics
- **Use Case**: API health monitoring and performance troubleshooting


## Access and Navigation

### Dashboard URLs
- **Grafana Main**: http://localhost:3000
- **Security Overview**: http://localhost:3000/d/security_overview
- **Detailed Security**: http://localhost:3000/d/tatou_detailed_security
- **API Monitor**: http://localhost:3000/d/tatou_api_monitor


### Default Credentials
- Username: `admin`
- Password: `admin`


## Operational Procedures

### Daily Checks
1. Verify all services are up: `docker compose ps`
2. Check Prometheus targets: http://localhost:9090/targets
3. Review active alerts: http://localhost:9090/alerts
4. Check Grafana dashboards for anomalies

### Incident Investigation Workflow
1. **Check Security Overview Dashboard** for immediate issues
2. **Drill down to Detailed Security Dashboard** for root cause analysis
3. **Use API Monitor Dashboard** if API-related issues are suspected
4. **Review application logs**: `docker compose logs server`
5. **Analyze metrics trends** in Prometheus for historical context
6. **Correlate events** across logs and metrics for complete picture

### Key Investigation Patterns

#### Suspicious Login Activity
1. Check "Login Failures by IP" in Detailed Security Dashboard
2. Review `user_login_failures_total` metric in Prometheus
3. Examine security logs for specific IP patterns

#### API Performance Issues
1. Monitor "API Error Rate" in API Monitor Dashboard
2. Check endpoint-specific errors in "Endpoint Performance" table
3. Review `api_errors_total` metrics by endpoint

#### File Processing Problems
1. View "File Processing Errors" in Detailed Security Dashboard
2. Check `file_processing_errors_total` metrics
3. Correlate with application error logs

### Maintenance Procedures

#### Routine Maintenance
- **Log rotation**: Daily, 7-day retention (automated)
- **Metrics retention**: 15 days in Prometheus (configured)
- **Dashboard updates**: As needed for new features or improved visualizations

#### Health Checks
```bash
# Verify monitoring stack is running
docker compose ps | grep -E "(prometheus|grafana|server)"

# Check metrics endpoint
curl -s http://localhost:5000/metrics | head -10

# Verify alert rules are loaded
curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[].name'
```


## Troubleshooting Common Issues

### Metrics Not Appearing

1. Check Prometheus targets: http://localhost:9090/targets
2. Verify application is exposing metrics: curl http://server:5000/metrics
3. Check Prometheus logs: docker compose logs prometheus

### Dashboards Not Loading

1. Verify Grafana datasource: http://localhost:3000/datasources
2. Check dashboard provisioning: docker compose logs grafana
3. Validate JSON syntax of dashboard files

### Alerts Not Triggering

1. Check rule evaluation: http://localhost:9090/rules
2. Verify metric names match alert rules
3. Check alertmanager configuration


## Integration with Logging System

The monitoring system works in tandem with the structured logging system:

· Metrics: Provide real-time numerical data for alerting
· Logs: Offer detailed context for metric anomalies
· Dashboards: Visualize both metric trends and log patterns

### Correlation Example

When security_events_total spikes:

1. Check Security Overview Dashboard for event types
2. Use Detailed Security Dashboard to identify patterns
3. Query application logs for detailed event context:
   ```bash
   grep "SECURITY" logs/app.log | jq '. | select(.event_type == "user_login_failure")'
   ```

This integrated approach provides comprehensive visibility into system security and performance.

