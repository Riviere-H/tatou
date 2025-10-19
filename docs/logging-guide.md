
# Tatou Structured Logging Guide

## 1. Overview


This document defines the structured logging standards for Tatou PDF watermarking platform. All application logs must follow this specification to ensure consistency, security, and auditability.

## 2. Log Format

All logs must use JSON format with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| timestamp | string | Yes | ISO 8601 format with timezone: `YYYY-MM-DDTHH:MM:SS.sssZ` |
| level | string | Yes | Log level: `INFO`, `ERROR`, `SECURITY`, `AUDIT` |
| event_type | string | Yes | Event category (see below) |
| user_id | integer | No | Associated user ID (if applicable) |
| login | string | No | User login name (if applicable) |
| client_ip | string | No | Client IP address (for security events) |
| message | string | Yes | Human-readable description of event |
| details | object | No | Additional structured data for event |

## 3. Log Levels

### 3.1 INFO
Regular application operation information. Examples:
- Application startup and shutdown
- User registration
- File upload and processing

### 3.2 ERROR
Unexpected errors and exceptions requiring investigation. Examples:
- Database connection errors
- File processing failures
- External service errors

### 3.3 SECURITY
Security-related events requiring immediate attention. Examples:
- Failed login attempts
- Suspicious API usage
- Authentication failures
- Access denied events

### 3.4 AUDIT
Critical business operations for compliance and tracking. Examples:
- User login and logout
- Sensitive data access
- Document watermark operations
- User account changes

## 4. Event Types

### 4.1 Authentication Events
- `user_login_success` - User authentication successful
- `user_login_failure` - Login attempt failed
- `user_logout` - User logged out
- `token_validation_failure` - JWT token validation failed

### 4.2 User Management Events
- `user_registration` - New user account created
- `password_change` - User changed password
- `account_lockout` - User account locked due to multiple failures

### 4.3 Document Operations
- `document_upload` - PDF document uploaded
- `document_download` - Document downloaded by owner
- `document_deletion` - Document deleted
- `watermark_creation` - Watermarked version created
- `watermark_read` - Watermark read from document

### 4.4 System Operations
- `api_call` - API endpoint called (critical endpoints)
- `database_error` - Database operation failed
- `file_processing_error` - File processing error

## 5. Security and Privacy

### 5.1 Data Masking
The following fields must be masked in logs:

| Field | Masking Rule |
|-------|--------------|
| password | Replace with `***` |
| token | Replace with `***` |
| secret | Replace with `***` |
| key | Replace with `***` (if contains sensitive material) |

### 5.2 Personal Identifiable Information (PII)
Avoid logging PII unless absolutely necessary for auditing. If PII is logged, ensure it is protected and log access is restricted.

## 6. Log Configuration

### 6.1 Log Storage
- Log files stored in `/logs/app.log`
- Logs rotated daily, retained for 7 days
- Maximum log file size: 100MB

### 6.2 Environment Log Levels
- Production: `INFO` and above
- Development: `DEBUG` and above

## 7. Examples

### 7.1 Security Event (Failed Login)
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "SECURITY",
  "event_type": "user_login_failure",
  "client_ip": "192.168.1.100",
  "message": "Failed login attempt for email: user@example.com",
  "details": {
    "email": "user@example.com",
    "reason": "invalid_password"
  }
}
```

7.2 Audit Event (Document Upload)

```json
{
  "timestamp": "2024-01-15T10:35:00.000Z",
  "level": "AUDIT",
  "event_type": "document_upload",
  "user_id": 123,
  "login": "alice",
  "message": "Document uploaded successfully",
  "details": {
    "document_id": 456,
    "file_name": "contract.pdf",
    "file_size": 1024000
  }
}
```

7.3 Error Event (Database Error)

```json
{
  "timestamp": "2024-01-15T10:40:00.000Z",
  "level": "ERROR",
  "event_type": "database_error",
  "message": "Database connection failed",
  "details": {
    "operation": "user_authentication",
    "error": "Connection timeout"
  }
}
```

## 8. Validation and Monitoring

### 8.1 Log Validation
Check log quality using the provided analysis tools:
```bash
python tools/scripts/log_analyzer.py
```

8.2 Key Metric Monitoring
· Security Incident Rate: Number of SECURITY-level logs
· Error Rate: Number of ERROR-level logs
· User Activity: Number of AUDIT-level logs
