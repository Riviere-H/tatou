
"""
Structured JSON logging implementation for Tatou security monitoring.
Provides security, audit, and operational logging with JSON formatting.
"""
import logging
import logging.config
import json
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pathlib import Path

try:
    from pythonjsonlogger import jsonlogger
except ImportError:
    # Fallback to basic JSON formatting if library not available
    jsonlogger = None


# Prometheus metrics integration
from metrics import (
    PDF_PARSER_ERRORS,
    FILE_UPLOAD_ERRORS,
    FILE_WRITE_ERRORS,
    WATERMARK_PROCESSING_ERRORS,
    WATERMARK_READ_ERRORS,
    RMAP_HANDSHAKE_FAILS,
    DB_EXCEPTIONS,
    SECURITY_EVENTS,
    AUDIT_EVENTS,
    USER_LOGIN_FAILURES,
    API_ERRORS,
    FILE_PROCESSING_ERRORS,
    RATE_LIMIT_HITS,
    WATERMARK_OPERATIONS,
)


# Prometheus metrics integration
from metrics import (
    SECURITY_EVENTS, AUDIT_EVENTS, USER_LOGIN_FAILURES, 
    API_ERRORS, FILE_PROCESSING_ERRORS, RATE_LIMIT_HITS,
    WATERMARK_OPERATIONS
)


class SecurityLogger:
    """
    Centralized logging service for Tatou security and audit events.
    Implements structured JSON logging for security monitoring.
    """
    
    def __init__(self):
        self._setup_logging()
        self.security_logger = logging.getLogger("tatou.security")
        self.audit_logger = logging.getLogger("tatou.audit") 
        self.app_logger = logging.getLogger("tatou")

    def _setup_logging(self):
        """Initialize logging configuration from JSON file."""
        config_path = Path("/app/configs/logging.json")
        if config_path.exists():
            try:
                import json
                with open(config_path, 'r') as f:
                    config = json.load(f)
                logging.config.dictConfig(config)
            except Exception as e:
                # Fallback configuration
                self._setup_fallback_logging()
        else:
            self._setup_fallback_logging()
    
    def _setup_fallback_logging(self):
        """Fallback logging configuration if config file not available."""
        # Ensure logs directory exists
        Path("logs").mkdir(exist_ok=True)
        
        # Create formatters
        if jsonlogger:
            formatter = jsonlogger.JsonFormatter(
            '%(timestamp)s %(log_level)s %(event_type)s %(log_message)s %(log_details)s'
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        # File handler - security and audit logs
        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename="logs/app.log",
            when="midnight",
            interval=1,
            backupCount=7,
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        
        # Console handler - for development
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Configure loggers
        security_logger = logging.getLogger("tatou.security")
        security_logger.setLevel(logging.INFO)
        security_logger.addHandler(file_handler)
        security_logger.propagate = False
        
        audit_logger = logging.getLogger("tatou.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.addHandler(file_handler)
        audit_logger.propagate = False
        
        app_logger = logging.getLogger("tatou")
        app_logger.setLevel(logging.INFO)
        app_logger.addHandler(file_handler)
        app_logger.addHandler(console_handler)
        app_logger.propagate = False
    
    def _create_log_record(self, level: str, event_type: str, message: str, 
                          user_id: Optional[int] = None, login: Optional[str] = None,
                          client_ip: Optional[str] = None, 
                          details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a structured log record with security best practices.
        
        Args:
            level: Log level (INFO, ERROR, SECURITY, AUDIT)
            event_type: Type of event being logged
            message: Human-readable description
            user_id: Associated user ID
            login: User login name
            client_ip: Client IP address
            details: Additional structured data
            
        Returns:
            Dictionary containing structured log data
        """
        # Mask sensitive fields in details
        safe_details = self._mask_sensitive_data(details) if details else {}
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "log_level": level,
            "event_type": event_type,
            "user_id": user_id,
            "user_login": login,
            "client_ip": client_ip,
            "log_message": message,
            "log_details": safe_details
        }


    def _mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mask sensitive fields in log data to prevent exposure.
        
        Args:
            data: Dictionary potentially containing sensitive data
            
        Returns:
            Dictionary with sensitive fields masked
        """
        sensitive_fields = {'password', 'token', 'secret', 'key', 'authorization'}
        masked_data = data.copy()
        
        for field in sensitive_fields:
            if field in masked_data:
                masked_data[field] = "***"
        
        # Recursively check nested dictionaries
        for key, value in masked_data.items():
            if isinstance(value, dict):
                masked_data[key] = self._mask_sensitive_data(value)
        
        return masked_data
    
    def security_event(self, event_type: str, message: str, 
                      client_ip: Optional[str] = None,
                      user_id: Optional[int] = None,
                      login: Optional[str] = None,
                      details: Optional[Dict[str, Any]] = None):
        """
        Log security-related events requiring immediate attention.
        
        Args:
            event_type: Security event type
            message: Event description
            client_ip: Client IP address
            user_id: User ID if applicable
            login: User login if applicable
            details: Additional security context
        """
        log_record = self._create_log_record(
            level="SECURITY",
            event_type=event_type,
            message=message,
            user_id=user_id,
            login=login,
            client_ip=client_ip,
            details=details
        )
        # Increment error metrics
        if "api" in event_type or "endpoint" in str(details):
            API_ERRORS.labels(
                endpoint=details.get("endpoint", "unknown") if details else "unknown",
                method=details.get("method", "unknown") if details else "unknown"
            ).inc()
        elif "file" in event_type or "upload" in event_type:
            FILE_PROCESSING_ERRORS.labels(
                operation=event_type
            ).inc()

        # Increment audit metrics
        AUDIT_EVENTS.labels(event_type=event_type).inc()
        if "watermark" in event_type:
            WATERMARK_OPERATIONS.labels(
                operation=event_type, 
                method=details.get("method", "unknown") if details else "unknown"
            ).inc()

        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        # Increment error metrics
        if "api" in event_type or "endpoint" in str(details):
            API_ERRORS.labels(
                endpoint=details.get("endpoint", "unknown") if details else "unknown",
                method=details.get("method", "unknown") if details else "unknown"
            ).inc()
        elif "file" in event_type or "upload" in event_type:
            FILE_PROCESSING_ERRORS.labels(
                operation=event_type
            ).inc()

        # Increment audit metrics
        AUDIT_EVENTS.labels(event_type=event_type).inc()
        if "watermark" in event_type:
            WATERMARK_OPERATIONS.labels(
                operation=event_type, 
                method=details.get("method", "unknown") if details else "unknown"
            ).inc()

        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        
        if jsonlogger:
            self.security_logger.info("", extra=log_record)
        else:
            self.security_logger.info(
                f"[SECURITY] {event_type}: {message} - {json.dumps(log_record)}"
            )
    
    def audit_event(self, event_type: str, message: str,
                   user_id: Optional[int] = None,
                   login: Optional[str] = None,
                   details: Optional[Dict[str, Any]] = None):
        """
        Log audit events for compliance and tracking.
        
        Args:
            event_type: Audit event type
            message: Event description
            user_id: User ID
            login: User login
            details: Additional audit context
        """
        log_record = self._create_log_record(
            level="AUDIT",
            event_type=event_type,
            message=message,
            user_id=user_id,
            login=login,
            details=details
        )
        # Increment error metrics
        if "api" in event_type or "endpoint" in str(details):
            API_ERRORS.labels(
                endpoint=details.get("endpoint", "unknown") if details else "unknown",
                method=details.get("method", "unknown") if details else "unknown"
            ).inc()
        elif "file" in event_type or "upload" in event_type:
            FILE_PROCESSING_ERRORS.labels(
                operation=event_type
            ).inc()

        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        # Increment error metrics
        if "api" in event_type or "endpoint" in str(details):
            API_ERRORS.labels(
                endpoint=details.get("endpoint", "unknown") if details else "unknown",
                method=details.get("method", "unknown") if details else "unknown"
            ).inc()
        elif "file" in event_type or "upload" in event_type:
            FILE_PROCESSING_ERRORS.labels(
                operation=event_type
            ).inc()

        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        
        if jsonlogger:
            self.audit_logger.info("", extra=log_record)
        else:
            self.audit_logger.info(
                f"[AUDIT] {event_type}: {message} - {json.dumps(log_record)}"
            )
    
    def error_event(self, event_type: str, message: str,
                   user_id: Optional[int] = None,
                   details: Optional[Dict[str, Any]] = None):
        """
        Log error events for system monitoring.
        
        Args:
            event_type: Error event type
            message: Error description
            user_id: User ID if applicable
            details: Error context and details
        """
        log_record = self._create_log_record(
            level="ERROR",
            event_type=event_type,
            message=message,
            user_id=user_id,
            details=details
        )
        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        
        if jsonlogger:
            self.app_logger.error("", extra=log_record)
        else:
            self.app_logger.error(
                f"[ERROR] {event_type}: {message} - {json.dumps(log_record)}"
            )
    
    def info_event(self, event_type: str, message: str,
                  user_id: Optional[int] = None,
                  details: Optional[Dict[str, Any]] = None):
        """
        Log informational events for system operation tracking.
        
        Args:
            event_type: Info event type
            message: Event description
            user_id: User ID if applicable
            details: Additional context
        """
        log_record = self._create_log_record(
            level="INFO",
            event_type=event_type,
            message=message,
            user_id=user_id,
            details=details
        )
        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        # Increment security metrics
        SECURITY_EVENTS.labels(event_type=event_type).inc()
        if event_type == "user_login_failure":
            USER_LOGIN_FAILURES.labels(client_ip=client_ip).inc()

        
        if jsonlogger:
            self.app_logger.info("", extra=log_record)
        else:
            self.app_logger.info(
                f"[INFO] {event_type}: {message} - {json.dumps(log_record)}"
            )


# Global logger instance for easy import
logger = SecurityLogger()

# Convenience functions for common logging patterns
def log_security_event(event_type: str, message: str, **kwargs):
    """Convenience function for security events."""
    logger.security_event(event_type, message, **kwargs)

def log_audit_event(event_type: str, message: str, **kwargs):
    """Convenience function for audit events."""
    logger.audit_event(event_type, message, **kwargs)

def log_error_event(event_type: str, message: str, **kwargs):
    """Convenience function for error events."""
    logger.error_event(event_type, message, **kwargs)

def log_info_event(event_type: str, message: str, **kwargs):
    """Convenience function for info events."""
    logger.info_event(event_type, message, **kwargs)
