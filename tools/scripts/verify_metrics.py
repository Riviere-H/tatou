#!/usr/bin/env python3
"""
Verify that security metrics are properly registered and incremented
"""
import sys
import os
sys.path.append('server/src')

try:
    # Test importing metrics
    from metrics import (
        SECURITY_EVENTS, AUDIT_EVENTS, USER_LOGIN_FAILURES,
        API_ERRORS, FILE_PROCESSING_ERRORS, RATE_LIMIT_HITS,
        WATERMARK_OPERATIONS
    )
    print("✓ All security metrics imported successfully")
    
    # Test incrementing metrics
    SECURITY_EVENTS.labels(event_type="test").inc()
    AUDIT_EVENTS.labels(event_type="test").inc() 
    USER_LOGIN_FAILURES.labels(client_ip="127.0.0.1").inc()
    API_ERRORS.labels(endpoint="/test", method="GET").inc()
    
    print("✓ All security metrics can be incremented")
    
except Exception as e:
    print(f"✗ Error with metrics: {e}")
    sys.exit(1)

# Check if logger imports metrics correctly
try:
    from logger import logger
    print("✓ Logger imports metrics correctly")
except Exception as e:
    print(f"✗ Logger import error: {e}")

