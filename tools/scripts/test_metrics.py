#!/usr/bin/env python3
"""
Metrics Integration Test Script
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../server/src'))

try:
    from metrics import (
        PDF_PARSER_ERRORS,
        FILE_UPLOAD_ERRORS,
        FILE_WRITE_ERRORS,
        WATERMARK_PROCESSING_ERRORS,
        WATERMARK_READ_ERRORS,
        RMAP_HANDSHAKE_FAILS,
        DB_EXCEPTIONS,
        SECURITY_EVENTS,
    )

    # Test metrics can be incremented normally 
    test_metrics = [
        PDF_PARSER_ERRORS,
        FILE_UPLOAD_ERRORS, 
        FILE_WRITE_ERRORS,
        WATERMARK_PROCESSING_ERRORS,
        WATERMARK_READ_ERRORS,
        RMAP_HANDSHAKE_FAILS,
        DB_EXCEPTIONS,
        SECURITY_EVENTS,
    ]
    
    for metric in test_metrics:
        metric.inc()
        print(f" {metric._name} - be incremented normally!")

    print("\n All metrics integration tests passed!")
    
except Exception as e:
    print(f" Metrics test failed: {e}")
    sys.exit(1)
