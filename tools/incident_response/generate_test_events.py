
"""
Generate test security events for monitoring system validation
"""
import requests
import json
import time
import random
from datetime import datetime

def test_failed_logins():
    """Simulate failed login attempts"""
    print(" Simulating failed login attempts...")
    for i in range(3):
        try:
            response = requests.post(
                "http://localhost:5000/api/login",
                json={
                    "email": f"testuser{i}@example.com",
                    "password": "wrongpassword123"
                },
                timeout=5
            )
            print(f"  Attempt {i+1}: HTTP {response.status_code}")
        except Exception as e:
            print(f"  Attempt {i+1}: Error - {e}")

def test_security_endpoints():
    """Test security-related endpoints"""
    endpoints = [
        "/healthz",
        "/api/get-watermarking-methods", 
        "/metrics"
    ]
    
    print(" Testing security endpoints...")
    for endpoint in endpoints:
        try:
            response = requests.get(f"http://localhost:5000{endpoint}", timeout=5)
            print(f"  {endpoint}: HTTP {response.status_code}")
        except Exception as e:
            print(f"  {endpoint}: Error - {e}")

def generate_log_events():
    """Generate sample log events through the application"""
    print(" Generating sample security log events...")
    
    # This would trigger log events through normal API usage
    try:
        # Get watermarking methods (should generate INFO log)
        response = requests.get("http://localhost:5000/api/get-watermarking-methods", timeout=5)
        print(f"  Watermark methods request: HTTP {response.status_code}")
        
        # Try to access non-existent endpoint (should generate ERROR log)
        response = requests.get("http://localhost:5000/api/non-existent", timeout=5)
        print(f"  Non-existent endpoint: HTTP {response.status_code}")
        
    except Exception as e:
        print(f"  Log generation error: {e}")

def main():
    print(" Generating Test Security Events")
    print("==================================")
    
    test_failed_logins()
    print("")
    test_security_endpoints() 
    print("")
    generate_log_events()
    
    print("\n Test events generated. Check:")
    print("  - Application logs: docker compose logs server | grep -i 'security\\|error'")
    print("  - Prometheus metrics: http://localhost:9090")
    print("  - Grafana dashboards: http://localhost:3000")

if __name__ == "__main__":
    main()
