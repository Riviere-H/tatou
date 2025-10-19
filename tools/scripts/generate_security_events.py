"""
Generate security events to test metrics collection
"""
import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def test_security_metrics():
    """Generate various security events to trigger metrics"""
    
    print("Generating security events for metrics testing...")
    
    # 1. Failed login attempts (should trigger USER_LOGIN_FAILURES)
    for i in range(3):
        try:
            response = requests.post(
                f"{BASE_URL}/api/login",
                json={"email": f"nonexistent{i}@example.com", "password": "wrongpassword"}
            )
            print(f"Failed login {i+1}: {response.status_code}")
        except Exception as e:
            print(f"Login test error: {e}")
    
    # 2. API calls to trigger various metrics
    endpoints_to_test = [
        "/healthz",
        "/api/get-watermarking-methods", 
        "/api/list-documents"  # This should 401 without auth
    ]
    
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}")
            print(f"API call to {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"API test error: {e}")
    
    # 3. Test file upload (should trigger file processing metrics)
    try:
        # Create a minimal PDF file for testing
        with open('/tmp/test.pdf', 'wb') as f:
            f.write(b'%PDF-1.4 fake pdf content')
        
        files = {'file': open('/tmp/test.pdf', 'rb')}
        response = requests.post(f"{BASE_URL}/api/upload-document", files=files)
        print(f"File upload test: {response.status_code}")
    except Exception as e:
        print(f"File upload test error: {e}")
    
    print("Security events generation completed")

if __name__ == "__main__":
    test_security_metrics()
