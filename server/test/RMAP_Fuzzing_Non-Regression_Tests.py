import pytest
import requests
import json
import base64
import binascii

# API Server URL (Assumed to be running on http://localhost:5000)
API_URL = "http://localhost:5000/api"

# --- Malicious Test Data ---

# 1. Malformed Base64 string (Caused 500 Server Error due to binascii.Error)
# 'ABC@' contains invalid Base64 characters and padding.
# Tests the Base64 error trapping in rmap_get_link
MALFORMED_BASE64_PAYLOAD = {
    "payload": "ABC@RMAP_SECRET_BASE64_PLACEHOLDER" 
}

# 2. Bare JSON Primitive (Caused 500 Server Error due to failed dict access)
# The entire request Body is a number, not the expected dictionary.
BARE_NUMBER_BODY = "-15681"

# 3. Schema-Violating Payload Value (Caused 200 OK Logic Bypass)
# 'payload' key exists, but value is boolean (False), not the required string.
SCHEMA_VIOLATING_PAYLOAD = {
    "payload": False
}

# 4. Valid Base64 for basic checks (Can be skipped if running against real RMAP)
VALID_BASE64_PAYLOAD = {
    "payload": base64.b64encode(b"This is a non-encrypted PGP message").decode('utf-8')
}

# --- NON-REGRESSION TESTS ---

@pytest.mark.parametrize("endpoint", ["rmap-initiate", "rmap-get-link"])
def test_regression_top_level_primitive_rejection(endpoint):
    """
    Regression Test: Ensures the server rejects non-dictionary top-level JSON requests (e.g., bare numbers).
    (Fixes the 500 Server Error caused by bare number input)
    Expected: 400 Bad Request
    """
    url = f"{API_URL}/{endpoint}"
    
    # Send a bare number as Content-Type: application/json Body.
    # We expect our top-level JSON validation to catch this and return 400.
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, data=BARE_NUMBER_BODY, headers=headers)
    
    assert response.status_code == 400, (
        f"Endpoint {endpoint}: Expected status code 400 (Bad Request), but received {response.status_code}. Response: {response.text}"
    )
    # Check for the error message from our strict validation layer.
    assert "Invalid JSON payload. Expected a JSON object" in response.text, (
        f"Endpoint {endpoint}: Top-level JSON validation failed."
    )


@pytest.mark.parametrize("endpoint", ["rmap-initiate", "rmap-get-link"])
def test_regression_payload_type_check(endpoint):
    """
    Regression Test: Ensures the server rejects requests where the 'payload' field value is not a string (e.g., False).
    (Fixes the 200 OK False Positive logic bypass)
    Expected: 400 Bad Request
    """
    url = f"{API_URL}/{endpoint}"
    
    # Send a payload where the 'payload' key exists, but the value is boolean.
    response = requests.post(url, json=SCHEMA_VIOLATING_PAYLOAD)
    
    assert response.status_code == 400, (
        f"Endpoint {endpoint}: Expected status code 400 (Bad Request), but received {response.status_code}. Response: {response.text}"
    )
    # Check for the error message from our payload type check.
    assert "must be a string" in response.text, (
        f"Endpoint {endpoint}: Payload type check failed."
    )


def test_regression_malformed_base64_rejection():
    """
    Regression Test: Ensures the server correctly catches and rejects malicious Base64 data (e.g., padding/format errors).
    (Fixes the 500 Server Error caused by binascii.Error)
    Expected: 400 Bad Request
    """
    url = f"{API_URL}/rmap-get-link"
    
    # Send a payload that will cause binascii.b64decode to crash.
    response = requests.post(url, json=MALFORMED_BASE64_PAYLOAD)
    
    assert response.status_code == 400, (
        f"Expected status code 400 (Bad Request), but received {response.status_code}. Response: {response.text}"
    )
    # Check for the error message from our specialized Base64/RMAP error handler.
    assert "Invalid RMAP message format or content" in response.text, (
        "Base64 error was not correctly caught, or returned the wrong message."
    )

# --- Sanity Check (Optional) ---

@pytest.mark.skip(reason="Requires a valid PGP setup to truly succeed; only tests basic structure in mock mode.")
def test_rmap_initiate_basic_structure():
    """
    Sanity Check: Ensures the service handles a valid-looking Base64 string correctly 
    (in test mode, this should return 200 OK with a mock result).
    """
    url = f"{API_URL}/rmap-initiate"
    response = requests.post(url, json=VALID_BASE64_PAYLOAD)
    
    # In test/mock mode, this should return 200 OK with the mock result
    assert response.status_code == 200
    assert "result" in response.json()