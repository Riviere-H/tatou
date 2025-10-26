"""
Integration test for RMAP endpoints using the new v2.0.0 library.
This test should be run inside the Docker container.
"""

import sys
import os
import base64
import json
import pytest

# Add the src directory to path to import server modules
sys.path.insert(0, '/app/src')

try:
    from rmap.identity_manager import IdentityManager
    from rmap.rmap import RMAP
except ImportError as e:
    pytest.skip(f"RMAP v2.0.0 not available: {e}", allow_module_level=True)


def test_rmap_full_flow():
    """Test the complete RMAP handshake and PDF generation flow"""
    
    # Initialize IdentityManager with container paths
    keys_dir = '/app/keys'
    im = IdentityManager(
        client_keys_dir=os.path.join(keys_dir, 'clients'),
        server_public_key_path=os.path.join(keys_dir, 'server', 'server_pub.asc'),
        server_private_key_path=os.path.join(keys_dir, 'server', 'server_priv.asc'),
        server_private_key_passphrase=os.environ.get('GPG_PASSPHRASE', '')
    )
    
    # Initialize RMAP
    rmap = RMAP(im)
    
    # Step 1: Generate Message 1 using IdentityManagerj's encryption
    message1 = {'nonceClient': 123456789, 'identity': 'Group_21'}
    encrypted_msg1 = im.encrypt_for_server(message1)    

    # Test the initiate endpoint
    from server import app
    with app.test_client() as client:
        # Message 1
        response1 = client.post(
            '/api/rmap-initiate',
            json={'payload': encrypted_msg1}
        )
        
        assert response1.status_code == 200
        response1_data = response1.get_json()
        assert 'payload' in response1_data
        
        # Decrypt Response 1
        resp1_payload = im.decrypt_for_server(response1_data['payload'])
        nonce_server = resp1_payload['nonceServer']
        
        # Step 2: Generate Message 2
        message2 = {'nonceServer': nonce_server}
        encrypted_msg2 = im.encrypt_for_server(message2)
        
        # Message 2
        response2 = client.post(
            '/api/rmap-get-link',
            json={'payload': encrypted_msg2}
        )
        
        assert response2.status_code == 200
        response2_data = response2.get_json()
        
        # Verify we got a valid session secret
        assert 'result' in response2_data
        session_secret = response2_data['result']
        assert len(session_secret) == 32  # 32 hex characters
        
        # Verify we can download the PDF
        pdf_response = client.get(f'/api/get-version/{session_secret}')
        assert pdf_response.status_code == 200
        assert pdf_response.content_type == 'application/pdf'
        assert len(pdf_response.data) > 0


if __name__ == "__main__":
    test_rmap_full_flow()
    print("RMAP integration test passed!")
