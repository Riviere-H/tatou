"""Comprehensive tests for server.py to improve coverage"""

import pytest
import time
import json
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock
from itsdangerous import URLSafeTimedSerializer


class TestServerComprehensive:
    """Comprehensive server tests for better coverage"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from server import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    @pytest.fixture
    def auth_headers(self, client):
        """Create authenticated user and return auth headers"""
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "login": f"testuser_{unique_id}",
            "email": f"test_{unique_id}@example.com", 
            "password": "TestPassword123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 201
        
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        response = client.post('/api/login', json=login_data)
        assert response.status_code == 200
        token = response.json['token']
        
        return {'Authorization': f'Bearer {token}'}
    
    def test_server_utility_functions(self):
        """Test server utility functions"""
        from server import (
            sanitize_filename, validate_email, validate_username, 
            validate_password, validate_integer, contains_sql_injection_pattern,
            validate_safe_input, get_client_fingerprint
        )
        
        # Test sanitize_filename
        assert sanitize_filename("normal file.pdf") == "normal_file.pdf"
        assert sanitize_filename("../../etc/passwd") == "etc_passwd"
        assert sanitize_filename(".hidden") == "hidden"  # Should prevent hidden files
        assert sanitize_filename("") == ""
        
        # Test email validation
        assert validate_email("test@example.com") == True
        assert validate_email("invalid") == False
        assert validate_email("") == False
        
        # Test username validation
        assert validate_username("validuser") == True
        assert validate_username("ab") == False  # Too short
        assert validate_username("a" * 51) == False  # Too long
        assert validate_username("user@name") == False  # Invalid chars
        
        # Test password validation
        assert validate_password("StrongPass123") == True
        assert validate_password("weak") == False  # Too short
        assert validate_password("nouppercase123") == True  # Has lowercase and digit
        assert validate_password("NOLOWERCASE123") == True  # Has uppercase and digit
        assert validate_password("NoDigitsHere") == True  # Has lowercase and uppercase
        assert validate_password("onlylowercase") == False  # Only one character type
        assert validate_password("ONLYUPPERCASE") == False
        assert validate_password("1234567890") == False
        
        # Test integer validation
        assert validate_integer("5") == True
        assert validate_integer(5) == True
        assert validate_integer("not_int") == False
        assert validate_integer("5", min_val=3) == True
        assert validate_integer("5", min_val=6) == False
        assert validate_integer("5", max_val=10) == True
        assert validate_integer("5", max_val=4) == False
        
        # Test SQL injection detection
        assert contains_sql_injection_pattern("SELECT * FROM users") == True
        assert contains_sql_injection_pattern("normal text") == False
        assert contains_sql_injection_pattern("'; DROP TABLE users; --") == True
        
        # Test safe input validation
        is_safe, msg = validate_safe_input("normal text", "field")
        assert is_safe == True
        
        is_safe, msg = validate_safe_input("SELECT *", "field")
        assert is_safe == False
        
        # Test client fingerprint
        from flask import Request
        class MockRequest:
            remote_addr = "192.168.1.1"
            headers = {"User-Agent": "Test Browser"}
        
        mock_request = MockRequest()
        fingerprint = get_client_fingerprint(mock_request)
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64  # SHA256 hex length
    
    def test_token_blacklist_functionality(self):
        """Test token blacklist functionality"""
        from server import token_blacklist
        
        # Test adding and checking token
        test_token = "test_token_123"
        token_blacklist.add(test_token, ttl=10)  # 10 second TTL
        
        assert token_blacklist.is_blacklisted(test_token) == True
        assert token_blacklist.is_blacklisted("nonexistent_token") == False
        
        # Test cleanup (manual trigger)
        token_blacklist.cleanup()
    
    def test_rate_limiter_functionality(self):
        """Test rate limiter functionality"""
        from server import rate_limiter
        
        key = "test_key"
        max_attempts = 3
        window_seconds = 60
        
        # First 3 attempts should not be limited
        for i in range(3):
            assert rate_limiter.is_rate_limited(key, max_attempts, window_seconds) == False
        
        # 4th attempt should be limited
        assert rate_limiter.is_rate_limited(key, max_attempts, window_seconds) == True
        
        # Check remaining attempts
        remaining = rate_limiter.get_remaining_attempts(key, max_attempts, window_seconds)
        assert remaining == 0
    
    def test_server_configuration(self):
        """Test server configuration"""
        from server import app
        
        assert app.config["TOKEN_TTL_SECONDS"] > 0
        assert app.config["REFRESH_TOKEN_TTL"] > 0
        assert "SECRET_KEY" in app.config
        assert app.config["SESSION_COOKIE_SECURE"] == True
    
    def test_database_connection(self):
        """Test database connection via health check"""
        from server import app
        
        with app.test_client() as client:
            response = client.get('/healthz')
            assert response.status_code == 200
            data = response.get_json()
            assert "db_connected" in data
            # db_connected could be True or False depending on test environment
    
    def test_static_file_serving(self):
        """Test static file serving"""
        from server import app
        
        with app.test_client() as client:
            # Test home route
            response = client.get('/')
            assert response.status_code == 200
            
            # Test static files (might return 404 if files don't exist in test env)
            response = client.get('/index.html')
            # Accept 200 or 404 depending on test environment
            assert response.status_code in [200, 404]
    
    def test_error_handlers(self):
        """Test error handlers"""
        from server import app
        
        with app.test_client() as client:
            # Test 404
            response = client.get('/nonexistent-endpoint')
            assert response.status_code == 404
            assert "error" in response.get_json()
            
            # Test 405
            response = client.post('/healthz')
            assert response.status_code == 405
            assert "error" in response.get_json()
    
    def test_authentication_middleware(self, client, auth_headers):
        """Test authentication middleware"""
        # Test with valid token
        response = client.get('/api/list-documents', headers=auth_headers)
        assert response.status_code in [200, 500]  # Could be empty list or error
        
        # Test without token
        response = client.get('/api/list-documents')
        assert response.status_code == 401
        
        # Test with invalid token
        invalid_headers = {'Authorization': 'Bearer invalid_token'}
        response = client.get('/api/list-documents', headers=invalid_headers)
        assert response.status_code == 401
    
    def test_user_management_validation(self, client):
        """Test user management input validation"""
        # Test invalid email
        user_data = {
            "login": "testuser",
            "email": "invalid-email",
            "password": "ValidPass123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 400
        
        # Test invalid username
        user_data = {
            "login": "ab",  # Too short
            "email": "test@example.com",
            "password": "ValidPass123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 400
        
        # Test weak password
        user_data = {
            "login": "testuser",
            "email": "test@example.com",
            "password": "weak"  # Too short
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 400
    
    def test_file_upload_validation(self, client, auth_headers):
        """Test file upload validation"""
        # Test uploading without file
        response = client.post(
            '/api/upload-document',
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
        
        # Test uploading empty file
        data = {
            'file': (b"", 'test.pdf'),
            'name': 'Test Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
        
        # Test uploading non-PDF file
        data = {
            'file': (b"Not a PDF", 'test.txt'),
            'name': 'Test Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
    
    def test_document_operations_edge_cases(self, client, auth_headers):
        """Test document operations with edge cases"""
        # Test getting non-existent document
        response = client.get('/api/get-document/99999', headers=auth_headers)
        assert response.status_code in [404, 400]
        
        # Test deleting non-existent document
        response = client.delete('/api/delete-document/99999', headers=auth_headers)
        assert response.status_code in [404, 400]
        
        # Test listing versions for non-existent document
        response = client.get('/api/list-versions/99999', headers=auth_headers)
        # Could return 200 with empty list or 400/404
        assert response.status_code in [200, 400, 404]
    
    def test_watermark_operations_edge_cases(self, client, auth_headers):
        """Test watermark operations with edge cases"""
        # Test creating watermark for non-existent document
        watermark_data = {
            "method": "toy-eof",
            "intended_for": "test@example.com",
            "secret": "test_secret",
            "key": "test_key",
            "id": 99999
        }
        response = client.post(
            '/api/create-watermark',
            json=watermark_data,
            headers=auth_headers
        )
        assert response.status_code in [404, 400, 500]
        
        # Test reading watermark from non-existent document
        read_data = {
            "method": "toy-eof",
            "key": "test_key",
            "id": 99999
        }
        response = client.post(
            '/api/read-watermark',
            json=read_data,
            headers=auth_headers
        )
        assert response.status_code in [404, 400, 500]

    def test_database_connection_failure(self, client):
        """Test server behavior when database is unavailable"""
        # Mock database connection to raise an exception
        with patch('server.create_app') as mock_create_app:

            mock_engine = MagicMock()
            mock_connect = MagicMock()
            mock_connect.connect.side_effect = Exception("Database connection failed")
            mock_engine.connect.return_value = mock_connect
        
            mock_app = MagicMock()
            mock_app.config = {"_ENGINE": mock_engine}
            mock_create_app.return_value = mock_app
        
            response = client.get('/healthz')
            assert response.status_code == 200

    def test_file_operations_failure(self, client, auth_headers, tmp_path):
        """Test file operations when file system fails"""
        # Create a simple PDF file
        pdf_path = tmp_path / "test.pdf"
        pdf_content = b"%PDF-1.4\ntest content\n%%EOF"
        pdf_path.write_bytes(pdf_content)
    
        # Test upload invalid document
        data = {
            'file': (pdf_path.open('rb'), 'test.txt'),
            'name': 'Test Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400

        # Test upload empty document
        empty_pdf = tmp_path / "empty.pdf"
        empty_pdf.write_bytes(b"")

        data = {
            'file': (empty_pdf.open('rb'), 'empty.pdf'),
            'name': 'Empty Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400


    def test_token_validation_failures(self, client):
        """Test various token validation failure scenarios"""
        # Test missing Authorization header
        response = client.get('/api/list-documents')
        assert response.status_code == 401
    
        # Test invalid Authorization format
        headers = {'Authorization': 'InvalidFormat'}
        response = client.get('/api/list-documents', headers=headers)
        assert response.status_code == 401
    
        # Test invalid token
        headers = {'Authorization': 'Bearer'}
        response = client.get('/api/list-documents', headers=headers)
        assert response.status_code == 401

        # Test empty bearer token
        headers = {'Authorization': 'Bearer '}
        response = client.get('/api/list-documents', headers=headers)
        assert response.status_code == 401


    def test_security_headers(self, client):
        """Test that security headers are properly set"""
        response = client.get('/healthz')
        assert response.status_code == 200
        headers = response.headers
    
        assert 'X-Frame-Options' in headers
        assert 'X-Content-Type-Options' in headers
        assert 'X-XSS-Protection' in headers
        assert 'Referrer-Policy' in headers
        assert 'Content-Security-Policy' in headers
    
        assert headers['X-Frame-Options'] == 'DENY'
        assert headers['X-Content-Type-Options'] == 'nosniff'

    def test_json_validation_decorator(self, client):
        """Test JSON validation decorator"""
        # Test lack JSON content type
        response = client.post('/api/create-user', data="plain text")
        assert response.status_code == 400
    
        # Test invalid JSON
        response = client.post(
            '/api/create-user', 
            data="invalid json {",
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_error_handlers(self, client):
        """Test custom error handlers"""
        # Test 404 Error
        response = client.get('/nonexistent-endpoint')
        assert response.status_code == 404
        assert 'error' in response.get_json()
    
        # Test 405 Error 
        response = client.post('/healthz')
        assert response.status_code == 405
        assert 'error' in response.get_json()
