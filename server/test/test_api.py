"""
Extended API tests for Tatou server
Covering all major endpoints to meet test coverage requirements
"""

import pytest
import json
import io
import base64
import time
from server import app

class TestTatouAPI:
    """Comprehensive API test suite"""

    @pytest.fixture
    def client(self):
        """Create test client"""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    @pytest.fixture
    def auth_headers(self, client):
        """Create authenticated user and return auth headers"""
        # Create test user for each test run
        timestamp = int(time.time())
        user_data = {
            "login": f"testuser_{timestamp}",
            "email": f"test_{timestamp}@example.com", 
            "password": "TestPassword123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 201
        
        # Login to get token
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        response = client.post('/api/login', json=login_data)
        assert response.status_code == 200
        token = response.json['token']
        
        return {'Authorization': f'Bearer {token}'}
    
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get('/healthz')
        assert response.status_code == 200
        assert 'message' in response.json
        assert 'db_connected' in response.json
    
    def test_create_user(self, client):
        """Test user creation endpoint"""
        timestamp = int(time.time())
        user_data = {
            "login": f"newuser_{timestamp}",
            "email": f"newuser_{timestamp}@example.com",
            "password": "SecurePass123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 201
        assert 'id' in response.json
        assert response.json['email'] == user_data['email']
    
    def test_create_user_duplicate(self, client):
        """Test duplicate user creation"""
        timestamp = int(time.time())
        user_data = {
            "login": f"duplicateuser_{timestamp}",
            "email": f"duplicate_{timestamp}@example.com", 
            "password": "SecurePass123"
        }
        # First creation should succeed
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 201
        
        # Second creation should fail
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 409
    
    def test_login_success(self, client):
        """Test successful login"""
        # Create user first
        timestamp = int(time.time())
        user_data = {
            "login": f"loginuser_{timestamp}",
            "email": f"login_{timestamp}@example.com",
            "password": "LoginPass123"
        }
        client.post('/api/create-user', json=user_data)
        
        # Test login
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        response = client.post('/api/login', json=login_data)
        assert response.status_code == 200
        assert 'token' in response.json
        assert response.json['token_type'] == 'bearer'
    
    def test_login_failure(self, client):
        """Test failed login"""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }
        response = client.post('/api/login', json=login_data)
        assert response.status_code == 401
    
    def test_get_watermarking_methods(self, client):
        """Test getting available watermarking methods"""
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200
        assert 'methods' in response.json
        assert 'count' in response.json
        assert isinstance(response.json['methods'], list)
    
    def test_rmap_initiate_basic(self, client):
        """Test RMAP initiate with basic payload validation"""
        # Test with invalid payload
        response = client.post('/api/rmap-initiate', json={})
        assert response.status_code == 400
        
        # Test with missing payload field
        response = client.post('/api/rmap-initiate', json={"wrong_field": "data"})
        assert response.status_code == 400
    
    def test_upload_document_unauthorized(self, client):
        """Test document upload without authentication"""
        response = client.post('/api/upload-document')
        assert response.status_code == 401
    
    def test_protected_endpoints_require_auth(self, client):
        """Test that protected endpoints require authentication"""
        endpoints = [
            ('/api/list-documents', 'GET'),
            ('/api/upload-document', 'POST'),
            ('/api/list-all-versions', 'GET'),
        ]
        
        for endpoint, method in endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            else:
                response = client.post(endpoint)
            assert response.status_code == 401
    
    def test_invalid_json_payload(self, client):
        """Test handling of invalid JSON payloads"""
        response = client.post(
            '/api/create-user',
            data="invalid json",
            content_type='application/json'
        )
        assert response.status_code == 400


class TestWatermarkingMethods:
    """Tests for watermarking method functionality"""
    
    @pytest.fixture
    def sample_pdf(self):
        """Create a minimal PDF file for testing"""
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"
        )
        return io.BytesIO(pdf_content)
    
    def test_watermark_method_registry(self):
        """Test that watermarking methods are properly registered"""
        import watermarking_utils as wm_utils
        assert len(wm_utils.METHODS) > 0
        for method_name, method_instance in wm_utils.METHODS.items():
            assert hasattr(method_instance, 'add_watermark')
            assert hasattr(method_instance, 'read_secret')
            assert hasattr(method_instance, 'is_watermark_applicable')
    
    def test_phantom_annotation_watermark_specific(self, sample_pdf):
        """Test the specific phantom annotation watermark method"""
        from phantom_annotation_watermark import PhantomAnnotationWatermark
        watermarker = PhantomAnnotationWatermark()
        
        # Test method properties
        assert watermarker.name == "phantom-annotation-g21"
        assert "annotation" in watermarker.get_usage().lower()
        
        # Test applicability with valid PDF using the fixture
        assert watermarker.is_watermark_applicable(sample_pdf) == True

        # Also test with invalid content should return false
        invalid_content = b"Not a PDF file"
        assert watermarker.is_watermark_applicable(invalid_content) == False

# Add more test classes for specific functionality if needed
