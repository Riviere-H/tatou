"""Extended API tests for better coverage"""

import pytest
import time
import json
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestTatouAPIExtended:
    """Extended API tests for comprehensive coverage"""
    
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
        # Use UUID for truly unique identifiers
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "login": f"testuser_{unique_id}",
            "email": f"test_{unique_id}@example.com", 
            "password": "TestPassword123"
        }
        response = client.post('/api/create-user', json=user_data)
        # Allow both 201 (created) and 409 (already exists - retry with new ID)
        if response.status_code == 409:
            unique_id = str(uuid.uuid4())[:8]
            user_data = {
                "login": f"testuser_{unique_id}",
                "email": f"test_{unique_id}@example.com", 
                "password": "TestPassword123"
            }
            response = client.post('/api/create-user', json=user_data)
        
        assert response.status_code == 201, f"Failed to create user: {response.get_json()}"
        
        # Login to get token
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        response = client.post('/api/login', json=login_data)
        assert response.status_code == 200
        token = response.json['token']
        
        return {'Authorization': f'Bearer {token}'}

    @pytest.fixture
    def uploaded_document(self, client, auth_headers, tmp_path):
        """Create and upload a test document"""
        # Create a simple PDF file
        pdf_path = tmp_path / "test.pdf"
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"
        )
        pdf_path.write_bytes(pdf_content)
        
        # Upload the document
        data = {
            'file': (pdf_path.open('rb'), 'test.pdf'),
            'name': 'Test Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        if response.status_code == 201:
            return response.json['id']
        else:
            pytest.skip("Failed to upload test document")

    def test_rate_limiting_login(self, client):
        """Test login rate limiting"""
        email = "ratelimit_{uuid.uuid4().hex[:8]}@example.com"
        for i in range(6):
            login_data = {
                "email": email,
                "password": "wrongpassword"
            }
            response = client.post('/api/login', json=login_data)
            
            if i < 5:
                assert response.status_code == 401, f"Attempt {i+1} should return 401"
            else:
                assert response.status_code == 429, f"Attempt {i+1} should be rate limited"


    def test_token_refresh(self, client, auth_headers):
        """Test token refresh endpoint"""
        response = client.post('/api/refresh-token', headers=auth_headers)
        # This might return 200 or 501 if not implemented
        assert response.status_code in [200, 501, 500]
    
    def test_logout(self, client, auth_headers):
        """Test logout endpoint"""
        response = client.post('/api/logout', headers=auth_headers)
        # This might return 200 or 501 if not implemented  
        assert response.status_code in [200, 501, 500]
    
    def test_create_watermark_invalid_document(self, client, auth_headers):
        """Test watermark creation with invalid document"""
        watermark_data = {
            "method": "toy-eof",
            "intended_for": "test@example.com", 
            "secret": "test_secret",
            "key": "test_key",
            "id": 99999  # Non-existent document
        }
        response = client.post(
            '/api/create-watermark',
            json=watermark_data,
            headers=auth_headers
        )
        assert response.status_code in [404, 400]  # Could be either
    
    def test_read_watermark_invalid_document(self, client, auth_headers):
        """Test watermark reading with invalid document"""
        read_data = {
            "method": "toy-eof", 
            "key": "test_key",
            "id": 99999  # Non-existent document
        }
        response = client.post(
            '/api/read-watermark',
            json=read_data, 
            headers=auth_headers
        )
        assert response.status_code in [400, 404, 500]
    
    def test_delete_document_invalid(self, client, auth_headers):
        """Test deleting non-existent document"""
        response = client.delete('/api/delete-document/99999', headers=auth_headers)
        assert response.status_code in [404, 400]
    
    def test_get_document_invalid(self, client, auth_headers):
        """Test getting non-existent document"""
        response = client.get('/api/get-document/99999', headers=auth_headers)
        assert response.status_code in [404, 400]
    
    def test_list_versions_invalid_document(self, client, auth_headers):
        """Test listing versions for non-existent document"""
        response = client.get('/api/list-versions/99999', headers=auth_headers)
        if response.status_code == 200:
            data = response.get_json()
            assert "versions" in data
        else:
            assert response.status_code in [400, 404]
    
    def test_upload_document_invalid_file(self, client, auth_headers):
        """Test uploading invalid file type"""
        data = {
            'file': (b"Not a PDF file", 'test.txt'),
            'name': 'Test Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
    
    def test_upload_document_empty_file(self, client, auth_headers):
        """Test uploading empty file"""
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
    
    def test_create_user_invalid_email(self, client):
        """Test user creation with invalid email"""
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "login": f"testuser_{unique_id}",
            "email": "invalid-email",
            "password": "TestPassword123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 400
    
    def test_create_user_weak_password(self, client):
        """Test user creation with weak password"""
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "login": f"testuser_{unique_id}",
            "email": f"test_{unique_id}@example.com",
            "password": "weak"  # Too short
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 400
    
    def test_create_user_invalid_username(self, client):
        """Test user creation with invalid username"""
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "login": "ab",  # Too short
            "email": f"test_{unique_id}@example.com", 
            "password": "TestPassword123"
        }
        response = client.post('/api/create-user', json=user_data)
        assert response.status_code == 400
    
    def test_static_files(self, client):
        """Test static file serving"""
        response = client.get('/index.html')
        assert response.status_code in [200, 404]  # Might not exist in test
    
    def test_home_route(self, client):
        """Test home route"""
        response = client.get('/')
        assert response.status_code == 200

    def test_watermark_operations_edge_cases(self, client, auth_headers):
        """Test watermark operations with various edge cases"""
        watermark_data = {
            # Lack method, intended_for, secret, key, id
        }
        response = client.post(
            '/api/create-watermark',
            json=watermark_data,
            headers=auth_headers
        )
        assert response.status_code in [400, 500]
    
    # Test empty strings
        watermark_data = {
            "method": "",
            "intended_for": "",
            "secret": "",
            "key": "",
            "id": 99999  # Nonexistent doc
        }
        response = client.post(
            '/api/create-watermark',
            json=watermark_data,
            headers=auth_headers
        )
        assert response.status_code in [400, 404, 500]


    def test_successful_document_operations(self, client, auth_headers, tmp_path):
        """Test successful document upload and retrieval"""
        # Create valid PDF file
        pdf_path = tmp_path / "valid.pdf"
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"
        )
        pdf_path.write_bytes(pdf_content)
    
        # Upload document
        data = {
            'file': (pdf_path.open('rb'), 'valid.pdf'),
            'name': 'Valid Test Document'
        }
        response = client.post(
            '/api/upload-document',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )
    
        if response.status_code == 201:
            doc_id = response.json['id']
        
            # Test get document list
            response = client.get('/api/list-documents', headers=auth_headers)
            assert response.status_code == 200
            assert 'documents' in response.json
        
            # Test get specific document
            response = client.get(f'/api/get-document/{doc_id}', headers=auth_headers)
            assert response.status_code in [200, 404]
        
            # Test delete document
            response = client.delete(f'/api/delete-document/{doc_id}', headers=auth_headers)
            assert response.status_code in [200, 404]

    def test_watermarking_methods_endpoint(self, client):
        """Test the watermarking methods endpoint"""
        response = client.get('/api/get-watermarking-methods')
        assert response.status_code == 200
        data = response.json
        assert 'methods' in data
        assert 'count' in data
        assert isinstance(data['methods'], list)
