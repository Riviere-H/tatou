"""Tests for watermarking_utils.py"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestWatermarkingUtils:
    """Test watermarking utilities"""
    
    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF file for testing"""
        pdf_path = tmp_path / "sample.pdf"
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"
        )
        pdf_path.write_bytes(pdf_content)
        return pdf_path

    def test_explore_pdf_basic(self, sample_pdf):
        """Test basic PDF exploration"""
        from watermarking_utils import explore_pdf
        
        result = explore_pdf(sample_pdf)
        assert "id" in result
        assert "type" in result
        assert result["type"] == "Document"
        assert "children" in result

    def test_get_method_existing(self):
        """Test getting existing method"""
        from watermarking_utils import get_method, METHODS
        
        if METHODS:
            method_name = list(METHODS.keys())[0]
            method = get_method(method_name)
            assert method is not None

    def test_get_method_nonexistent(self):
        """Test getting nonexistent method"""
        from watermarking_utils import get_method
        
        with pytest.raises(KeyError):
            get_method("nonexistent_method")

    def test_register_method(self):
        """Test method registration"""
        from watermarking_utils import register_method, METHODS, get_method
        
        # Create a mock method
        class MockMethod:
            name = "test-method"
            
            def get_usage(self):
                return "Test method"
            
            def add_watermark(self, pdf, secret, key, position=None):
                return b"watermarked"
            
            def read_secret(self, pdf, key):
                return "secret"
            
            def is_watermark_applicable(self, pdf, position=None):
                return True
        
        original_count = len(METHODS)
        mock_method = MockMethod()
        
        # Register the method
        register_method(mock_method)
        assert len(METHODS) == original_count + 1
        assert "test-method" in METHODS
        
        # Clean up
        del METHODS["test-method"]

    def test_apply_watermark_basic(self, sample_pdf):
        """Test basic watermark application"""
        from watermarking_utils import apply_watermark, METHODS
        
        if "toy-eof" in METHODS:
            result = apply_watermark(
                method="toy-eof",
                pdf=sample_pdf,
                secret="test_secret", 
                key="test_key"
            )
            assert isinstance(result, bytes)
            assert len(result) > 0

    def test_read_watermark_basic(self, sample_pdf):
        """Test basic watermark reading"""
        from watermarking_utils import read_watermark, apply_watermark, METHODS
        
        if "toy-eof" in METHODS:
            # First apply watermark
            watermarked = apply_watermark(
                method="toy-eof",
                pdf=sample_pdf,
                secret="test_secret",
                key="test_key"
            )
            
            # Save to temp file to read
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
                f.write(watermarked)
                temp_path = f.name
            
            try:
                # Try to read the watermark
                secret = read_watermark(
                    method="toy-eof",
                    pdf=temp_path,
                    key="test_key"
                )
                assert secret == "test_secret"
            finally:
                Path(temp_path).unlink(missing_ok=True)
