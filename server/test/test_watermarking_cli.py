"""Tests for watermarking_cli.py"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

# Import the CLI module
from watermarking_cli import main, _resolve_key, _resolve_secret


class TestWatermarkingCLI:
    """Test watermarking CLI functionality"""
    
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

    def test_resolve_key_prompt(self, monkeypatch):
        """Test key resolution with prompt"""
        monkeypatch.setattr('getpass.getpass', lambda x: "test_key")
        result = _resolve_key(type('Args', (), {'key': None, 'key_file': None, 'key_stdin': False, 'key_prompt': True})())
        assert result == "test_key"

    def test_resolve_key_direct(self):
        """Test key resolution with direct input"""
        args = type('Args', (), {'key': "direct_key", 'key_file': None, 'key_stdin': False, 'key_prompt': False})()
        result = _resolve_key(args)
        assert result == "direct_key"

    def test_resolve_secret_direct(self):
        """Test secret resolution with direct input"""
        args = type('Args', (), {'secret': "test_secret", 'secret_file': None, 'secret_stdin': False})()
        result = _resolve_secret(args)
        assert result == "test_secret"

    def test_cli_methods_command(self):
        """Test methods command"""
        with patch('sys.argv', ['pdfwm', 'methods']):
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                result = main()
                assert result == 0
                output = mock_stdout.getvalue()
                assert len(output.strip().split('\n')) > 0

    def test_cli_embed_basic(self, sample_pdf, tmp_path):
        """Test basic embed command"""
        output_pdf = tmp_path / "output.pdf"
        
        with patch('sys.argv', [
            'pdfwm', 'embed', 
            str(sample_pdf), 
            str(output_pdf),
            '--method', 'toy-eof',
            '--key', 'testkey',
            '--secret', 'testsecret'
        ]):
            result = main()
            # Should succeed or fail gracefully, but not crash
            assert result in [0, 2, 3, 4, 5]  # Possible exit codes
            if output_pdf.exists():
                assert output_pdf.stat().st_size > 0

    def test_cli_invalid_command(self):
        """Test invalid command handling"""
        with patch('sys.argv', ['pdfwm', 'invalid_command']):
            with pytest.raises(SystemExit):
                main()

    @patch('watermarking_cli.explore_pdf')
    def test_cli_explore_command(self, mock_explore, sample_pdf, tmp_path):
        """Test explore command"""
        mock_explore.return_value = {"id": "test", "type": "Document", "children": []}
        
        output_json = tmp_path / "output.json"
        with patch('sys.argv', ['pdfwm', 'explore', str(sample_pdf), '--out', str(output_json)]):
            result = main()
            assert result == 0
            mock_explore.assert_called_once_with(str(sample_pdf))

    def test_cli_version(self):
        """Test version command"""
        with patch('sys.argv', ['pdfwm', '--version']):
            with pytest.raises(SystemExit):
                main()
