import pytest
from pathlib import Path
from src.meta_svd_watermark import MetaSVDWatermark
from watermarking_method import SecretNotFoundError

@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    """PDF sample with valid page structure"""
    pdf = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"180\n"
        b"%%EOF\n"
    )
    pdf.write_bytes(pdf_content)
    return pdf

@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"

@pytest.fixture(scope="session")
def key() -> str:
    # This assumes we are using the auto-generated test keys
    return "unit-test-key"

def test_read_watermark_metadata_success(sample_pdf_path: Path, secret: str, key: str, tmp_path: Path):
    """
    Tests if read_watermark_metadata returns the correct dict structure
    for a successfully watermarked file.
    """
    wm_impl = MetaSVDWatermark()
    
    # 1. Generate a watermarked PDF
    out_pdf_bytes = wm_impl.add_watermark(sample_pdf_path, secret=secret, key=key)
    out_pdf = tmp_path / "metadata_test.pdf"
    out_pdf.write_bytes(out_pdf_bytes)
    
    # 2. Call the function we want to test
    metadata_dict = wm_impl.read_watermark_metadata(out_pdf, key=key)
    
    # 3. Assert that the results are correct
    assert isinstance(metadata_dict, dict)
    assert metadata_dict.get("provider") == "G21-MetaSVD"
    assert "encrypted_base64" in metadata_dict
    assert len(metadata_dict.get("encrypted_base64", "")) > 50 # Ensure it returns the full Base64 string
    assert metadata_dict.get("hint") is not None # Ensure the hint exists

def test_read_watermark_metadata_no_watermark(sample_pdf_path: Path, key: str):
    """
    Tests if read_watermark_metadata correctly raises 
    SecretNotFoundError when given a *clean* (non-watermarked) PDF.
    """
    wm_impl = MetaSVDWatermark()
    
    # 1. We use the *original* sample_pdf_path (which has no watermark)
    
    # 2. Assert that calling the function raises the expected error
    with pytest.raises(SecretNotFoundError, match="No watermark metadata found"):
        wm_impl.read_watermark_metadata(sample_pdf_path, key=key)