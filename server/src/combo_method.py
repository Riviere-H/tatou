import json
from typing import Final, Optional, Dict, Any

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    WatermarkingError
)

from phantom_annotation_watermark import PhantomAnnotationWatermark
from meta_svd_watermark import MetaSVDWatermark
from PyPDF2 import PdfReader, PdfWriter
import io

class ComboWatermark(WatermarkingMethod):
    """
    Combo watermark method (by Group 21). Combines phantom annotation watermark and metadata+SVD method.
    Embeds same encrypted payload into both annotation and image metadata.
    """
    name: Final[str] = "group21-combo"
    SIGNATURE: Final[str] = "G21-Combo"

    def __init__(self):
        self.phantom = PhantomAnnotationWatermark()
        self.meta_svd = MetaSVDWatermark()

    def get_usage(self) -> str:
        return (
            "Group21 combo method combining phantom annotation + metadata+SVD. "
            "Embeds the same encrypted payload into both invisible annotations and image metadata. "
            "Supports client tracking and PGP encryption."
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
        client_identity: Optional[str] = None,
        **kwargs
    ) -> bytes:
        """
        Embed watermark using both phantom and metadata+SVD.
        """
        if not secret or not key:
            raise ValueError("Secret and key are required")

        # First apply Phantom watermark
        phantom_pdf_bytes = self.phantom.add_watermark(
            pdf=pdf,
            secret=secret,
            key=key,
            position=position,
            client_identity=client_identity
        )

        # Then apply MetaSVD on Phantom result
        combined_pdf_bytes = self.meta_svd.add_watermark(
            pdf=phantom_pdf_bytes,
            secret=secret,
            key=key,
            client_identity=client_identity
        )

        return combined_pdf_bytes

    def read_secret(self, pdf: PdfSource, key: str, **kwargs) -> str:
        """
        Try to extract watermark from Phantom first, fallback to MetaSVD.
        """
        try:
            return self.phantom.read_secret(pdf, key)
        except SecretNotFoundError:
            return self.meta_svd.read_secret(pdf, key)

    def read_watermark_metadata(self, pdf: PdfSource, key: str) -> Dict[str, Any]:
        """
        Extract metadata from Phantom or MetaSVD watermark.
        """
        try:
            return self.phantom.read_watermark_metadata(pdf, key)
        except SecretNotFoundError:
            return self.meta_svd.read_watermark_metadata(pdf, key)

    def is_watermark_applicable(self, pdf: PdfSource, **kwargs) -> bool:
        """
        Ensure PDF is valid and has at least one page.
        """
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            reader = PdfReader(io.BytesIO(pdf_bytes))
            return len(reader.pages) > 0
        except Exception:
            return False


__all__ = ["ComboWatermark"]