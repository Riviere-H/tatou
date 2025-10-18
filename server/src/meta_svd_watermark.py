import base64
import io
import json
import numpy as np
import os
from typing import Any, Dict, Optional
from pgpy import PGPKey, PGPMessage
import fitz  # PyMuPDF
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, createStringObject

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    WatermarkingError
)

class MetaSVDWatermark(WatermarkingMethod):
    name = "group21-metadata-svd"
    SIGNATURE = "G21-MetaSVD"

    def get_usage(self) -> str:
        return (
            "Watermark method combining PDF metadata and image SVD (by Group 21). "
            "Embeds encrypted secret using PGP public key into metadata and modifies singular values of embedded images."
        )

    def generate_watermark_data(self, secret: str, client_identity: Optional[str] = None) -> str:
        payload = {
            "version": "1.0",
            "provider": self.SIGNATURE,
            "client": client_identity or "unknown",
            "content": secret,
        }
        return json.dumps(payload, separators=(",", ":"))

    def encrypt_secret(self, secret: str, key_path: str) -> str:
        """
        Encrypt the given secret using a public PGP key(from each group).
        Automatically resolves relative key filenames to the mounted /app/keys/clients directory.
        """
        try:
            if not os.path.isabs(key_path):
                key_filename = key_path if key_path.endswith(".asc") else f"{key_path}.asc"
                key_path = os.path.join("/app/keys/clients", key_filename)

            if not os.path.exists(key_path):
                raise WatermarkingError(f"Key file not found: {key_path}")

            with open(key_path, "r") as f:
                key_data = f.read()
            public_key, _ = PGPKey.from_blob(key_data)
            message = PGPMessage.new(secret)
            encrypted = public_key.encrypt(message)
            return str(encrypted)
        except Exception as e:
            raise WatermarkingError(f"Encryption failed: {str(e)}")

    def encode_metadata(self, pdf_bytes: bytes, encrypted_secret: str) -> bytes:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        meta = reader.metadata or {}
        meta[NameObject("/Author")] = createStringObject(self.SIGNATURE)
        meta[NameObject("/Title")] = createStringObject(f"WM-{base64.b64encode(encrypted_secret.encode()).decode()[:50]}"
        )

        writer.add_metadata(meta)

        output = io.BytesIO()
        writer.write(output)
        return output.getvalue()

    def embed_svd_rgb(self, pdf_bytes: bytes, encrypted_secret: str) -> bytes:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            for page_index in range(len(doc)):
                images = doc[page_index].get_images(full=True)
                if not images:
                    continue

                for img in images:
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]

                    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
                    img_array = np.array(image).astype(float)
                    secret_bytes = encrypted_secret.encode()[:15]

                    for c in range(3):
                        channel = img_array[:, :, c]
                        U, S, V = np.linalg.svd(channel, full_matrices=False)
                        for i, b in enumerate(secret_bytes[:5]):
                            S[i] += (b % 5)
                        img_array[:, :, c] = np.dot(U, np.dot(np.diag(S), V))

                    img_encoded = Image.fromarray(np.clip(img_array, 0, 255).astype(np.uint8))
                    buffer = io.BytesIO()
                    img_encoded.save(buffer, format="PNG")
                    doc[page_index].insert_image(doc[page_index].rect, stream=buffer.getvalue())
                    break
                break
            return doc.write()
        except Exception as e:
            raise WatermarkingError(f"SVD embedding failed: {str(e)}")
        finally:
            doc.close()

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
        client_identity: Optional[str] = None,
    ) -> bytes:
        if not secret or not key:
            raise ValueError("Secret and key required")

        pdf_bytes = load_pdf_bytes(pdf)
        watermark_payload = self.generate_watermark_data(secret, client_identity)
        encrypted_secret = self.encrypt_secret(watermark_payload, key)
        pdf_with_meta = self.encode_metadata(pdf_bytes, encrypted_secret)
        return self.embed_svd_rgb(pdf_with_meta, encrypted_secret)

    def read_secret(self, pdf: PdfSource, key: str, **kwargs) -> str:
        pdf_bytes = load_pdf_bytes(pdf)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata or {}
        title_val = meta.get("/Title", "")
        if title_val.startswith("WM-"):
            b64_encrypted = title_val[3:]
            try:
                return base64.b64decode(b64_encrypted).decode("utf-8")
            except Exception:
                raise SecretNotFoundError("Failed to decode Base64 watermark")
        raise SecretNotFoundError("No watermark metadata found")

    def read_watermark_metadata(self, pdf: PdfSource, key: str) -> Dict[str, Any]:
        pdf_bytes = load_pdf_bytes(pdf)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata or {}
        title_val = meta.get("/Title", "")
        if title_val.startswith("WM-"):
            b64_encrypted = title_val[3:]
            return {
                "provider": self.SIGNATURE,
                "encrypted_base64": b64_encrypted,
                "hint": "Use your private key to decrypt this PGP message."
            }
        raise SecretNotFoundError("No watermark metadata found")

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            reader = PdfReader(io.BytesIO(pdf_bytes))
            return len(reader.pages) > 0
        except Exception:
            return False

__all__ = ["MetaSVDWatermark"]
