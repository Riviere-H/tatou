"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF.

    """

    name: Final[str] = "bash-bridge-eof"

    # Constants
    _MAGIC: Final[bytes] = b"\n%%WM-BASH-BRIDGE-EOF:v1\n"
    _CONTEXT: Final[bytes] = b"wm:bash-bridge-eof:v1:"

    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position and key are ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` and ``key`` parameters are accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key,str) or not key:
            raise ValueError("Key must be a non-empty string")

        # Build authenticated payload
        payload = self._build_payload(secret, key)

        # Append
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload +b"\n"
        return out

        
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticate by key.
           Prints whatever there is after %EOF
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key,str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No BashbridgeEOF watermark found")

        start = idx + len(self._MAGIC)
        # payload ends at the next newline or EOF
        end_n1 = data.find(b"\n", start)
        end = len(data) if end_n1 == -1 else end_n1
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not(isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("UNsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except EXception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")


    # -----------------
    # Internal helpers
    # -----------------

    def _build_payload(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""
        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v":1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compare JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        """Compare HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()


__all__ = ["UnsafeBashBridgeAppendEOF"]

