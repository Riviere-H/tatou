"""
phantom_annotation_watermark.py

Annotation Watermarking System by Group 21.
Implements a stealthy watermarking technique using invisible PDF annotations with enhanced stream cipher encryption and multi-property encoding.
Support client identity tracking for RMAP protocol integration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
from datetime import datetime, timezone
from typing import Final, Dict, Any, Optional, Tuple
import fitz  # PyMuPDF

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError
)


class PhantomAnnotationWatermark(WatermarkingMethod):
    """
    Watermarking system using invisible PDF annotations with stream cipher encryption.
    This method creates completely transparent annotations placed outside visible page areas.
    Features enhanced encryption using HMAC-based stream cipher and multi-property encoding for robust watermark embedding and extraction.
    """
    
    # Identifier for this watermarking method
    name: Final[str] = "phantom-annotation-g21"
    
    # Group21 signature for identification
    GROUP21_SIGNATURE: Final[str] = "G21-Phantom"
    
    # Annotation coordinates (outside visible area)
    PHANTOM_COORDINATES: Final[Tuple[int, int]] = (-1000, -1000)
    
    # Fixed annotation size
    ANNOTATION_SIZE: Final[int] = 1
    
    @staticmethod
    def get_usage() -> str:
        """Return method description for API documentation."""
        return (
            "Annotation watermarking with stream cipher encryption and client identity tracking. "
            "Embeds watermarks in invisible annotations using HMAC-based encryption "
            "and multi-property encoding for enhanced security."
            "Supports RMAP protocol integration for tracking PDF downloads by client groups."
        )
    
    def build_watermark_payload(self, base_secret: str, client_identity: Optional[str] = None) -> str:
        """
        Build watermark payload with client identity information.
        
        This payload includes both the original secret and client identity for RMAP protocol tracking requirements.
        
        Args:
            base_secret: The original secret content to watermark
            client_identity: Identity of the client requesting the watermark (for RMAP tracking)
            
        Returns:
            JSON string containing structured watermark data
        """
        payload = {
            "version": "1.0",  # Version indicator for enhanced format
            "provider": self.GROUP21_SIGNATURE,  # Original provider signature
            "client": client_identity or "unknown",  # Client identity for RMAP tracking
            "content": base_secret,  # Original secret content
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_type": "rmap" if client_identity else "standard"
        }
        
        # Use compact JSON formatting for efficient embedding
        return json.dumps(payload, separators=(',', ':'))
    

    def derive_key(self, user_key: str, salt: bytes) -> bytes:
        """
        Derive a secure encryption key from user input using PBKDF2.
        
        This prevents weak key issues and provides key stretching against brute force.
        
        Args:
            user_key: User-provided key string
            salt: Random salt for key derivation
            
        Returns:
            32-byte derived key
        """
        return hashlib.pbkdf2_hmac(
            'sha256',
            user_key.encode('utf-8'),
            salt,
            iterations=10000,  # Balance between security and performance
            dklen=32
        )
    
    def stream_cipher_encrypt(self, plaintext: str, key: bytes) -> Tuple[str, str]:
        """
        Encrypt using HMAC-based stream cipher for enhanced security.
        Generates cryptographically secure keystream using HMAC-SHA256 in counter mode.
        Provides semantic security through random IV usage.
        
        Args:
            plaintext: Text to encrypt
            key: 32-byte encryption key
            
        Returns:
            Tuple of (base64_ciphertext, base64_iv)
        """

        # Generate random initialization vector
        iv = os.urandom(16)
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Generate keystream using HMAC in counter mode
        keystream = b''
        block_count = 0
        
        while len(keystream) < len(plaintext_bytes):
            counter_block = iv + block_count.to_bytes(4, 'big')
            keystream_block = hmac.new(key, counter_block, hashlib.sha256).digest()
            keystream += keystream_block
            block_count += 1
        
        # XOR encryption with keystream
        keystream = keystream[:len(plaintext_bytes)]
        ciphertext = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])
        
        return base64.b64encode(ciphertext).decode('ascii'), base64.b64encode(iv).decode('ascii')
    
    def stream_cipher_decrypt(self, ciphertext_b64: str, iv_b64: str, key: bytes) -> str:
        """
        Decrypt data encrypted with the stream cipher.
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            iv_b64: Base64-encoded initialization vector
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            ValueError: If decryption fails
        """
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            # Regenerate the same keystream
            keystream = b''
            block_count = 0
            
            while len(keystream) < len(ciphertext):
                counter_block = iv + block_count.to_bytes(4, 'big')
                keystream_block = hmac.new(key, counter_block, hashlib.sha256).digest()
                keystream += keystream_block
                block_count += 1
            
            # XOR decryption
            keystream = keystream[:len(ciphertext)]
            plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
            
            return plaintext.decode('utf-8').rstrip('\0')  # Remove padding
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def generate_watermark_data(self, secret: str, key: str, client_identity: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate encrypted watermark payload with integrity protection and client tracking.
        
        Args:
            secret: Plaintext secret to watermark
            key: User-provided encryption key
            Client_identity: Optional client identity for tracking

        Returns:
            Structured watermark data dictionary
        """

        if not secret or not key:
            raise ValueError("Secret and key must be non-empty")

        # Build watermark payload
        watermark_payload = self.build_watermark_payload(secret, client_identity)
        
        # Generate random salt for key derivation
        salt = os.urandom(16)
        
        # Derive encryption key
        encryption_key = self.derive_key(key, salt)
        
        # Encrypt watermark payload
        encrypted_payload, iv = self.stream_cipher_encrypt(watermark_payload, encryption_key)
        
        # Create timestamp and HMAC for integrity
        timestamp = datetime.now(timezone.utc).isoformat()
        hmac_data = f"{encrypted_payload}{iv}{timestamp}{self.GROUP21_SIGNATURE}"
        hmac_signature = hmac.new(encryption_key, hmac_data.encode(), hashlib.sha256).hexdigest()
        
        return {
            "version": "1.0",
            "provider_signature": self.GROUP21_SIGNATURE,
            "timestamp": timestamp,
            "salt": base64.b64encode(salt).decode('ascii'),
            "payload_encrypted": encrypted_payload,
            "iv": iv,
            "hmac": hmac_signature,
            "client_tracking": client_identity is not None
        }
    
    def verify_watermark_data(self, data: Dict[str, Any], key: str) -> str:

        """
        Verify and extract secret from watermark data.
        
        Args:
            data: Watermark data dictionary
            key: User-provided verification key
            
        Returns:
            Extracted secret string
            
        Raises:
            InvalidKeyError: If HMAC verification fails
            SecretNotFoundError: If data is invalid
        """

        try:
            # Validate required fields
            required = ["provider_signature", "hmac", "timestamp", "payload_encrypted", "iv", "salt"]
            if not all(field in data for field in required):
                raise SecretNotFoundError("Invalid watermark data structure")
            
            if data["provider_signature"] != self.GROUP21_SIGNATURE:
                raise SecretNotFoundError("Invalid group signature")
            
            # Derive key using stored salt
            salt = base64.b64decode(data["salt"])
            encryption_key = self.derive_key(key, salt)
            
            # Verify HMAC integrity
            verification_data = f"{data['payload_encrypted']}{data['iv']}{data['timestamp']}{self.GROUP21_SIGNATURE}"
            expected_hmac = hmac.new(encryption_key, verification_data.encode(), hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(data["hmac"], expected_hmac):
                raise InvalidKeyError("HMAC verification failed")
            
            # Decrypt the payload
            decrypted_payload = self.stream_cipher_decrypt(data["payload_encrypted"], data["iv"], encryption_key)
          
            # Parse the payload to extract the original secret
            try:
                payload_obj = json.loads(decrypted_payload)
                if isinstance(payload_obj, dict) and "content" in payload_obj:
                    # extract content field
                    return payload_obj["content"]
                else:
                    # Legacy format: return entire payload
                    return decrypted_payload
            except json.JSONDecodeError:
                # Legacy format: not JSON, return as-is
                return decrypted_payload            

        except (ValueError, KeyError) as e:
            raise SecretNotFoundError(f"Watermark data corruption: {str(e)}")
    
    def extract_watermark_metadata(self, data: Dict[str, Any], key: str) -> Dict[str, Any]:
        """
        Extract complete watermark metadata including client identity.
        
        This method provides full access to watermark data for advanced analysis and RMAP client tracking.
        
        Args:
            data: Watermark data dictionary
            key: User-provided verification key
            
        Returns:
            Complete watermark metadata dictionary
        """
        try:
            # First verify and decrypt the payload
            decrypted_payload = self.verify_watermark_data(data, key)
            
            # Try to parse as JSON for enhanced format
            try:
                metadata = json.loads(decrypted_payload)
                if isinstance(metadata, dict):
                    return metadata
                else:
                    return {"content": decrypted_payload, "format": "legacy"}
            except json.JSONDecodeError:
                return {"content": decrypted_payload, "format": "legacy"}
                
        except Exception as e:
            raise SecretNotFoundError(f"Metadata extraction failed: {str(e)}")

    def encode_in_color(self, data: str) -> Tuple[float, float, float]:
        """
        Encode verification data in RGB color values for multi-property encoding.
        
        Args:
            data: String data to encode
            
        Returns:
            Tuple of (R, G, B) values between 0.0 and 1.0
        """

        hash_val = hashlib.sha256(data.encode()).hexdigest()[:6]
        return (
            int(hash_val[0:2], 16) / 255.0,
            int(hash_val[2:4], 16) / 255.0, 
            int(hash_val[4:6], 16) / 255.0
        )
    
    def create_phantom_annotation(self, page, watermark_data: Dict[str, Any]) -> None:
        """
        Create invisible annotation with multi-property encoding.
        
        Args:
            page: PDF page to add annotation to
            watermark_data: Watermark data to encode
        """
        try:
            # Create rectangle outside visible area
            rect = fitz.Rect(
                self.PHANTOM_COORDINATES[0],
                self.PHANTOM_COORDINATES[1],
                self.PHANTOM_COORDINATES[0] + self.ANNOTATION_SIZE,
                self.PHANTOM_COORDINATES[1] + self.ANNOTATION_SIZE
            )
            
            # Create text annotation
            annot = page.add_text_annot(rect.tl, " ")
            
            # Multi-property encoding for robustness
            # 1. Title contains signature and basic info, content contains full watermark data
            title_hash = hashlib.sha256(watermark_data["timestamp"].encode()).hexdigest()[:6]
            watermark_json = json.dumps(watermark_data, separators=(',', ':'))
            annot.set_info(title=f"{self.GROUP21_SIGNATURE}_TS{title_hash}", content=watermark_json)
    
            
            # 3. Color encodes verification hash
            color_vals = self.encode_in_color(watermark_data["hmac"])
            annot.set_colors(stroke=color_vals, fill=color_vals)
            
            # 4. Make invisible and non-printable
            annot.set_flags(annot.flags | 1)  # Invisible flag
            annot.set_border(dashes=[0])  # No border
            annot.set_opacity(0.0)  # Completely transparent
            
            annot.update()
            
        except Exception as e:
            raise WatermarkingError(f"Annotation creation failed: {str(e)}")
    
    def find_phantom_annotations(self, doc) -> list:
        """
        Scan document for annotations.
        
        Args:
            doc: PDF document object
            
        Returns:
            List of (page_num, annotation) tuples
        """
        annotations = []
        
        for page_num in range(len(doc)):
            page = doc[page_num]
            annots = page.annots()
            
            if annots:
                for annot in annots:
                    try:                            
                        info = annot.info
                        title = info.get("title", "")
                        content = info.get("content", "")
                
                        if content and self.GROUP21_SIGNATURE in content:
                                annotations.append((page_num, annot))
                        elif title and self.GROUP21_SIGNATURE in title:
                                annotations.append((page_num, annot))
                                
                    except Exception as e:
                        #log problematic annotations but continue processing others
                        print(f"Warning: Skipping problematic annotation: {e}")
                        continue  
        
        return annotations
    
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
        client_identity: Optional[str] = None
    ) -> bytes:
        """
        Embed watermark into PDF using phantom annotations.
        
        Args:
            pdf: Source PDF document
            secret: Secret message to embed
            key: Encryption key
            position: Optional position hint (ignored)
            client_identity: Optional client identity for RMAP tracking

        Returns:
            Watermarked PDF bytes
        """
        if not secret or not key:
            raise ValueError("Secret and key required")
        
        pdf_bytes = load_pdf_bytes(pdf)
        doc = None
        
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            
            if len(doc) == 0:
                raise WatermarkingError("PDF has no pages")

            # Generate and embed watermark data
            watermark_data = self.generate_watermark_data(secret, key, client_identity)
            self.create_phantom_annotation(doc[0], watermark_data)
            
            return doc.write()
            
        except Exception as e:
            if isinstance(e, (WatermarkingError, ValueError)):
                raise
            raise WatermarkingError(f"Watermark embedding failed: {str(e)}")
        finally:
            if doc:
                doc.close()
    
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """
        Extract watermark secret from PDF.
        
        Args:
            pdf: PDF document to scan
            key: Verification key
            
        Returns:
            Extracted secret string
        """
        if not key:
            raise ValueError("Key required for extraction")
        
        pdf_bytes = load_pdf_bytes(pdf)
        doc = None
        
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            annotations = self.find_phantom_annotations(doc)
            
            if not annotations:
                raise SecretNotFoundError("No phantom annotations found")
            
            # Try each found annotation
            for page_num, annot in annotations:
                try:
                    info = annot.info
                    content = info.get("content", "")
                    if content and content.startswith("{"):
                        data = json.loads(content)
                        return self.verify_watermark_data(data, key)
                except Exception as e:
                    #Log watermark extraction error but continue to try other annotation
                    print (f"Warning: Failed to extract watermark from annotation: {e}")
                    continue
            
            raise SecretNotFoundError("No valid watermark found in annotations")
            
        except (SecretNotFoundError, InvalidKeyError):
            raise
        except Exception as e:
            raise WatermarkingError(f"Watermark extraction failed: {str(e)}")
        finally:
            if doc:
                doc.close()

    def read_watermark_metadata(self, pdf: PdfSource, key: str) -> Dict[str, Any]:
        """
        Extract complete watermark metadata including client identity for RMAP client tracking and advanced analysis.
        
        Args:
            pdf: PDF document to scan
            key: Verification key
            
        Returns:
            Complete watermark metadata dictionary
        """
        if not key:
            raise ValueError("Key required for extraction")
        
        pdf_bytes = load_pdf_bytes(pdf)
        doc = None    

        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            annotations = self.find_phantom_annotations(doc)
            
            if not annotations:
                raise SecretNotFoundError("No phantom annotations found")
            
            # Try each found annotation
            for page_num, annot in annotations:
                try:
                    content = annot.content or ""
                    if content.startswith("{"):
                        data = json.loads(content)
                        return self.extract_watermark_metadata(data, key)
                except Exception as e:
                    # Log metadata extraction error but continue to try other annotations 
                    print (f"Warning: Failed to extract watermark metadata: {e}")
                    continue
            
            raise SecretNotFoundError("No valid watermark found in annotations")
            
        except (SecretNotFoundError, InvalidKeyError):
            raise
        except Exception as e:
            raise WatermarkingError(f"Watermark metadata extraction failed: {str(e)}")
        finally:
            if doc:
                doc.close()


    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        """
        Check if watermark can be applied to PDF.
        
        Args:
            pdf: PDF document to check
            position: Optional position hint (ignored)
            
        Returns:
            True if applicable, False otherwise
        """
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            applicable = len(doc) > 0
            doc.close()
            return applicable
        except Exception:
            return False


__all__ = ["PhantomAnnotationWatermark"]
