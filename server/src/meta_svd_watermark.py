import base64
import io
import json
import numpy as np
import os
from typing import Any, Dict, Optional
from pgpy import PGPKey, PGPMessage
from pgpy.errors import PGPError
import fitz  # PyMuPDF
from PIL import Image


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

    # def encode_metadata(self, pdf_bytes: bytes, encrypted_secret: str) -> bytes:
    #     reader = PdfReader(io.BytesIO(pdf_bytes))
    #     writer = PdfWriter()

    #     for page in reader.pages:
    #         writer.add_page(page)

    #     meta = reader.metadata or {}
    #     meta[NameObject("/Author")] = createStringObject(self.SIGNATURE)
    #     meta[NameObject("/Title")] = createStringObject(f"WM-{base64.b64encode(encrypted_secret.encode()).decode()[:50]}"
    #     )

    #     writer.add_metadata(meta)

    #     output = io.BytesIO()
    #     writer.write(output)
    #     return output.getvalue()

    def decrypt_secret(self, encrypted_secret: str, key_path: str) -> str:
        try:
            if not os.path.isabs(key_path):
                key_filename = key_path if key_path.endswith(".asc") else f"{key_path}.asc"
                # Private keys are stored on the server
                key_path = os.path.join("/app/keys/server", key_filename)

            if not os.path.exists(key_path):
                raise WatermarkingError(f"Private key file not found: {key_path}")

            # Load the private key
            priv_key, _ = PGPKey.from_file(key_path)
            
            
            # Parse the encrypted message
            message = PGPMessage.from_blob(encrypted_secret)
            
            # Decrypt the message
            decrypted_payload = priv_key.decrypt(message).message
            
            # The payload is JSON, parse it
            payload = json.loads(decrypted_payload)
            
            # Return the actual secret content
            content = payload.get("content")
            if content is None:
                raise WatermarkingError("Decrypted payload has no 'content' field")
            return content
            
        except Exception as e:
            raise WatermarkingError(f"Decryption failed: {str(e)}")


    def embed_svd_rgb(self, pdf_bytes: bytes, encrypted_secret: str) -> bytes:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            # 1. Add metadata 
            meta = doc.metadata or {}
            meta['author'] = self.SIGNATURE
            meta['title'] = f"WM-{base64.b64encode(encrypted_secret.encode()).decode()}"
            doc.set_metadata(meta)

            # 2. SVD Watermarking Logic
            # Define minimum dimensions to watermark.
            # This skips small images like logos or icons.
            MIN_DIM_FOR_SVD = 5   # SVD math requires at least 5x5
            MIN_WIDTH = 100       # pixels
            MIN_HEIGHT = 100      # pixels

            secret_bytes = encrypted_secret.encode()[:15]

            for page_index in range(len(doc)):
                images = doc[page_index].get_images(full=True)
                if not images:
                    continue

                for img in images:
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]

                    try:
                        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
                        img_array = np.array(image).astype(float)

                        # Check if image is too small (e.g., a logo)
                        # or too small for the SVD operation.
                        if (image.width < MIN_WIDTH or
                            image.height < MIN_HEIGHT or
                            min(img_array.shape[0], img_array.shape[1]) < MIN_DIM_FOR_SVD):
                            continue # Skip this small image and check the next one

                        for c in range(3):
                            channel = img_array[:, :, c]

                            if min(channel.shape) < MIN_DIM_FOR_SVD:
                                continue
                            # 1. First SVD (I = U * S * V^T)
                            U, S_vector, V = np.linalg.svd(channel, full_matrices=False)

                            # 2. Modify the singular values (D = S + a*W) 
                            S_vector_modified = np.copy(S_vector)
                            for i, b in enumerate(secret_bytes[:5]):
                                S_vector_modified[i] += (b % 5)

                            # Create the modified diagonal matrix D
                            D_matrix = np.diag(S_vector_modified)

                            # 3. Perform the SECOND SVD on D (D = U_w * S_w * V_w^T) 
                            U_w, S_w_vector, V_w = np.linalg.svd(D_matrix, full_matrices=False)
                            
                            # 4. Reconstruct the image using ORIGINAL U, V but NEW S_w (I_w = U * S_w * V^T) 
                            # Ensures S_w_matrix has the right shape
                            S_w_matrix = np.diag(S_w_vector)
                            
                            # Reconstruct the channel using the new stable singular values
                            reconstructed_channel = np.dot(U, np.dot(S_w_matrix, V))
                            
                            img_array[:, :, c] = reconstructed_channel

                        # Uses np.clip as a final safeguard instead of min-max scaling.
                        img_array_clipped = np.clip(img_array, 0, 255)
                        img_encoded = Image.fromarray(img_array_clipped.astype(np.uint8))
                        
                        buffer = io.BytesIO()

                        original_ext = base_image.get("ext", "png").lower()
                        save_format = "PNG"
                        if original_ext in ["jpeg", "jpg"]:
                            save_format = "JPEG"

                        img_encoded.save(buffer, format=save_format)

                        doc.update_stream(xref, buffer.getvalue())
                    
                        break
                    except Exception as e_img:
                        # Log or ignore error for this image and continue
                        print(f"Skipping image {xref} due to error: {e_img}")
                        continue # Move to the next image
                break

            return doc.write(garbage=3, deflate=True)
        except Exception as e:
            raise WatermarkingError(f"SVD and metadata embedding failed: {str(e)}")
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
        
        # pdf_with_meta = self.encode_metadata(pdf_bytes, encrypted_secret)
        return self.embed_svd_rgb(pdf_bytes, encrypted_secret)

    def read_secret(self, pdf: PdfSource, key: str, **kwargs) -> str:
        pdf_bytes = load_pdf_bytes(pdf)
        # reader = PdfReader(io.BytesIO(pdf_bytes))
        # meta = reader.metadata or {}
        # title_val = meta.get("/Title", "")
        doc = None
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            meta = doc.metadata or {}
            title_val = meta.get("title", "") 
            
            if not title_val.startswith("WM-"):
                raise SecretNotFoundError("No watermark metadata found")
                
            b64_encrypted = title_val[3:]
            encrypted_pgp_message = ""
            try:
                # This gets the raw PGP message string 
                encrypted_pgp_message = base64.b64decode(b64_encrypted).decode("utf-8")
            except Exception:
                raise SecretNotFoundError("Failed to decode Base64 watermark")
            
            # Now, decrypt the PGP message
            # The 'key' parameter is the *name* of the private key, e.g., "unit-test-key"
            decrypted_content = self.decrypt_secret(encrypted_pgp_message, key)
            return decrypted_content

        except Exception as e:
            # Catch decryption errors as well
            if isinstance(e, (SecretNotFoundError, WatermarkingError, PGPError)):
                raise SecretNotFoundError(f"Failed to read or decrypt secret: {str(e)}")
            raise SecretNotFoundError(f"An unexpected error occurred: {str(e)}")
        finally:
            if doc:
                doc.close()

    def read_watermark_metadata(self, pdf: PdfSource, key: str) -> Dict[str, Any]:
        # Use PyMuPDF (fitz) for reading
        pdf_bytes = load_pdf_bytes(pdf)
        doc = None
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            meta = doc.metadata or {}
            title_val = meta.get("title", "") # Lowercase key
            if title_val.startswith("WM-"):
                b64_encrypted = title_val[3:]
                return {
                    "provider": self.SIGNATURE,
                    "encrypted_base64": b64_encrypted,
                    "hint": "Use your private key to decrypt this PGP message."
                }
            raise SecretNotFoundError("No watermark metadata found")
        except Exception as e:
            raise SecretNotFoundError(f"Failed to read PDF metadata: {e}")
        finally:
            if doc:
                doc.close()

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        # Use PyMuPDF (fitz) for reading
        doc = None
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            return doc.page_count > 0
        except Exception:
            return False
        finally:
            if doc:
                doc.close()

__all__ = ["MetaSVDWatermark"]
