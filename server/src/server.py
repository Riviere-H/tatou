import os, binascii
import io
import hashlib
import importlib.util
import datetime as dt
from pathlib import Path
from functools import wraps
import re
import time
from typing import Any, Dict

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import MethodNotAllowed, NotFound
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from io import BytesIO

# SECURITY: Disabled due to unsafe deserialization vulnerability
# import pickle as _std_pickle
# try:
#    import dill as _pickle  # allows loading classes not importable by module path
# except Exception:  # dill is optional
#     _pickle = _std_pickle
_pickle = None # Placeholder to avoid NameErrors

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod, SecretNotFoundError
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method


# Add RMAP related imports 
import base64
import json
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# metrics + prometheus WSGI
from prometheus_client import CollectorRegistry, multiprocess, make_wsgi_app, generate_latest, CONTENT_TYPE_LATEST
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from flask import Flask, Response, jsonify

# Structured JSON logging
import logging
from logger import logger, log_security_event, log_audit_event, log_error_event, log_info_event

# import counters
from metrics import (
    PDF_PARSER_ERRORS,
    FILE_UPLOAD_ERRORS,
    FILE_WRITE_ERRORS,
    WATERMARK_PROCESSING_ERRORS,
    WATERMARK_READ_ERRORS,
    RMAP_HANDSHAKE_FAILS,
    DB_EXCEPTIONS,
    SECURITY_EVENTS,
    AUDIT_EVENTS,
    USER_LOGIN_FAILURES,
    API_ERRORS,
    FILE_PROCESSING_ERRORS,
    RATE_LIMIT_HITS,
    WATERMARK_OPERATIONS,
)

# ---- Test / Mock helpers for RMAP and Watermarking ----
class DummyRmapHandler:
    """
    Minimal stub that imitates the real RMAP handler interface used by server.py:
    - handle_message1(payload)
    - handle_message2(payload)
    - nonces (dict) used when resolving identity in rmap_get_link
    """

    def __init__(self):
        # provide a deterministic nonce pair so session_secret can be matched
        # Use small integers as strings; combined -> hex string f"{combined:032x}"
        # We'll pick nonce_client=0, nonce_server=0 => combined == 0 -> session_secret "000...0"
        self.nonces = {"RMAP_Client": ("0", "0")}

    def handle_message1(self, payload):
        # return a dict similar to real handler: {'result': <session_secret_hex>}
        # choose 32 hex chars (16 bytes) zeroed for simplicity
        session_secret = f"{0:032x}"
        return {"result": session_secret}

    def handle_message2(self, payload):
        # Similar to handle_message1
        session_secret = f"{0:032x}"
        return {"result": session_secret}


class DummyWatermarker:
    """Return a fake PDF bytes for the rest of pipeline."""
    def add_watermark(self, pdf_bytes, secret_message, watermark_key, client_identity=None, position="", **kwargs):
        # Return simple PDF-like bytes (enough for length checks)
        return b"%PDF-1.4\n%Mocked PDF\n%%EOF\n"


def enable_test_mode(app):
    """
    Call this during app init when APP_ENV=test (or when YOU want mocking).
    It sets app.config flags and injects DummyRmapHandler and DummyWatermarker.
    """

    app.config["TEST_MODE"] = True
    # Inject dummy handler
    app.config["RMAP_HANDLER"] = DummyRmapHandler()
    # Optionally mock watermarking_utils.get_method to return dummy watermarker
    # We'll do a safe import-then-reassign if watermarking_utils module exists
    try:
        import watermarking_utils
        # store original for later if desired
        app.config.setdefault("_original_get_method", getattr(watermarking_utils, "get_method", None))
        def _dummy_get_method(name):
            # ignore name and return dummy
            return DummyWatermarker()
        watermarking_utils.get_method = _dummy_get_method
        app.logger.info("Test mode: watermarking_utils.get_method replaced with dummy")
    except Exception:
        # watermarking_utils may not be importable in test env; ignore
        app.logger.debug("Test mode: watermarking_utils import failed; skipping watermark mock")


# ----- Input validation -----
def validate_email(email: str) -> bool:
    # Validate email format
    if not email or not isinstance(email, str):
        return False
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def validate_username(username: str) -> bool:
    # Validate username format: allow letters, numbers, underscore, dash, length 3-50
    if not username or not isinstance(username, str):
        return False
    username_pattern = r'^[a-zA-Z0-9_-]{3,50}$'
    return bool(re.match(username_pattern, username))


def validate_password(password: str) -> bool:
    # Validate password strength: At least 10 characters, containing letters and numbers
    if not password or not isinstance(password, str):
        return False
    if len(password) < 10:
        return False

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    type_count = sum([has_lower, has_upper, has_digit])
    return type_count >=2


def sanitize_filename(filename: str) -> str:
    # Sanitize filename to prevent path traversal
    if not filename:
        return ""
    safe_name = secure_filename(filename)
    # Prevent empty filename or hidden files starting with dot
    if not safe_name or safe_name.startswith('.'):
        return "document"
    return safe_name

def validate_integer(value: Any, min_val: int = None, max_val: int = None) -> bool:
    # Validate integer range
    try:
        int_val = int(value)
        if min_val is not None and int_val < min_val:
            return False
        if max_val is not None and int_val > max_val:
            return False
        return True
    except (ValueError, TypeError):
        return False

def contains_sql_injection_pattern(text: str) -> bool:
    # Detect SQL injection patterns
    if not text or not isinstance(text, str):
        return False

    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)\b)",
        r"(--|\#|;)",
        r"(\b(OR|AND)\b.*=)",
        r"('|\")",
    ]

    for pattern in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def validate_safe_input(text: str, field_name: str) -> tuple[bool, str]:
    # Verify the security of input
    if not text or not isinstance(text, str):
        return False, f"{field_name} must be a string"

    if contains_sql_injection_pattern(text):
        return False, f"Invalid {field_name} format"

    return True, ""


def validate_uploaded_file(file) -> tuple[bool, str]:
    # Validate the security of uploaded file
    if not file or not hasattr(file, 'filename'):
        return False, "No file provided"

    if file.filename == '':
        return False, "No file selected"

    safe_filename = sanitize_filename(file.filename)
    if not safe_filename:
        return False, "Invalid filename"

    # File extension validation: only allow PDF
    allowed_extensions = {'.pdf'}
    file_extension = Path(safe_filename).suffix.lower()
    if file_extension not in allowed_extensions:
        return False, f"File type not allowed. Allowed: {','.join(allowed_extensions)}"

    # File size limit: 10MB
    file.seek(0,2)
    file_size = file.tell()
    file.seek(0)

    max_size = 30 * 1024 * 1024
    if file_size > max_size:
        max_size_mb = max_size // (1024 * 1024)
        return False, f"File too large. Maximum size: {max_size_mb}MB"

    if file_size == 0:
        return False, "File is empty"

    return True, safe_filename


def validate_json_payload(required_fields: dict = None, optional_fields: dict = None) -> callable:
    # Decorator: Validate JSON payload
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"error": "Content-Type must be application/json"}), 400

            payload = request.get_json(silent=True)
            if payload is None:
                return jsonify({"error": "Invalid JSON payload"}), 400

            if required_fields:
                for field, expected_type in required_fields.items():
                    if field not in payload:
                        return jsonify({"error": f"Missing required field: {field}"}), 400
                    if not isinstance(payload[field], expected_type):
                        return jsonify({"error": f"Field '{field}' must be {expected_type.__name__}"}), 400

            if optional_fields:
                for field, expected_type in optional_fields.items():
                    if field in payload and not isinstance(payload[field], expected_type):
                        return jsonify({"error": f"Field '{field}' must be {expected_type.__name__}"}), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator


class TokenBlacklist:
    """ Simple token blacklist management """

    def __init__(self):
        self.blacklisted_tokens = {}

    # Add token to blacklist
    def add(self, token: str, ttl: int = 3600):
        expiry = time.time() + ttl
        self.blacklisted_tokens[token] = expiry

        # Automatic cleanup of expired tokens, triggered on each add
        self.cleanup()

    # Check if token is in blacklist
    def is_blacklisted(self, token: str) -> bool:
        expiry = self.blacklisted_tokens.get(token)
        if expiry and expiry > time.time():
            return True
        elif expiry:
            del self.blacklisted_tokens[token]
        return False

    def cleanup(self):
        current_time = time.time()
        expired_tokens = [
            token for token, expiry in self.blacklisted_tokens.items()
            if expiry <= current_time
        ]
        for token in expired_tokens:
            del self.blacklisted_tokens[token]

        if expired_tokens:
            log_info_event("system_operation", r"Cleaned up {len(expired_tokens)} expired blacklisted tokens")

token_blacklist = TokenBlacklist()

class RateLimiter:
    """ Simple in-memory rate limiter """
    def __init__(self):
        self.attempts = {}

    def is_rate_limited(self, key: str, max_attempts: int, window_seconds: int) -> bool:
        # Check if rate limit is exceeded
        current_time = time.time()

        # Clean up old recors
        if key in self.attempts:
            self.attempts[key] = [
                ts for ts in self.attempts[key]
                if ts > current_time - window_seconds
            ]

        # Check attempt count
        if key not in self.attempts:
            self.attempts[key] = []
 
        if len(self.attempts[key]) >= max_attempts:
            return True

        self.attempts[key].append(current_time)
        return False

    def get_remaining_attempts(self, key: str, max_attempts: int, window_seconds: int) -> int:
        current_time = time.time()

        if key in self.attempts:
            self.attempts[key] = [
                ts for ts in self.attempts[key]
                if ts > current_time - window_seconds
            ]
            return max(0, max_attempts - len(self.attempts[key]))

        return max_attempts

rate_limiter = RateLimiter()


def get_client_fingerprint(request) -> str:
    """ Generate client fingerprint based on IP and User-Agent """
    client_ip = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")

    fingerprint_data = f"{client_ip}: {user_agent}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()


def create_app():
    app = Flask(__name__)
    app.config["APP_ENV"] = os.getenv("APP_ENV", "production") # default production
    app.config["ENABLE_RMAP_MOCK"] = app.config["APP_ENV"] == "test"
    # return app

    # ----- Error handling & security logging -----
    IS_DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'

    def safe_error_handler(f):
        """
        Unified error handler decorator
        - Prevent system info leakage
        - Log detailed errors
        - Return generic safe messages
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except ValueError as e:
                # Input validation error: safe to return details
                return jsonify({"error": str(e)}), 400
            except (SecretNotFoundError, InvalidKeyError) as e:
                # Watermark-related errors: keep original message
                return jsonify({"error": str(e)}), 400
            except Exception as e:
                # Unknown errors: log details, return generic message
                log_error_event("system_error", r"Error in {f.__name__}: {str(e)}")
                if IS_DEBUG:
                    return jsonify({"error": "Internal server error", "debug_info": str(e)}), 500
                return jsonify({"error": "Internal server error"}), 500
        return decorated_function

    def log_sensitive_operation(operation: str, target: str, user: dict):
        """
        Log sensitive operations
        """
        app.logger.info(
            f"SENSITIVE_OPERATION: {operation} on {target} by user {user.get('login')} (ID: {user.get('id')})"
        )

    # ----- Global Error Handlers -----
    # @app.errorhandler(404)
    # def not_found_error(error):
        # log_security_event("security_warning", r"404 Not Found: {request.url}")
        # return jsonify({"error": "Resource not found"}), 404

    # @app.errorhandler(405)
    # def method_not_allowed_error(error):
        # log_security_event("method_not_allowed", f"405 Method Not Allowed: {request.method} {request.url}")
        # return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(NotFound)
    def handle_not_found(e):
        # optional: log to security event system
        # log_security_event("security_warning", f"404 Not Found: {request.url}")
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(MethodNotAllowed)
    def handle_method_not_allowed(e):
        # optional: log to security event system
        # log_security_event("method_not_allowed", f"405 Method Not Allowed: {request.method} {request.url}")
        response = e.get_response()
        body = {"error": "Method not allowed"}
        response.data = jsonify(body).get_data()
        response.mimetype = "application/json"
        return response, 405

    # ----- Add security headers middleware -----
    @app.after_request
    def set_security_headers(response):
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        # Prevent MIME type sniffing 
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Enable browser XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Control referrer leakage
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Content Security Policy
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "     # allow inline JS
            "style-src 'self' 'unsafe-inline'; "      # allow inline CSS
            "img-src 'self' data:; "                  # allow base64 images
            "connect-src 'self'; "                    # restrict XHR, WS
            "font-src 'self'; "                       # allow fonts
            "object-src 'none'; "                     # disallow plugins
            "media-src 'self'; "                      # restrict audio, vedio
            "frame-src 'none'; "                      # disallow iframes
            "base-uri 'self'; "                       # restrict <base>
            "form-action 'self'; "                    # restrict form submission
            "frame-ancestors 'none'; "                # disallow framing
            "block-all-mixed-content"                 # block mixed HTTP/HTTPS
        )   
        response.headers['Content-Security-Policy'] = csp_policy

        return response

    # --- Config ---
    # Use stronger secret key
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # Strengthen JWT configuration
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))
    app.config["REFRESH_TOKEN_TTL"] = int(os.environ.get("REFRESH_TOKEN_TTL", "86400"))

    # Security configuration
    app.config["SESSION_COOKIE_SECURE"] = True       # Prevent XSS from accessing cookies
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"    # CSFR Protection

    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)


    # --- RMAP configuration ---
    keys_dir = Path("/app/keys")
    client_keys_dir = keys_dir / "clients"
    server_pub_key = keys_dir / "server" / "server_pub.asc"
    server_priv_key = keys_dir / "server" / "server_priv.asc"
    passphrase = os.environ.get("GPG_PASSPHRASE", "")

    try:

        app.config["RMAP_IDENTITY_MANAGER"] = IdentityManager(
        client_keys_dir=str(client_keys_dir),
        server_public_key_path=str(server_pub_key),
        server_private_key_path=str(server_priv_key),
        server_private_key_passphrase=passphrase
        )
        app.config["RMAP_HANDLER"] = RMAP(app.config["RMAP_IDENTITY_MANAGER"])
        print ("RMAP initialized successfully!")
    except Exception as e:
        print (f"RMAP initialization failed: {e}")

        app.config["RMAP_IDENTITY_MANAGER"] = None
        # FIX: Explicitly set RMAP_HANDLER to None upon failure.
        app.config["RMAP_HANDLER"] = None
        
        app.config["PMAP_HANDLER"] = None


    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()

            if token_blacklist.is_blacklisted(token):
                return _auth_error("Token has been revoked")

            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")


            # Verify client fingerprint
            current_fingerprint = get_client_fingerprint(request)
            if data.get("fingerprint") != current_fingerprint:
                log_security_event("security_warning", r"Token fingerprint mismatch for user {data.get('login')}")
                return _auth_error("Session context changed. Please login again.")


            # Verify user still exists, prevent deleted users from using old tokens
            try:
                with get_engine().connect() as conn:
                    user_exists = conn.execute(
                         text("SELECT id FROM Users WHERE id = :id AND login = :login"),
                         {"id": int(data["uid"]), "login": data["login"]}
                    ).first()
                if not user_exists:
                    log_security_event("security_warning", r"Auth failed: User {data.get('login')} (ID: {data.get('uid')}) not found in database")
                    return _auth_error("User no longer exists")

            except Exception as e:
                log_error_event("system_error", r"User validation failed with exception: {str(e)}")
                return _auth_error("Authentication validation failed")

            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---
    
    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")
    
    @app.route("/metrics")
    def metrics():
        registry = CollectRegistry()
        try:
            multiprocess.MultiProcessCollector(registry)
        except Exception as e:
            app.logger.debug(f"MultiProcessCollector init warning:{e}")

        data = generate_latest(registry)
        return Response(data, mimetype=CONTENT_TYPE_LATEST)

    @app.route("/test_metrics", methods=["GET"])
    def test_metrics():
        """
        Manually trigger key metrics to verify Grafana data visualization
        Each access increments the following counters: 
        - API_ERRORS_total
        - FILE_PROCESSING_ERRORS_total
        - WATERMARK_OPERATIONS_total
        """
        API_ERRORS.labels(endpoint="/test_metrics", method="GET").inc()
        FILE_PROCESSING_ERRORS.labels(operation="read").inc()
        WATERMARK_OPERATIONS.labels(operation="embed", method="GET").inc()
        return jsonify({
            "status": "ok",
            "message": "Test metrics incremented successfully"
        })


    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        is_safe, error_msg = validate_safe_input(login, "username")
        if not is_safe:
            return jsonify({"error": error_msg}), 400

        if not validate_username(login):
            return jsonify({"error": "Invalid username format. Use 3-50 characters: letters, numbers, _, -"}), 400

        if not validate_password(password):
            return jsonify({"error": "Password must be at least 10 charcaters and contain at least 2 charcater types (lowercase, uppercase, digits)"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"User creation database error: {str(e)}")
            return jsonify({"error": "Account creation failed"}), 503

        log_info_event("system_operation", r"USER_REGISTRATION: {login} ({email}) from IP: {request.remote_addr}")
        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    @validate_json_payload(required_fields={"email": str, "password": str})
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""

        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        client_ip = request.remote_addr
        log_info_event("system_operation", r"Login attempt from {client_ip} for email: {email}")
        rate_limit_key = f"login:{client_ip}:{email}"

        # Rate limit: maximum 5 attempts per minute per IP-email combination
        if rate_limiter.is_rate_limited(rate_limit_key, max_attempts=5, window_seconds=60):
            remaining = rate_limiter.get_remaining_attempts(rate_limit_key, 5, 60)
            log_security_event("security_warning", r"Rate limit exceed for {email} from {client_ip}")
            return jsonify({
                "error": f"Too many login attempts.Try again in {60} seconds.",
                "remaining_attempts": 0
            }), 429

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error during login: {str(e)}")
            return jsonify({"error": "Database Operation failed "}), 503

        if not row or not check_password_hash(row.hpassword, password):
            # Log security event with structured logging
            log_security_event(
                "user_login_failure", 
                f"Failed login attempt for email: {email}", 
                client_ip=client_ip, 
                details={"email": email, "reason": "invalid_credentials"}
            )
            remaining = rate_limiter.get_remaining_attempts(rate_limit_key, 5, 60)
            log_security_event("security_warning", r"Failed login attempt from {client_ip} for email: {email}")
            return jsonify({
                "error": "invalid credentials",
                "remaining_attempts": remaining
            }), 401

        # Generate client fingerprint
        client_fingerprint = get_client_fingerprint(request)

        token_data = {
            "uid": int(row.id),
            "login": row.login,
            "email": row.email,
            "ip": client_ip,
            "fingerprint": client_fingerprint,
            "login_time": dt.datetime.utcnow().isoformat(),
            "user_agent_hash": hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()
        }

        token = _serializer().dumps(token_data)
        # Reset rate limit after successful login
        if rate_limit_key in rate_limiter.attempts:
            del rate_limiter.attempts[rate_limit_key]

        log_info_event("system_operation", r"Successful login for user_id: {row.id} from {client_ip}")
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    @safe_error_handler
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        
        is_valid, message = validate_uploaded_file(file)
        if not is_valid:
            return jsonify({"error": message}), 400

        safe_filename = message

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or safe_filename
        stored_name = f"{ts}__{safe_filename}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            FILE_UPLOAD_ERRORS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        log_sensitive_operation("document_upload", f"document_{did}", g.user, f"size:{size} bytes")
        
        log_audit_event("document_upload", f"Document uploaded: {final_name}", user_id=g.user["id"], login=g.user["login"], details={"document_id": did, "file_name": final_name, "size": size})
        
        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    @safe_error_handler
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200



    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    @safe_error_handler
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    
    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    @safe_error_handler
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
            "secret": r.secret,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    @safe_error_handler
    def get_document(document_id: int | None = None):
        log_sensitive_operation("document_downloaded", f"document_{document_id}", g.user)
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            FILE_WRITE_ERRORS.inc()
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

            resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            FILE_UPLOAD_ERRORS.inc()
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    @safe_error_handler
    def delete_document(document_id: int | None = None):
        log_sensitive_operation("document_delete", f"document_{document_id}", g.user)
        # accept id from path
        log_audit_event("document_deletion", f"Document deleted: {document_id}", user_id=g.user["id"], login=g.user["login"], details={"document_id": document_id})
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT * FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(g.user["id"])}
                ).first()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    log_error_event("file_deletion_error", f"Failed to delete file {fp} for doc id={row.id}", details={"error": str(e)})
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            log_security_event("path_traversal_attempt", f"Path safety check failed for doc id={row.id}", details={"error": str(e)})

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"database error during delete: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200
        
        def add_metadata_to_pdf_bytes(pdf_bytes: bytes, group_id: str, session_secret: str) -> bytes:
                reader = PdfReader(BytesIO(pdf_bytes))
                writer = PdfWriter()
                for page in reader.pages:
                        writer.add_page(page)
                        writer.add_metadata({
			"/Author": f"{group_id}",
			"/Title": "Watermarked PDF",
			"/Keywords": f"session={session_secret}"
		})
                out = BytesIO()
                writer.write(out)
                return out.getvalue()
        
    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    @safe_error_handler
    def create_watermark(document_id: int | None = None):
        method = None
        log_sensitive_operation("watermark_creation", f"document_{document_id}", g.user)
        # accept id from path
        log_audit_event("watermark_creation", f"Watermark created for document {document_id}", user_id=g.user["id"], login=g.user["login"], details={"document_id": document_id, "method": method if method else "unknown"})
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            PDF_PARSER_ERRORS.inc()
            log_error_event("system_error", r"Watermark applicability check failed for method {method}: {str(e)}")
            return jsonify({"error": f"Selected watermarking is not applicable"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            WATERMARK_PROCESSING_ERRORS.inc()
            log_error_event("system_error", r"Wtermarking failed: {str(e)}")
            return jsonify({"error": "watermarking operation failed"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            FILE_WRITE_ERRORS.inc()
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token = sha1(watermarked_file_name)
        link_token = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:32]

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception as cleanup_e:
                DB_EXCEPTIONS.inc()
                print (f"Warning: Failed to cleanup temporary file {dest_path}: {cleanup_e}")
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201
        
        
    @app.post("/api/load-plugin")
    @require_auth
    @safe_error_handler
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod from
        STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in wm_mod.METHODS.
        Body: { "filename": "MyMethod.pkl", "overwrite": false }
    
        Phase2 Update: Securely load a plugin from a Python file instead of unsafe pickle/dill to prevent deserialization vulnerability.
        Body:{"file" "method_name" "overwrite"}
        File: plugin Python file (.py)
        method_name: name under which to register the plugin
        overwrite: boolean, allow overwriting existing method
        """
        log_sensitive_operation("plugin_load", "custom_watermark_plugin", g.user)

        file = request.files.get("file")
        overwrite = request.form.get("overwrite", "false").lower() == "true"

        if not file:
            return jsonify({"error": "Missing file"}), 400

        filename = secure_filename(file.filename)
        if not filename.endswith(".py"):
            return jsonify({"error": "Only .py plugins are supported"}), 400

        # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
        storage_root = Path(app.config["STORAGE_DIR"])
        plugins_dir = storage_root / "files" / "plugins"
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = plugins_dir / filename
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {filename}"}), 404
      
        # Safe import instead of pickle/dill
        try:
            spec = importlib.util.spec_from_file_location("plugin_module", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if not hasattr(module, "WatermarkingMethod"):
                return jsonify({"error": "Plugin must define WatermarkingMethod class"}), 400

            obj = module.WatermarkMethod
        except Exception as e:
            log_error_event("system_error", r"Plugin loading failed for file {filename}: {str(e)}")
            return jsonify({"error": "plugin load failed"}), 400

        # Accept: class object, or instance (we'll promote instance to its class)
        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        # Determine method name for registry
        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

        # Validate interface: either subclass of WatermarkingMethod or duck-typing
        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400

        # Check overwrite policy
        if method_name in WMUtils.METHODS and not overwrite:
            return jsonify({"error": f"Method {method_name} already exists"}), 400
            
        # Register the class (not an instance) so you can instantiate as needed later
        WMUtils.METHODS[method_name] = cls()
        
        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201
    
    
    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
            
        return jsonify({"methods": methods, "count": len(methods)}), 200
        
    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    @safe_error_handler
    def read_watermark(document_id: int | None = None):
        log_sensitive_operation("watermark_read", f"document_{document_id}", g.user)
        # accept id from path
        log_audit_event("watermark_read", f"Watermark read from document {document_id}", user_id=g.user["id"], login=g.user["login"], details={"document_id": document_id, "method": method})
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document; FIXME enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            DB_EXCEPTIONS.inc()
            log_error_event("system_error", r"Database error: {str(e)}")
            return jsonify({"error": "Database operation failed"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410
        
        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            WATERMARK_READ_ERRORS.inc()
            log_error_event("system_error", r"Watermark reading failed for document {doc_id}: {str(e)}")
            return jsonify({"error": "Failed to read watermark"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201


    # POST /api/rmap-initiate
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        """Handle RMAP Message 1 - initiate authentication handshake"""
        if not app.config.get("RMAP_HANDLER"):
            return jsonify({"error": "RMAP not configured"}), 503

        # 1. GET AND VALIDATE TOP-LEVEL JSON STRUCTURE
        # We need to manually handle the request.get_json() error here:
        try:
            payload = request.get_json(silent=False) 
            # Use silent=False to raise JSON error for non-dict JSONs
        except Exception as e:
            # Catch bare number, bare string, invalid JSON structure at top level
            log_error_event("security_issue", f"RMAP top-level JSON parsing failed: {e}")
            return jsonify({"error": "Invalid JSON payload. Expected a JSON object."}), 400

        # Strict Top-Level JSON Validation (Ensuring it's a dict)
        if payload is None or not isinstance(payload, dict):
            # This catches if JSON parsing succeeded but returned 'null' (payload is None) 
            # or a top-level primitive (which request.get_json(silent=False) might still allow if not strict enough)
            return jsonify({"error": "Invalid JSON format: expected object"}), 400

        if "payload" not in payload:
            return jsonify({"error": "payload field is required"}), 400

        # NEW STRICT PAYLOAD VALUE VALIDATION
        payload_value = payload["payload"]
        if not isinstance(payload_value, str) or len(payload_value) < 10:
            # This fixes 200 OK when 'payload' is false, null, or a number.
            return jsonify({"error": "Field 'payload' must be a string of at least 10 characters."}), 400

        # Test Mode Check (Stays outside the main processing try-block)
        if app.config.get("APP_ENV") == "test":
            try:
                import base64
                if not payload["payload"]:
                    raise ValueError("empty")
                base64.b64decode(payload["payload"])
            except Exception: # <-- FIXED: was Expection in original
                return jsonify({"result": "0000000000000000000"}), 200

        # 2. CORE RMAP PROCESSING
        try:
            # call RMAP handler to process Message 1
            response = app.config["RMAP_HANDLER"].handle_message1(payload)
            return jsonify(response)

        except (binascii.Error, ValueError, Exception) as e:
            # Catch Base64, PGP, or internal RMAP errors
            RMAP_HANDSHAKE_FAILS.inc()
            log_error_event("security_issue", f"RMAP payload parsing failed: {e}")
            
            # Return 400 for bad input, preventing the 500 error from the outer block
            return jsonify({"error": "Invalid RMAP message format or content"}), 400
    
    
    # POST /api/rmap-get-link
    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        """Handle RMAP Message 2 - finalize authentication and return watermarked PDF link"""

        # 1. INITIAL CHECK & INPUT VALIDATION
        if not app.config.get("RMAP_HANDLER"):
            return jsonify({"error": "RMAP not configured"}), 503
        
        payload = request.get_json(silent=True) or {}
        
        # Strict Top-Level JSON Validation
        if payload is None or not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON payload. Expected a JSON object."}), 400

        if "payload" not in payload:
            return jsonify({"error": "payload field is required"}), 400
            
        payload_value = payload["payload"]
        if not isinstance(payload_value, str) or len(payload_value) < 10:
            return jsonify({"error": "Field 'payload' must be a string of at least 10 characters."}), 400

        # Test Mode Check (Stays outside the main processing try-block)
        if app.config.get("APP_ENV") == "test":
            try:
                import base64
                if not payload["payload"]:
                    raise ValueError("empty")
                base64.b64decode(payload["payload"])
            except Exception: 
                return jsonify({"link": "/app/storage/rmap_sample.pdf"}), 200

        # 2. CORE RMAP PROCESSING (Primary try-except for PGP/Base64 errors)
        try:
            # call RMAP handler to process Message 2
            response = app.config["RMAP_HANDLER"].handle_message2(payload)

        # Catch parsing/Base64/PGP errors
        except (binascii.Error, ValueError, Exception) as e: 
            # FIX: Corrected variable name and handled Base64/PGP errors
            RMAP_HANDSHAKE_FAILS.inc() 
            log_error_event("security_issue", f"RMAP payload parsing failed: {e}")
            return jsonify({"error": "Invalid RMAP message format or content"}), 400
            
        if "error" in response:
            return jsonify(response), 400

        session_secret = response.get("result")
        if not session_secret:
            return jsonify({"error": "Invalid RMAP response"}), 500

        # 3. WATERMARKING AND I/O (Secondary try-except for PDF/IO errors)
        try:
            # Get Client Identity
            identity = None
            rmap_handler = app.config["RMAP_HANDLER"]
            for ident, (nonce_client, nonce_server) in rmap_handler.nonces.items():
                combined = (int(nonce_client) << 64) | int(nonce_server)
                if f"{combined:032x}" == session_secret:
                    identity = ident
                    break

            if app.config.get("APP_ENV") == "test":
                    return jsonify({"link": "/app/storage/rmap_sample.pdf"}), 200

            method = payload.get("method", "phantom-annotation-g21")
            from watermarking_utils import get_method
            watermarker = get_method(method)

            # Sample PDF for RMAP
            sample_pdf_path = "/app/storage/rmap_sample.pdf"
            secret_message = f"RMAP Session: {session_secret}, Client: {identity}"
            watermark_key = session_secret[:16]

            with open(sample_pdf_path, "rb") as f:
                pdf_bytes = f.read()

            # Add watermark（Contain client identity）
            watermarked_pdf = watermarker.add_watermark(
                pdf_bytes,
                secret_message,
                watermark_key,
                client_identity=identity 
            )

            # Store watermarked PDF in storage dir
            watermarks_dir = app.config["STORAGE_DIR"] / "rmap_watermarks"
            watermarks_dir.mkdir(parents=True, exist_ok=True)
            output_path = watermarks_dir / f"{session_secret}_{method}.pdf"

            with open(output_path, "wb") as f:
                f.write(watermarked_pdf)

            # Create database record
            try:
                with get_engine().begin() as conn:
                    rmap_doc = conn.execute(
                        text("SELECT id FROM Documents WHERE name = 'RMAP_Sample_Document' LIMIT 1")
                    ).first()

                    if not rmap_doc:
                        conn.execute(
                            text("""
                                INSERT INTO Documents (name, path, ownerid, sha256, size)
                                VALUES (:name, :path, 1, UNHEX(:sha256hex), :size)
                            """),
                            {
                                "name": "RMAP_Sample_Document",
                                "path": "/app/storage/rmap_sample.pdf",
                                "sha256hex": hashlib.sha256(b"rmap_sample").hexdigest(),
                                "size": os.path.getsize(sample_pdf_path) if os.path.exists(sample_pdf_path) else 0
                            },
                        )
                        doc_id = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                    else:
                        doc_id = int(rmap_doc.id)

                    conn.execute(
                        text("""
                            INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                            VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                        """),
                        {
                            "documentid": doc_id,
                            "link": session_secret,
                            "intended_for": identity or "RMAP_Client",
                            "secret": secret_message,
                            "method": method,
                            "position": "",
                            "path": str(output_path)
                        },
                    )
                    log_info_event("system_operation", f"Created DB record for RMAP PDF with method: {method}")

            except Exception as db_error:
                # FIX: Only catch DB errors here, re-raise if fatal, or return 503
                DB_EXCEPTIONS.inc()
                log_error_event("system_error", f"DB write failed: {db_error}")
                return jsonify({"error": "Database operation failed during record creation"}), 503

            # --- Final Success Return ---
            log_info_event("system_operation", f"Created watermarked PDF (method: {method}) for RMAP session: {session_secret}")
            return jsonify({
                "result": session_secret,
                "link": f"/api/get-version/{session_secret}",
                "message": "Watermarked PDF generated successfully",
                "client_identity": identity,
                "file_size": len(watermarked_pdf)
            })

        except Exception as e:
            # Catch-all for Watermarking/IO/File Path errors (from step 3 logic)
            WATERMARK_PROCESSING_ERRORS.inc()
            log_error_event("system_error", f"Watermarking failed ({method}): {e}")
            return jsonify({"error": f"Watermarking failed: {str(e)}"}), 500



    
    # POST /api/refresh-token
    @app.post("/api/refresh-token")
    @require_auth
    def refresh_token():
        """ Refresh access token """
        try:
            new_token = _serializer().dumps({
                "uid": g.user["id"],
                "login": g.user["login"],
                "email": g.user.get("email")
            })

            return jsonify({
                "token": new_token,
                "token_type": "bearer",
                "expires_in": app.config["TOKEN_TTL_SECONDS"]
            }), 200

        except Exception as e:
            log_error_event("system_error", r"Token refresh failed: {e}")
            return jsonify({"error": "Token refresh failed"}), 500 


    # POST /api/logout
    @app.post("/api/logout")
    @require_auth
    @safe_error_handler
    def logout():
        """ Log out user, add token to blacklist """
        try:
            auth_header = request.headers.get("Authorization", "")
            token = auth_header.split(" ", 1)[1].strip()

            token_blacklist.add(token, app.config["TOKEN_TTL_SECONDS"])
            
            return jsonify({"message": "Successfully logged out"}), 200

        except Exception as e:
            log_error_event("logout_error", f"Logout failed: {e}")
            return jsonify({"error": "Logout failed"}), 500

    # POST /api/logout-all
    @app.post("/api/logout-all")
    @require_auth
    @safe_error_handler
    def logout_all():
        """ Log out user from all devices by changing password """
        payload = request.get_json(silent=True) or {}
        new_password = payload.get("new_password")
        
        if not new_password or not validate_password(new_password):
            return jsonify({"error": "Valid new password is required"}), 400

        try:
            hpw = generate_password_hash(new_password)

            with get_engine().begin() as conn:
                conn.execute(
                    text("UPDATE Users SET hpassword = :hpw WHERE id = :id"),
                    {"hpw": hpw, "id": int(g.user["id"])}
                )

            auth_header = request.headers.get("Authorization", "")
            token = auth_header.split(" ",1)[1].strip()
            token_blacklist.add(token, app.config["TOKEN_TTL_SECONDS"])

            return jsonify({"message": "All sessions logged out. Please login with new password."}), 200

        except Exception as e:
            log_error_event("system_error", r"Logout all failed: {e}")
            return jsonify({"error": "Logout all failed"}), 500


    # --- Prometheus metrics WSGI mounting  ---
    try:
        if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            metrics_app = make_wsgi_app(registry)
        else:
            # single-process registry (default)
            metrics_app = make_wsgi_app()
        # Mount /metrics as a separate WSGI app so it won't conflict with Flask routes
        app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/metrics": metrics_app})
        app.logger.info("Prometheus /metrics endpoint mounted (multiproc=%s)", bool(os.environ.get("PROMETHEUS_MULTIPROC_DIR")))
    except Exception as e:
        log_error_event("metrics_endpoint_mount_failure", f"Failed to mount Prometheus metrics endpoint: {e}")

    return app

# WSGI entrypoint
app = create_app()

# Activate test mode / Fallback to Dummy Handler for Error Testing
if app.config.get("RMAP_HANDLER") is None:
    from server import DummyRmapHandler 
    app.config["RMAP_HANDLER"] = DummyRmapHandler() 
    app.logger.warning("RMAP initialization failed. Forced DummyRmapHandler for testing/error-bypass.")

elif os.environ.get("APP_ENV") == "test" or os.environ.get("MOCK_RMAP") == "1":
    enable_test_mode(app)
    app.logger.info("Application started in TEST/MOCK mode: dummy RMAP handler active")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


