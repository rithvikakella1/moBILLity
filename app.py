import asyncio
import base64
import binascii
import gzip
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from dotenv import load_dotenv

load_dotenv()  # loads .env before any os.getenv() calls

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

import bcrypt
import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.responses import Response as FastAPIResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from openai import OpenAI
from psycopg.rows import dict_row
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.sessions import SessionMiddleware

from logging_setup import configure_logging, request_id_var

# ── SECURITY CONFIG ──────────────────────────────────────────────────────────
configure_logging()
logger = logging.getLogger("mobillity.auth")
# Area-specific loggers so levels can be tuned independently.
dispatch_logger = logging.getLogger("mobillity.dispatch")
llm_logger = logging.getLogger("mobillity.llm")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production"
SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_hex(32)
SESSION_SECRET = os.getenv("SESSION_SECRET_KEY") or secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ACTION_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACTION_TOKEN_EXPIRE_MINUTES", "60"))
ANALYTICS_RETENTION_DAYS = min(max(int(os.getenv("ANALYTICS_RETENTION_DAYS", "90")), 1), 365)
ADMIN_EMAILS = {
    email.strip().lower()
    for email in os.getenv("ADMIN_EMAILS", "").split(",")
    if email.strip()
}
PRIVACY_CONTACT_EMAIL = os.getenv("PRIVACY_CONTACT_EMAIL", "privacy@example.com").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
# Pages are built by the Astro frontend and served from FRONTEND_BASE_URL, which
# proxies /api, /auth, /webhooks, and /admin back here so the browser sees one
# origin. Leaving this unset keeps the legacy HTML files serving from this
# process, so the cut-over is a configuration change rather than a code change —
# and is reversible the same way.
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").rstrip("/")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", str(IS_PRODUCTION)).lower() == "true"

if IS_PRODUCTION and (
    not os.getenv("JWT_SECRET_KEY")
    or not os.getenv("SESSION_SECRET_KEY")
    or not os.getenv("PRIVACY_CONTACT_EMAIL")
):
    raise RuntimeError(
        "JWT_SECRET_KEY, SESSION_SECRET_KEY, and PRIVACY_CONTACT_EMAIL are required in production."
    )

_KEY_HELP = (
    "Generate one with: "
    'python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"'
)


def _load_encryption_key(encoded: str) -> bytes:
    """Decode and validate a base64 AES-256 key.

    Never pad and never truncate. Zero-padding a short key produces something
    that looks like a 256-bit key but carries only the entropy that was typed,
    and every failure mode is silent — the app happily writes ciphertext you
    cannot distinguish from correctly encrypted data.
    """
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(f"ENCRYPTION_KEY is not valid base64. {_KEY_HELP}") from exc
    if len(raw) != 32:
        raise RuntimeError(
            f"ENCRYPTION_KEY must decode to exactly 32 bytes, got {len(raw)}. {_KEY_HELP}"
        )
    return raw


def _derive_phone_hmac_key(root: bytes) -> bytes:
    """A distinct key for the phone lookup index, derived from the master key."""
    explicit = os.getenv("PHONE_HMAC_KEY", "").strip()
    if explicit:
        return _load_encryption_key(explicit)
    return hashlib.sha256(b"mobillity-phone-lookup-v1" + root).digest()


_enc_env = os.getenv("ENCRYPTION_KEY", "").strip()
if _enc_env:
    ENCRYPTION_KEY = _load_encryption_key(_enc_env)
elif IS_PRODUCTION:
    raise RuntimeError(f"ENCRYPTION_KEY is required in production. {_KEY_HELP}")
else:
    # Persist the development key so that data written before a restart is still
    # readable after it. A per-boot random key makes the workflow features
    # effectively untestable locally.
    _dev_key_path = os.path.join(BASE_DIR, ".dev-encryption-key")
    if os.path.exists(_dev_key_path):
        with open(_dev_key_path, encoding="utf-8") as handle:
            ENCRYPTION_KEY = _load_encryption_key(handle.read().strip())
    else:
        ENCRYPTION_KEY = secrets.token_bytes(32)
        with open(_dev_key_path, "w", encoding="utf-8") as handle:
            handle.write(base64.b64encode(ENCRYPTION_KEY).decode())
        logger.warning(
            "ENCRYPTION_KEY not set. Generated a development key at %s. "
            "Set ENCRYPTION_KEY explicitly before deploying.",
            _dev_key_path,
        )

PHONE_HMAC_KEY = _derive_phone_hmac_key(ENCRYPTION_KEY)

# ── USER STORE ────────────────────────────────────────────────────────────────
# Production uses PostgreSQL when DATABASE_URL is configured. SQLite remains
# available for local development and the test suite.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USING_POSTGRES = bool(DATABASE_URL)
DATABASE_FILE = os.getenv("DATABASE_FILE", os.path.join(BASE_DIR, "users.db"))

# A fresh connect() per use costs a TCP handshake, a TLS negotiation, and an auth
# round trip — roughly 30-50ms before any query runs, on every authenticated
# request. The pool is created lazily so importing this module stays cheap.
_POOL = None
_POOL_LOCK = threading.Lock()


def _pool():
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                from psycopg_pool import ConnectionPool

                _POOL = ConnectionPool(
                    DATABASE_URL,
                    min_size=int(os.getenv("DB_POOL_MIN", "2")),
                    max_size=int(os.getenv("DB_POOL_MAX", "10")),
                    kwargs={"row_factory": dict_row},
                    open=True,
                )
    return _POOL


def _close_pool() -> None:
    global _POOL
    if _POOL is not None:
        _POOL.close()
        _POOL = None


class _Database:
    def __enter__(self):
        if USING_POSTGRES:
            self._pooled = _pool().connection()
            self.connection = self._pooled.__enter__()
        else:
            self._pooled = None
            self.connection = sqlite3.connect(DATABASE_FILE)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._pooled is not None:
            # psycopg's pooled context manager commits on success, rolls back on
            # error, and returns the connection to the pool.
            return self._pooled.__exit__(exc_type, exc_value, traceback)
        try:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        finally:
            self.connection.close()

    def execute(self, statement: str, parameters=()):
        if USING_POSTGRES:
            statement = statement.replace("?", "%s")
        return self.connection.execute(statement, parameters)

def _db() -> _Database:
    return _Database()

def _init_db() -> None:
    with _db() as db:
        id_definition = "BIGSERIAL PRIMARY KEY" if USING_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
        email_definition = "TEXT NOT NULL UNIQUE" if USING_POSTGRES else "TEXT NOT NULL UNIQUE COLLATE NOCASE"
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS users (
                id {id_definition},
                email {email_definition},
                password_hash TEXT,
                full_name TEXT NOT NULL DEFAULT '',
                google_sub TEXT UNIQUE,
                email_verified INTEGER NOT NULL DEFAULT 0,
                session_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS action_tokens (
                id {id_definition},
                user_id BIGINT NOT NULL,
                purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        if USING_POSTGRES:
            db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS analytics_enabled INTEGER NOT NULL DEFAULT 1")
        else:
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "analytics_enabled" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN analytics_enabled INTEGER NOT NULL DEFAULT 1")
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS analytics_events (
                id {id_definition},
                user_id BIGINT NOT NULL,
                event_name TEXT NOT NULL,
                page TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_action_tokens_lookup ON action_tokens(token_hash, purpose)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_analytics_user_time ON analytics_events(user_id, occurred_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_analytics_event_time ON analytics_events(event_name, occurred_at)")
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS patients (
                id {id_definition},
                owner_user_id BIGINT NOT NULL,
                name_encrypted TEXT NOT NULL,
                phone_encrypted TEXT,
                email_encrypted TEXT,
                timezone TEXT NOT NULL DEFAULT 'America/New_York',
                phone_hmac TEXT,
                sms_consent INTEGER NOT NULL DEFAULT 0,
                voice_consent INTEGER NOT NULL DEFAULT 0,
                email_consent INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        # Phone numbers are encrypted with a per-row nonce, so they cannot be
        # looked up by ciphertext. A deterministic HMAC gives inbound webhooks a
        # way to find the patient without storing the number in plaintext.
        if USING_POSTGRES:
            db.execute("ALTER TABLE patients ADD COLUMN IF NOT EXISTS phone_hmac TEXT")
        else:
            patient_columns = {row["name"] for row in db.execute("PRAGMA table_info(patients)")}
            if "phone_hmac" not in patient_columns:
                db.execute("ALTER TABLE patients ADD COLUMN phone_hmac TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_patients_phone_hmac ON patients(phone_hmac)")
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS appointments (
                id {id_definition},
                owner_user_id BIGINT NOT NULL,
                patient_id BIGINT NOT NULL,
                starts_at TEXT NOT NULL,
                clinician TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'scheduled'
                    CHECK (status IN ('scheduled', 'confirmed', 'cancelled', 'completed')),
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS reminder_jobs (
                id {id_definition},
                owner_user_id BIGINT NOT NULL,
                appointment_id BIGINT NOT NULL,
                channel TEXT NOT NULL CHECK (channel IN ('sms', 'voice', 'email')),
                scheduled_for TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'sent', 'failed', 'cancelled')),
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                sent_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(appointment_id, channel),
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS communication_events (
                id {id_definition},
                owner_user_id BIGINT,
                appointment_id BIGINT,
                patient_id BIGINT,
                channel TEXT NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
                outcome TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                provider_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY(appointment_id) REFERENCES appointments(id) ON DELETE SET NULL,
                FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE SET NULL
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS call_handoffs (
                id {id_definition},
                owner_user_id BIGINT,
                caller_phone_encrypted TEXT,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'transferred', 'resolved')),
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        # Maps an inbound Twilio number to the practice that owns it, so calls
        # can be attributed to a tenant and surfaced in that tenant's queue.
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS practice_phone_numbers (
                id {id_definition},
                owner_user_id BIGINT NOT NULL,
                phone_number TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        if USING_POSTGRES:
            db.execute("ALTER TABLE call_handoffs ADD COLUMN IF NOT EXISTS owner_user_id BIGINT")
        else:
            handoff_columns = {row["name"] for row in db.execute("PRAGMA table_info(call_handoffs)")}
            if "owner_user_id" not in handoff_columns:
                db.execute("ALTER TABLE call_handoffs ADD COLUMN owner_user_id BIGINT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_appointments_owner_start ON appointments(owner_user_id, starts_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reminder_jobs_due ON reminder_jobs(status, scheduled_for)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_analytics_occurred ON analytics_events(occurred_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_owner_time ON communication_events(owner_user_id, created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_handoffs_owner_status ON call_handoffs(owner_user_id, status)")

# Schema creation happens in the lifespan handler, not at import time, so that
# importing this module has no side effects.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=False)

# ── RATE LIMITER ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── APP ───────────────────────────────────────────────────────────────────────
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=COOKIE_SECURE,
    same_site="lax",
    max_age=600,
)

if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_BASE_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── HIPAA SECURITY HEADERS ────────────────────────────────────────────────────
def _content_security_policy() -> str:
    """Build the CSP, tightening script-src once the legacy pages are retired.

    The Astro build emits no inline <script>, and /admin's script now lives in
    /static/admin.js, so once FRONTEND_BASE_URL is set nothing this process
    serves needs 'unsafe-inline' for scripts — an injected handler cannot
    execute at all. Until then the legacy HTML files still carry inline scripts
    and would break under the strict policy.

    style-src keeps 'unsafe-inline' either way. Inline CSS is a far weaker
    vector than inline JS, and connect-src 'self' independently blocks the
    exfiltration path that makes an injection worth attempting.
    """
    script_src = "script-src 'self'" if FRONTEND_BASE_URL else "script-src 'self' 'unsafe-inline'"
    return "; ".join(
        (
            "default-src 'self'",
            script_src,
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
        )
    )

# Paths that may carry patient data or credentials must never be stored by any
# cache. Everything else gets a policy appropriate to its content.
NO_STORE_PREFIXES = ("/api/", "/auth/", "/webhooks/")


@app.middleware("http")
async def add_request_context(request: Request, call_next):
    """Bind a correlation id to every request and return it to the client.

    Pairs with the extraction error reference, so a user can quote one value and
    have it match a log line.
    """
    incoming = request.headers.get("X-Request-ID", "")
    request_id = incoming[:64] if incoming else secrets.token_hex(8)
    token = request_id_var.set(request_id)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = _content_security_policy()

    path = request.url.path
    if path.startswith(NO_STORE_PREFIXES):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Vary"] = "Cookie"
    elif path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        # HTML shells hold no patient data — it arrives over fetch — so they may
        # be revalidated rather than re-downloaded.
        response.headers["Cache-Control"] = "no-cache"
    return response

# ── AES-256-GCM UTILITIES ─────────────────────────────────────────────────────
# Ciphertext is tagged with the key version that produced it, so a compromised
# key can be retired without taking the application offline to re-encrypt every
# row at once. Values written before versioning carry no prefix and are read
# with the legacy key.
#
# Format: "v<n>:<base64(nonce || ciphertext)>"
# The base64 alphabet contains no colon, so the separator unambiguously
# distinguishes a versioned value from a legacy one.
_VERSION_SEPARATOR = ":"


def _load_key_ring() -> tuple[dict[int, bytes], int]:
    """Collect every key the application can decrypt with, and the write key.

    ENCRYPTION_KEY is version 1. Additional versions come from
    ENCRYPTION_KEY_V2, ENCRYPTION_KEY_V3, and so on; ENCRYPTION_KEY_CURRENT
    selects which one new writes use.
    """
    ring = {1: ENCRYPTION_KEY}
    for version in range(2, 10):
        encoded = os.getenv(f"ENCRYPTION_KEY_V{version}", "").strip()
        if encoded:
            ring[version] = _load_encryption_key(encoded)
    current = int(os.getenv("ENCRYPTION_KEY_CURRENT", max(ring)))
    if current not in ring:
        raise RuntimeError(
            f"ENCRYPTION_KEY_CURRENT={current} has no matching key. Available: {sorted(ring)}"
        )
    return ring, current


KEY_RING, CURRENT_KEY_VERSION = _load_key_ring()


def aes_encrypt(plaintext: str) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(KEY_RING[CURRENT_KEY_VERSION]).encrypt(nonce, plaintext.encode(), None)
    body = base64.b64encode(nonce + ct).decode()
    return f"v{CURRENT_KEY_VERSION}{_VERSION_SEPARATOR}{body}"


def aes_decrypt(token: str) -> str:
    version, _, body = token.partition(_VERSION_SEPARATOR)
    if body and version.startswith("v") and version[1:].isdigit():
        key = KEY_RING.get(int(version[1:]))
        if key is None:
            raise InvalidTag(f"No key available for {version}")
    else:
        # Written before key versioning existed.
        key, body = KEY_RING[1], token
    raw = base64.b64decode(body)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()


def aes_needs_rotation(token: str | None) -> bool:
    """True when a stored value was written under a superseded key."""
    if not token:
        return False
    version, _, body = token.partition(_VERSION_SEPARATOR)
    if not (body and version.startswith("v") and version[1:].isdigit()):
        return True
    return int(version[1:]) != CURRENT_KEY_VERSION

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode()

def _utcnow() -> datetime:
    return datetime.now(UTC)

def _normalize_email(email: str) -> str:
    return email.strip().lower()

def _password_is_valid(password: str) -> bool:
    return 12 <= len(password) <= 128

def _authenticate_user(email: str, password: str):
    with _db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (_normalize_email(email),)).fetchone()
    password_hash = user["password_hash"] if user and user["password_hash"] else DUMMY_PASSWORD_HASH
    valid = bcrypt.checkpw(password.encode(), password_hash.encode())
    return user if user and valid else None

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def _set_auth_cookies(response: Response, user) -> None:
    csrf_token = secrets.token_urlsafe(32)
    token = create_access_token(
        {
            "sub": str(user["id"]),
            "email": user["email"],
            "full_name": user["full_name"],
            "sv": user["session_version"],
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    max_age = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        "mobillity_session", token, max_age=max_age, httponly=True,
        secure=COOKIE_SECURE, samesite="lax", path="/",
    )
    response.set_cookie(
        "mobillity_csrf", csrf_token, max_age=max_age, httponly=False,
        secure=COOKIE_SECURE, samesite="lax", path="/",
    )

def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("mobillity_session", path="/")
    response.delete_cookie("mobillity_csrf", path="/")

def _require_csrf(request: Request) -> None:
    cookie_token = request.cookies.get("mobillity_csrf")
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")

def get_current_user(request: Request, token: str | None = Depends(oauth2_scheme)):
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        encoded = token or request.cookies.get("mobillity_session")
        if not encoded:
            raise exc
        payload = jwt.decode(encoded, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub", ""))
        with _db() as db:
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or payload.get("sv") != user["session_version"]:
            raise exc
        return user
    except JWTError as error:
        raise exc from error
    except (TypeError, ValueError) as error:
        raise exc from error

def _is_admin(user) -> bool:
    return _normalize_email(user["email"]) in ADMIN_EMAILS

def get_admin_user(current_user=Depends(get_current_user)):
    if not _is_admin(current_user):
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return current_user

def _purge_expired_analytics(db: _Database) -> None:
    cutoff = (_utcnow() - timedelta(days=ANALYTICS_RETENTION_DAYS)).isoformat()
    db.execute("DELETE FROM analytics_events WHERE occurred_at < ?", (cutoff,))

def _record_event(user_id: int, event_name: str, page: str = "app") -> None:
    """Record one allowlisted event.

    Retention purging deliberately does not happen here. Running a full-table
    DELETE scan on every page view is expensive and pointless — the scheduler
    purges hourly, and the admin dashboard purges before it reads.
    """
    with _db() as db:
        db.execute(
            """INSERT INTO analytics_events(user_id, event_name, page, occurred_at)
               SELECT ?, ?, ?, ? WHERE EXISTS (
                   SELECT 1 FROM users WHERE id = ? AND analytics_enabled = 1
               )""",
            (user_id, event_name, page, _utcnow().isoformat(), user_id),
        )

def _create_action_token(user_id: int, purpose: str) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = _utcnow() + timedelta(minutes=ACTION_TOKEN_EXPIRE_MINUTES)
    with _db() as db:
        db.execute(
            "UPDATE action_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL",
            (_utcnow().isoformat(), user_id, purpose),
        )
        db.execute(
            "INSERT INTO action_tokens(user_id, purpose, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, purpose, token_hash, expires_at.isoformat(), _utcnow().isoformat()),
        )
    return raw_token

def _consume_action_token(raw_token: str, purpose: str):
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with _db() as db:
        row = db.execute(
            """SELECT action_tokens.id AS token_id, action_tokens.expires_at, action_tokens.used_at,
                      users.*
               FROM action_tokens JOIN users ON users.id = action_tokens.user_id
               WHERE action_tokens.token_hash = ? AND action_tokens.purpose = ?""",
            (token_hash, purpose),
        ).fetchone()
        if not row or row["used_at"] or datetime.fromisoformat(row["expires_at"]) <= _utcnow():
            return None
        db.execute("UPDATE action_tokens SET used_at = ? WHERE id = ?", (_utcnow().isoformat(), row["token_id"]))
    return row

def _send_email(to_email: str, subject: str, body: str) -> None:
    brevo_api_key = os.getenv("BREVO_API_KEY")
    if brevo_api_key:
        from_email = os.getenv("BREVO_FROM_EMAIL") or os.getenv("SMTP_FROM")
        if not from_email:
            raise RuntimeError("BREVO_FROM_EMAIL is required when BREVO_API_KEY is configured.")
        try:
            response = httpx.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "accept": "application/json",
                    "api-key": brevo_api_key,
                    "content-type": "application/json",
                },
                json={
                    "sender": {
                        "name": os.getenv("BREVO_FROM_NAME", "moBILLity"),
                        "email": from_email,
                    },
                    "to": [{"email": to_email}],
                    "subject": subject,
                    "textContent": body,
                },
                timeout=15,
            )
            response.raise_for_status()
            return
        except httpx.HTTPError as exc:
            raise RuntimeError("Email API request failed.") from exc

    smtp_host = os.getenv("SMTP_HOST")
    if not smtp_host:
        if os.getenv("AUTH_DEV_SHOW_LINKS", "false").lower() == "true" and not IS_PRODUCTION:
            logger.warning("Development auth email for %s: %s", to_email, body)
            return
        raise RuntimeError("Email delivery is not configured.")

    message = EmailMessage()
    message["From"] = os.getenv("SMTP_FROM", "no-reply@mobillity.local")
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as smtp:
            if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
                smtp.starttls()
            if os.getenv("SMTP_USERNAME"):
                smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise RuntimeError("SMTP delivery failed.") from exc

def _send_verification_email(user) -> None:
    token = _create_action_token(user["id"], "verify_email")
    link = f"{APP_BASE_URL}/verify-email?token={token}"
    _send_email(user["email"], "Verify your moBILLity email", f"Verify your email within one hour:\n\n{link}")

def _send_reset_email(user) -> None:
    token = _create_action_token(user["id"], "reset_password")
    link = f"{APP_BASE_URL}/reset-password?token={token}"
    _send_email(user["email"], "Reset your moBILLity password", f"Reset your password within one hour:\n\n{link}\n\nIf you did not request this, ignore this email.")

# Google OpenID Connect. Google accounts are considered email-verified only when
# Google's signed ID token includes email_verified=true.
oauth = OAuth()
if os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# ── OPENAI CLIENT ─────────────────────────────────────────────────────────────
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ── CONFIDENCE THRESHOLD ──────────────────────────────────────────────────────
# Codes below this threshold are moved to suggested_codes at parse time.
# Raise this value to increase precision; lower it to increase recall.
# Measured, not guessed: tests/benchmark.py sweeps this. Against the 100-case
# set the curve is flat from 0.50 to 0.90 and steps hard at 0.95 -- precision
# 0.781 -> 0.941 for a recall cost of 0.904 -> 0.877. That trades 4 true
# positives for 29 false ones, which is the right direction for billing.
# Re-measure after any prompt change: tightening the prompt moved this step
# up from 0.90, so the operating point is a property of the prompt, not a
# constant.
CONFIRMED_CONFIDENCE_THRESHOLD = 0.95

# ── PHYSICIAN BILLING PROMPT ──────────────────────────────────────────────────
# NOTE: Uses a two-pass chain-of-thought style:
#   1. The system message instructs the model to reason carefully before emitting JSON.
#   2. The user prompt contains strict rules + few-shot HCPCS examples to anchor
#      the model's understanding of HCPCS Level II codes alongside ICD-10 and CPT.

SYSTEM_PROMPT = """You are a board-certified professional medical coder and physician billing specialist with 20+ years of experience in ICD-10-CM, ICD-10-PCS, CPT, and HCPCS Level II coding.

PRECISION RULES — follow these exactly to achieve ≥90% coding accuracy:
1. Only assign a code when there is EXPLICIT, UNAMBIGUOUS documentation supporting it. When in doubt, move it to suggested_codes.
2. For ICD-10-CM: always code to the highest specificity — include 7th character, laterality, episode of care, and severity where required. A truncated code (e.g., S52 without full extension) is WRONG.
3. For CPT: verify that the procedure is fully documented (operative note, procedure note, or attending attestation). Do not infer a procedure from a diagnosis alone. This restriction is about procedures, NOT about the visit itself:
   - Nearly every outpatient encounter carries an evaluation and management code. Do not omit it. When total time is documented, select by time: established patient 99212 (10-19 min), 99213 (20-29), 99214 (30-39), 99215 (40-54); new patient 99202 (15-29), 99203 (30-44), 99204 (45-59), 99205 (60-74). Preventive visits use the age-banded 993xx/994xx series.
   - When a drug or vaccine is administered, code BOTH the product AND its administration (for example 96372 for a therapeutic injection, 90471 for the first vaccine administered).
   - Match documented size, count, or extent to the correct code in a banded family: a 3.5 cm simple repair is 12002, not 12001.
4. For HCPCS Level II: assign a code when, and only when, the note states the item was dispensed, administered, or ordered AT THIS ENCOUNTER. When the note does say so, do not omit it — a dispensed brace, splint, monitor, or concentrator is billable. Then:
   - J-codes are for drugs given by INJECTION OR INFUSION only. NEVER assign a J-code for an oral, topical, inhaled, or nebulized medication, and never for a prescription the patient will fill at a pharmacy.
   - NEVER assign a DME or orthotic code for equipment the patient already owns or is already using. "Compliant with CPAP" and "on an insulin pump" are history, not a supply being billed today.
   - Match the documented dose or size exactly. Drug J-codes are dose-banded and the wrong band is the wrong code.
5. NEVER code "possible," "probable," "suspected," "rule out," or "likely" conditions as confirmed diagnoses.
6. Apply correct sequencing: principal/primary diagnosis first, then complications, then comorbidities.
7. Set confidence as a strict self-assessment:
   - 0.90–1.00: Code is exact, unambiguous, and fully documented — safe to bill.
   - 0.75–0.89: Code is correct but documentation has minor gaps — bill with addendum recommended.
   - <0.75: Too uncertain — place in suggested_codes instead.
8. Never hallucinate codes. If you are uncertain of the exact code, use suggested_codes with documentation_needed.

HCPCS LEVEL II FORMAT REFERENCE — these show what a HCPCS code looks like.
They are NOT a menu and NOT suggestions. Never emit one of these codes
unless the note documents that exact item at this encounter:
- E0601 — Continuous positive airway pressure (CPAP) device
- L3000 — Foot insert, removable, molded to patient model
- J0696 — Injection, ceftriaxone sodium, per 250mg
- A4570 — Splint
- K0001 — Standard manual wheelchair
- G0008 — Administration of influenza virus vaccine

You MUST respond ONLY with valid JSON — no markdown fences, no prose, no explanation outside the JSON object.
"""

PROMPT_TEMPLATE = """Extract all billable medical codes from the clinical note below: ICD-10-CM diagnosis codes, CPT procedure codes, and HCPCS Level II codes where an item was actually dispensed or administered.

Return this exact JSON structure:
{
  "confirmed_codes": [
    {
      "type": "Diagnosis | Procedure | Supply | Drug | DME | Orthotic | Other",
      "code_type": "ICD-10-CM | ICD-10-PCS | CPT | HCPCS",
      "code": "<exact full code with all required characters>",
      "description": "<full official description>",
      "reasoning": "<quote or paraphrase the specific documentation that supports this code>",
      "confidence": <float 0.75–1.0>,
      "documentation_strength": "strong | moderate | weak",
      "billing_priority": "primary | secondary | procedural | supplemental"
    }
  ],
  "suggested_codes": [
    {
      "code_type": "ICD-10-CM | ICD-10-PCS | CPT | HCPCS",
      "code": "<exact code>",
      "description": "<full official description>",
      "reason_suggested": "<why this code may apply>",
      "documentation_needed": "<what additional documentation would confirm this code>"
    }
  ]
}

Rules:
- confirmed_codes: only codes with confidence ≥ 0.75 and strong/moderate documentation.
- suggested_codes: codes that clinically likely apply but need more documentation, OR any code where confidence < 0.75.
- Include a HCPCS code for every item dispensed, administered, or ordered at this encounter, and for nothing else. Many notes have none; a note that dispenses equipment has one.
- Every ICD-10-CM code must be a complete billable code. Codes that have been subdivided are not billable at the parent level: M54.5, N18.3, and similar stems require further characters. If you are unsure a code is complete, it is not.
- Do not fabricate codes to fill a section. An empty array is a valid answer.

Clinical Note:
"""

# ── RESPONSE PARSING ──────────────────────────────────────────────────────────
# ── ICD-10-CM CODE VALIDATION ────────────────────────────────────────────────
# The 2025 CMS billable-code list (public domain), shipped compressed. The model
# reliably emits parent stems that were subdivided in recent updates -- M54.5 and
# N18.3 both stopped being billable in FY2022 -- and a payer rejects those
# outright, which is worse than a merely debatable code.
#
# Scope note: this only helps ICD-10-CM. The model's invented HCPCS codes
# (J8499 for an oral statin, J0456 for oral azithromycin) are all VALID codes
# used in the wrong place, so no code list can catch them; only the prompt rules
# above address that.

ICD10_CODES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "data", "icd10cm_2025_codes.txt.gz")
_ICD10_CODES: set[str] | None = None


def _icd10_codes() -> set[str]:
    """Load the billable-code set once, on first use."""
    global _ICD10_CODES
    if _ICD10_CODES is None:
        try:
            with gzip.open(ICD10_CODES_FILE, "rt", encoding="ascii") as handle:
                _ICD10_CODES = {line.strip() for line in handle if line.strip()}
        except OSError:
            # Validation is an improvement, not a dependency. Without the file
            # every code passes through, which is the old behaviour.
            logger.warning("ICD-10 code list unavailable at %s; skipping validation",
                           ICD10_CODES_FILE)
            _ICD10_CODES = set()
    return _ICD10_CODES


def icd10_is_billable(code: str) -> bool:
    """True when the code is a complete billable ICD-10-CM code.

    Returns True when the list could not be loaded, so a missing data file
    degrades to the previous permissive behaviour rather than rejecting
    everything.
    """
    codes = _icd10_codes()
    if not codes:
        return True
    return str(code).strip().upper().replace(".", "").replace(" ", "") in codes


def _reject_unbillable_codes(data: dict) -> dict:
    """Demote confirmed ICD-10-CM codes that are not billable as written.

    Demoted rather than deleted: the code is usually the right family with a
    missing character, so a coder wants to see it and add the specificity.
    """
    kept, demoted = [], []
    for item in data.get("confirmed_codes") or []:
        if not isinstance(item, dict):
            continue
        system = str(item.get("code_type", "")).strip().upper()
        if system.startswith("ICD-10-CM") and not icd10_is_billable(item.get("code", "")):
            demoted.append({
                "code_type": item.get("code_type", ""),
                "code": item.get("code", ""),
                "description": item.get("description", ""),
                "reason_suggested": (
                    "Not a billable ICD-10-CM code as written — this stem was "
                    "subdivided and requires further characters."
                ),
                "documentation_needed": (
                    "Document the detail needed to select a complete code "
                    "(laterality, severity, episode, or site)."
                ),
            })
        else:
            kept.append(item)

    if demoted:
        logger.info("rejected %d non-billable ICD-10-CM code(s)", len(demoted))
    data["confirmed_codes"] = kept
    data["suggested_codes"] = (data.get("suggested_codes") or []) + demoted
    return data


def _apply_confidence_threshold(data: dict) -> dict:
    """Move under-confident confirmed codes into suggestions.

    A false confirmed code is far more costly than a missed suggestion, so the
    threshold biases toward precision.
    """
    confirmed = []
    downgraded = []

    for item in data.get("confirmed_codes") or []:
        if not isinstance(item, dict):
            continue
        try:
            item["confidence"] = round(float(item.get("confidence", 0)), 2)
        except (TypeError, ValueError):
            item["confidence"] = 0.0

        if item["confidence"] < CONFIRMED_CONFIDENCE_THRESHOLD:
            downgraded.append({
                "code_type": item.get("code_type", ""),
                "code": item.get("code", ""),
                "description": item.get("description", ""),
                "reason_suggested": (
                    f"Confidence {item['confidence']} below threshold — "
                    f"{item.get('reasoning', '')}"
                ),
                "documentation_needed": "Strengthen documentation to support billing.",
            })
        else:
            confirmed.append(item)

    data["confirmed_codes"] = confirmed
    data["suggested_codes"] = (data.get("suggested_codes") or []) + downgraded
    return _reject_unbillable_codes(data)


def _parse_llm_response(text: str) -> dict:
    cleaned = re.sub(r"```json|```", "", text).strip()

    object_start, object_end = cleaned.find("{"), cleaned.rfind("}")
    array_start, array_end = cleaned.find("["), cleaned.rfind("]")

    # An array of code objects also contains braces, so the object branch would
    # otherwise always win and extract a single inner object — silently dropping
    # every code. Whichever delimiter appears first determines the shape.
    prefer_array = array_start != -1 and (object_start == -1 or array_start < object_start)
    if prefer_array and array_end > array_start:
        try:
            items = json.loads(cleaned[array_start:array_end + 1])
            if isinstance(items, list):
                return _apply_confidence_threshold(
                    {"confirmed_codes": items, "suggested_codes": []}
                )
        except (ValueError, TypeError):
            pass

    if object_start == -1 or object_end == -1 or object_end <= object_start:
        return {"confirmed_codes": [], "suggested_codes": [], "raw": cleaned}
    candidate = cleaned[object_start:object_end + 1]

    try:
        data = json.loads(candidate)
        if not isinstance(data, dict):
            return {"confirmed_codes": [], "suggested_codes": [], "raw": cleaned}
        return _apply_confidence_threshold(data)
    except (ValueError, TypeError):
        return {"confirmed_codes": [], "suggested_codes": [], "raw": cleaned}


def extract_medical_codes(note: str) -> dict:
    response = client.chat.completions.create(
        # gpt-4o substantially outperforms gpt-4o-mini on medical coding precision.
        # For cost-sensitive deployments, use "gpt-4o-mini" and accept ~5–10% lower accuracy.
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": PROMPT_TEMPLATE + note.strip(),
            },
        ],
        temperature=0,       # deterministic output — critical for coding accuracy
        top_p=1,
        response_format={"type": "json_object"},
    )
    return _parse_llm_response(response.choices[0].message.content)


# ── CLINICAL WORKFLOW AUTOMATION ─────────────────────────────────────────────
REMINDER_LEAD_TIME = timedelta(days=int(os.getenv("REMINDER_LEAD_DAYS", "7")))
# Used when a visit is booked inside the normal lead window.
SHORT_NOTICE_LEAD_TIME = timedelta(hours=int(os.getenv("REMINDER_SHORT_NOTICE_HOURS", "24")))
# Below this, a reminder has no useful purpose.
MINIMUM_REMINDER_NOTICE = timedelta(hours=int(os.getenv("REMINDER_MINIMUM_NOTICE_HOURS", "2")))
# TCPA calling window, in the patient's local time.
QUIET_HOURS_END = 8
QUIET_HOURS_START = 21
DEFAULT_TIMEZONE = os.getenv("DEFAULT_PATIENT_TIMEZONE", "America/New_York")
KNOWN_TIMEZONES = available_timezones()
FRONT_DESK_KEYWORDS = {
    "bill", "billing", "insurance", "refund", "payment", "medical record",
    "records", "referral", "prior authorization", "complaint", "manager",
    "change provider", "new patient",
}


UNREADABLE = "[unreadable]"

# Standard carrier opt-out and opt-in keywords.
SMS_STOP_KEYWORDS = {"stop", "stopall", "unsubscribe", "cancel", "end", "quit", "revoke", "optout"}
SMS_START_KEYWORDS = {"start", "unstop", "yes", "optin"}


def _normalize_phone(value: str) -> str:
    """Reduce a phone number to digits and a leading + for stable hashing."""
    cleaned = re.sub(r"[^\d+]", "", value or "")
    return cleaned


def phone_fingerprint(value: str) -> str | None:
    """Deterministic HMAC of a phone number, for lookup without plaintext.

    Keyed separately from the encryption key so that a lookup index leak does not
    also compromise stored ciphertext.
    """
    normalized = _normalize_phone(value)
    if not normalized:
        return None
    return hmac.new(PHONE_HMAC_KEY, normalized.encode(), hashlib.sha256).hexdigest()


def _encrypt_optional(value: str | None) -> str | None:
    cleaned = (value or "").strip()
    return aes_encrypt(cleaned) if cleaned else None


def _decrypt_optional(value: str | None) -> str:
    """Decrypt a nullable column, degrading to a sentinel rather than raising.

    The overview endpoint decrypts every patient across four result sets, so one
    unreadable row would otherwise take down the whole page and hide the ninety-
    nine records that are fine.
    """
    if not value:
        return ""
    try:
        return aes_decrypt(value)
    except (InvalidTag, ValueError, binascii.Error):
        logger.error("Could not decrypt a stored value; returning a placeholder.")
        return UNREADABLE


def _iso_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _appointment_row(db: "_Database", appointment_id: int, owner_user_id: int):
    return db.execute(
        """SELECT appointments.*, patients.name_encrypted, patients.phone_encrypted,
                  patients.email_encrypted, patients.sms_consent,
                  patients.voice_consent, patients.email_consent,
                  patients.timezone AS patient_timezone
           FROM appointments JOIN patients ON patients.id = appointments.patient_id
           WHERE appointments.id = ? AND appointments.owner_user_id = ?""",
        (appointment_id, owner_user_id),
    ).fetchone()


def _patient_json(row) -> dict:
    return {
        "id": row["id"],
        "name": _decrypt_optional(row["name_encrypted"]),
        "phone": _decrypt_optional(row["phone_encrypted"]),
        "email": _decrypt_optional(row["email_encrypted"]),
        "timezone": row["timezone"],
        "consent": {
            "sms": bool(row["sms_consent"]),
            "voice": bool(row["voice_consent"]),
            "email": bool(row["email_consent"]),
        },
        "created_at": row["created_at"],
    }


def _appointment_json(row) -> dict:
    result = {
        "id": row["id"],
        "patient_id": row["patient_id"],
        "starts_at": row["starts_at"],
        "clinician": row["clinician"],
        "location": row["location"],
        "status": row["status"],
    }
    if "name_encrypted" in row.keys():
        result["patient_name"] = _decrypt_optional(row["name_encrypted"])
    return result


def _reminder_send_time(appointment) -> datetime | None:
    """Choose when a reminder should go out, or None if it should be skipped.

    Subtracting a flat seven days meant a visit booked three days out scheduled
    its reminder four days in the past, so the dispatcher fired it within the
    minute — the patient got a 'reminder' seconds after booking. Fall back to a
    24-hour notice inside the lead window, and skip entirely when the visit is
    too close for a reminder to be useful.
    """
    starts_at = datetime.fromisoformat(appointment["starts_at"])
    if starts_at.tzinfo is None:
        starts_at = starts_at.replace(tzinfo=UTC)
    now = _utcnow()
    if starts_at - now < MINIMUM_REMINDER_NOTICE:
        return None
    scheduled_for = starts_at - REMINDER_LEAD_TIME
    if scheduled_for <= now:
        scheduled_for = starts_at - SHORT_NOTICE_LEAD_TIME
    # Never schedule in the past: a same-day booking must not trigger an
    # immediate phone call.
    return max(scheduled_for, now + timedelta(minutes=5))


def _within_quiet_hours(moment: datetime, appointment) -> bool:
    """TCPA restricts calls and texts to 8am-9pm in the recipient's local time."""
    local_hour = moment.astimezone(_appointment_timezone(appointment)).hour
    return local_hour < QUIET_HOURS_END or local_hour >= QUIET_HOURS_START


def _shift_out_of_quiet_hours(moment: datetime, appointment) -> datetime:
    zone = _appointment_timezone(appointment)
    local = moment.astimezone(zone)
    if local.hour < QUIET_HOURS_END:
        local = local.replace(hour=QUIET_HOURS_END, minute=0, second=0, microsecond=0)
    elif local.hour >= QUIET_HOURS_START:
        local = (local + timedelta(days=1)).replace(
            hour=QUIET_HOURS_END, minute=0, second=0, microsecond=0
        )
    return local.astimezone(UTC)


def _schedule_reminders(db: "_Database", appointment) -> int:
    if appointment["status"] != "scheduled":
        return 0
    scheduled_for = _reminder_send_time(appointment)
    if scheduled_for is None:
        return 0
    consent = {
        "sms": bool(appointment["sms_consent"]) and bool(appointment["phone_encrypted"]),
        "voice": bool(appointment["voice_consent"]) and bool(appointment["phone_encrypted"]),
        "email": bool(appointment["email_consent"]) and bool(appointment["email_encrypted"]),
    }
    created = 0
    for channel, allowed in consent.items():
        if not allowed:
            continue
        channel_time = scheduled_for
        # Email may arrive overnight; a phone ringing at 3am may not.
        if channel in ("sms", "voice") and _within_quiet_hours(channel_time, appointment):
            channel_time = _shift_out_of_quiet_hours(channel_time, appointment)
        cursor = db.execute(
            """INSERT INTO reminder_jobs
               (owner_user_id, appointment_id, channel, scheduled_for, created_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (appointment_id, channel) DO NOTHING""",
            (
                appointment["owner_user_id"],
                appointment["id"],
                channel,
                _iso_datetime(channel_time),
                _utcnow().isoformat(),
            ),
        )
        created += cursor.rowcount
    return created


def _appointment_timezone(appointment) -> ZoneInfo:
    """Resolve a patient's timezone, falling back to the practice default."""
    keys = appointment.keys() if hasattr(appointment, "keys") else ()
    name = (appointment["patient_timezone"] if "patient_timezone" in keys else "") or ""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        if name:
            logger.warning("Unknown patient timezone %r; falling back to %s", name, DEFAULT_TIMEZONE)
        return ZoneInfo(DEFAULT_TIMEZONE)


def _format_when(moment: datetime) -> str:
    """Format a local datetime without glibc-only strftime extensions.

    '%-d' and '%-I' raise ValueError on Windows, which previously made every
    reminder fail on a non-Linux host.
    """
    hour = moment.hour % 12 or 12
    meridiem = "AM" if moment.hour < 12 else "PM"
    zone = moment.strftime("%Z") or "local time"
    return f"{moment:%A, %B} {moment.day} at {hour}:{moment.minute:02d} {meridiem} {zone}"


def _reminder_copy(appointment, channel: str) -> tuple[str, str]:
    patient_name = _decrypt_optional(appointment["name_encrypted"])
    first_name = patient_name.split()[0] if patient_name else "there"
    # Patients read their own local time. Sending UTC is worse than sending
    # nothing, because a patient who trusts it arrives at the wrong hour.
    starts = datetime.fromisoformat(appointment["starts_at"]).astimezone(
        _appointment_timezone(appointment)
    )
    when = _format_when(starts)
    practice = os.getenv("PRACTICE_NAME", "your care team")
    location = f" at {appointment['location']}" if appointment["location"] else ""
    if channel == "email":
        subject = f"Appointment reminder for {starts:%B} {starts.day}"
        body = (
            f"Hello {first_name},\n\nThis is a reminder from {practice} that you have "
            f"an appointment on {when}{location}.\n\n"
            "Please call the office if you need to reschedule. Do not reply with medical information."
        )
        return subject, body
    body = (
        f"Hello {first_name}, this is {practice}. Reminder: your appointment is {when}{location}. "
        "Call the office to reschedule. Reply STOP to opt out."
    )
    return "", body


def _twilio_request(path: str, data: dict) -> dict:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    if not account_sid or not auth_token:
        raise RuntimeError("Twilio delivery is not configured.")
    response = httpx.post(
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/{path}",
        data=data,
        auth=(account_sid, auth_token),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def _deliver_reminder(appointment, channel: str) -> str:
    subject, body = _reminder_copy(appointment, channel)
    delivery_mode = os.getenv("COMMUNICATION_DELIVERY_MODE", "preview").lower()
    if delivery_mode == "preview":
        return f"preview-{secrets.token_hex(8)}"
    if channel == "email":
        _send_email(_decrypt_optional(appointment["email_encrypted"]), subject, body)
        return f"smtp-{secrets.token_hex(8)}"

    twilio_number = os.getenv("TWILIO_PHONE_NUMBER")
    if not twilio_number:
        raise RuntimeError("TWILIO_PHONE_NUMBER is not configured.")
    to_number = _decrypt_optional(appointment["phone_encrypted"])
    if channel == "sms":
        result = _twilio_request(
            "Messages.json", {"From": twilio_number, "To": to_number, "Body": body}
        )
    else:
        voice_url = f"{APP_BASE_URL}/webhooks/twilio/reminder-voice?appointment_id={appointment['id']}"
        result = _twilio_request(
            "Calls.json", {"From": twilio_number, "To": to_number, "Url": voice_url}
        )
    return result.get("sid", "")


MAX_REMINDER_ATTEMPTS = 3
STUCK_JOB_TIMEOUT = timedelta(minutes=15)


def _requeue_stuck_jobs(db: _Database, now: datetime) -> int:
    """Recover jobs claimed by a process that died before recording an outcome.

    Without this, a crash between claim and record strands a job in 'processing'
    forever. Jobs that have exhausted their attempts are failed rather than
    retried, so a permanently broken recipient cannot loop.
    """
    cutoff = _iso_datetime(now - STUCK_JOB_TIMEOUT)
    db.execute(
        """UPDATE reminder_jobs SET status = 'failed', last_error = ?
           WHERE status = 'processing' AND created_at < ? AND attempts >= ?""",
        (f"Abandoned after {MAX_REMINDER_ATTEMPTS} attempts", cutoff, MAX_REMINDER_ATTEMPTS),
    )
    return db.execute(
        """UPDATE reminder_jobs SET status = 'pending'
           WHERE status = 'processing' AND created_at < ? AND attempts < ?""",
        (cutoff, MAX_REMINDER_ATTEMPTS),
    ).rowcount


def _claim_due_reminders(now: datetime, limit: int, owner_user_id: int | None) -> list:
    """Phase one: atomically claim due jobs and commit before any network call.

    The commit is what makes the claim visible to other workers. Holding it open
    across provider calls would both serialise the dispatchers and roll back
    delivery records if the process died mid-batch.
    """
    claimed: list = []
    with _db() as db:
        _requeue_stuck_jobs(db, now)
        # A NULL owner_user_id parameter means "all tenants", expressed in SQL so
        # that no part of the statement is built by string concatenation.
        jobs = db.execute(
            """SELECT * FROM reminder_jobs
               WHERE status = 'pending' AND scheduled_for <= ?
                 AND (? IS NULL OR owner_user_id = ?)
               ORDER BY scheduled_for LIMIT ?""",
            (_iso_datetime(now), owner_user_id, owner_user_id, limit),
        ).fetchall()
        for job in jobs:
            if db.execute(
                """UPDATE reminder_jobs SET status = 'processing', attempts = attempts + 1
                   WHERE id = ? AND status = 'pending'""",
                (job["id"],),
            ).rowcount:
                claimed.append(dict(job))
    return claimed


def _record_reminder_outcome(job: dict, provider_id: str | None, error: str | None) -> None:
    """Phase three: persist one job's terminal state in its own transaction."""
    with _db() as db:
        if error is not None:
            db.execute(
                "UPDATE reminder_jobs SET status = 'failed', last_error = ? WHERE id = ?",
                (error[:500], job["id"]),
            )
            return
        sent_at = _utcnow().isoformat()
        db.execute(
            "UPDATE reminder_jobs SET status = 'sent', sent_at = ?, last_error = NULL WHERE id = ?",
            (sent_at, job["id"]),
        )
        db.execute(
            """INSERT INTO communication_events
               (owner_user_id, appointment_id, patient_id, channel, direction,
                outcome, detail, provider_id, created_at)
               VALUES (?, ?, ?, ?, 'outbound', 'sent', ?, ?, ?)""",
            (
                job["owner_user_id"], job["appointment_id"], job["patient_id"],
                job["channel"], "Appointment reminder", provider_id, sent_at,
            ),
        )


def dispatch_due_reminders(
    now: datetime | None = None,
    limit: int = 50,
    owner_user_id: int | None = None,
) -> dict:
    """Claim, deliver, then record — each phase committing independently.

    Manual dispatch passes owner_user_id so a practice only ever triggers its own
    reminders. The background scheduler runs unscoped across all tenants.
    """
    now = now or _utcnow()
    jobs = _claim_due_reminders(now, limit, owner_user_id)
    sent = failed = cancelled = 0

    for job in jobs:
        # Re-read the appointment outside the claim transaction; it may have been
        # cancelled between scheduling and now.
        with _db() as db:
            appointment = _appointment_row(db, job["appointment_id"], job["owner_user_id"])
        if not appointment or appointment["status"] not in ("scheduled", "confirmed"):
            with _db() as db:
                db.execute(
                    "UPDATE reminder_jobs SET status = 'cancelled' WHERE id = ?", (job["id"],)
                )
            cancelled += 1
            continue

        job["patient_id"] = appointment["patient_id"]
        try:
            provider_id = _deliver_reminder(appointment, job["channel"])
        except Exception as exc:
            dispatch_logger.exception(
                "Reminder delivery failed",
                extra={
                    "event": "reminder.failed", "job_id": job["id"],
                    "appointment_id": job["appointment_id"], "channel": job["channel"],
                    "attempts": job.get("attempts"),
                },
            )
            _record_reminder_outcome(job, None, str(exc))
            failed += 1
            continue
        # Delivery succeeded. Record it immediately so a crash on the next job
        # cannot roll this one back and cause a duplicate send on restart.
        _record_reminder_outcome(job, provider_id, None)
        dispatch_logger.info(
            "Reminder delivered",
            extra={
                "event": "reminder.sent", "job_id": job["id"],
                "appointment_id": job["appointment_id"], "channel": job["channel"],
                "provider_id": provider_id,
            },
        )
        sent += 1

    return {"processed": len(jobs), "sent": sent, "failed": failed, "cancelled": cancelled}


# ── PAGE ROUTES ───────────────────────────────────────────────────────────────
def _serve(filename: str) -> str:
    with open(os.path.join(BASE_DIR, filename), encoding="utf-8") as f:
        return f.read()


def _page(filename: str, path: str):
    """Serve a legacy page, or redirect to the canonical frontend once set.

    /admin deliberately does not use this: it stays server-rendered here because
    its access check runs before the HTML is returned.
    """
    if FRONTEND_BASE_URL:
        return RedirectResponse(f"{FRONTEND_BASE_URL}{path}", status_code=308)
    return HTMLResponse(_serve(filename))


@app.get("/", response_class=HTMLResponse)
def serve_landing():
    return _page("index.html", "/")


@app.get("/app", response_class=HTMLResponse)
def serve_app():
    return _page("app.html", "/app")

@app.get("/admin", response_class=HTMLResponse)
def serve_admin(request: Request):
    """Browser navigation deserves a redirect or a rendered page, not a raw JSON
    error body. The API behind this page enforces admin access independently."""
    try:
        # Pass token explicitly: called outside FastAPI's dependency injection,
        # the Depends(oauth2_scheme) default would arrive as a Depends object.
        user = get_current_user(request, token=None)
    except HTTPException:
        return RedirectResponse("/login?next=/admin", status_code=303)
    if not _is_admin(user):
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'><title>Not authorised</title>"
            "<body style=\"font-family:system-ui;padding:3rem;max-width:32rem\">"
            "<h1>Administrator access required</h1>"
            "<p>This account cannot view analytics. "
            "<a href='/app'>Return to the code extractor</a>.</p>",
            status_code=403,
        )
    return HTMLResponse(_serve("admin.html"))

@app.get("/privacy", response_class=HTMLResponse)
def serve_privacy():
    if FRONTEND_BASE_URL:
        return RedirectResponse(f"{FRONTEND_BASE_URL}/privacy", status_code=308)
    # The built page reads these from /api/privacy-config instead.
    return HTMLResponse(
        _serve("privacy.html")
        .replace("{{RETENTION_DAYS}}", str(ANALYTICS_RETENTION_DAYS))
        .replace("{{PRIVACY_CONTACT}}", html.escape(PRIVACY_CONTACT_EMAIL, quote=True))
    )


@app.get("/api/privacy-config")
def privacy_config():
    """Retention period and privacy contact, for the statically built page.

    These were previously substituted into privacy.html at serve time, which a
    static build cannot do. Serving them from the API keeps the notice accurate
    when the deployment's configuration changes, without a frontend rebuild —
    which matters because both values are compliance-visible.
    """
    return {
        "retention_days": ANALYTICS_RETENTION_DAYS,
        "privacy_contact": PRIVACY_CONTACT_EMAIL,
    }


@app.get("/workflows", response_class=HTMLResponse)
def serve_workflows():
    return _page("workflows.html", "/workflows")


@app.get("/login", response_class=HTMLResponse)
def serve_login():
    return _page("login.html", "/login")


@app.get("/signup", response_class=HTMLResponse)
def serve_signup():
    return _page("signup.html", "/signup")

@app.get("/forgot-password", response_class=HTMLResponse)
def serve_forgot_password():
    return _page("forgot-password.html", "/forgot-password")

@app.get("/reset-password", response_class=HTMLResponse)
def serve_reset_password():
    return _page("reset-password.html", "/reset-password")

@app.get("/verify-email", response_class=HTMLResponse)
def serve_verify_email():
    return _page("verify-email.html", "/verify-email")


# ── API ROUTES ────────────────────────────────────────────────────────────────
@app.get("/health")
def health(response: Response):
    """A health check that can fail. The previous one always returned ok, which
    meant it monitored nothing."""
    checks = {"database": "ok"}
    try:
        with _db() as db:
            db.execute("SELECT 1")
    except Exception:
        logger.exception("Health check: database unreachable")
        checks["database"] = "error"

    integrations = {
        "google_oauth": bool(getattr(oauth, "google", None)),
        "email": bool(os.getenv("BREVO_API_KEY") or os.getenv("SMTP_HOST")),
        "twilio": bool(os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN")),
    }
    healthy = all(value == "ok" for value in checks.values())
    if not healthy:
        response.status_code = 503
    return {
        "status": "ok" if healthy else "degraded",
        "checks": checks,
        "integrations": integrations,
        "dispatcher": "active" if _scheduler_enabled() else "inactive",
        "delivery_mode": os.getenv("COMMUNICATION_DELIVERY_MODE", "preview"),
    }


@app.post("/api/token")
@limiter.limit("5/minute")
def login(response: Response, request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = _authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user["email_verified"]:
        raise HTTPException(status_code=403, detail="Verify your email before signing in.")
    _set_auth_cookies(response, user)
    return {"message": "Signed in.", "user": {"email": user["email"], "full_name": user["full_name"]}}


class RegisterInput(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


@app.post("/api/register", status_code=201)
@limiter.limit("3/minute")
def register(request: Request, body: RegisterInput):
    if not _password_is_valid(body.password):
        raise HTTPException(status_code=400, detail="Password must be between 12 and 128 characters.")

    email = _normalize_email(str(body.email))
    with _db() as db:
        existing = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            if not existing["email_verified"] and existing["password_hash"]:
                try:
                    _send_verification_email(existing)
                except RuntimeError:
                    logger.exception("Could not resend verification email")
            return {"message": "If this email can be registered, a verification message has been sent."}
        cursor = db.execute(
            """INSERT INTO users(email, password_hash, full_name, email_verified, created_at)
               VALUES (?, ?, ?, 0, ?) RETURNING id""",
            (
                email,
                bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode(),
                (body.full_name or "").strip()[:120],
                _utcnow().isoformat(),
            ),
        )
        user_id = cursor.fetchone()["id"]
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    try:
        _send_verification_email(user)
    except RuntimeError as exc:
        logger.exception("Could not send verification email")
        raise HTTPException(status_code=503, detail="Account created, but email delivery is unavailable. Contact support.") from exc
    return {"message": "Check your email to verify your account before signing in."}


class EmailInput(BaseModel):
    email: EmailStr

@app.post("/api/resend-verification")
@limiter.limit("3/hour")
def resend_verification(request: Request, body: EmailInput):
    with _db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (_normalize_email(str(body.email)),)).fetchone()
    if user and not user["email_verified"]:
        try:
            _send_verification_email(user)
        except RuntimeError:
            logger.exception("Could not send verification email")
    return {"message": "If an unverified account exists, a verification message has been sent."}

@app.post("/api/verify-email")
@limiter.limit("10/hour")
def verify_email(request: Request, body: dict):
    raw_token = str(body.get("token", ""))
    user = _consume_action_token(raw_token, "verify_email")
    if not user:
        raise HTTPException(status_code=400, detail="This verification link is invalid or expired.")
    with _db() as db:
        db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user["id"],))
    return {"message": "Email verified. You can now sign in."}

@app.post("/api/forgot-password")
@limiter.limit("3/hour")
def forgot_password(request: Request, body: EmailInput):
    with _db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (_normalize_email(str(body.email)),)).fetchone()
    if user and user["password_hash"]:
        try:
            _send_reset_email(user)
        except RuntimeError:
            logger.exception("Could not send password reset email")
    return {"message": "If an account exists for that email, a password reset link has been sent."}

class ResetPasswordInput(BaseModel):
    token: str
    password: str

@app.post("/api/reset-password")
@limiter.limit("5/hour")
def reset_password(request: Request, body: ResetPasswordInput):
    if not _password_is_valid(body.password):
        raise HTTPException(status_code=400, detail="Password must be between 12 and 128 characters.")
    user = _consume_action_token(body.token, "reset_password")
    if not user:
        raise HTTPException(status_code=400, detail="This password reset link is invalid or expired.")
    password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    with _db() as db:
        db.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
            (password_hash, user["id"]),
        )
        db.execute(
            "UPDATE action_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
            (_utcnow().isoformat(), user["id"]),
        )
    try:
        _send_email(user["email"], "Your moBILLity password was changed", "Your password was changed. If this was not you, contact support immediately.")
    except RuntimeError:
        logger.exception("Could not send password change notification")
    return {"message": "Password updated. Sign in with your new password."}

@app.get("/auth/google")
@limiter.limit("20/hour")
async def google_login(request: Request):
    if not getattr(oauth, "google", None):
        # This is a browser navigation, so send the visitor back to a page that
        # explains itself. The callback already behaves this way; raising a raw
        # JSON 503 here left them staring at {"detail": ...}.
        return RedirectResponse("/login?error=google_unavailable", status_code=303)
    redirect_uri = f"{APP_BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    if not getattr(oauth, "google", None):
        return RedirectResponse("/login?error=google_unavailable", status_code=303)
    try:
        token = await oauth.google.authorize_access_token(request)
        info = token.get("userinfo") or await oauth.google.userinfo(token=token)
    except OAuthError:
        logger.exception("Google OAuth failed")
        return RedirectResponse("/login?error=google_failed", status_code=303)
    if not info.get("sub") or not info.get("email") or not info.get("email_verified"):
        return RedirectResponse("/login?error=google_unverified", status_code=303)

    email = _normalize_email(info["email"])
    with _db() as db:
        user = db.execute("SELECT * FROM users WHERE google_sub = ? OR email = ?", (info["sub"], email)).fetchone()
        if user:
            if user["google_sub"] and user["google_sub"] != info["sub"]:
                return RedirectResponse("/login?error=account_conflict", status_code=303)
            db.execute(
                "UPDATE users SET google_sub = ?, email_verified = 1, full_name = COALESCE(NULLIF(full_name, ''), ?) WHERE id = ?",
                (info["sub"], str(info.get("name", ""))[:120], user["id"]),
            )
            user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        else:
            cursor = db.execute(
                """INSERT INTO users(email, full_name, google_sub, email_verified, created_at)
                   VALUES (?, ?, ?, 1, ?) RETURNING id""",
                (email, str(info.get("name", ""))[:120], info["sub"], _utcnow().isoformat()),
            )
            user_id = cursor.fetchone()["id"]
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    response = RedirectResponse("/app", status_code=303)
    _set_auth_cookies(response, user)
    return response

@app.get("/api/me")
def me(current_user=Depends(get_current_user)):
    return {
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "is_admin": _is_admin(current_user),
        "analytics_enabled": bool(current_user["analytics_enabled"]),
    }

@app.post("/api/logout")
def logout(request: Request, response: Response):
    _require_csrf(request)
    _clear_auth_cookies(response)
    return {"message": "Signed out."}


class PatientInput(BaseModel):
    name: str
    phone: str | None = None
    email: EmailStr | None = None
    timezone: str = "America/New_York"
    sms_consent: bool = False
    voice_consent: bool = False
    email_consent: bool = False


class AppointmentInput(BaseModel):
    patient_id: int
    starts_at: datetime
    clinician: str = ""
    location: str = ""


class AppointmentStatusInput(BaseModel):
    status: Literal["scheduled", "confirmed", "cancelled", "completed"]


def _authenticated_write(request: Request) -> None:
    if request.cookies.get("mobillity_session"):
        _require_csrf(request)


@app.get("/api/workflows/overview")
def workflow_overview(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user=Depends(get_current_user),
):
    """Paginated. Previously this returned every patient and appointment, and
    each patient costs three AES decryptions — so a practice with thousands of
    records produced a multi-megabyte response the UI then truncated to five
    rows per table."""
    with _db() as db:
        totals = db.execute(
            """SELECT
                 (SELECT COUNT(*) FROM patients WHERE owner_user_id = ?) AS patients,
                 (SELECT COUNT(*) FROM appointments WHERE owner_user_id = ?) AS appointments,
                 (SELECT COUNT(*) FROM reminder_jobs WHERE owner_user_id = ?) AS reminders,
                 (SELECT COUNT(*) FROM communication_events WHERE owner_user_id = ?) AS events""",
            (current_user["id"],) * 4,
        ).fetchone()
        patients = db.execute(
            """SELECT * FROM patients WHERE owner_user_id = ?
               ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (current_user["id"], limit, offset),
        ).fetchall()
        appointments = db.execute(
            """SELECT appointments.*, patients.name_encrypted, patients.timezone AS patient_timezone
               FROM appointments JOIN patients ON patients.id = appointments.patient_id
               WHERE appointments.owner_user_id = ?
               ORDER BY appointments.starts_at LIMIT ? OFFSET ?""",
            (current_user["id"], limit, offset),
        ).fetchall()
        jobs = db.execute(
            """SELECT reminder_jobs.*, appointments.starts_at, patients.name_encrypted
               FROM reminder_jobs
               JOIN appointments ON appointments.id = reminder_jobs.appointment_id
               JOIN patients ON patients.id = appointments.patient_id
               WHERE reminder_jobs.owner_user_id = ?
               ORDER BY reminder_jobs.scheduled_for DESC LIMIT ? OFFSET ?""",
            (current_user["id"], limit, offset),
        ).fetchall()
        events = db.execute(
            """SELECT communication_events.*, patients.name_encrypted
               FROM communication_events
               LEFT JOIN patients ON patients.id = communication_events.patient_id
               WHERE communication_events.owner_user_id = ?
               ORDER BY communication_events.created_at DESC LIMIT ? OFFSET ?""",
            (current_user["id"], limit, offset),
        ).fetchall()
    return {
        "patients": [_patient_json(row) for row in patients],
        "appointments": [_appointment_json(row) for row in appointments],
        "reminders": [
            {
                "id": row["id"], "appointment_id": row["appointment_id"],
                "patient_name": _decrypt_optional(row["name_encrypted"]),
                "starts_at": row["starts_at"], "channel": row["channel"],
                "scheduled_for": row["scheduled_for"], "status": row["status"],
                "last_error": row["last_error"],
            }
            for row in jobs
        ],
        "events": [
            {
                "id": row["id"],
                "patient_name": _decrypt_optional(row["name_encrypted"]),
                "channel": row["channel"], "direction": row["direction"],
                "outcome": row["outcome"], "detail": row["detail"],
                "created_at": row["created_at"],
            }
            for row in events
        ],
        "delivery_mode": os.getenv("COMMUNICATION_DELIVERY_MODE", "preview"),
        "page": {"limit": limit, "offset": offset, "totals": dict(totals)},
    }


@app.post("/api/workflows/patients", status_code=201)
def create_patient(
    request: Request, body: PatientInput, current_user=Depends(get_current_user)
):
    _authenticated_write(request)
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Patient name is required.")
    if (body.sms_consent or body.voice_consent) and not (body.phone or "").strip():
        raise HTTPException(status_code=400, detail="A phone number is required for SMS or voice consent.")
    if body.email_consent and not body.email:
        raise HTTPException(status_code=400, detail="An email address is required for email consent.")
    patient_timezone = body.timezone.strip()
    if patient_timezone not in KNOWN_TIMEZONES:
        # Caught here rather than inside the dispatcher, where the failure would
        # be invisible to the person who entered it.
        raise HTTPException(
            status_code=400,
            detail=f"Unknown timezone {patient_timezone!r}. Use an IANA name such as America/New_York.",
        )
    with _db() as db:
        cursor = db.execute(
            """INSERT INTO patients
               (owner_user_id, name_encrypted, phone_encrypted, email_encrypted,
                phone_hmac, timezone, sms_consent, voice_consent, email_consent, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (
                current_user["id"], aes_encrypt(body.name.strip()),
                _encrypt_optional(body.phone), _encrypt_optional(str(body.email) if body.email else None),
                phone_fingerprint(body.phone or ""),
                patient_timezone, int(body.sms_consent), int(body.voice_consent),
                int(body.email_consent), _utcnow().isoformat(),
            ),
        )
        patient_id = cursor.fetchone()["id"]
        row = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    return _patient_json(row)


@app.post("/api/workflows/appointments", status_code=201)
def create_appointment(
    request: Request, body: AppointmentInput, current_user=Depends(get_current_user)
):
    _authenticated_write(request)
    starts_at = body.starts_at
    if starts_at.tzinfo is None:
        raise HTTPException(status_code=400, detail="Appointment time must include a timezone.")
    with _db() as db:
        patient = db.execute(
            "SELECT id FROM patients WHERE id = ? AND owner_user_id = ?",
            (body.patient_id, current_user["id"]),
        ).fetchone()
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found.")
        cursor = db.execute(
            """INSERT INTO appointments
               (owner_user_id, patient_id, starts_at, clinician, location, created_at)
               VALUES (?, ?, ?, ?, ?, ?) RETURNING id""",
            (
                current_user["id"], body.patient_id, _iso_datetime(starts_at),
                body.clinician.strip()[:120], body.location.strip()[:200],
                _utcnow().isoformat(),
            ),
        )
        appointment_id = cursor.fetchone()["id"]
        appointment = _appointment_row(db, appointment_id, current_user["id"])
        reminders_created = _schedule_reminders(db, appointment)
    result = _appointment_json(appointment)
    result["reminders_created"] = reminders_created
    return result


@app.patch("/api/workflows/appointments/{appointment_id}")
def update_appointment_status(
    appointment_id: int,
    request: Request,
    body: AppointmentStatusInput,
    current_user=Depends(get_current_user),
):
    _authenticated_write(request)
    with _db() as db:
        updated = db.execute(
            "UPDATE appointments SET status = ? WHERE id = ? AND owner_user_id = ?",
            (body.status, appointment_id, current_user["id"]),
        ).rowcount
        if not updated:
            raise HTTPException(status_code=404, detail="Appointment not found.")
        if body.status in ("cancelled", "completed"):
            db.execute(
                """UPDATE reminder_jobs SET status = 'cancelled'
                   WHERE appointment_id = ? AND status IN ('pending', 'processing')""",
                (appointment_id,),
            )
        appointment = _appointment_row(db, appointment_id, current_user["id"])
    return _appointment_json(appointment)


@app.post("/api/workflows/dispatch")
def dispatch_reminders_now(
    request: Request, current_user=Depends(get_current_user)
):
    _authenticated_write(request)
    # Scoped to the caller: a practice may only trigger delivery of its own
    # reminders. The background scheduler is the only unscoped caller.
    return dispatch_due_reminders(owner_user_id=current_user["id"])


class HandoffStatusInput(BaseModel):
    status: Literal["queued", "transferred", "resolved"]


@app.get("/api/workflows/handoffs")
def list_handoffs(current_user=Depends(get_current_user)):
    """The front-desk callback queue. Without this the inbound-call feature
    writes rows that no one can read."""
    with _db() as db:
        rows = db.execute(
            """SELECT * FROM call_handoffs
               WHERE owner_user_id = ? AND status != 'resolved'
               ORDER BY created_at DESC LIMIT 100""",
            (current_user["id"],),
        ).fetchall()
    return {
        "handoffs": [
            {
                "id": row["id"],
                "caller_phone": _decrypt_optional(row["caller_phone_encrypted"]),
                "reason": row["reason"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


@app.patch("/api/workflows/handoffs/{handoff_id}")
def update_handoff(
    handoff_id: int,
    request: Request,
    body: HandoffStatusInput,
    current_user=Depends(get_current_user),
):
    _authenticated_write(request)
    resolved_at = _utcnow().isoformat() if body.status == "resolved" else None
    with _db() as db:
        updated = db.execute(
            "UPDATE call_handoffs SET status = ?, resolved_at = ? WHERE id = ? AND owner_user_id = ?",
            (body.status, resolved_at, handoff_id, current_user["id"]),
        ).rowcount
    if not updated:
        raise HTTPException(status_code=404, detail="Handoff not found.")
    return {"id": handoff_id, "status": body.status}


def _twiml(content: str) -> FastAPIResponse:
    return FastAPIResponse(
        content=f'<?xml version="1.0" encoding="UTF-8"?><Response>{content}</Response>',
        media_type="application/xml",
    )


def _twilio_webhook_url(request: Request) -> str:
    """Rebuild the URL Twilio signed.

    Behind a TLS-terminating proxy, request.url reports http:// while Twilio
    signed the https:// URL configured on the number, so the HMACs never match
    and every webhook 403s. APP_BASE_URL is required in production and cannot be
    spoofed by a request header, so it is the trustworthy source for scheme and
    host.
    """
    target = APP_BASE_URL + request.url.path
    return f"{target}?{request.url.query}" if request.url.query else target


def _twilio_signature_is_valid(request: Request, form: dict) -> bool:
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    signature = request.headers.get("X-Twilio-Signature", "")
    if not auth_token:
        # Fail closed unless the bypass is asked for by name. Deriving it from a
        # merely-absent credential means one unset variable silently opens the
        # webhook to anyone.
        allow_unsigned = os.getenv("TWILIO_SKIP_SIGNATURE_CHECK", "false").lower() == "true"
        if allow_unsigned and IS_PRODUCTION:
            raise RuntimeError("TWILIO_SKIP_SIGNATURE_CHECK must never be enabled in production.")
        return allow_unsigned
    payload = _twilio_webhook_url(request) + "".join(
        key + str(form[key]) for key in sorted(form)
    )
    expected = base64.b64encode(
        hmac.new(auth_token.encode(), payload.encode(), hashlib.sha1).digest()
    ).decode()
    return hmac.compare_digest(signature, expected)


def _resolve_practice(called_number: str) -> int | None:
    """Attribute an inbound call to the practice that owns the dialled number."""
    if not called_number:
        return None
    with _db() as db:
        row = db.execute(
            "SELECT owner_user_id FROM practice_phone_numbers WHERE phone_number = ?",
            (called_number,),
        ).fetchone()
    return row["owner_user_id"] if row else None


def _record_inbound_call(speech: str, caller: str, called: str, wants_front_desk: bool) -> None:
    """Persist an inbound call. Runs off the event loop via asyncio.to_thread."""
    owner_user_id = _resolve_practice(called)
    now = _utcnow().isoformat()
    with _db() as db:
        db.execute(
            """INSERT INTO communication_events
               (owner_user_id, channel, direction, outcome, detail, created_at)
               VALUES (?, 'voice', 'inbound', ?, ?, ?)""",
            (
                owner_user_id,
                "front_desk_handoff" if wants_front_desk else "automated_triage",
                speech[:500], now,
            ),
        )
        if wants_front_desk:
            db.execute(
                """INSERT INTO call_handoffs
                   (owner_user_id, caller_phone_encrypted, reason, status, created_at)
                   VALUES (?, ?, ?, 'queued', ?)""",
                (
                    owner_user_id, _encrypt_optional(caller),
                    (speech or "Caller pressed zero")[:500], now,
                ),
            )


def _apply_sms_optout(from_number: str, opting_out: bool) -> int:
    """Record a STOP or START and bring consent into line with it.

    The carrier stops delivery on STOP regardless, but without this the database
    keeps asserting consent the patient has withdrawn — and for a product built
    around per-channel consent, knowingly wrong consent state is the problem.
    """
    fingerprint = phone_fingerprint(from_number)
    if not fingerprint:
        return 0
    now = _utcnow().isoformat()
    with _db() as db:
        patients = db.execute(
            "SELECT id, owner_user_id FROM patients WHERE phone_hmac = ?", (fingerprint,)
        ).fetchall()
        for patient in patients:
            db.execute(
                "UPDATE patients SET sms_consent = ? WHERE id = ?",
                (0 if opting_out else 1, patient["id"]),
            )
            if opting_out:
                db.execute(
                    """UPDATE reminder_jobs SET status = 'cancelled'
                       WHERE channel = 'sms' AND status IN ('pending', 'processing')
                         AND appointment_id IN (
                             SELECT id FROM appointments WHERE patient_id = ?
                         )""",
                    (patient["id"],),
                )
            db.execute(
                """INSERT INTO communication_events
                   (owner_user_id, patient_id, channel, direction, outcome, detail, created_at)
                   VALUES (?, ?, 'sms', 'inbound', ?, ?, ?)""",
                (
                    patient["owner_user_id"], patient["id"],
                    "opt_out" if opting_out else "opt_in",
                    "Patient replied STOP" if opting_out else "Patient replied START",
                    now,
                ),
            )
    return len(patients)


@app.post("/webhooks/twilio/inbound-sms")
async def inbound_sms(request: Request):
    """Handle STOP/START replies to outbound reminders."""
    form_data = dict(await request.form())
    if not _twilio_signature_is_valid(request, form_data):
        raise HTTPException(status_code=403, detail="Invalid provider signature.")
    body = str(form_data.get("Body", "")).strip().lower()
    from_number = str(form_data.get("From", ""))

    if body in SMS_STOP_KEYWORDS:
        matched = await asyncio.to_thread(_apply_sms_optout, from_number, True)
        logger.info("SMS opt-out applied to %d patient record(s)", matched)
        return _twiml(
            "<Message>You are unsubscribed and will not receive further messages. "
            "Reply START to resubscribe.</Message>"
        )
    if body in SMS_START_KEYWORDS:
        matched = await asyncio.to_thread(_apply_sms_optout, from_number, False)
        logger.info("SMS opt-in applied to %d patient record(s)", matched)
        return _twiml("<Message>You are resubscribed to appointment reminders.</Message>")

    # Never invite clinical detail over SMS.
    return _twiml(
        "<Message>This number is not monitored. Please call the office for help. "
        "Reply STOP to unsubscribe.</Message>"
    )


@app.post("/webhooks/twilio/inbound-call")
async def inbound_call(request: Request):
    form_data = dict(await request.form())
    if not _twilio_signature_is_valid(request, form_data):
        raise HTTPException(status_code=403, detail="Invalid provider signature.")
    speech = str(form_data.get("SpeechResult", "")).lower()
    digits = str(form_data.get("Digits", ""))
    caller = str(form_data.get("From", ""))
    called = str(form_data.get("To", ""))
    wants_front_desk = digits == "0" or any(keyword in speech for keyword in FRONT_DESK_KEYWORDS)
    await asyncio.to_thread(_record_inbound_call, speech, caller, called, wants_front_desk)
    if wants_front_desk:
        number = os.getenv("FRONT_DESK_PHONE_NUMBER")
        if number:
            safe_number = html.escape(number, quote=True)
            return _twiml(
                f"<Say>Please hold while I connect you to the front desk.</Say>"
                f"<Dial>{safe_number}</Dial>"
            )
        return _twiml(
            "<Say>The front desk is unavailable. Your request has been queued for a callback.</Say>"
        )
    if speech or digits:
        return _twiml(
            "<Say>I can help with appointment reminders. For scheduling changes, billing, "
            "insurance, records, or a manager, please say front desk or press zero.</Say>"
            "<Redirect method=\"POST\">/webhooks/twilio/inbound-call</Redirect>"
        )
    return _twiml(
        '<Gather input="speech dtmf" numDigits="1" timeout="5" '
        'action="/webhooks/twilio/inbound-call" method="POST">'
        "<Say>Thank you for calling. Tell me how I can help. "
        "For the front desk, press zero at any time.</Say></Gather>"
        "<Redirect method=\"POST\">/webhooks/twilio/inbound-call</Redirect>"
    )


@app.post("/webhooks/twilio/reminder-voice")
async def reminder_voice(request: Request, appointment_id: int):
    form_data = dict(await request.form())
    if not _twilio_signature_is_valid(request, form_data):
        raise HTTPException(status_code=403, detail="Invalid provider signature.")
    with _db() as db:
        appointment = db.execute(
            """SELECT appointments.*, patients.name_encrypted, patients.phone_encrypted,
                      patients.email_encrypted
               FROM appointments JOIN patients ON patients.id = appointments.patient_id
               WHERE appointments.id = ?""",
            (appointment_id,),
        ).fetchone()
    if not appointment:
        return _twiml("<Say>This reminder is no longer available.</Say>")
    _, message = _reminder_copy(appointment, "voice")
    return _twiml(f"<Say>{html.escape(message)}</Say>")


_shutdown = asyncio.Event()


def _purge_expired_analytics_now() -> None:
    with _db() as db:
        _purge_expired_analytics(db)


async def _reminder_scheduler() -> None:
    """Dispatch loop. Exits at a clean iteration boundary on shutdown."""
    purge_countdown = 0
    while not _shutdown.is_set():
        try:
            await asyncio.to_thread(dispatch_due_reminders)
            # Retention housekeeping runs hourly here rather than on every
            # analytics write, where it cost a full-table scan per page view.
            purge_countdown -= 1
            if purge_countdown <= 0:
                await asyncio.to_thread(_purge_expired_analytics_now)
                purge_countdown = 60
        except Exception:
            logger.exception("Reminder scheduler iteration failed")
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=60)
        except TimeoutError:
            continue


def _scheduler_enabled() -> bool:
    """Default off. A dispatcher that runs in every web worker sends duplicate
    reminders, so enabling it must be a deliberate act on exactly one service."""
    legacy = os.getenv("WORKFLOW_SCHEDULER_ENABLED")
    if legacy is not None:
        logger.warning("WORKFLOW_SCHEDULER_ENABLED is deprecated; use WORKFLOW_WORKER.")
        return legacy.lower() == "true"
    return os.getenv("WORKFLOW_WORKER", "false").lower() == "true"


ENCRYPTED_COLUMNS = {
    "patients": ("name_encrypted", "phone_encrypted", "email_encrypted"),
    "call_handoffs": ("caller_phone_encrypted",),
}


def rotate_encryption_keys(batch_size: int = 500) -> dict:
    """Re-encrypt values written under a superseded key.

    Safe to run repeatedly and safe to interrupt: each row is independent, and a
    row already on the current version is skipped. Run it after adding a new key
    version until it reports zero rotated.
    """
    rotated = 0
    for table, columns in ENCRYPTED_COLUMNS.items():
        with _db() as db:
            selected = ", ".join(("id", *columns))
            rows = db.execute(
                f"SELECT {selected} FROM {table} LIMIT ?",  # noqa: S608 - identifiers are module constants
                (batch_size,),
            ).fetchall()
            for row in rows:
                updates = {}
                for column in columns:
                    value = row[column]
                    if not aes_needs_rotation(value):
                        continue
                    try:
                        updates[column] = aes_encrypt(aes_decrypt(value))
                    except (InvalidTag, ValueError, binascii.Error):
                        logger.error(
                            "Cannot rotate %s.%s for id=%s: value is unreadable",
                            table, column, row["id"],
                        )
                if updates:
                    assignments = ", ".join(f"{column} = ?" for column in updates)
                    db.execute(
                        f"UPDATE {table} SET {assignments} WHERE id = ?",  # noqa: S608 - identifiers are module constants
                        (*updates.values(), row["id"]),
                    )
                    rotated += 1
    if rotated:
        logger.info("Re-encrypted %d row(s) to key version %d", rotated, CURRENT_KEY_VERSION)
    return {"rotated": rotated, "key_version": CURRENT_KEY_VERSION}


def _backfill_phone_fingerprints() -> int:
    """Populate phone_hmac for patients created before the column existed."""
    with _db() as db:
        rows = db.execute(
            "SELECT id, phone_encrypted FROM patients WHERE phone_hmac IS NULL AND phone_encrypted IS NOT NULL"
        ).fetchall()
        updated = 0
        for row in rows:
            fingerprint = phone_fingerprint(_decrypt_optional(row["phone_encrypted"]))
            if fingerprint:
                db.execute(
                    "UPDATE patients SET phone_hmac = ? WHERE id = ?", (fingerprint, row["id"])
                )
                updated += 1
    if updated:
        logger.info("Backfilled phone fingerprints for %d patient(s)", updated)
    return updated


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Alembic owns the PostgreSQL schema ('alembic upgrade head' runs pre-deploy).
    # _init_db() remains for local SQLite development, and tests assert the two
    # produce the same schema so they cannot drift.
    if not USING_POSTGRES:
        _init_db()
    _backfill_phone_fingerprints()
    task = None
    if _scheduler_enabled():
        logger.info("reminder dispatcher: ACTIVE in this process")
        task = asyncio.create_task(_reminder_scheduler())
    else:
        logger.info("reminder dispatcher: INACTIVE (set WORKFLOW_WORKER=true on one service)")
    try:
        yield
    finally:
        _shutdown.set()
        if task:
            try:
                await asyncio.wait_for(task, timeout=10)
            except (TimeoutError, asyncio.CancelledError):
                task.cancel()
        _close_pool()


app.router.lifespan_context = lifespan


class NoteInput(BaseModel):
    note: str

class AnalyticsEventInput(BaseModel):
    event_name: str
    page: str

ALLOWED_ANALYTICS_EVENTS = {
    "page_view",
    "analyze_clicked",
    "dictation_started",
    "extraction_succeeded",
    "extraction_failed",
}
ALLOWED_ANALYTICS_PAGES = {"app"}

@app.post("/api/analytics/events", status_code=204)
@limiter.limit("60/minute")
def analytics_event(
    request: Request,
    body: AnalyticsEventInput,
    current_user=Depends(get_current_user),
):
    if request.cookies.get("mobillity_session"):
        _require_csrf(request)
    if body.event_name not in ALLOWED_ANALYTICS_EVENTS or body.page not in ALLOWED_ANALYTICS_PAGES:
        raise HTTPException(status_code=400, detail="Unsupported analytics event.")
    _record_event(current_user["id"], body.event_name, body.page)
    return Response(status_code=204)

@app.delete("/api/analytics/me", status_code=204)
def disable_my_analytics(request: Request, current_user=Depends(get_current_user)):
    _require_csrf(request)
    with _db() as db:
        db.execute("DELETE FROM analytics_events WHERE user_id = ?", (current_user["id"],))
        db.execute("UPDATE users SET analytics_enabled = 0 WHERE id = ?", (current_user["id"],))
    return Response(status_code=204)

@app.put("/api/analytics/me", status_code=204)
def enable_my_analytics(request: Request, current_user=Depends(get_current_user)):
    _require_csrf(request)
    with _db() as db:
        db.execute("UPDATE users SET analytics_enabled = 1 WHERE id = ?", (current_user["id"],))
    return Response(status_code=204)

@app.get("/api/admin/analytics")
def admin_analytics(admin_user=Depends(get_admin_user)):
    with _db() as db:
        _purge_expired_analytics(db)
        totals = db.execute("""
            SELECT
              (SELECT COUNT(*) FROM users) AS registered_users,
              (SELECT COUNT(*) FROM users WHERE email_verified = 1) AS verified_users,
              (SELECT COUNT(DISTINCT user_id) FROM analytics_events) AS active_users,
              (SELECT COUNT(*) FROM analytics_events) AS total_events
        """).fetchone()
        users = db.execute("""
            SELECT u.id, u.email, u.full_name, u.email_verified, u.created_at,
                   u.analytics_enabled, COUNT(a.id) AS event_count,
                   MAX(a.occurred_at) AS last_active_at,
                   SUM(CASE WHEN a.event_name = 'analyze_clicked' THEN 1 ELSE 0 END) AS analyses
            FROM users u LEFT JOIN analytics_events a ON a.user_id = u.id
            GROUP BY u.id ORDER BY u.created_at DESC
        """).fetchall()
        top_events = db.execute("""
            SELECT event_name, page, COUNT(*) AS count
            FROM analytics_events GROUP BY event_name, page ORDER BY count DESC
        """).fetchall()
        if USING_POSTGRES:
            daily = db.execute("""
                SELECT dates.day::text AS day,
                  (SELECT COUNT(*) FROM users WHERE created_at::date = dates.day) AS registrations,
                  (SELECT COUNT(*) FROM analytics_events WHERE occurred_at::date = dates.day) AS events
                FROM generate_series(
                  CURRENT_DATE - INTERVAL '29 days',
                  CURRENT_DATE,
                  INTERVAL '1 day'
                ) AS dates(day)
            """).fetchall()
        else:
            daily = db.execute("""
                WITH RECURSIVE dates(day) AS (
                  SELECT date('now', '-29 days')
                  UNION ALL SELECT date(day, '+1 day') FROM dates WHERE day < date('now')
                )
                SELECT dates.day,
                  (SELECT COUNT(*) FROM users WHERE date(created_at) = dates.day) AS registrations,
                  (SELECT COUNT(*) FROM analytics_events WHERE date(occurred_at) = dates.day) AS events
                FROM dates
            """).fetchall()
    return {
        "retention_days": ANALYTICS_RETENTION_DAYS,
        "totals": dict(totals),
        "users": [dict(row) for row in users],
        "top_events": [dict(row) for row in top_events],
        "daily": [dict(row) for row in daily],
    }


@app.post("/api/extract")
@limiter.limit("10/minute")
def api_extract(
    request: Request,
    input: NoteInput,
    current_user=Depends(get_current_user),
):
    if request.cookies.get("mobillity_session"):
        _require_csrf(request)
    if not input.note.strip():
        raise HTTPException(status_code=400, detail="No clinical note provided.")
    try:
        result = extract_medical_codes(input.note)
        _record_event(current_user["id"], "extraction_succeeded")
        return {"result": result}
    except Exception:
        # Never surface provider exception text to the client: SDK errors carry
        # request ids, org identifiers, and occasionally fragments of the request.
        reference = secrets.token_hex(6)
        logger.exception(
            "Extraction failed (reference=%s, user=%s)", reference, current_user["id"]
        )
        _record_event(current_user["id"], "extraction_failed")
        raise HTTPException(  # noqa: B904 - the cause is logged; clients get a reference only
            status_code=500,
            detail=(
                "Extraction failed. Try again, or contact support with "
                f"reference {reference} if this continues."
            ),
        )
