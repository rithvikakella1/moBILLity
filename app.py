import os
import asyncio
import json
import re
import base64
import secrets
import hashlib
import hmac
import html
import logging
import smtplib
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Optional, Literal

from dotenv import load_dotenv
load_dotenv()  # loads .env before any os.getenv() calls

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from openai import OpenAI
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response as FastAPIResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import bcrypt
import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt

# ── SECURITY CONFIG ──────────────────────────────────────────────────────────
logger = logging.getLogger("mobillity.auth")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production"
SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_hex(32)
SESSION_SECRET = os.getenv("SESSION_SECRET_KEY") or secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ACTION_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACTION_TOKEN_EXPIRE_MINUTES", "60"))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", str(IS_PRODUCTION)).lower() == "true"

if IS_PRODUCTION and (not os.getenv("JWT_SECRET_KEY") or not os.getenv("SESSION_SECRET_KEY")):
    raise RuntimeError("JWT_SECRET_KEY and SESSION_SECRET_KEY are required in production.")

_enc_env = os.getenv("ENCRYPTION_KEY", "")
if _enc_env:
    _raw = base64.b64decode(_enc_env + "==")
    ENCRYPTION_KEY = (_raw + b"\x00" * 32)[:32]
else:
    ENCRYPTION_KEY = secrets.token_bytes(32)

if IS_PRODUCTION and not _enc_env:
    raise RuntimeError("ENCRYPTION_KEY is required in production.")

# ── USER STORE (SQLite) ───────────────────────────────────────────────────────
DATABASE_FILE = os.getenv("DATABASE_FILE", os.path.join(BASE_DIR, "users.db"))

def _db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection

def _init_db() -> None:
    with _db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT,
                full_name TEXT NOT NULL DEFAULT '',
                google_sub TEXT UNIQUE,
                email_verified INTEGER NOT NULL DEFAULT 0,
                session_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS action_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_action_tokens_lookup ON action_tokens(token_hash, purpose)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                name_encrypted TEXT NOT NULL,
                phone_encrypted TEXT,
                email_encrypted TEXT,
                timezone TEXT NOT NULL DEFAULT 'America/New_York',
                sms_consent INTEGER NOT NULL DEFAULT 0,
                voice_consent INTEGER NOT NULL DEFAULT 0,
                email_consent INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                patient_id INTEGER NOT NULL,
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
        db.execute("""
            CREATE TABLE IF NOT EXISTS reminder_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                appointment_id INTEGER NOT NULL,
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
        db.execute("""
            CREATE TABLE IF NOT EXISTS communication_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER,
                appointment_id INTEGER,
                patient_id INTEGER,
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
        db.execute("""
            CREATE TABLE IF NOT EXISTS call_handoffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                caller_phone_encrypted TEXT,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'transferred', 'resolved')),
                created_at TEXT NOT NULL,
                resolved_at TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_appointments_owner_start ON appointments(owner_user_id, starts_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reminder_jobs_due ON reminder_jobs(status, scheduled_for)")

_init_db()
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
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response

# ── AES-256-GCM UTILITIES ─────────────────────────────────────────────────────
def aes_encrypt(plaintext: str) -> str:
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def aes_decrypt(token: str) -> str:
    raw = base64.b64decode(token)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ct, None).decode()

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode()

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

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

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
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

async def get_current_user(request: Request, token: Optional[str] = Depends(oauth2_scheme)):
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
    except JWTError:
        raise exc
    except (TypeError, ValueError):
        raise exc

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
    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as smtp:
        if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
            smtp.starttls()
        if os.getenv("SMTP_USERNAME"):
            smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        smtp.send_message(message)

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
CONFIRMED_CONFIDENCE_THRESHOLD = 0.75

# ── PHYSICIAN BILLING PROMPT ──────────────────────────────────────────────────
# NOTE: Uses a two-pass chain-of-thought style:
#   1. The system message instructs the model to reason carefully before emitting JSON.
#   2. The user prompt contains strict rules + few-shot HCPCS examples to anchor
#      the model's understanding of HCPCS Level II codes alongside ICD-10 and CPT.

SYSTEM_PROMPT = """You are a board-certified professional medical coder and physician billing specialist with 20+ years of experience in ICD-10-CM, ICD-10-PCS, CPT, and HCPCS Level II coding.

PRECISION RULES — follow these exactly to achieve ≥90% coding accuracy:
1. Only assign a code when there is EXPLICIT, UNAMBIGUOUS documentation supporting it. When in doubt, move it to suggested_codes.
2. For ICD-10-CM: always code to the highest specificity — include 7th character, laterality, episode of care, and severity where required. A truncated code (e.g., S52 without full extension) is WRONG.
3. For CPT: verify that the procedure is fully documented (operative note, procedure note, or attending attestation). Do not infer a procedure from a diagnosis alone.
4. For HCPCS Level II: assign codes for durable medical equipment (DME), orthotics/prosthetics, ambulance services, drugs administered in the office (J-codes), supplies (A-codes), and other non-physician services. Only assign when the item/service is explicitly documented as provided or ordered.
5. NEVER code "possible," "probable," "suspected," "rule out," or "likely" conditions as confirmed diagnoses.
6. Apply correct sequencing: principal/primary diagnosis first, then complications, then comorbidities.
7. Set confidence as a strict self-assessment:
   - 0.90–1.00: Code is exact, unambiguous, and fully documented — safe to bill.
   - 0.75–0.89: Code is correct but documentation has minor gaps — bill with addendum recommended.
   - <0.75: Too uncertain — place in suggested_codes instead.
8. Never hallucinate codes. If you are uncertain of the exact code, use suggested_codes with documentation_needed.

HCPCS LEVEL II EXAMPLES (use these as anchors):
- E0601 — Continuous positive airway pressure (CPAP) device
- L3000 — Foot insert, removable, molded to patient model
- J0696 — Injection, ceftriaxone sodium, per 250mg
- A4570 — Splint
- K0001 — Standard manual wheelchair
- G0008 — Administration of influenza virus vaccine

You MUST respond ONLY with valid JSON — no markdown fences, no prose, no explanation outside the JSON object.
"""

PROMPT_TEMPLATE = """Extract all billable medical codes from the clinical note below. Include ICD-10-CM diagnosis codes, CPT procedure codes, AND HCPCS Level II codes (DME, supplies, drugs, orthotics, ambulance, vaccines, etc.).

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
- Do NOT omit HCPCS codes for any DME, supply, injectable drug, or non-physician service documented in the note.
- If no HCPCS codes apply, return an empty array for that section — do not fabricate codes.

Clinical Note:
"""

# ── RESPONSE PARSING ──────────────────────────────────────────────────────────
def _parse_llm_response(text: str) -> dict:
    cleaned = re.sub(r"```json|```", "", text).strip()

    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start:end + 1]
    else:
        s, e = cleaned.find("["), cleaned.rfind("]")
        if s != -1 and e != -1:
            try:
                arr = json.loads(cleaned[s:e + 1])
                return {"confirmed_codes": arr, "suggested_codes": []}
            except Exception:
                pass
        return {"confirmed_codes": [], "suggested_codes": [], "raw": cleaned}

    try:
        data = json.loads(candidate)

        confirmed = []
        downgraded = []

        for item in data.get("confirmed_codes", []):
            try:
                item["confidence"] = round(float(item.get("confidence", 0)), 2)
            except Exception:
                item["confidence"] = 0.0

            # Enforce threshold: low-confidence confirmed codes move to suggested
            if item["confidence"] < CONFIRMED_CONFIDENCE_THRESHOLD:
                downgraded.append({
                    "code_type": item.get("code_type", ""),
                    "code": item.get("code", ""),
                    "description": item.get("description", ""),
                    "reason_suggested": f"Confidence {item['confidence']} below threshold — {item.get('reasoning', '')}",
                    "documentation_needed": "Strengthen documentation to support billing.",
                })
            else:
                confirmed.append(item)

        data["confirmed_codes"] = confirmed
        data["suggested_codes"] = data.get("suggested_codes", []) + downgraded

        return data

    except Exception:
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
REMINDER_LEAD_TIME = timedelta(days=7)
FRONT_DESK_KEYWORDS = {
    "bill", "billing", "insurance", "refund", "payment", "medical record",
    "records", "referral", "prior authorization", "complaint", "manager",
    "change provider", "new patient",
}


def _encrypt_optional(value: Optional[str]) -> Optional[str]:
    cleaned = (value or "").strip()
    return aes_encrypt(cleaned) if cleaned else None


def _decrypt_optional(value: Optional[str]) -> str:
    return aes_decrypt(value) if value else ""


def _iso_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _appointment_row(db: sqlite3.Connection, appointment_id: int, owner_user_id: int):
    return db.execute(
        """SELECT appointments.*, patients.name_encrypted, patients.phone_encrypted,
                  patients.email_encrypted, patients.sms_consent,
                  patients.voice_consent, patients.email_consent
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


def _schedule_reminders(db: sqlite3.Connection, appointment) -> int:
    if appointment["status"] != "scheduled":
        return 0
    scheduled_for = datetime.fromisoformat(appointment["starts_at"]) - REMINDER_LEAD_TIME
    consent = {
        "sms": bool(appointment["sms_consent"]) and bool(appointment["phone_encrypted"]),
        "voice": bool(appointment["voice_consent"]) and bool(appointment["phone_encrypted"]),
        "email": bool(appointment["email_consent"]) and bool(appointment["email_encrypted"]),
    }
    created = 0
    for channel, allowed in consent.items():
        if allowed:
            cursor = db.execute(
                """INSERT OR IGNORE INTO reminder_jobs
                   (owner_user_id, appointment_id, channel, scheduled_for, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    appointment["owner_user_id"],
                    appointment["id"],
                    channel,
                    _iso_datetime(scheduled_for),
                    _utcnow().isoformat(),
                ),
            )
            created += cursor.rowcount
    return created


def _reminder_copy(appointment, channel: str) -> tuple[str, str]:
    patient_name = _decrypt_optional(appointment["name_encrypted"])
    first_name = patient_name.split()[0] if patient_name else "there"
    starts = datetime.fromisoformat(appointment["starts_at"]).astimezone(timezone.utc)
    when = starts.strftime("%A, %B %-d at %-I:%M %p UTC")
    practice = os.getenv("PRACTICE_NAME", "your care team")
    location = f" at {appointment['location']}" if appointment["location"] else ""
    if channel == "email":
        subject = f"Appointment reminder for {starts.strftime('%B %-d')}"
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


def dispatch_due_reminders(now: Optional[datetime] = None, limit: int = 50) -> dict:
    now = now or _utcnow()
    sent = failed = 0
    with _db() as db:
        jobs = db.execute(
            """SELECT * FROM reminder_jobs
               WHERE status = 'pending' AND scheduled_for <= ?
               ORDER BY scheduled_for LIMIT ?""",
            (_iso_datetime(now), limit),
        ).fetchall()
        for job in jobs:
            claimed = db.execute(
                """UPDATE reminder_jobs SET status = 'processing', attempts = attempts + 1
                   WHERE id = ? AND status = 'pending'""",
                (job["id"],),
            ).rowcount
            if not claimed:
                continue
            appointment = _appointment_row(db, job["appointment_id"], job["owner_user_id"])
            if not appointment or appointment["status"] not in ("scheduled", "confirmed"):
                db.execute("UPDATE reminder_jobs SET status = 'cancelled' WHERE id = ?", (job["id"],))
                continue
            try:
                provider_id = _deliver_reminder(appointment, job["channel"])
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
                        job["owner_user_id"], appointment["id"], appointment["patient_id"],
                        job["channel"], "Seven-day appointment reminder",
                        provider_id, sent_at,
                    ),
                )
                sent += 1
            except Exception as exc:
                logger.exception("Reminder job %s failed", job["id"])
                db.execute(
                    "UPDATE reminder_jobs SET status = 'failed', last_error = ? WHERE id = ?",
                    (str(exc)[:500], job["id"]),
                )
                failed += 1
    return {"processed": len(jobs), "sent": sent, "failed": failed}


# ── PAGE ROUTES ───────────────────────────────────────────────────────────────
def _serve(filename: str) -> str:
    with open(os.path.join(BASE_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


@app.get("/", response_class=HTMLResponse)
async def serve_landing():
    return _serve("index.html")


@app.get("/app", response_class=HTMLResponse)
async def serve_app():
    return _serve("app.html")


@app.get("/workflows", response_class=HTMLResponse)
async def serve_workflows():
    return _serve("workflows.html")


@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    return _serve("login.html")


@app.get("/signup", response_class=HTMLResponse)
async def serve_signup():
    return _serve("signup.html")

@app.get("/forgot-password", response_class=HTMLResponse)
async def serve_forgot_password():
    return _serve("forgot-password.html")

@app.get("/reset-password", response_class=HTMLResponse)
async def serve_reset_password():
    return _serve("reset-password.html")

@app.get("/verify-email", response_class=HTMLResponse)
async def serve_verify_email():
    return _serve("verify-email.html")


# ── API ROUTES ────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/token")
@limiter.limit("5/minute")
async def login(response: Response, request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
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
    full_name: Optional[str] = None


@app.post("/api/register", status_code=201)
@limiter.limit("3/minute")
async def register(request: Request, body: RegisterInput):
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
               VALUES (?, ?, ?, 0, ?)""",
            (
                email,
                bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode(),
                (body.full_name or "").strip()[:120],
                _utcnow().isoformat(),
            ),
        )
        user = db.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
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
async def resend_verification(request: Request, body: EmailInput):
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
async def verify_email(request: Request, body: dict):
    raw_token = str(body.get("token", ""))
    user = _consume_action_token(raw_token, "verify_email")
    if not user:
        raise HTTPException(status_code=400, detail="This verification link is invalid or expired.")
    with _db() as db:
        db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user["id"],))
    return {"message": "Email verified. You can now sign in."}

@app.post("/api/forgot-password")
@limiter.limit("3/hour")
async def forgot_password(request: Request, body: EmailInput):
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
async def reset_password(request: Request, body: ResetPasswordInput):
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
        raise HTTPException(status_code=503, detail="Google sign-in is not configured.")
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
                   VALUES (?, ?, ?, 1, ?)""",
                (email, str(info.get("name", ""))[:120], info["sub"], _utcnow().isoformat()),
            )
            user = db.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    response = RedirectResponse("/app", status_code=303)
    _set_auth_cookies(response, user)
    return response

@app.get("/api/me")
async def me(current_user=Depends(get_current_user)):
    return {"email": current_user["email"], "full_name": current_user["full_name"]}

@app.post("/api/logout")
async def logout(request: Request, response: Response):
    _require_csrf(request)
    _clear_auth_cookies(response)
    return {"message": "Signed out."}


class PatientInput(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
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
async def workflow_overview(current_user=Depends(get_current_user)):
    with _db() as db:
        patients = db.execute(
            "SELECT * FROM patients WHERE owner_user_id = ? ORDER BY created_at DESC",
            (current_user["id"],),
        ).fetchall()
        appointments = db.execute(
            """SELECT appointments.*, patients.name_encrypted
               FROM appointments JOIN patients ON patients.id = appointments.patient_id
               WHERE appointments.owner_user_id = ?
               ORDER BY appointments.starts_at""",
            (current_user["id"],),
        ).fetchall()
        jobs = db.execute(
            """SELECT reminder_jobs.*, appointments.starts_at, patients.name_encrypted
               FROM reminder_jobs
               JOIN appointments ON appointments.id = reminder_jobs.appointment_id
               JOIN patients ON patients.id = appointments.patient_id
               WHERE reminder_jobs.owner_user_id = ?
               ORDER BY reminder_jobs.scheduled_for DESC LIMIT 100""",
            (current_user["id"],),
        ).fetchall()
        events = db.execute(
            """SELECT communication_events.*, patients.name_encrypted
               FROM communication_events
               LEFT JOIN patients ON patients.id = communication_events.patient_id
               WHERE communication_events.owner_user_id = ?
               ORDER BY communication_events.created_at DESC LIMIT 100""",
            (current_user["id"],),
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
    }


@app.post("/api/workflows/patients", status_code=201)
async def create_patient(
    request: Request, body: PatientInput, current_user=Depends(get_current_user)
):
    _authenticated_write(request)
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Patient name is required.")
    if (body.sms_consent or body.voice_consent) and not (body.phone or "").strip():
        raise HTTPException(status_code=400, detail="A phone number is required for SMS or voice consent.")
    if body.email_consent and not body.email:
        raise HTTPException(status_code=400, detail="An email address is required for email consent.")
    with _db() as db:
        cursor = db.execute(
            """INSERT INTO patients
               (owner_user_id, name_encrypted, phone_encrypted, email_encrypted,
                timezone, sms_consent, voice_consent, email_consent, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                current_user["id"], aes_encrypt(body.name.strip()),
                _encrypt_optional(body.phone), _encrypt_optional(str(body.email) if body.email else None),
                body.timezone.strip()[:80], int(body.sms_consent), int(body.voice_consent),
                int(body.email_consent), _utcnow().isoformat(),
            ),
        )
        row = db.execute("SELECT * FROM patients WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _patient_json(row)


@app.post("/api/workflows/appointments", status_code=201)
async def create_appointment(
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
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                current_user["id"], body.patient_id, _iso_datetime(starts_at),
                body.clinician.strip()[:120], body.location.strip()[:200],
                _utcnow().isoformat(),
            ),
        )
        appointment = _appointment_row(db, cursor.lastrowid, current_user["id"])
        reminders_created = _schedule_reminders(db, appointment)
    result = _appointment_json(appointment)
    result["reminders_created"] = reminders_created
    return result


@app.patch("/api/workflows/appointments/{appointment_id}")
async def update_appointment_status(
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
async def dispatch_reminders_now(
    request: Request, current_user=Depends(get_current_user)
):
    _authenticated_write(request)
    # The dispatcher safely claims jobs across all tenants. It returns only counts,
    # and never exposes another practice's data.
    return dispatch_due_reminders()


def _twiml(content: str) -> FastAPIResponse:
    return FastAPIResponse(
        content=f'<?xml version="1.0" encoding="UTF-8"?><Response>{content}</Response>',
        media_type="application/xml",
    )


def _twilio_signature_is_valid(request: Request, form: dict) -> bool:
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    signature = request.headers.get("X-Twilio-Signature", "")
    if not auth_token:
        return not IS_PRODUCTION
    url = str(request.url)
    payload = url + "".join(key + str(form[key]) for key in sorted(form))
    expected = base64.b64encode(
        hmac.new(auth_token.encode(), payload.encode(), hashlib.sha1).digest()
    ).decode()
    return hmac.compare_digest(signature, expected)


@app.post("/webhooks/twilio/inbound-call")
async def inbound_call(request: Request):
    form_data = dict(await request.form())
    if not _twilio_signature_is_valid(request, form_data):
        raise HTTPException(status_code=403, detail="Invalid provider signature.")
    speech = str(form_data.get("SpeechResult", "")).lower()
    digits = str(form_data.get("Digits", ""))
    caller = str(form_data.get("From", ""))
    wants_front_desk = digits == "0" or any(keyword in speech for keyword in FRONT_DESK_KEYWORDS)
    with _db() as db:
        db.execute(
            """INSERT INTO communication_events
               (channel, direction, outcome, detail, created_at)
               VALUES ('voice', 'inbound', ?, ?, ?)""",
            (
                "front_desk_handoff" if wants_front_desk else "automated_triage",
                speech[:500], _utcnow().isoformat(),
            ),
        )
        if wants_front_desk:
            db.execute(
                """INSERT INTO call_handoffs(caller_phone_encrypted, reason, status, created_at)
                   VALUES (?, ?, 'queued', ?)""",
                (_encrypt_optional(caller), (speech or "Caller pressed zero")[:500], _utcnow().isoformat()),
            )
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


async def _reminder_scheduler() -> None:
    while True:
        try:
            await asyncio.to_thread(dispatch_due_reminders)
        except Exception:
            logger.exception("Reminder scheduler iteration failed")
        await asyncio.sleep(60)


@app.on_event("startup")
async def start_reminder_scheduler():
    if os.getenv("WORKFLOW_SCHEDULER_ENABLED", "true").lower() == "true":
        app.state.reminder_scheduler_task = asyncio.create_task(_reminder_scheduler())


@app.on_event("shutdown")
async def stop_reminder_scheduler():
    task = getattr(app.state, "reminder_scheduler_task", None)
    if task:
        task.cancel()


class NoteInput(BaseModel):
    note: str


@app.post("/api/extract")
@limiter.limit("10/minute")
async def api_extract(
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
        _ = aes_encrypt(input.note)  # audit log (persist in production)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
