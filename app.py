import os
import json
import re
import base64
import secrets
import hashlib
import logging
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Optional

from dotenv import load_dotenv
load_dotenv()  # loads .env before any os.getenv() calls

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from openai import OpenAI
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import bcrypt
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
