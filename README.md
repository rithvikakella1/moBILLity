# moBILLity – Clinical Workflow Automation

FastAPI-based clinical operations platform with AI-powered ICD-10, CPT, and
HCPCS extraction plus consent-aware appointment outreach.

## Workflow Hub

The authenticated `/workflows` area supports:

- encrypted patient contact details and per-channel consent
- appointments with SMS, voice, and email reminders queued exactly seven days
  before the visit
- an in-process dispatcher with retry-safe job claiming and an audit trail
- a Twilio-compatible inbound voice webhook that hands billing, insurance,
  medical-record, referral, complaint, manager, and other front-desk requests
  to staff
- preview delivery by default, so local development never contacts patients

Set a stable `ENCRYPTION_KEY` before storing patient data. It must be a
base64-encoded 32-byte value and is mandatory in production.

For live email, use the SMTP settings below and set:

```bash
COMMUNICATION_DELIVERY_MODE=live
PRACTICE_NAME="Example Health"
```

For live SMS, outbound voice reminders, and inbound calls, also set:

```bash
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_PHONE_NUMBER=+15555550100
FRONT_DESK_PHONE_NUMBER=+15555550101
```

Configure the Twilio number's incoming voice webhook as:

```text
POST https://your-domain.example/webhooks/twilio/inbound-call
```

`WORKFLOW_SCHEDULER_ENABLED=true` runs the due-job dispatcher once per minute
(the default). For horizontally scaled production deployments, run the
dispatcher in one dedicated worker rather than in every web process.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY="..."
export AUTH_DEV_SHOW_LINKS=true
uvicorn app:app --reload
```

Open `http://localhost:8000`. In local development,
`AUTH_DEV_SHOW_LINKS=true` writes verification and password-reset links to the
server log. Never enable that option in production.

## Authentication

Accounts are stored in SQLite (`users.db` by default). Password accounts must
verify their email before signing in. Google accounts rely on Google's verified
email claim.

Set these values in production:

```bash
ENVIRONMENT=production
APP_BASE_URL=https://your-domain.example
JWT_SECRET_KEY=<at-least-32-random-bytes>
SESSION_SECRET_KEY=<a-different-random-value>
COOKIE_SECURE=true
```

Configure SMTP for verification and password-reset messages:

```bash
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_STARTTLS=true
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_FROM=no-reply@your-domain.example
```

For Google sign-in, create a Google OAuth **Web application** client and add
this exact authorized redirect URI:

```text
https://your-domain.example/auth/google/callback
```

Then set:

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

Do not commit these values. `.env`, SQLite databases, and the legacy
`users.json` file are ignored by Git.

### Security controls

- bcrypt password hashing and a 12-character minimum
- verified email required for non-Google accounts
- single-use, one-hour email verification and password-reset tokens
- generic password-reset responses to reduce account enumeration
- rate limits on login, registration, verification, recovery, and extraction
- `HttpOnly`, `SameSite=Lax`, secure-in-production session cookies
- CSRF tokens on authenticated write requests
- all sessions invalidated when a password is reset
- HSTS, clickjacking, MIME-sniffing, referrer, and no-store headers

## Pages

| URL | Description |
|---|---|
| `/` | Landing page |
| `/signup` | Create an account |
| `/login` | Sign in |
| `/forgot-password` | Request a reset link |
| `/app` | Code extractor (requires authentication) |
| `/workflows` | Patient outreach and appointment workflow hub (requires authentication) |
