# moBILLity – AI Medical Code Extractor

AI-powered ICD-10, CPT, and HCPCS extraction from clinical notes, built with
FastAPI and OpenAI.

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
ADMIN_EMAILS=admin@example.com
ANALYTICS_RETENTION_DAYS=90
PRIVACY_CONTACT_EMAIL=privacy@example.com
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

On hosts that block SMTP ports, configure Brevo's HTTPS transactional email API
instead:

```bash
BREVO_API_KEY=...
BREVO_FROM_EMAIL=your-verified-sender@example.com
BREVO_FROM_NAME=moBILLity
```

When `BREVO_API_KEY` is set, the HTTPS email API is preferred over SMTP.

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
| `/admin` | Privacy-minimized account analytics (admin only) |
| `/privacy` | Analytics notice and user opt-out |

## Privacy-minimized analytics

Set `ADMIN_EMAILS` to a comma-separated list of verified account emails. The
server—not the page UI—enforces admin access. Analytics stores only allowlisted
feature events, a user ID, a coarse page name, and a timestamp. It never stores
clinical notes, extracted codes, IP addresses, location, or device fingerprints.
Users can disable and erase their event history from `/privacy`; the default
event retention period is 90 days.

Before production launch, confirm the notice matches actual operational
practices, document a consumer-request and appeal workflow, and have qualified
privacy counsel review the deployment. Production startup requires a monitored
`PRIVACY_CONTACT_EMAIL`.
