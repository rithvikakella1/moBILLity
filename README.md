# moBILLity – Clinical Workflow Automation

FastAPI-based clinical operations platform with AI-powered ICD-10, CPT, and
HCPCS extraction plus consent-aware appointment outreach.

## Workflow Hub

The authenticated `/workflows` area supports:

- encrypted patient contact details and per-channel consent
- appointment reminders by SMS, voice, and email, sent seven days before the
  visit — or 24 hours before when the visit is booked inside that window, and
  skipped entirely under two hours' notice
- reminder times rendered in the patient's own timezone, and phone channels
  held outside 8pm–8am local time
- a dispatcher that claims, delivers, and records each job in separate
  transactions, so a crash mid-batch cannot re-send a delivered message
- STOP/START handling on inbound SMS, which revokes consent and cancels that
  patient's queued texts
- a Twilio-compatible inbound voice webhook that routes billing, insurance,
  medical-record, referral, complaint, and manager requests to a front-desk
  queue staff can work from
- preview delivery by default, so local development never contacts patients

Set a stable `ENCRYPTION_KEY` before storing patient data. It must be a
base64-encoded value that decodes to exactly 32 bytes, and is mandatory in
production. A short or malformed key is rejected at startup rather than being
padded. Generate one with:

```bash
python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
```

Keys are versioned, so one can be retired without downtime: add
`ENCRYPTION_KEY_V2`, point `ENCRYPTION_KEY_CURRENT` at it, and run
`rotate_encryption_keys()` until it reports zero rotated. Values written under
an older key stay readable throughout.

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

Configure the Twilio number's webhooks as:

```text
Voice:    POST https://your-domain.example/webhooks/twilio/inbound-call
Messaging: POST https://your-domain.example/webhooks/twilio/inbound-sms
```

The messaging webhook is required: outbound texts advertise "Reply STOP", and
without it a withdrawn consent is never recorded.

Both webhooks verify Twilio's signature against `APP_BASE_URL`, not the request
URL, so TLS termination at a proxy cannot break validation. Run uvicorn with
`--proxy-headers --forwarded-allow-ips='*'` behind a load balancer, or per-IP
rate limiting collapses into one global bucket.

`WORKFLOW_WORKER=true` runs the due-job dispatcher once per minute. **It
defaults to false and must be enabled on exactly one process** — a dispatcher in
every web worker sends every patient duplicate reminders. `render.yaml` deploys
it as a dedicated worker running `worker.py`.

## Local setup

The app runs as two processes: the FastAPI API and the Astro frontend. The
frontend proxies `/api`, `/auth`, `/webhooks`, `/admin`, `/health`, and
`/static` to the API, so the browser sees a single origin — which is what keeps
the session cookie first-party.

### One-time setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env             # then fill in OPENAI_API_KEY

cd frontend && npm install && cd ..
```

Generate the secrets `.env` needs:

```bash
python -c "import base64,os;print('ENCRYPTION_KEY=' + base64.b64encode(os.urandom(32)).decode())"
python -c "import secrets;print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets;print('SESSION_SECRET_KEY=' + secrets.token_hex(32))"
```

Keep `ENCRYPTION_KEY` stable across restarts, or patient data written before a
restart becomes unreadable after it.

### Every run — two terminals

```bash
# terminal 1 — API on :8000
uvicorn app:app --reload

# terminal 2 — frontend on :4321
cd frontend && npm run dev
```

Open **http://localhost:4321**. Do not use `:8000` directly — the API serves the
legacy pages there, and running both would leave two copies of the app fighting
over the same cookie.

To sign in: register at `/signup`, then copy the verification link out of
terminal 1. `AUTH_DEV_SHOW_LINKS=true` writes it to the log, so no email
configuration is needed locally.

To skip that entirely, seed a pre-verified account:

```bash
python scripts/seed_admin.py                       # admin@local.test
python scripts/seed_admin.py --email me@x.test --password "..."
```

It is idempotent, so re-running resets the password rather than failing, and it
refuses to run when `ENVIRONMENT=production`. Admin access is not stored on the
row -- `_is_admin()` matches the signed-in address against `ADMIN_EMAILS`, so the
script prints the exact line to add if the address is not already listed. That
variable is read at import, and `--reload` only watches `.py` files, so restart
the API after changing it.

### When a port is busy

Astro moves to 4322 without saying much — check terminal 2 for the real URL. On
Windows a stale uvicorn can hold :8000 and produce `WinError 10013`.

Do not go by the PID that `Get-NetTCPConnection` reports: with `--reload`, uvicorn
runs the server in a `multiprocessing` child that inherits the listening socket,
so the port keeps answering after the parent dies and the reported owner is a PID
that no longer exists. Killing by command line misses it too — the child's command
line is a `spawn_main` bootstrap with no `uvicorn` in it. Match on the parent
instead:

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -match 'python' -and
                 ($_.CommandLine -match 'uvicorn' -or $_.CommandLine -match 'multiprocessing-fork') } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

Then confirm the port is actually free — `netstat -ano | findstr :8000` should
print nothing before you start again.

### Checks

Run the checks the CI pipeline runs:

```bash
pytest                      # 116 tests
ruff check .
node scripts/check-xss.js   # prompt-injection payloads must render as text
```

Schema changes go through Alembic:

```bash
alembic upgrade head              # apply
alembic revision -m "add x"       # create
alembic stamp 0001                # mark an existing database as current
```

`tests/test_migrations.py` fails the build if the migrations and the local
development schema ever diverge.

Before changing the prompt, the model, or the confidence threshold, measure the
effect:

```bash
python tests/benchmark.py --sweep
```


## Authentication

Accounts are stored in PostgreSQL when `DATABASE_URL` is set, and in SQLite
(`users.db`) otherwise. Password accounts must verify their email before signing
in. Google accounts rely on Google's verified email claim.

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
- HSTS, clickjacking, MIME-sniffing, referrer, and cache-control headers
- a Content-Security-Policy whose `connect-src 'self'` blocks exfiltration
- all model output HTML-escaped before rendering, since a clinical note can
  carry a prompt injection
- AES-256-GCM field encryption with versioned keys and a rotation path
- provider errors logged server-side and never returned to the client
- per-tenant scoping on every workflow read, write, and dispatch

## Pages

| URL | Description |
|---|---|
| `/` | Landing page |
| `/signup` | Create an account |
| `/login` | Sign in |
| `/forgot-password` | Request a reset link |
| `/app` | Code extractor (requires authentication) |
| `/workflows` | Patient outreach and appointment workflow hub (requires authentication) |
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
