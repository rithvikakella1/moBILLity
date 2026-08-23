"""Create a verified local account for testing, bypassing the email flow.

Signing up normally means fishing a verification link out of the server log.
That is fine once, tedious every time you reset the database. This writes the
row directly with email_verified already set.

    python scripts/seed_admin.py
    python scripts/seed_admin.py --email me@example.com --password "..."

Admin access is not a column -- _is_admin() compares the signed-in address
against the ADMIN_EMAILS environment variable, so the account is only an admin
if its address appears there. The script checks and tells you if it does not.

Development only. It refuses to run against a production environment, since a
known-password account with a verified address is exactly the sort of thing
that should never exist on a real deployment.
"""

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bcrypt  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import app  # noqa: E402

DEFAULT_EMAIL = "admin@local.test"
# noqa justified: a known password is the entire point of a dev seed, and the
# production guard above is what keeps it off a real deployment.
DEFAULT_PASSWORD = "LocalAdmin!2026"  # noqa: S105


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default=DEFAULT_EMAIL)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--name", default="Local Admin")
    args = parser.parse_args()

    if app.IS_PRODUCTION:
        print("refusing to seed: ENVIRONMENT is production", file=sys.stderr)
        return 1

    email = app._normalize_email(args.email)
    if not app._password_is_valid(args.password):
        print(
            f"password must be 12-128 characters (got {len(args.password)})",
            file=sys.stderr,
        )
        return 1

    password_hash = bcrypt.hashpw(args.password.encode(), bcrypt.gensalt()).decode()
    now = datetime.now(UTC).isoformat()

    with app._db() as db:
        existing = db.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            # Bumping session_version logs out any token issued under the old
            # password, matching what a real password reset does.
            db.execute(
                """UPDATE users
                      SET password_hash = ?, full_name = ?, email_verified = 1,
                          session_version = session_version + 1
                    WHERE id = ?""",
                (password_hash, args.name, existing["id"]),
            )
            action = "updated"
        else:
            db.execute(
                """INSERT INTO users(email, password_hash, full_name,
                                     email_verified, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (email, password_hash, args.name, now),
            )
            action = "created"

    print(f"{action} account")
    print(f"  email    : {email}")
    print(f"  password : {args.password}")
    print(f"  sign in  : {app.APP_BASE_URL}/login")

    if email in app.ADMIN_EMAILS:
        print(f"  admin    : yes -> {app.APP_BASE_URL}/admin")
    else:
        current = os.getenv("ADMIN_EMAILS", "")
        combined = f"{current},{email}" if current else email
        print("  admin    : NO -- add this line to .env and restart the API:")
        print(f"             ADMIN_EMAILS={combined}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
