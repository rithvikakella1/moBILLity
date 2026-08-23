"""Shared test configuration.

Every environment variable the application reads at import time must be set
before ``app`` is imported anywhere. conftest is imported before test modules,
so this module is the only correct place to do it — a test file that sets them
itself only works when it happens to be collected first.
"""
import base64
import os
import tempfile

_TEST_DB = os.path.join(tempfile.mkdtemp(prefix="mobillity-test-"), "test.db")

os.environ.update(
    DATABASE_FILE=_TEST_DB,
    DATABASE_URL="",
    ENVIRONMENT="test",
    OPENAI_API_KEY="test-key",
    JWT_SECRET_KEY="test-jwt-secret-that-is-long-and-random",
    SESSION_SECRET_KEY="test-session-secret-that-is-long-and-random",
    # Generated per run rather than hard-coded. No test asserts a fixed
    # ciphertext -- they encrypt and decrypt within the run -- so a literal key
    # bought nothing and put a valid 32-byte AES key in the repository, where
    # someone could paste it into a real environment. A fresh one each session
    # also proves the tests do not secretly depend on a particular key.
    ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode(),
    ADMIN_EMAILS="admin@example.com",
    COMMUNICATION_DELIVERY_MODE="preview",
    WORKFLOW_WORKER="false",
    PRACTICE_NAME="Test Health",
    # Webhook tests post unsigned payloads. The bypass must be requested by name;
    # it is never implied by a missing Twilio credential.
    TWILIO_SKIP_SIGNATURE_CHECK="true",
)

import pytest  # noqa: E402

import app as application  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema():
    """Build the schema once for the session."""
    application._init_db()
    yield


@pytest.fixture(autouse=True)
def _no_rate_limits():
    """Rate limiting is verified in its own test.

    Left on, the 5/minute login limit throttles every other test that signs in,
    producing failures that have nothing to do with what is under test.
    """
    application.limiter.enabled = False
    yield
    application.limiter.enabled = False


@pytest.fixture
def rate_limits():
    """Opt back in for tests that assert throttling behaviour."""
    application.limiter.enabled = True
    application.limiter.reset()
    yield
    application.limiter.enabled = False


@pytest.fixture
def db():
    """Direct database access for arranging and asserting state."""
    return application._db


@pytest.fixture
def client():
    """A fresh, unauthenticated client with its own cookie jar."""
    from fastapi.testclient import TestClient

    with TestClient(application.app) as test_client:
        yield test_client


@pytest.fixture
def captured_email(monkeypatch):
    """Collect outbound mail instead of sending it."""
    messages = []
    monkeypatch.setattr(
        application, "_send_email", lambda to, subject, body: messages.append((to, subject, body))
    )
    return messages


@pytest.fixture
def make_user():
    """Create a verified password account and return its email and password."""
    import bcrypt

    created = []

    def _make(email, password="a sufficiently long test password"):
        with application._db() as handle:
            handle.execute("DELETE FROM users WHERE email = ?", (email,))
            handle.execute(
                """INSERT INTO users (email, password_hash, full_name, email_verified, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (
                    email,
                    bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
                    email.split("@")[0],
                    application._utcnow().isoformat(),
                ),
            )
        created.append(email)
        return email, password

    yield _make

    with application._db() as handle:
        for email in created:
            handle.execute("DELETE FROM users WHERE email = ?", (email,))


@pytest.fixture
def signed_in(client, make_user):
    """A client authenticated as a verified user, plus its CSRF header."""

    def _sign_in(email="user@example.com"):
        address, password = make_user(email)
        response = client.post("/api/token", data={"username": address, "password": password})
        assert response.status_code == 200, response.text
        headers = {"X-CSRF-Token": client.cookies.get("mobillity_csrf")}
        return client, headers, address

    return _sign_in
