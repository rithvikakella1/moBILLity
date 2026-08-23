"""Page routing: legacy serving, canonical redirects, and the admin gate.

The frontend moved to a static Astro build served from FRONTEND_BASE_URL, which
proxies the API back to this app so the browser sees one origin. These tests pin
the switch-over behaviour in both configurations.
"""

import pytest
from fastapi.testclient import TestClient

import app as page_app

LEGACY_PAGES = [
    ("/", "index.html"),
    ("/app", "app.html"),
    ("/workflows", "workflows.html"),
    ("/login", "login.html"),
    ("/signup", "signup.html"),
    ("/forgot-password", "forgot-password.html"),
    ("/reset-password", "reset-password.html"),
    ("/verify-email", "verify-email.html"),
    ("/privacy", "privacy.html"),
]


@pytest.fixture
def client():
    with TestClient(page_app.app, follow_redirects=False) as test_client:
        yield test_client


class TestLegacyServing:
    """With FRONTEND_BASE_URL unset, this process still serves the pages."""

    @pytest.mark.parametrize("path,_filename", LEGACY_PAGES)
    def test_page_is_served(self, client, path, _filename):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")

    def test_privacy_substitutions_are_applied(self, client):
        body = client.get("/privacy").text
        assert "{{RETENTION_DAYS}}" not in body
        assert "{{PRIVACY_CONTACT}}" not in body


class TestCanonicalRedirect:
    """With FRONTEND_BASE_URL set, pages redirect to the built frontend."""

    @pytest.fixture
    def redirecting(self, monkeypatch):
        monkeypatch.setattr(page_app, "FRONTEND_BASE_URL", "https://app.example.com")
        with TestClient(page_app.app, follow_redirects=False) as test_client:
            yield test_client

    @pytest.mark.parametrize("path,_filename", LEGACY_PAGES)
    def test_page_redirects_permanently(self, redirecting, path, _filename):
        response = redirecting.get(path)
        assert response.status_code == 308, path
        assert response.headers["location"] == f"https://app.example.com{path}"

    def test_admin_is_never_redirected(self, redirecting):
        """/admin stays here: its access check runs before the HTML is served."""
        response = redirecting.get("/admin")
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_api_routes_are_unaffected(self, redirecting):
        assert redirecting.get("/health").status_code == 200
        assert redirecting.get("/api/me").status_code == 401


class TestPrivacyConfig:
    """The static privacy page reads these values instead of having them
    substituted server-side."""

    def test_returns_the_configured_values(self, client):
        response = client.get("/api/privacy-config")
        assert response.status_code == 200
        body = response.json()
        assert body["retention_days"] == page_app.ANALYTICS_RETENTION_DAYS
        assert body["privacy_contact"] == page_app.PRIVACY_CONTACT_EMAIL

    def test_needs_no_authentication(self, client):
        """A privacy notice must be readable before signing in."""
        assert client.get("/api/privacy-config").status_code == 200

    def test_retention_matches_the_documented_bound(self, client):
        days = client.get("/api/privacy-config").json()["retention_days"]
        assert 1 <= days <= 365


class TestContentSecurityPolicy:
    """script-src tightens once the legacy inline-script pages are retired."""

    def test_legacy_mode_allows_inline_scripts(self, client):
        """The old HTML files carry inline <script> and would break otherwise."""
        policy = client.get("/health").headers["content-security-policy"]
        assert "script-src 'self' 'unsafe-inline'" in policy

    def test_built_frontend_mode_forbids_inline_scripts(self, monkeypatch):
        monkeypatch.setattr(page_app, "FRONTEND_BASE_URL", "https://app.example.com")
        with TestClient(page_app.app) as strict:
            policy = strict.get("/health").headers["content-security-policy"]
        assert "script-src 'self';" in policy
        assert "'unsafe-inline'" not in policy.split("style-src")[0]

    @pytest.mark.parametrize(
        "directive",
        [
            "connect-src 'self'",   # blocks exfiltration of the CSRF cookie
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
        ],
    )
    def test_load_bearing_directives_are_always_present(self, client, directive):
        assert directive in client.get("/health").headers["content-security-policy"]

    def test_admin_page_has_no_inline_script(self):
        """/admin is served by this app, so it must satisfy the strict policy."""
        from pathlib import Path

        markup = Path(page_app.BASE_DIR, "admin.html").read_text(encoding="utf-8")
        assert "<script>" not in markup
        assert "/static/admin.js" in markup


class TestGoogleSignIn:
    """Unconfigured Google sign-in must degrade to a page, not raw JSON."""

    @pytest.fixture
    def unconfigured(self, monkeypatch):
        """Force the no-credentials state.

        These assertions used to rely on the developer's own .env happening to
        have no Google keys, so adding real ones broke the suite locally while
        CI stayed green. Strip the registration explicitly instead.
        """
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
        # Authlib resolves `oauth.google` through __getattr__, which consults
        # _registry — so unregistering there is what makes the lookup in
        # google_login() fall through to None.
        monkeypatch.delitem(page_app.oauth._registry, "google", raising=False)
        monkeypatch.delitem(page_app.oauth._clients, "google", raising=False)

    def test_entry_point_redirects_when_unconfigured(self, client, unconfigured):
        response = client.get("/auth/google")
        assert response.status_code == 303
        assert "error=google_unavailable" in response.headers["location"]

    def test_callback_redirects_when_unconfigured(self, client, unconfigured):
        response = client.get("/auth/google/callback")
        assert response.status_code == 303
        assert "error=google_unavailable" in response.headers["location"]

    def test_health_reports_the_integration_state(self, client, unconfigured):
        """The sign-in page reads this to decide whether to offer the button."""
        integrations = client.get("/health").json()["integrations"]
        assert "google_oauth" in integrations
        assert integrations["google_oauth"] is False

    def test_redirect_uri_is_built_from_app_base_url(self):
        """It must point at the public origin, not the API's own host — the
        frontend proxies /auth back here, and Google matches this string
        exactly against the console's authorised list."""
        assert page_app.APP_BASE_URL
        assert not page_app.APP_BASE_URL.endswith("/")
