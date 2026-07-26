import os
import re
import tempfile
import unittest

os.environ["DATABASE_FILE"] = tempfile.mktemp(prefix="mobillity-test-", suffix=".db")
os.environ["OPENAI_API_KEY"] = "test-key"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-that-is-long-and-random"
os.environ["SESSION_SECRET_KEY"] = "test-session-secret-that-is-long-and-random"

from fastapi.testclient import TestClient

import app as auth_app


class AuthenticationFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.messages = []
        auth_app._send_email = lambda to, subject, body: cls.messages.append((to, subject, body))
        cls.client = TestClient(auth_app.app)

    def _latest_token(self):
        match = re.search(r"token=([A-Za-z0-9_-]+)", self.messages[-1][2])
        self.assertIsNotNone(match)
        return match.group(1)

    def test_complete_password_account_flow(self):
        email = "doctor@example.com"
        old_password = "a long initial passphrase"
        new_password = "a different secure passphrase"

        created = self.client.post(
            "/api/register",
            json={"email": email, "password": old_password, "full_name": "Dr. Test"},
        )
        self.assertEqual(created.status_code, 201)
        self.assertIn("verify", created.json()["message"].lower())

        unverified_login = self.client.post(
            "/api/token", data={"username": email, "password": old_password}
        )
        self.assertEqual(unverified_login.status_code, 403)

        verified = self.client.post("/api/verify-email", json={"token": self._latest_token()})
        self.assertEqual(verified.status_code, 200)

        reused = self.client.post("/api/verify-email", json={"token": self._latest_token()})
        self.assertEqual(reused.status_code, 400)

        login = self.client.post(
            "/api/token", data={"username": email, "password": old_password}
        )
        self.assertEqual(login.status_code, 200)
        old_session = self.client.cookies.get("mobillity_session")
        self.assertTrue(old_session)
        self.assertEqual(self.client.get("/api/me").json()["email"], email)

        forgot = self.client.post("/api/forgot-password", json={"email": email})
        self.assertEqual(forgot.status_code, 200)
        reset_token = self._latest_token()

        reset = self.client.post(
            "/api/reset-password",
            json={"token": reset_token, "password": new_password},
        )
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(
            self.client.post(
                "/api/reset-password",
                json={"token": reset_token, "password": "yet another passphrase"},
            ).status_code,
            400,
        )

        stale_client = TestClient(auth_app.app)
        stale_client.cookies.set("mobillity_session", old_session)
        self.assertEqual(stale_client.get("/api/me").status_code, 401)

        self.assertEqual(
            self.client.post(
                "/api/token", data={"username": email, "password": old_password}
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/token", data={"username": email, "password": new_password}
            ).status_code,
            200,
        )

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(os.environ["DATABASE_FILE"])
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    unittest.main()
