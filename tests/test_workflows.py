import os
import unittest
from datetime import timedelta

import bcrypt
from fastapi.testclient import TestClient

import app as workflow_app


class WorkflowAutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["COMMUNICATION_DELIVERY_MODE"] = "preview"
        workflow_app._init_db()
        cls.email = "workflow@example.com"
        cls.password = "a sufficiently long workflow password"
        with workflow_app._db() as db:
            db.execute("DELETE FROM users WHERE email = ?", (cls.email,))
            db.execute(
                """INSERT INTO users
                   (email, password_hash, full_name, email_verified, created_at)
                   VALUES (?, ?, 'Workflow Tester', 1, ?)""",
                (
                    cls.email,
                    bcrypt.hashpw(cls.password.encode(), bcrypt.gensalt()).decode(),
                    workflow_app._utcnow().isoformat(),
                ),
            )
        cls.client = TestClient(workflow_app.app)
        login = cls.client.post(
            "/api/token", data={"username": cls.email, "password": cls.password}
        )
        assert login.status_code == 200

    def _headers(self):
        return {
            "X-CSRF-Token": self.client.cookies.get("mobillity_csrf"),
            "Content-Type": "application/json",
        }

    def test_consent_schedules_and_dispatches_seven_day_reminders(self):
        patient = self.client.post(
            "/api/workflows/patients",
            headers=self._headers(),
            json={
                "name": "Jordan Patient",
                "phone": "+15555550123",
                "email": "jordan@example.com",
                "sms_consent": True,
                "voice_consent": True,
                "email_consent": True,
            },
        )
        self.assertEqual(patient.status_code, 201)

        starts_at = workflow_app._utcnow() + timedelta(days=6)
        appointment = self.client.post(
            "/api/workflows/appointments",
            headers=self._headers(),
            json={
                "patient_id": patient.json()["id"],
                "starts_at": starts_at.isoformat(),
                "clinician": "Dr. Rivera",
                "location": "Main clinic",
            },
        )
        self.assertEqual(appointment.status_code, 201)
        self.assertEqual(appointment.json()["reminders_created"], 3)

        overview = self.client.get("/api/workflows/overview")
        scheduled_for = overview.json()["reminders"][0]["scheduled_for"]
        expected = starts_at - timedelta(days=7)
        self.assertLess(
            abs((workflow_app.datetime.fromisoformat(scheduled_for) - expected).total_seconds()),
            1,
        )

        dispatched = self.client.post(
            "/api/workflows/dispatch", headers=self._headers()
        )
        self.assertEqual(dispatched.status_code, 200)
        self.assertEqual(dispatched.json()["sent"], 3)

        final = self.client.get("/api/workflows/overview").json()
        self.assertEqual(
            len([reminder for reminder in final["reminders"] if reminder["status"] == "sent"]),
            3,
        )
        self.assertEqual(len(final["events"]), 3)

    def test_front_desk_intent_creates_handoff(self):
        response = self.client.post(
            "/webhooks/twilio/inbound-call",
            data={"From": "+15555550199", "SpeechResult": "I need help with my insurance"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("front desk", response.text.lower())
        with workflow_app._db() as db:
            handoff = db.execute(
                "SELECT * FROM call_handoffs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(handoff["status"], "queued")
        self.assertIn("insurance", handoff["reason"].lower())


if __name__ == "__main__":
    unittest.main()
