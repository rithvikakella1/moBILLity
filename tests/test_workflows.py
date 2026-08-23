"""Workflow scheduling, dispatch, tenant isolation, and inbound call handling."""
from datetime import timedelta

import pytest

import app as workflow_app


def _make_patient(client, headers, name="Jordan Patient", **overrides):
    payload = {
        "name": name,
        "phone": "+15555550123",
        "email": "jordan@example.com",
        "timezone": "America/New_York",
        "sms_consent": True,
        "voice_consent": True,
        "email_consent": True,
    }
    payload.update(overrides)
    response = client.post("/api/workflows/patients", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _make_appointment(client, headers, patient_id, days_out, hours_out=0):
    starts_at = workflow_app._utcnow() + timedelta(days=days_out, hours=hours_out)
    response = client.post(
        "/api/workflows/appointments",
        headers=headers,
        json={
            "patient_id": patient_id,
            "starts_at": starts_at.isoformat(),
            "clinician": "Dr. Rivera",
            "location": "Main clinic",
        },
    )
    assert response.status_code == 201, response.text
    return response.json(), starts_at


class TestReminderScheduling:
    def test_consent_creates_one_job_per_consented_channel(self, signed_in):
        client, headers, _ = signed_in("scheduling@example.com")
        patient = _make_patient(client, headers)
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=30)
        assert appointment["reminders_created"] == 3

    def test_channels_without_consent_are_not_scheduled(self, signed_in):
        client, headers, _ = signed_in("partial@example.com")
        patient = _make_patient(
            client, headers, name="Email Only",
            sms_consent=False, voice_consent=False, email_consent=True,
        )
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=30)
        assert appointment["reminders_created"] == 1

    def test_far_future_appointment_uses_the_seven_day_lead(self, signed_in):
        client, headers, _ = signed_in("leadtime@example.com")
        patient = _make_patient(client, headers, sms_consent=False, voice_consent=False)
        _, starts_at = _make_appointment(client, headers, patient["id"], days_out=30)

        reminder = client.get("/api/workflows/overview").json()["reminders"][0]
        scheduled = workflow_app.datetime.fromisoformat(reminder["scheduled_for"])
        expected = starts_at - timedelta(days=7)
        assert abs((scheduled - expected).total_seconds()) < 60

    def test_short_notice_booking_falls_back_to_a_day_ahead(self, signed_in):
        """A visit booked inside the lead window must not fire instantly."""
        client, headers, _ = signed_in("shortnotice@example.com")
        patient = _make_patient(client, headers, sms_consent=False, voice_consent=False)
        _, starts_at = _make_appointment(client, headers, patient["id"], days_out=3)

        reminder = client.get("/api/workflows/overview").json()["reminders"][0]
        scheduled = workflow_app.datetime.fromisoformat(reminder["scheduled_for"])
        assert scheduled > workflow_app._utcnow(), "reminder must never be scheduled in the past"
        expected = starts_at - timedelta(hours=24)
        assert abs((scheduled - expected).total_seconds()) < 60

    def test_imminent_appointment_schedules_nothing(self, signed_in):
        client, headers, _ = signed_in("imminent@example.com")
        patient = _make_patient(client, headers)
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=0, hours_out=1)
        assert appointment["reminders_created"] == 0

    def test_quiet_hours_push_voice_out_of_the_night(self, signed_in):
        client, headers, _ = signed_in("quiet@example.com")
        patient = _make_patient(client, headers, email_consent=False)
        _make_appointment(client, headers, patient["id"], days_out=30)

        zone = workflow_app.ZoneInfo("America/New_York")
        for reminder in client.get("/api/workflows/overview").json()["reminders"]:
            scheduled = workflow_app.datetime.fromisoformat(reminder["scheduled_for"])
            local_hour = scheduled.astimezone(zone).hour
            assert 8 <= local_hour < 21, f"{reminder['channel']} scheduled at {local_hour}:00 local"

    def test_unknown_timezone_is_rejected_at_entry(self, signed_in):
        client, headers, _ = signed_in("badzone@example.com")
        response = client.post(
            "/api/workflows/patients",
            headers=headers,
            json={"name": "Bad Zone", "timezone": "Mars/Olympus_Mons"},
        )
        assert response.status_code == 400
        assert "timezone" in response.json()["detail"].lower()


class TestDispatch:
    def test_due_reminders_are_delivered_and_recorded(self, signed_in):
        client, headers, _ = signed_in("dispatch@example.com")
        patient = _make_patient(client, headers)
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=30)

        # Pull the jobs into the past so they are due now.
        with workflow_app._db() as db:
            db.execute(
                "UPDATE reminder_jobs SET scheduled_for = ? WHERE appointment_id = ?",
                (workflow_app._iso_datetime(workflow_app._utcnow() - timedelta(minutes=1)),
                 appointment["id"]),
            )

        result = client.post("/api/workflows/dispatch", headers=headers).json()
        assert result["sent"] == 3, result

        overview = client.get("/api/workflows/overview").json()
        assert len([r for r in overview["reminders"] if r["status"] == "sent"]) == 3
        assert len(overview["events"]) == 3

    def test_cancelling_an_appointment_cancels_its_reminders(self, signed_in):
        client, headers, _ = signed_in("cancel@example.com")
        patient = _make_patient(client, headers)
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=30)

        response = client.patch(
            f"/api/workflows/appointments/{appointment['id']}",
            headers=headers, json={"status": "cancelled"},
        )
        assert response.status_code == 200

        statuses = {
            r["status"] for r in client.get("/api/workflows/overview").json()["reminders"]
        }
        assert statuses == {"cancelled"}

    def test_delivery_failure_is_recorded_not_raised(self, signed_in, monkeypatch):
        client, headers, _ = signed_in("failure@example.com")
        patient = _make_patient(client, headers, sms_consent=False, voice_consent=False)
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=30)

        with workflow_app._db() as db:
            db.execute(
                "UPDATE reminder_jobs SET scheduled_for = ? WHERE appointment_id = ?",
                (workflow_app._iso_datetime(workflow_app._utcnow() - timedelta(minutes=1)),
                 appointment["id"]),
            )

        def _boom(*_args, **_kwargs):
            raise RuntimeError("provider unavailable")

        monkeypatch.setattr(workflow_app, "_deliver_reminder", _boom)
        result = client.post("/api/workflows/dispatch", headers=headers).json()
        assert result["failed"] == 1 and result["sent"] == 0

        reminder = client.get("/api/workflows/overview").json()["reminders"][0]
        assert reminder["status"] == "failed"
        assert "provider unavailable" in reminder["last_error"]


class TestTenantIsolation:
    """The property that most needs to hold, and previously had no coverage."""

    def _tenant(self, client_factory, email):
        client, headers, _ = client_factory(email)
        patient = _make_patient(client, headers, name=f"Patient of {email}")
        appointment, _ = _make_appointment(client, headers, patient["id"], days_out=30)
        return client, headers, patient, appointment

    def test_a_tenant_cannot_see_another_tenants_records(self, client, signed_in, make_user):
        from fastapi.testclient import TestClient

        # Tenant A
        client_a, headers_a, _ = signed_in("tenant-a@example.com")
        patient_a = _make_patient(client_a, headers_a, name="Alice Patient")
        _make_appointment(client_a, headers_a, patient_a["id"], days_out=30)

        # Tenant B, on a separate cookie jar
        email_b, password_b = make_user("tenant-b@example.com")
        client_b = TestClient(workflow_app.app)
        assert client_b.post(
            "/api/token", data={"username": email_b, "password": password_b}
        ).status_code == 200

        overview_b = client_b.get("/api/workflows/overview").json()
        names = [p["name"] for p in overview_b["patients"]]
        assert "Alice Patient" not in names
        assert overview_b["appointments"] == []

    def test_a_tenant_cannot_book_against_another_tenants_patient(self, signed_in, make_user):
        from fastapi.testclient import TestClient

        client_a, headers_a, _ = signed_in("owner@example.com")
        patient_a = _make_patient(client_a, headers_a, name="Owned Patient")

        email_b, password_b = make_user("intruder@example.com")
        client_b = TestClient(workflow_app.app)
        client_b.post("/api/token", data={"username": email_b, "password": password_b})
        headers_b = {"X-CSRF-Token": client_b.cookies.get("mobillity_csrf")}

        response = client_b.post(
            "/api/workflows/appointments",
            headers=headers_b,
            json={
                "patient_id": patient_a["id"],
                "starts_at": (workflow_app._utcnow() + timedelta(days=30)).isoformat(),
            },
        )
        assert response.status_code == 404

    def test_dispatch_does_not_touch_another_tenants_jobs(self, signed_in, make_user):
        from fastapi.testclient import TestClient

        # Tenant A has a due job.
        client_a, headers_a, _ = signed_in("dispatch-a@example.com")
        patient_a = _make_patient(client_a, headers_a, sms_consent=False, voice_consent=False)
        appointment_a, _ = _make_appointment(client_a, headers_a, patient_a["id"], days_out=30)
        with workflow_app._db() as db:
            db.execute(
                "UPDATE reminder_jobs SET scheduled_for = ? WHERE appointment_id = ?",
                (workflow_app._iso_datetime(workflow_app._utcnow() - timedelta(minutes=1)),
                 appointment_a["id"]),
            )

        # Tenant B dispatches. Tenant A's job must be untouched.
        email_b, password_b = make_user("dispatch-b@example.com")
        client_b = TestClient(workflow_app.app)
        client_b.post("/api/token", data={"username": email_b, "password": password_b})
        headers_b = {"X-CSRF-Token": client_b.cookies.get("mobillity_csrf")}

        result = client_b.post("/api/workflows/dispatch", headers=headers_b).json()
        assert result["sent"] == 0, "tenant B triggered tenant A's deliveries"

        with workflow_app._db() as db:
            job = db.execute(
                "SELECT status FROM reminder_jobs WHERE appointment_id = ?",
                (appointment_a["id"],),
            ).fetchone()
        assert job["status"] == "pending"


class TestCsrf:
    @pytest.mark.parametrize(
        "method,path",
        [
            ("post", "/api/workflows/patients"),
            ("post", "/api/workflows/dispatch"),
            ("post", "/api/logout"),
        ],
    )
    def test_write_requires_a_matching_csrf_token(self, signed_in, method, path):
        client, _, _ = signed_in("csrf@example.com")
        response = getattr(client, method)(path, json={"name": "No Token"})
        assert response.status_code == 403

    def test_mismatched_csrf_token_is_rejected(self, signed_in):
        client, _, _ = signed_in("csrf2@example.com")
        response = client.post(
            "/api/workflows/patients",
            headers={"X-CSRF-Token": "not-the-real-token"},
            json={"name": "Wrong Token"},
        )
        assert response.status_code == 403


class TestInboundCalls:
    def test_front_desk_intent_creates_a_handoff(self, client):
        response = client.post(
            "/webhooks/twilio/inbound-call",
            data={"From": "+15555550199", "SpeechResult": "I need help with my insurance"},
        )
        assert response.status_code == 200
        assert "front desk" in response.text.lower()

        with workflow_app._db() as db:
            handoff = db.execute(
                "SELECT * FROM call_handoffs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        assert handoff["status"] == "queued"
        assert "insurance" in handoff["reason"].lower()

    def test_a_call_to_a_registered_number_is_attributed_and_queued(self, signed_in, client):
        """An inbound call must reach the owning practice's queue."""
        owner_client, headers, email = signed_in("frontdesk@example.com")
        with workflow_app._db() as db:
            owner = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            db.execute("DELETE FROM practice_phone_numbers WHERE phone_number = ?", ("+15555559000",))
            db.execute(
                """INSERT INTO practice_phone_numbers
                   (owner_user_id, phone_number, label, created_at)
                   VALUES (?, ?, 'Main line', ?)""",
                (owner["id"], "+15555559000", workflow_app._utcnow().isoformat()),
            )

        client.post(
            "/webhooks/twilio/inbound-call",
            data={
                "From": "+15555550111",
                "To": "+15555559000",
                "SpeechResult": "question about my bill",
            },
        )

        queue = owner_client.get("/api/workflows/handoffs").json()["handoffs"]
        assert len(queue) == 1
        assert queue[0]["caller_phone"] == "+15555550111"
        assert queue[0]["status"] == "queued"

    def test_a_handoff_can_be_resolved(self, signed_in, client):
        owner_client, headers, email = signed_in("resolve@example.com")
        with workflow_app._db() as db:
            owner = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            db.execute(
                """INSERT INTO call_handoffs
                   (owner_user_id, caller_phone_encrypted, reason, status, created_at)
                   VALUES (?, ?, 'billing', 'queued', ?)""",
                (owner["id"], workflow_app._encrypt_optional("+15555550222"),
                 workflow_app._utcnow().isoformat()),
            )

        queued = owner_client.get("/api/workflows/handoffs").json()["handoffs"]
        assert queued
        response = owner_client.patch(
            f"/api/workflows/handoffs/{queued[0]['id']}",
            headers=headers, json={"status": "resolved"},
        )
        assert response.status_code == 200
        assert owner_client.get("/api/workflows/handoffs").json()["handoffs"] == []


class TestSmsOptOut:
    """STOP is advertised in every outbound message, so it must be honoured."""

    def _patient_with_phone(self, signed_in, email, phone="+15555557777"):
        client, headers, _ = signed_in(email)
        patient = _make_patient(client, headers, phone=phone, email_consent=False)
        return client, headers, patient

    def test_stop_revokes_sms_consent(self, signed_in, client):
        owner, headers, patient = self._patient_with_phone(signed_in, "stop@example.com")
        response = client.post(
            "/webhooks/twilio/inbound-sms",
            data={"From": "+15555557777", "Body": "STOP"},
        )
        assert response.status_code == 200
        assert "unsubscribed" in response.text.lower()

        with workflow_app._db() as db:
            row = db.execute(
                "SELECT sms_consent FROM patients WHERE id = ?", (patient["id"],)
            ).fetchone()
        assert row["sms_consent"] == 0

    def test_stop_cancels_pending_sms_jobs_only(self, signed_in, client):
        owner, headers, patient = self._patient_with_phone(signed_in, "stopjobs@example.com",
                                                           phone="+15555558888")
        _make_appointment(owner, headers, patient["id"], days_out=30)

        client.post("/webhooks/twilio/inbound-sms",
                    data={"From": "+15555558888", "Body": "stop"})

        reminders = owner.get("/api/workflows/overview").json()["reminders"]
        by_channel = {r["channel"]: r["status"] for r in reminders}
        assert by_channel["sms"] == "cancelled"
        assert by_channel["voice"] == "pending", "voice consent must be unaffected by an SMS STOP"

    def test_start_restores_consent(self, signed_in, client):
        owner, headers, patient = self._patient_with_phone(signed_in, "start@example.com",
                                                           phone="+15555556666")
        client.post("/webhooks/twilio/inbound-sms",
                    data={"From": "+15555556666", "Body": "STOP"})
        client.post("/webhooks/twilio/inbound-sms",
                    data={"From": "+15555556666", "Body": "START"})

        with workflow_app._db() as db:
            row = db.execute(
                "SELECT sms_consent FROM patients WHERE id = ?", (patient["id"],)
            ).fetchone()
        assert row["sms_consent"] == 1

    def test_an_unrecognised_reply_does_not_change_consent(self, signed_in, client):
        owner, headers, patient = self._patient_with_phone(signed_in, "chat@example.com",
                                                           phone="+15555555555")
        response = client.post(
            "/webhooks/twilio/inbound-sms",
            data={"From": "+15555555555", "Body": "my chest hurts"},
        )
        assert "not monitored" in response.text.lower()
        with workflow_app._db() as db:
            row = db.execute(
                "SELECT sms_consent FROM patients WHERE id = ?", (patient["id"],)
            ).fetchone()
        assert row["sms_consent"] == 1

    def test_phone_fingerprint_is_stable_across_formatting(self):
        assert workflow_app.phone_fingerprint("+1 (555) 555-7777") == \
               workflow_app.phone_fingerprint("+15555557777")

    def test_phone_fingerprint_is_not_the_plaintext(self):
        fingerprint = workflow_app.phone_fingerprint("+15555557777")
        assert "5555557777" not in fingerprint
        assert len(fingerprint) == 64
