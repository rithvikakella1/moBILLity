"""Baseline schema.

Captures the schema as built by the former _init_db(), including the columns
previously added by ad-hoc ALTER statements: users.analytics_enabled,
patients.phone_hmac, and call_handoffs.owner_user_id.

On an existing deployment, do not run this — stamp it instead, so Alembic
records it as already applied:

    alembic stamp 0001

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _id_column() -> sa.Column:
    if _is_postgres():
        return sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True)
    return sa.Column("id", sa.Integer, primary_key=True, autoincrement=True)


def upgrade() -> None:
    op.create_table(
        "users",
        _id_column(),
        sa.Column("email", sa.Text, nullable=False, unique=True),
        sa.Column("password_hash", sa.Text),
        sa.Column("full_name", sa.Text, nullable=False, server_default=""),
        sa.Column("google_sub", sa.Text, unique=True),
        sa.Column("email_verified", sa.Integer, nullable=False, server_default="0"),
        sa.Column("session_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("analytics_enabled", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "action_tokens",
        _id_column(),
        sa.Column("user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("purpose", sa.Text, nullable=False),
        sa.Column("token_hash", sa.Text, nullable=False, unique=True),
        sa.Column("expires_at", sa.Text, nullable=False),
        sa.Column("used_at", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint(
            "purpose IN ('verify_email', 'reset_password')", name="ck_action_tokens_purpose"
        ),
    )
    op.create_index("idx_action_tokens_lookup", "action_tokens", ["token_hash", "purpose"])

    op.create_table(
        "analytics_events",
        _id_column(),
        sa.Column("user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("event_name", sa.Text, nullable=False),
        sa.Column("page", sa.Text, nullable=False),
        sa.Column("occurred_at", sa.Text, nullable=False),
    )
    op.create_index("idx_analytics_user_time", "analytics_events", ["user_id", "occurred_at"])
    op.create_index("idx_analytics_event_time", "analytics_events", ["event_name", "occurred_at"])
    op.create_index("idx_analytics_occurred", "analytics_events", ["occurred_at"])

    op.create_table(
        "patients",
        _id_column(),
        sa.Column("owner_user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name_encrypted", sa.Text, nullable=False),
        sa.Column("phone_encrypted", sa.Text),
        sa.Column("email_encrypted", sa.Text),
        # Deterministic lookup index for inbound STOP handling; the number
        # itself is never stored in plaintext.
        sa.Column("phone_hmac", sa.Text),
        sa.Column("timezone", sa.Text, nullable=False, server_default="America/New_York"),
        sa.Column("sms_consent", sa.Integer, nullable=False, server_default="0"),
        sa.Column("voice_consent", sa.Integer, nullable=False, server_default="0"),
        sa.Column("email_consent", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.Text, nullable=False),
    )
    op.create_index("idx_patients_phone_hmac", "patients", ["phone_hmac"])

    op.create_table(
        "appointments",
        _id_column(),
        sa.Column("owner_user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("patient_id", sa.BigInteger, sa.ForeignKey("patients.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("starts_at", sa.Text, nullable=False),
        sa.Column("clinician", sa.Text, nullable=False, server_default=""),
        sa.Column("location", sa.Text, nullable=False, server_default=""),
        sa.Column("status", sa.Text, nullable=False, server_default="scheduled"),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint(
            "status IN ('scheduled', 'confirmed', 'cancelled', 'completed')",
            name="ck_appointments_status",
        ),
    )
    op.create_index("idx_appointments_owner_start", "appointments",
                    ["owner_user_id", "starts_at"])

    op.create_table(
        "reminder_jobs",
        _id_column(),
        sa.Column("owner_user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("appointment_id", sa.BigInteger,
                  sa.ForeignKey("appointments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.Text, nullable=False),
        sa.Column("scheduled_for", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text),
        sa.Column("sent_at", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint("channel IN ('sms', 'voice', 'email')", name="ck_reminder_channel"),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'sent', 'failed', 'cancelled')",
            name="ck_reminder_status",
        ),
        sa.UniqueConstraint("appointment_id", "channel", name="uq_reminder_appointment_channel"),
    )
    op.create_index("idx_reminder_jobs_due", "reminder_jobs", ["status", "scheduled_for"])

    op.create_table(
        "communication_events",
        _id_column(),
        sa.Column("owner_user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("appointment_id", sa.BigInteger,
                  sa.ForeignKey("appointments.id", ondelete="SET NULL")),
        sa.Column("patient_id", sa.BigInteger, sa.ForeignKey("patients.id", ondelete="SET NULL")),
        sa.Column("channel", sa.Text, nullable=False),
        sa.Column("direction", sa.Text, nullable=False),
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
        sa.Column("provider_id", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.CheckConstraint("direction IN ('inbound', 'outbound')", name="ck_event_direction"),
    )
    op.create_index("idx_events_owner_time", "communication_events",
                    ["owner_user_id", "created_at"])

    op.create_table(
        "call_handoffs",
        _id_column(),
        sa.Column("owner_user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("caller_phone_encrypted", sa.Text),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="queued"),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("resolved_at", sa.Text),
        sa.CheckConstraint(
            "status IN ('queued', 'transferred', 'resolved')", name="ck_handoff_status"
        ),
    )
    op.create_index("idx_handoffs_owner_status", "call_handoffs", ["owner_user_id", "status"])

    op.create_table(
        "practice_phone_numbers",
        _id_column(),
        sa.Column("owner_user_id", sa.BigInteger, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("phone_number", sa.Text, nullable=False, unique=True),
        sa.Column("label", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.Text, nullable=False),
    )


def downgrade() -> None:
    for table in (
        "practice_phone_numbers",
        "call_handoffs",
        "communication_events",
        "reminder_jobs",
        "appointments",
        "patients",
        "analytics_events",
        "action_tokens",
        "users",
    ):
        op.drop_table(table)
