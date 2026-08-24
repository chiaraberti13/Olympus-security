"""initial schema

Revision ID: 20260406_0001
Revises:
Create Date: 2026-04-06
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260406_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("scan_type", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("findings_json", sa.Text(), nullable=True),
        sa.Column("report_path", sa.String(length=255), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.Column("child_task_ids_json", sa.Text(), nullable=True),
        sa.Column("total_scanners", sa.Integer(), nullable=True),
        sa.Column("completed_scanners", sa.Integer(), nullable=True),
        sa.Column("logs_json", sa.Text(), nullable=True),
        sa.Column("notifications_json", sa.Text(), nullable=True),
        sa.Column("scan_configuration_json", sa.Text(), nullable=True),
        sa.Column("scan_configuration_version", sa.String(length=32), nullable=True),
        sa.Column("scan_configuration_checksum", sa.String(length=64), nullable=True),
        sa.Column("data_subject_id", sa.String(length=64), nullable=True),
        sa.Column("data_classification", sa.String(length=40), nullable=False),
        sa.Column("tests_performed", sa.Integer(), nullable=True),
        sa.Column("urls_spidered", sa.Integer(), nullable=True),
        sa.Column("injection_points", sa.Integer(), nullable=True),
        sa.Column("http_requests_total", sa.Integer(), nullable=True),
        sa.Column("avg_response_time_ms", sa.Float(), nullable=True),
        sa.Column("redirect_from", sa.String(length=512), nullable=True),
    )
    op.create_index("ix_scans_id", "scans", ["id"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_deleted_at", "scans", ["deleted_at"])
    op.create_index("ix_scans_subject_id", "scans", ["data_subject_id"])

    op.create_table(
        "consent_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("consent_type", sa.String(length=40), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_consent_records_id", "consent_records", ["id"])
    op.create_index("ix_consent_subject_type", "consent_records", ["subject_id", "consent_type"])
    op.create_index("ix_consent_accepted_at", "consent_records", ["accepted_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event", sa.String(length=80), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=True),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
    )
    op.create_index("ix_audit_events_id", "audit_events", ["id"])
    op.create_index("ix_audit_event", "audit_events", ["event"])
    op.create_index("ix_audit_subject", "audit_events", ["subject_id"])
    op.create_index("ix_audit_created_at", "audit_events", ["created_at"])

    op.create_table(
        "learning_feedback",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_type", sa.String(length=50), nullable=False),
        sa.Column("target_experience_level", sa.String(length=20), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("clarity_score", sa.Integer(), nullable=False),
        sa.Column("confidence_after_scan", sa.Integer(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_learning_feedback_id", "learning_feedback", ["id"])
    op.create_index("ix_learning_feedback_created_at", "learning_feedback", ["created_at"])
    op.create_index("ix_learning_feedback_scan_type", "learning_feedback", ["scan_type"])
    op.create_index("ix_learning_feedback_rating", "learning_feedback", ["rating"])

    op.create_table(
        "learning_path_progress",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("path_id", sa.String(length=80), nullable=False),
        sa.Column("completed_modules", sa.Integer(), nullable=False),
        sa.Column("total_modules", sa.Integer(), nullable=False),
        sa.Column("is_completed", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_learning_path_progress_id", "learning_path_progress", ["id"])
    op.create_index(
        "ix_learning_path_progress_subject_path",
        "learning_path_progress",
        ["subject_id", "path_id"],
    )
    op.create_index(
        "ix_learning_path_progress_subject_completed",
        "learning_path_progress",
        ["subject_id", "is_completed"],
    )
    op.create_index("ix_learning_path_progress_updated_at", "learning_path_progress", ["updated_at"])


def downgrade() -> None:
    op.drop_index("ix_learning_path_progress_updated_at", table_name="learning_path_progress")
    op.drop_index("ix_learning_path_progress_subject_completed", table_name="learning_path_progress")
    op.drop_index("ix_learning_path_progress_subject_path", table_name="learning_path_progress")
    op.drop_index("ix_learning_path_progress_id", table_name="learning_path_progress")
    op.drop_table("learning_path_progress")

    op.drop_index("ix_learning_feedback_rating", table_name="learning_feedback")
    op.drop_index("ix_learning_feedback_scan_type", table_name="learning_feedback")
    op.drop_index("ix_learning_feedback_created_at", table_name="learning_feedback")
    op.drop_index("ix_learning_feedback_id", table_name="learning_feedback")
    op.drop_table("learning_feedback")

    op.drop_index("ix_audit_created_at", table_name="audit_events")
    op.drop_index("ix_audit_subject", table_name="audit_events")
    op.drop_index("ix_audit_event", table_name="audit_events")
    op.drop_index("ix_audit_events_id", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_consent_accepted_at", table_name="consent_records")
    op.drop_index("ix_consent_subject_type", table_name="consent_records")
    op.drop_index("ix_consent_records_id", table_name="consent_records")
    op.drop_table("consent_records")

    op.drop_index("ix_scans_subject_id", table_name="scans")
    op.drop_index("ix_scans_deleted_at", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_index("ix_scans_id", table_name="scans")
    op.drop_table("scans")
