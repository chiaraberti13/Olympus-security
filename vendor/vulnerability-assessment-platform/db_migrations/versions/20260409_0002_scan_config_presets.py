"""scan configuration presets

Revision ID: 20260409_0002
Revises: 20260406_0001
Create Date: 2026-04-09
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260409_0002"
down_revision = "20260406_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_configuration_presets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("scan_type", sa.String(length=50), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False),
        sa.Column("config_version", sa.String(length=32), nullable=False),
        sa.Column("config_checksum", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scan_configuration_presets_id", "scan_configuration_presets", ["id"])
    op.create_index("ix_scan_config_presets_subject", "scan_configuration_presets", ["subject_id"])
    op.create_index("ix_scan_config_presets_scan_type", "scan_configuration_presets", ["scan_type"])
    op.create_index("ix_scan_config_presets_created_at", "scan_configuration_presets", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_config_presets_created_at", table_name="scan_configuration_presets")
    op.drop_index("ix_scan_config_presets_scan_type", table_name="scan_configuration_presets")
    op.drop_index("ix_scan_config_presets_subject", table_name="scan_configuration_presets")
    op.drop_index("ix_scan_configuration_presets_id", table_name="scan_configuration_presets")
    op.drop_table("scan_configuration_presets")
