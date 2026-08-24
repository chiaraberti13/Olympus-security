"""scan configuration preset lifecycle states

Revision ID: 20260417_0003
Revises: 20260409_0002
Create Date: 2026-04-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260417_0003"
down_revision = "20260409_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_configuration_presets",
        sa.Column("lifecycle_state", sa.String(length=20), nullable=False, server_default="draft"),
    )
    op.create_index(
        "ix_scan_config_presets_subject_lifecycle",
        "scan_configuration_presets",
        ["subject_id", "lifecycle_state"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_config_presets_subject_lifecycle", table_name="scan_configuration_presets")
    op.drop_column("scan_configuration_presets", "lifecycle_state")
