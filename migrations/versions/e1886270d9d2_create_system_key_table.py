"""Create system_key table

Revision ID: e1886270d9d2
Revises:
Create Date: 2024-11-18 11:12:41.727481

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e1886270d9d2"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "system_key",
        sa.Column("key_id", sa.VARCHAR(), nullable=False),
        sa.Column("key_secret", sa.VARCHAR(), nullable=False),
        sa.Column("user_id", sa.VARCHAR(), nullable=False),
        sa.Column(
            "created_time", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("key_id", name="system_key_pkey"),
    )


def downgrade() -> None:
    op.drop_table("system_key")
