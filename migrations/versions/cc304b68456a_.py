"""fix order columns migration

Revision ID: cc304b68456a
Revises: 
Create Date: 2026-03-26 22:18:58.087102
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cc304b68456a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('order', schema=None) as batch_op:
        # Only add total_amount (others already exist)
        batch_op.add_column(
            sa.Column('total_amount', sa.Float(), nullable=False, server_default='0')
        )


def downgrade():
    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.drop_column('total_amount')
