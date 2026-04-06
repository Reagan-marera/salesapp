"""fix order cleanup migration sqlite-safe

Revision ID: e7df40cac482
Revises: 0d430b6c2d6a
Create Date: 2026-03-26 23:53:59.667123
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e7df40cac482'
down_revision = '0d430b6c2d6a'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('order', schema=None) as batch_op:
        # ❌ REMOVE drop_constraint (SQLite cannot drop unnamed constraints)

        # drop columns (only if they still exist)
        batch_op.drop_column('quantity')
        batch_op.drop_column('product_id')


def downgrade():
    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.add_column(sa.Column('product_id', sa.INTEGER(), nullable=False))
        batch_op.add_column(sa.Column('quantity', sa.INTEGER(), nullable=True))

        # ✅ add named foreign key
        batch_op.create_foreign_key(
            'fk_order_product_id',
            'product',
            ['product_id'],
            ['id']
        )
