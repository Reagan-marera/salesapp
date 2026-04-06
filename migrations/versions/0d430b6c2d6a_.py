"""fix payment migration sqlite-safe

Revision ID: 0d430b6c2d6a
Revises: cc304b68456a
Create Date: 2026-03-26 22:56:23.908552
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0d430b6c2d6a'
down_revision = 'cc304b68456a'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('payment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('checkout_request_id', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('order_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('mpesa_receipt_number', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('phone_number', sa.String(length=20), nullable=True))

        batch_op.alter_column(
            'user_id',
            existing_type=sa.INTEGER(),
            nullable=False
        )

        # ✅ named unique constraint
        batch_op.create_unique_constraint(
            'uq_payment_checkout_request_id',
            ['checkout_request_id']
        )

        # ❌ REMOVE drop_constraint (SQLite can't find it)

        # ✅ create new FK
        batch_op.create_foreign_key(
            'fk_payment_order_id',
            'order',
            ['order_id'],
            ['id']
        )

        batch_op.drop_column('product_id')


def downgrade():
    with op.batch_alter_table('payment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('product_id', sa.INTEGER(), nullable=True))

        # drop new FK
        batch_op.drop_constraint(
            'fk_payment_order_id',
            type_='foreignkey'
        )

        # ⚠️ DO NOT recreate old FK (SQLite limitation, optional)

        batch_op.drop_constraint(
            'uq_payment_checkout_request_id',
            type_='unique'
        )

        batch_op.alter_column(
            'user_id',
            existing_type=sa.INTEGER(),
            nullable=True
        )

        batch_op.drop_column('phone_number')
        batch_op.drop_column('mpesa_receipt_number')
        batch_op.drop_column('order_id')
        batch_op.drop_column('checkout_request_id')
