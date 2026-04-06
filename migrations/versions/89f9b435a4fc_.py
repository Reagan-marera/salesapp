"""fix foreign keys with proper names (sqlite-safe)

Revision ID: 89f9b435a4fc
Revises: e7df40cac482
Create Date: 2026-03-29 14:23:17.485455
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '89f9b435a4fc'
down_revision = 'e7df40cac482'
branch_labels = None
depends_on = None


def upgrade():
    # ⚠️ SQLite cannot reliably drop unnamed constraints
    # So we ONLY create new ones safely

    with op.batch_alter_table('order_item', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_order_item_order_id',
            'order',
            ['order_id'],
            ['id'],
            ondelete='CASCADE'
        )

    with op.batch_alter_table('order_status_history', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_order_status_history_order_id',
            'order',
            ['order_id'],
            ['id'],
            ondelete='CASCADE'
        )

    with op.batch_alter_table('payment', schema=None) as batch_op:
        # drop only if it was named (safe case)
        try:
            batch_op.drop_constraint('fk_payment_order_id', type_='foreignkey')
        except:
            pass

        batch_op.create_foreign_key(
            'fk_payment_order_id_new',
            'order',
            ['order_id'],
            ['id'],
            ondelete='SET NULL'
        )


def downgrade():
    with op.batch_alter_table('payment', schema=None) as batch_op:
        batch_op.drop_constraint('fk_payment_order_id_new', type_='foreignkey')

        batch_op.create_foreign_key(
            'fk_payment_order_id',
            'order',
            ['order_id'],
            ['id']
        )

    with op.batch_alter_table('order_status_history', schema=None) as batch_op:
        batch_op.drop_constraint(
            'fk_order_status_history_order_id',
            type_='foreignkey'
        )

        batch_op.create_foreign_key(
            'fk_order_status_history_order_id_old',
            'order',
            ['order_id'],
            ['id']
        )

    with op.batch_alter_table('order_item', schema=None) as batch_op:
        batch_op.drop_constraint(
            'fk_order_item_order_id',
            type_='foreignkey'
        )

        batch_op.create_foreign_key(
            'fk_order_item_order_id_old',
            'order',
            ['order_id'],
            ['id']
        )
