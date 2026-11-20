"""add plaid consent expiration and reconnect-required fields

Additive only: two nullable columns on ``plaid_connections`` so PyCashFlow can
warn users before a bank connection expires and tell them when it already
has.

- consent_expiration_time: Plaid's ``item.consent_expiration_time`` from
  /item/get (naive UTC). Null means no expiration is scheduled.
- reconnect_required_at: set when Plaid reports an Item error that only the
  user can fix through Plaid Link (e.g. ITEM_LOGIN_REQUIRED after a Chase
  consent expires); cleared by the next successful sync.

Revision ID: c3e5f7a9b1d2
Revises: b7c8d9e0f1a2
Create Date: 2026-11-20 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3e5f7a9b1d2'
down_revision = 'b7c8d9e0f1a2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('plaid_connections', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('consent_expiration_time', sa.DateTime(), nullable=True)
        )
        batch_op.add_column(
            sa.Column('reconnect_required_at', sa.DateTime(), nullable=True)
        )


def downgrade():
    with op.batch_alter_table('plaid_connections', schema=None) as batch_op:
        batch_op.drop_column('reconnect_required_at')
        batch_op.drop_column('consent_expiration_time')
