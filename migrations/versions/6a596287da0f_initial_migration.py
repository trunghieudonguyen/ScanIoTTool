"""Initial migration

Revision ID: 6a596287da0f
Revises: 
Create Date: 2025-03-11 01:37:23.676170

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6a596287da0f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('scan_history', schema=None) as batch_op:
        batch_op.add_column(sa.Column('open_ports', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('services', sa.String(length=500), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('scan_history', schema=None) as batch_op:
        batch_op.drop_column('services')
        batch_op.drop_column('open_ports')

    # ### end Alembic commands ###
