"""Sentinel_api migration message

Revision ID: dd727fdd32e7
Revises: ba191901989f
Create Date: 2024-01-07 15:07:38.795150

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dd727fdd32e7'
down_revision = 'ba191901989f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('sentinel_iam_access_users',
    sa.Column('id', sa.String(length=200), nullable=False),
    sa.Column('email', sa.String(length=80), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('id'),
    sa.UniqueConstraint('username')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('sentinel_iam_access_users')
    # ### end Alembic commands ###
