"""script library

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('scripts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=150), nullable=False),
    sa.Column('description', sa.String(length=1000), nullable=False),
    sa.Column('target', sa.String(length=20), nullable=False),
    sa.Column('mode', sa.String(length=10), nullable=False),
    sa.Column('risk', sa.String(length=10), nullable=False),
    sa.Column('body', sa.UnicodeText(), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('run_as_root', sa.Boolean(), nullable=False),
    sa.Column('save_config', sa.Boolean(), nullable=False),
    sa.Column('timeout_seconds', sa.Integer(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.Column('updated_by', sa.Integer(), nullable=False),
    sa.Column('approved_by', sa.Integer(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('approved_sha256', sa.String(length=64), nullable=True),
    sa.Column('review_comment', sa.String(length=1000), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )


def downgrade() -> None:
    op.drop_table('scripts')
