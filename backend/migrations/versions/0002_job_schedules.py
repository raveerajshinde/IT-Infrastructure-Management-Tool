"""job schedules

Revision ID: 0002
Revises: 0001_initial
Create Date: 2026-11-14
"""
from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('job_schedules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=150), nullable=False),
    sa.Column('description', sa.String(length=1000), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('operation_id', sa.String(length=100), nullable=True),
    sa.Column('template_id', sa.Integer(), nullable=True),
    sa.Column('device_ids', sa.JSON(), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('check_mode', sa.Boolean(), nullable=False),
    sa.Column('cron', sa.String(length=100), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.Column('next_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_job_id', sa.Integer(), nullable=True),
    sa.Column('last_error', sa.String(length=1000), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['template_id'], ['job_templates.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_job_schedules_next_run_at'), 'job_schedules', ['next_run_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_job_schedules_next_run_at'), table_name='job_schedules')
    op.drop_table('job_schedules')
