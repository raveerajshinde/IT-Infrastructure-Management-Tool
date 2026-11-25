from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import get_settings
from app.core.db import Base
import app.models  # noqa: F401  (register models)

config = context.config
target_metadata = Base.metadata


def run_offline():
    context.configure(url=get_settings().resolved_database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_online():
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = get_settings().resolved_database_url()
    eng = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with eng.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
