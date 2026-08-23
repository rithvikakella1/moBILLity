"""Alembic environment.

The URL is resolved here rather than in alembic.ini so that a single command
works against both the production PostgreSQL database and the local SQLite file,
using the same environment variables the application reads.
"""
import os
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

config = context.config


def database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if url:
        # SQLAlchemy needs an explicit driver for psycopg 3.
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg://", 1)
        elif url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        return url
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.getenv("DATABASE_FILE", os.path.join(base_dir, "users.db"))
    return f"sqlite:///{path}"


config.set_main_option("sqlalchemy.url", database_url())

# Schema is defined in raw SQL in the revision files rather than by model
# metadata, so autogenerate is not used.
target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Batch mode lets SQLite handle ALTER operations it cannot do natively.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
