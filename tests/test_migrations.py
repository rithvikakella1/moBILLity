"""Guard against drift between the Alembic baseline and _init_db().

Alembic owns the production schema; _init_db() builds the local development
database. Two sources of truth drift silently, and the failure shows up as a
missing column in production. This test makes drift a red build instead.
"""
import os
import sqlite3
import subprocess
import sys
import tempfile

import pytest

import app as application

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _schema_of(db_path: str) -> dict[str, set[str]]:
    connection = sqlite3.connect(db_path)
    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' AND name != 'alembic_version'"
            )
        ]
        return {
            table: {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            for table in tables
        }
    finally:
        connection.close()


@pytest.fixture(scope="module")
def migrated_schema():
    directory = tempfile.mkdtemp(prefix="mobillity-migrations-")
    db_path = os.path.join(directory, "migrated.db")
    environment = {**os.environ, "DATABASE_FILE": db_path, "DATABASE_URL": ""}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT, env=environment, capture_output=True, text=True,
    )
    assert result.returncode == 0, f"alembic upgrade failed:\n{result.stderr}"
    return _schema_of(db_path)


@pytest.fixture(scope="module")
def init_db_schema():
    directory = tempfile.mkdtemp(prefix="mobillity-initdb-")
    db_path = os.path.join(directory, "initdb.db")
    original = application.DATABASE_FILE
    application.DATABASE_FILE = db_path
    try:
        application._init_db()
        return _schema_of(db_path)
    finally:
        application.DATABASE_FILE = original


def test_the_same_tables_exist_in_both(migrated_schema, init_db_schema):
    assert set(migrated_schema) == set(init_db_schema)


def test_every_table_has_the_same_columns(migrated_schema, init_db_schema):
    differences = {}
    for table in sorted(set(migrated_schema) & set(init_db_schema)):
        only_migrated = migrated_schema[table] - init_db_schema[table]
        only_init = init_db_schema[table] - migrated_schema[table]
        if only_migrated or only_init:
            differences[table] = {
                "only_in_migration": sorted(only_migrated),
                "only_in_init_db": sorted(only_init),
            }
    assert not differences, f"schema drift: {differences}"


def test_the_migration_is_reversible():
    directory = tempfile.mkdtemp(prefix="mobillity-downgrade-")
    db_path = os.path.join(directory, "roundtrip.db")
    environment = {**os.environ, "DATABASE_FILE": db_path, "DATABASE_URL": ""}
    for command in (["upgrade", "head"], ["downgrade", "base"], ["upgrade", "head"]):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", *command],
            cwd=REPO_ROOT, env=environment, capture_output=True, text=True,
        )
        assert result.returncode == 0, f"alembic {command} failed:\n{result.stderr}"
