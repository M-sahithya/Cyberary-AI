"""
PostgreSQL / SQLite Database Configuration
Uses SQLite for local development when PostgreSQL is not available.
Uses async SQLAlchemy engine and session factory.
"""

import os
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from app.config.settings import settings

# Determine database URL — use SQLite fallback for local dev without Docker
_db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
os.makedirs(_db_dir, exist_ok=True)
_sqlite_path = os.path.join(_db_dir, 'cyberary.db').replace('\\', '/')
_sqlite_url = f"sqlite+aiosqlite:///{_sqlite_path}"

_db_url = settings.DATABASE_URL

# Fallback to SQLite if USE_SQLITE is set, or if DATABASE_URL contains docker host 'postgres:'
if os.environ.get("USE_SQLITE", "false").lower() == "true" or "@postgres:" in _db_url:
    _db_url = _sqlite_url
else:
    try:
        import asyncpg
    except ImportError:
        _db_url = _sqlite_url

# Create async engine
_engine_kwargs = {
    "echo": settings.APP_ENV == "development",
}

# SQLite doesn't support pool_size / max_overflow
if "sqlite" not in _db_url:
    _engine_kwargs["pool_size"] = 20
    _engine_kwargs["max_overflow"] = 10
    _engine_kwargs["pool_pre_ping"] = True

engine = create_async_engine(_db_url, **_engine_kwargs)

# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# Declarative base for models
class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency that yields a database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def _migrate_missing_columns(sync_conn):
    """
    Safely inspect tables and add any columns missing from models.
    Prevents sqlite3.OperationalError: no such column errors without dropping existing data.
    """
    for table_name, table in Base.metadata.tables.items():
        try:
            res = sync_conn.exec_driver_sql(f"PRAGMA table_info({table_name})")
            existing_cols = {row[1] for row in res.fetchall()}
            if not existing_cols:
                continue
            for col in table.columns:
                if col.name not in existing_cols:
                    col_type = col.type.compile(sync_conn.dialect)
                    default_clause = ""
                    if col.default is not None and hasattr(col.default, "arg"):
                        default_val = col.default.arg
                        if isinstance(default_val, (int, float)):
                            default_clause = f" DEFAULT {default_val}"
                        elif isinstance(default_val, str):
                            default_clause = f" DEFAULT '{default_val}'"
                        elif isinstance(default_val, bool):
                            default_clause = f" DEFAULT {1 if default_val else 0}"
                    alter_query = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}{default_clause}"
                    sync_conn.exec_driver_sql(alter_query)
        except Exception:
            pass

    # Backfill threats risk_score if any existing row has NULL
    try:
        sync_conn.exec_driver_sql(
            "UPDATE threats SET risk_score = CASE severity "
            "WHEN 'CRITICAL' THEN 95.0 "
            "WHEN 'HIGH' THEN 80.0 "
            "WHEN 'MEDIUM' THEN 50.0 "
            "ELSE 25.0 END WHERE risk_score IS NULL"
        )
    except Exception:
        pass


async def init_postgres():
    """Create all tables on startup and apply missing columns if any."""
    # Ensure all models are imported so Base.metadata is fully populated
    import app.models  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if "sqlite" in _db_url:
            await conn.run_sync(_migrate_missing_columns)


async def close_postgres():
    """Dispose engine on shutdown."""
    await engine.dispose()

