"""
database/db.py
==============
Database engine, session factory, and helper context manager.

Usage
-----
    from database.db import get_db, init_db

    # One-time initialisation (creates tables if they don't exist):
    init_db()

    # Context-manager session (auto-commit on success, rollback on error):
    with get_db() as db:
        db.add(some_model_instance)

    # Raw session (caller is responsible for commit/rollback/close):
    session = get_session()
"""

import os
import sys
from contextlib import contextmanager

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so that `config` can be imported
# regardless of the working directory.
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import settings          # provides DATABASE_URL
from database.models import Base     # declarative base with all table metadata


DB_AVAILABLE = True

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _build_engine():
    db_url: str = settings.DATABASE_URL
    if db_url.startswith("sqlite:///"):
        path_part = db_url[len("sqlite:///"):]
        if not os.path.isabs(path_part) and ":/" not in path_part and ":\\" not in path_part:
            abs_path = os.path.normpath(os.path.join(_PROJECT_ROOT, path_part))
        else:
            abs_path = os.path.normpath(path_part)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        clean_path = abs_path.replace("\\", "/")
        db_url = f"sqlite:///{clean_path}"
    connect_args = {}
    if db_url.startswith("sqlite"):
        # SQLite is not thread-safe by default; allow cross-thread use and set 30s timeout.
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30.0
    eng = create_engine(db_url, connect_args=connect_args)

    if db_url.startswith("sqlite"):
        from sqlalchemy import event
        @event.listens_for(eng, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            try:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.close()
            except Exception:
                pass
    return eng


engine = _build_engine()

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)



# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Create all tables defined in Base.metadata if they do not already exist,
    and apply automatic schema migrations for newly added columns.
    """
    Base.metadata.create_all(bind=engine)
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            # Migrate alert table columns
            alert_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(alert)")).fetchall()]
            if "explainability" not in alert_cols:
                conn.execute(text("ALTER TABLE alert ADD COLUMN explainability JSON"))
            # Migrate risk_score table columns
            risk_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(risk_score)")).fetchall()]
            if "explainability" not in risk_cols:
                conn.execute(text("ALTER TABLE risk_score ADD COLUMN explainability JSON"))
            conn.commit()
    except Exception:
        pass

    try:
        from security.auth import seed_default_users
        with get_db() as session:
            seed_default_users(session)
    except Exception:
        pass


@contextmanager
def get_db():
    """
    Context manager that yields a SQLAlchemy Session.

    Commits automatically on clean exit; rolls back on any exception and
    re-raises.  Always closes the session in the ``finally`` block.

    Example::

        with get_db() as db:
            db.add(obj)
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_session():
    """
    Return a raw ``SessionLocal`` instance.

    The caller is responsible for committing, rolling back, and closing the
    session.  Prefer :func:`get_db` for most use cases.
    """
    return SessionLocal()
