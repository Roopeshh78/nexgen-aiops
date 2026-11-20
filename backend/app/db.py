import os
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DB_URL

os.makedirs("data", exist_ok=True)
engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def utcnow() -> datetime:
    """Naive UTC timestamp — every timestamp in this system is UTC by contract."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
