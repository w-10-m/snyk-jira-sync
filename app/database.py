from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        from app.config import Settings
        settings = Settings()
        _engine = create_engine(settings.database_url)
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=_get_engine())
    return _SessionLocal


def get_db():
    """Yield a database session, closing it when done."""
    Session = _get_session_factory()
    db = Session()
    try:
        yield db
    finally:
        db.close()
