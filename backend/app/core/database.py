from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.models.domain import Base, User

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            default_users = [
                User(name="Ведущий специалист П.П. Петров", role="specialist"),
                User(name="Начальник И.И. Иванов", role="lead"),
            ]
            db.add_all(default_users)
            db.commit()
    finally:
        db.close()
