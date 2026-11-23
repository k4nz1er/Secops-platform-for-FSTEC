import enum
from datetime import datetime, date, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Date, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class TaskStatus(str, enum.Enum):
    IN_PROGRESS = "В работе"
    COMPLETED = "Выполнена"
    CLOSED = "Закрыта"


class VulnStatus(str, enum.Enum):
    IN_PROGRESS = "В работе"
    COMPLETED = "Выполнена"
    CLOSED = "Закрыта"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="specialist")

    tasks = relationship("Task", back_populates="user")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    bdu = Column(String(100), nullable=True, index=True)
    cve = Column(String(100), nullable=True, index=True)
    source_document = Column(String(255), nullable=True, index=True)
    affected_software = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)
    description = Column(Text, nullable=False, default="")
    action_taken = Column(Text, nullable=False, default="")
    status = Column(String(50), nullable=False, default=VulnStatus.IN_PROGRESS.value, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    tasks = relationship(
        "Task",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assignee = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    deadline = Column(Date, nullable=False, default=date.today)
    status = Column(String(50), nullable=False, default=TaskStatus.IN_PROGRESS.value, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="tasks")
    user = relationship("User", back_populates="tasks")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(50), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    source = Column(String(255), nullable=False, index=True)
    reputation = Column(String(100), nullable=False, default="Вредоносный")
    status = Column(String(50), nullable=False, default="Активен", index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ActionHistory(Base):
    __tablename__ = "action_history"

    id = Column(Integer, primary_key=True, index=True)
    object_type = Column(String(50), nullable=False, index=True)
    object_id = Column(Integer, nullable=False, index=True)
    action = Column(Text, nullable=False)
    user = Column(String(255), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
