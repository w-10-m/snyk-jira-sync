import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), default="running")  # running, completed, failed
    repo_filter = Column(String(500), nullable=True)
    dry_run = Column(Boolean, default=False)
    trigger = Column(String(20), default="api")  # cli, api, schedule, webhook
    total_checked = Column(Integer, default=0)
    total_resolved = Column(Integer, default=0)
    total_updated = Column(Integer, default=0)
    total_skipped = Column(Integer, default=0)
    total_errors = Column(Integer, default=0)

    actions = relationship("SyncAction", back_populates="run", cascade="all, delete-orphan")


class SyncAction(Base):
    __tablename__ = "sync_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), ForeignKey("sync_runs.id"), nullable=False)
    snyk_issue_id = Column(String(200), nullable=False)
    jira_key = Column(String(50), nullable=False)
    action = Column(String(30), nullable=False)  # transitioned, commented, reassigned, skipped, errored
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    run = relationship("SyncRun", back_populates="actions")
