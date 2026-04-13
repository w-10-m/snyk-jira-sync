from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class SyncRequest(BaseModel):
    repos: list[str] | None = None
    dry_run: bool = False


class SyncOneRequest(BaseModel):
    jira_key: str
    dry_run: bool = False


class SyncActionResponse(BaseModel):
    id: UUID
    project_name: str | None = None
    snyk_issue_id: str
    jira_key: str
    action: str
    detail: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class SyncRunResponse(BaseModel):
    id: UUID
    started_at: datetime
    completed_at: datetime | None
    status: str
    repo_filter: str | None
    dry_run: bool
    trigger: str
    total_checked: int
    total_resolved: int
    total_updated: int
    total_skipped: int
    total_errors: int
    actions: list[SyncActionResponse] = []

    model_config = {"from_attributes": True}


class SyncRunSummary(BaseModel):
    """Lightweight version without nested actions for list endpoints."""
    id: UUID
    started_at: datetime
    completed_at: datetime | None
    status: str
    repo_filter: str | None
    dry_run: bool
    trigger: str
    total_checked: int
    total_resolved: int
    total_updated: int
    total_skipped: int
    total_errors: int

    model_config = {"from_attributes": True}


class ProjectResponse(BaseModel):
    id: str
    name: str
    origin: str | None = None
    type: str | None = None


class ProjectIssueResponse(BaseModel):
    snyk_issue_id: str
    title: str
    status: str
    severity: str
    jira_keys: list[str]


class HealthResponse(BaseModel):
    status: str = "ok"
