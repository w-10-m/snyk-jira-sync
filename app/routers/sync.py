import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import get_db
from app.dependencies import get_settings, get_sync_service
from app.models import SyncAction, SyncRun
from app.schemas import SyncRequest, SyncRunResponse, SyncRunSummary
from app.services.sync import SyncService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sync", tags=["sync"])


@router.post("", response_model=SyncRunResponse)
def trigger_sync(
    request: SyncRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    service: SyncService = Depends(get_sync_service),
):
    """Trigger a sync run. Checks Snyk for resolved vulnerabilities and updates Jira."""
    repo_filter = ",".join(request.repos) if request.repos else settings.snyk_repo_names
    dry_run = request.dry_run or settings.dry_run

    # Create run record
    run = SyncRun(
        repo_filter=repo_filter,
        dry_run=dry_run,
        trigger="api",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        totals = service.run(
            org_id=settings.snyk_org_id,
            security_manager=settings.jira_security_manager_username,
            repo_filter=repo_filter,
            dry_run=dry_run,
        )

        run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
        run.total_checked = totals["checked"]
        run.total_resolved = totals["resolved"]
        run.total_updated = totals["updated"]
        run.total_skipped = totals["skipped"]
        run.total_errors = totals["errors"]

    except Exception:
        logger.exception("Sync run %s failed", run.id)
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(run)
    return run


@router.get("/history", response_model=list[SyncRunSummary])
def get_sync_history(
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List past sync runs, most recent first."""
    runs = (
        db.query(SyncRun)
        .order_by(SyncRun.started_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return runs


@router.get("/{run_id}", response_model=SyncRunResponse)
def get_sync_run(
    run_id: UUID,
    db: Session = Depends(get_db),
):
    """Get details of a specific sync run including all actions."""
    run = db.query(SyncRun).filter(SyncRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Sync run not found")
    return run
