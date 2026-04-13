import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import get_db
from app.dependencies import get_settings, get_sync_service
from app.models import SyncAction, SyncRun
from app.schemas import SyncOneRequest, SyncRequest, SyncRunResponse, SyncRunSummary
from app.services.sync import SyncSelectionError, SyncService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sync", tags=["sync"])


def _write_sync_report(run: SyncRun, report_dir: str) -> None:
    """Write sync run summary to a local JSON file for easy inspection."""
    out_dir = Path(report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"sync-{run.id}.json"

    payload = {
        "id": str(run.id),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "status": run.status,
        "repo_filter": run.repo_filter,
        "dry_run": run.dry_run,
        "trigger": run.trigger,
        "total_checked": run.total_checked,
        "total_resolved": run.total_resolved,
        "total_updated": run.total_updated,
        "total_skipped": run.total_skipped,
        "total_errors": run.total_errors,
        "actions": [
            {
                "project_name": action.project_name,
                "snyk_issue_id": action.snyk_issue_id,
                "jira_key": action.jira_key,
                "action": action.action,
                "detail": action.detail,
                "created_at": action.created_at.isoformat() if action.created_at else None,
            }
            for action in run.actions
        ],
    }

    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _persist_ticket_actions(db: Session, run: SyncRun, totals: dict) -> None:
    for item in totals.get("ticket_actions", []):
        jira_key = item.get("jira_key")
        snyk_issue_id = item.get("snyk_issue_id")
        action = item.get("action")
        if not jira_key or not snyk_issue_id or not action:
            continue
        db.add(
                SyncAction(
                    run_id=run.id,
                    project_name=item.get("project_name"),
                    snyk_issue_id=snyk_issue_id,
                    jira_key=jira_key,
                    action=action,
                detail=item.get("detail"),
            )
        )


def _finalize_run(run: SyncRun, totals: dict) -> None:
    run.status = "completed"
    run.completed_at = datetime.now(timezone.utc)
    run.total_checked = totals["checked"]
    run.total_resolved = totals["resolved"]
    run.total_updated = totals["updated"]
    run.total_skipped = totals["skipped"]
    run.total_errors = totals["errors"]


@router.post("", response_model=SyncRunResponse)
def trigger_sync(
    request: SyncRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    service: SyncService = Depends(get_sync_service),
):
    """Trigger a sync run. Checks Snyk for resolved vulnerabilities and updates Jira."""
    repo_filter = ",".join(request.repos) if request.repos else settings.snyk_repo_names
    project_tags = settings.snyk_project_tags  # Use tags from config
    jira_jql = settings.jira_snyk_jql
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
            target_status=settings.jira_target_status,
            repo_filter=repo_filter,
            project_tags=project_tags,
            jira_jql=jira_jql,
            dry_run=dry_run,
        )
        _persist_ticket_actions(db, run, totals)
        _finalize_run(run, totals)

    except Exception:
        logger.exception("Sync run %s failed", run.id)
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(run)

    try:
        _write_sync_report(run, settings.sync_report_dir)
    except Exception:
        logger.exception("Failed to write sync report file for run %s", run.id)

    return run


@router.post("/one", response_model=SyncRunResponse)
def trigger_sync_one(
    request: SyncOneRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    service: SyncService = Depends(get_sync_service),
):
    """Trigger a sync run for exactly one Jira ticket."""
    dry_run = request.dry_run or settings.dry_run

    run = SyncRun(
        repo_filter=request.jira_key,
        dry_run=dry_run,
        trigger="api",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        totals = service.run_one(
            org_id=settings.snyk_org_id,
            jira_key=request.jira_key,
            security_manager=settings.jira_security_manager_username,
            target_status=settings.jira_target_status,
            repo_filter=settings.snyk_repo_names,
            project_tags=settings.snyk_project_tags,
            dry_run=dry_run,
        )
        _persist_ticket_actions(db, run, totals)
        _finalize_run(run, totals)
    except SyncSelectionError as exc:
        logger.warning("Sync-one run %s rejected: %s", run.id, exc.detail)
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(run)
        try:
            _write_sync_report(run, settings.sync_report_dir)
        except Exception:
            logger.exception("Failed to write sync report file for run %s", run.id)
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    except Exception:
        logger.exception("Sync-one run %s failed", run.id)
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(run)

    try:
        _write_sync_report(run, settings.sync_report_dir)
    except Exception:
        logger.exception("Failed to write sync report file for run %s", run.id)

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
