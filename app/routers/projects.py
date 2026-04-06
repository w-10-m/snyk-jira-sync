from fastapi import APIRouter, Depends, Query

from app.config import Settings
from app.dependencies import get_settings, get_snyk_client
from app.clients.snyk import SnykClient
from app.schemas import ProjectResponse, ProjectIssueResponse
from app.services.sync import SyncService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectResponse])
def list_projects(
    name: str | None = Query(default=None, description="Filter by project name"),
    settings: Settings = Depends(get_settings),
    snyk: SnykClient = Depends(get_snyk_client),
):
    """List Snyk projects in the configured org."""
    projects = snyk.get_projects(settings.snyk_org_id, name_filter=name)
    return [
        ProjectResponse(
            id=p["id"],
            name=p.get("attributes", {}).get("name", p["id"]),
            origin=p.get("attributes", {}).get("origin"),
            type=p.get("attributes", {}).get("type"),
        )
        for p in projects
    ]


@router.get("/{project_id}/issues", response_model=list[ProjectIssueResponse])
def get_project_issues(
    project_id: str,
    settings: Settings = Depends(get_settings),
    snyk: SnykClient = Depends(get_snyk_client),
):
    """Get issues for a Snyk project with linked Jira ticket keys."""
    org_id = settings.snyk_org_id

    issues = snyk.get_issues(org_id, project_id)
    jira_map = snyk.get_jira_issues(org_id, project_id)

    result = []
    for issue in issues:
        attrs = issue.get("attributes", {})
        for problem in attrs.get("problems", []):
            problem_id = problem.get("id")
            if not problem_id:
                continue

            jira_tickets = jira_map.get(problem_id, [])
            jira_keys = []
            if isinstance(jira_tickets, list):
                jira_keys = [
                    t.get("jiraIssue", {}).get("key")
                    for t in jira_tickets
                    if t.get("jiraIssue", {}).get("key")
                ]

            result.append(
                ProjectIssueResponse(
                    snyk_issue_id=problem_id,
                    title=attrs.get("title", ""),
                    status=attrs.get("status", "open"),
                    severity=attrs.get("effective_severity_level", "unknown"),
                    jira_keys=jira_keys,
                )
            )

    return result
