from fastapi import APIRouter, Depends, HTTPException, Query

from app.clients.jira import JiraClient
from app.config import Settings
from app.dependencies import get_jira_client, get_settings, get_snyk_client
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
    jira: JiraClient = Depends(get_jira_client),
):
    """Get issues for a Snyk project with linked Jira ticket keys.

    This mirrors the sync path by discovering Jira tickets via JQL instead of
    relying on Snyk's optional jira-issues integration endpoint.
    """
    org_id = settings.snyk_org_id

    project = next(
        (p for p in snyk.get_projects(org_id) if p.get("id") == project_id),
        None,
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project_name = project.get("attributes", {}).get("name", project_id)
    issues = snyk.get_issues(org_id, project_id)
    jira_issues = jira.search_issues(jql=settings.jira_snyk_jql)
    jira_map = SyncService(snyk=snyk, jira=jira).build_project_jira_map(
        project_name=project_name,
        jira_issues=jira_issues,
    )

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
