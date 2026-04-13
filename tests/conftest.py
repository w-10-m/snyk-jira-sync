import pytest

from app.clients.snyk import SnykClient
from app.clients.jira import JiraClient


@pytest.fixture
def snyk_client():
    """SnykClient with a fake token (no real HTTP calls)."""
    return SnykClient(token="test-snyk-token", base_url="https://api.snyk.io")


@pytest.fixture
def jira_client():
    """JiraClient with a fake PAT (no real HTTP calls)."""
    return JiraClient(base_url="https://jira.example.com", pat="test-jira-pat")


def make_snyk_issue(problem_id, status="open"):
    """Helper to build a Snyk REST API issue dict."""
    return {
        "id": f"uuid-{problem_id}",
        "type": "issue",
        "attributes": {
            "key": f"key-{problem_id}",
            "title": f"Vuln {problem_id}",
            "status": status,
            "effective_severity_level": "high",
            "problems": [
                {"id": problem_id, "source": "snyk", "type": "vulnerability"}
            ],
        },
    }


def make_jira_issue(key, status_name="To Do", status_category_key="new"):
    """Helper to build a Jira issue response dict."""
    return {
        "id": "10001",
        "key": key,
        "fields": {
            "summary": f"Vuln in {key}",
            "status": {
                "name": status_name,
                "statusCategory": {"key": status_category_key},
            },
            "assignee": {"name": "dev-user", "displayName": "Dev User"},
            "labels": ["snyk"],
        },
    }


def make_jira_map(entries):
    """Helper to build a Snyk V1 jira-issues response.

    entries: list of (snyk_issue_id, jira_key) tuples
    """
    result = {}
    for snyk_id, jira_key in entries:
        if snyk_id not in result:
            result[snyk_id] = []
        result[snyk_id].append({"jiraIssue": {"id": "10001", "key": jira_key}})
    return result
