from unittest.mock import MagicMock

import pytest

from app.services.sync import SyncSelectionError, SyncService
from tests.conftest import make_jira_issue, make_snyk_issue


@pytest.fixture
def sync_service():
    snyk = MagicMock()
    jira = MagicMock()
    return SyncService(snyk=snyk, jira=jira)


class TestBuildIssueStatusMap:
    def test_maps_problem_ids_to_status(self):
        issues = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="open"),
            make_snyk_issue("SNYK-JS-EXPRESS-456", status="resolved"),
        ]

        result = SyncService.build_issue_status_map(issues)

        assert result["SNYK-JS-LODASH-123"] == "open"
        assert result["SNYK-JS-EXPRESS-456"] == "resolved"


class TestJiraTextMatching:
    def test_extract_snyk_ids(self, sync_service):
        text = "Fix SNYK-JS-LODASH-123 and SNYK-PYTHON-REQUESTS-999"
        result = sync_service.extract_snyk_ids(text)
        assert "SNYK-JS-LODASH-123" in result
        assert "SNYK-PYTHON-REQUESTS-999" in result

    def test_build_project_jira_map_uses_project_alias(self, sync_service):
        jira_issues = [
            {
                "key": "SEC-1",
                "fields": {
                    "summary": "project-tag/background-job-svc vulnerability SNYK-JS-LODASH-123",
                    "description": "",
                },
            },
            {
                "key": "SEC-2",
                "fields": {
                    "summary": "other-service SNYK-JS-LODASH-123",
                    "description": "",
                },
            },
        ]

        jira_map = sync_service.build_project_jira_map(
            project_name="project-tag/background-job-svc(master):package.json",
            jira_issues=jira_issues,
        )

        assert "SNYK-JS-LODASH-123" in jira_map
        assert jira_map["SNYK-JS-LODASH-123"] == [{"jiraIssue": {"key": "SEC-1"}}]


class TestProcessProject:
    def _run(self, sync_service, dry_run=False):
        return sync_service.process_project(
            org_id="org-1",
            project_id="proj-1",
            project_name="project-tag/background-job-svc(master):package.json",
            security_manager="sec.mgr",
            target_status="In Review",
            dry_run=dry_run,
            jira_issues=[
                {
                    "key": "SEC-1",
                    "fields": {
                        "summary": "project-tag/background-job-svc SNYK-JS-LODASH-123",
                        "description": "",
                    },
                }
            ],
        )

    def test_no_matching_jira_tickets(self, sync_service):
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="open"),
        ]

        stats = sync_service.process_project(
            org_id="org-1",
            project_id="proj-1",
            project_name="project-tag/background-job-svc(master):package.json",
            security_manager="sec.mgr",
            target_status="In Review",
            dry_run=False,
            jira_issues=[
                {
                    "key": "SEC-1",
                    "fields": {"summary": "other-service SNYK-JS-LODASH-123", "description": ""},
                }
            ],
        )

        assert stats["checked"] == 0
        sync_service.jira.get_issue.assert_not_called()

    def test_resolved_issue_updates_ticket(self, sync_service):
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "To Do", "new")
        sync_service.jira.find_transition_id.return_value = "21"

        stats = self._run(sync_service)

        assert stats["checked"] == 1
        assert stats["resolved"] == 1
        assert stats["updated"] == 1
        assert any(
            action["project_name"] == "project-tag/background-job-svc(master):package.json"
            for action in stats["ticket_actions"]
        )
        sync_service.jira.transition_issue.assert_called_once()
        sync_service.jira.reassign_issue.assert_called_once_with("SEC-1", "sec.mgr")
        sync_service.jira.find_transition_id.assert_called_once_with("SEC-1", "In Review")

    def test_open_issue_does_not_update_ticket(self, sync_service):
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="open"),
        ]

        stats = self._run(sync_service)

        assert stats["checked"] == 1
        assert stats["updated"] == 0
        sync_service.jira.get_issue.assert_not_called()

    def test_dry_run_no_jira_modifications(self, sync_service):
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "To Do", "new")

        stats = self._run(sync_service, dry_run=True)

        assert stats["updated"] == 1
        sync_service.jira.transition_issue.assert_not_called()
        sync_service.jira.reassign_issue.assert_not_called()

    def test_already_in_target_status_and_assigned_is_skipped(self, sync_service):
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        jira_issue = make_jira_issue("SEC-1", "In Review", "indeterminate")
        jira_issue["fields"]["assignee"]["name"] = "sec.mgr"
        sync_service.jira.get_issue.return_value = jira_issue

        stats = self._run(sync_service, dry_run=True)

        assert stats["checked"] == 1
        assert stats["resolved"] == 1
        assert stats["updated"] == 0
        assert stats["skipped"] == 1
        assert any(
            action["action"] == "skipped"
            and action["detail"] == "Already in target status and assigned to security manager"
            for action in stats["ticket_actions"]
        )
        sync_service.jira.find_transition_id.assert_not_called()
        sync_service.jira.transition_issue.assert_not_called()
        sync_service.jira.reassign_issue.assert_not_called()

    def test_null_assignee_does_not_error_and_still_updates(self, sync_service):
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        jira_issue = make_jira_issue("SEC-1", "To Do", "new")
        jira_issue["fields"]["assignee"] = None
        sync_service.jira.get_issue.return_value = jira_issue

        stats = self._run(sync_service, dry_run=True)

        assert stats["errors"] == 0
        assert stats["updated"] == 1
        sync_service.jira.transition_issue.assert_not_called()
        sync_service.jira.reassign_issue.assert_not_called()


class TestRun:
    def test_run_fetches_jira_once_and_processes_projects(self, sync_service):
        sync_service.snyk.get_projects_by_name_prefix.return_value = [
            {"id": "p1", "attributes": {"name": "project-tag/background-job-svc(master):package.json"}},
            {"id": "p2", "attributes": {"name": "project-tag/ui(master):package.json"}},
        ]
        sync_service.snyk.get_projects_by_tags.return_value = []
        sync_service.jira.search_issues.return_value = [
            {
                "key": "SEC-1",
                "fields": {
                    "summary": "project-tag/background-job-svc SNYK-JS-LODASH-123",
                    "description": "",
                },
            },
            {
                "key": "SEC-2",
                "fields": {
                    "summary": "project-tag/ui SNYK-JS-EXPRESS-456",
                    "description": "",
                },
            },
        ]
        sync_service.snyk.get_issues.side_effect = [
            [make_snyk_issue("SNYK-JS-LODASH-123", status="resolved")],
            [make_snyk_issue("SNYK-JS-EXPRESS-456", status="resolved")],
        ]
        sync_service.jira.get_issue.side_effect = [
            make_jira_issue("SEC-1", "To Do", "new"),
            make_jira_issue("SEC-2", "To Do", "new"),
        ]

        totals = sync_service.run(
            org_id="org-1",
            security_manager="sec.mgr",
            target_status="In Review",
            project_tags="project-tag/",
            jira_jql='text ~ "SNYK-"',
            dry_run=True,
        )

        assert totals["checked"] == 3
        assert totals["resolved"] == 2
        assert totals["updated"] == 2
        assert totals["skipped"] == 0
        assert totals["errors"] == 0
        assert isinstance(totals["ticket_actions"], list)
        assert all("project_name" in action for action in totals["ticket_actions"])
        sync_service.jira.search_issues.assert_called_once_with(jql='text ~ "SNYK-"')
        assert sync_service.snyk.get_issues.call_count == 2

    def test_run_does_not_mark_ticket_resolved_when_open_in_another_matched_project(
        self, sync_service
    ):
        sync_service.snyk.get_projects_by_name_prefix.return_value = [
            {"id": "p1", "attributes": {"name": "project-tag/service(master)"}},
            {"id": "p2", "attributes": {"name": "project-tag/service(master):package.json"}},
        ]
        sync_service.snyk.get_projects_by_tags.return_value = []
        sync_service.jira.search_issues.return_value = [
            {
                "key": "SEC-1",
                "fields": {
                    "summary": "project-tag/service SNYK-JS-LODASH-123",
                    "description": "",
                },
            },
        ]
        sync_service.snyk.get_issues.side_effect = [
            [],
            [make_snyk_issue("SNYK-JS-LODASH-123", status="open")],
        ]

        totals = sync_service.run(
            org_id="org-1",
            security_manager="sec.mgr",
            target_status="In Review",
            project_tags="project-tag/",
            jira_jql='text ~ "SNYK-"',
            dry_run=True,
        )

        assert totals["checked"] == 2
        assert totals["resolved"] == 0
        assert totals["updated"] == 0
        assert totals["errors"] == 0
        sync_service.jira.get_issue.assert_not_called()


class TestRunOne:
    def test_run_one_processes_matching_project(self, sync_service):
        jira_issue = {
            "key": "SEC-1",
            "fields": {
                "summary": "project-tag/background-job-svc SNYK-JS-LODASH-123",
                "description": "",
                "status": {"name": "To Do", "statusCategory": {"key": "new"}},
            },
        }
        sync_service.jira.get_issue.return_value = jira_issue
        sync_service.snyk.get_projects_by_name_prefix.return_value = [
            {"id": "p1", "attributes": {"name": "project-tag/background-job-svc(master):package.json"}},
        ]
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.find_transition_id.return_value = "21"

        totals = sync_service.run_one(
            org_id="org-1",
            jira_key="SEC-1",
            security_manager="sec.mgr",
            target_status="In Review",
            project_tags="project-tag/",
            dry_run=True,
        )

        assert totals["checked"] == 1
        assert totals["updated"] == 1
        assert totals["errors"] == 0
        assert totals["ticket_actions"][0]["project_name"] == "project-tag/background-job-svc(master):package.json"

    def test_run_one_raises_when_no_snyk_ids_found(self, sync_service):
        sync_service.jira.get_issue.return_value = {
            "key": "SEC-1",
            "fields": {"summary": "no snyk id here", "description": ""},
        }

        with pytest.raises(SyncSelectionError, match="does not reference any SNYK issue IDs") as exc:
            sync_service.run_one(
                org_id="org-1",
                jira_key="SEC-1",
                security_manager="sec.mgr",
                target_status="In Review",
                dry_run=True,
            )

        assert exc.value.status_code == 400

    def test_run_one_raises_when_multiple_projects_match(self, sync_service):
        sync_service.jira.get_issue.return_value = {
            "key": "SEC-1",
            "fields": {
                "summary": "project-tag/shared-lib SNYK-JS-LODASH-123",
                "description": "",
            },
        }
        sync_service.snyk.get_projects_by_name_prefix.return_value = [
            {"id": "p1", "attributes": {"name": "project-tag/shared-lib(master):package.json"}},
            {"id": "p2", "attributes": {"name": "project-tag/shared-lib(release):package.json"}},
        ]
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]

        with pytest.raises(SyncSelectionError, match="matched multiple Snyk projects") as exc:
            sync_service.run_one(
                org_id="org-1",
                jira_key="SEC-1",
                security_manager="sec.mgr",
                target_status="In Review",
                project_tags="project-tag/",
                dry_run=True,
            )

        assert exc.value.status_code == 409
