from unittest.mock import MagicMock, patch, call

import pytest

from app.services.sync import SyncService
from tests.conftest import make_snyk_issue, make_jira_issue, make_jira_map


@pytest.fixture
def sync_service():
    """SyncService with mocked clients."""
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

    def test_empty_issues(self):
        result = SyncService.build_issue_status_map([])

        assert result == {}

    def test_multiple_problems_per_issue(self):
        issues = [
            {
                "id": "uuid-1",
                "attributes": {
                    "status": "open",
                    "problems": [
                        {"id": "CVE-2024-0001", "source": "nvd", "type": "vulnerability"},
                        {"id": "SNYK-JS-FOO-111", "source": "snyk", "type": "vulnerability"},
                    ],
                },
            }
        ]

        result = SyncService.build_issue_status_map(issues)

        assert result["CVE-2024-0001"] == "open"
        assert result["SNYK-JS-FOO-111"] == "open"

    def test_skips_problems_without_id(self):
        issues = [
            {
                "id": "uuid-1",
                "attributes": {
                    "status": "open",
                    "problems": [
                        {"source": "snyk", "type": "vulnerability"},  # no id
                    ],
                },
            }
        ]

        result = SyncService.build_issue_status_map(issues)

        assert result == {}

    def test_defaults_status_to_open(self):
        issues = [
            {
                "id": "uuid-1",
                "attributes": {
                    # no "status" field
                    "problems": [{"id": "SNYK-1", "source": "snyk", "type": "vulnerability"}],
                },
            }
        ]

        result = SyncService.build_issue_status_map(issues)

        assert result["SNYK-1"] == "open"


class TestProcessProject:
    def _run(self, sync_service, dry_run=False):
        return sync_service.process_project(
            org_id="org-1",
            project_id="proj-1",
            project_name="test-project",
            security_manager="sec.mgr",
            dry_run=dry_run,
        )

    def test_no_jira_tickets(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = {}

        stats = self._run(sync_service)

        assert stats["checked"] == 0
        sync_service.jira.get_issue.assert_not_called()

    def test_resolved_issue_transitions_and_reassigns(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "To Do", "new")
        sync_service.jira.find_transition_id.return_value = "21"

        stats = self._run(sync_service)

        assert stats["checked"] == 1
        assert stats["resolved"] == 1
        assert stats["updated"] == 1
        sync_service.jira.transition_issue.assert_called_once()
        assert sync_service.jira.transition_issue.call_args[0][0] == "SEC-1"
        assert sync_service.jira.transition_issue.call_args[0][1] == "21"
        sync_service.jira.reassign_issue.assert_called_once_with("SEC-1", "sec.mgr")

    def test_open_issue_skipped(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="open"),
        ]

        stats = self._run(sync_service)

        assert stats["checked"] == 1
        assert stats["resolved"] == 0
        assert stats["updated"] == 0
        sync_service.jira.get_issue.assert_not_called()

    def test_already_closed_jira_ticket_skipped(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "Done", "done")

        stats = self._run(sync_service)

        assert stats["skipped"] == 1
        assert stats["updated"] == 0
        sync_service.jira.transition_issue.assert_not_called()
        sync_service.jira.reassign_issue.assert_not_called()

    def test_dry_run_does_not_modify(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "To Do", "new")

        stats = self._run(sync_service, dry_run=True)

        assert stats["updated"] == 1
        sync_service.jira.transition_issue.assert_not_called()
        sync_service.jira.reassign_issue.assert_not_called()
        sync_service.jira.add_comment.assert_not_called()

    def test_transition_not_available_adds_comment(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue(
            "SEC-1", "Blocked", "indeterminate"
        )
        sync_service.jira.find_transition_id.return_value = None

        stats = self._run(sync_service)

        assert stats["updated"] == 1
        sync_service.jira.transition_issue.assert_not_called()
        sync_service.jira.add_comment.assert_called_once()
        assert "Could not auto-transition" in sync_service.jira.add_comment.call_args[0][1]
        sync_service.jira.reassign_issue.assert_called_once_with("SEC-1", "sec.mgr")

    def test_snyk_issue_not_in_status_map_treated_as_resolved(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-REMOVED-999", "SEC-5"),
        ])
        sync_service.snyk.get_issues.return_value = []
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-5", "To Do", "new")
        sync_service.jira.find_transition_id.return_value = "21"

        stats = self._run(sync_service)

        assert stats["resolved"] == 1
        assert stats["updated"] == 1
        sync_service.jira.transition_issue.assert_called_once()
        sync_service.jira.reassign_issue.assert_called_once()

    def test_multiple_jira_tickets_per_snyk_issue(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = {
            "SNYK-JS-LODASH-123": [
                {"jiraIssue": {"id": "10001", "key": "SEC-1"}},
                {"jiraIssue": {"id": "10002", "key": "SEC-2"}},
            ]
        }
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.side_effect = [
            make_jira_issue("SEC-1", "To Do", "new"),
            make_jira_issue("SEC-2", "To Do", "new"),
        ]
        sync_service.jira.find_transition_id.return_value = "21"

        stats = self._run(sync_service)

        assert stats["checked"] == 2
        assert stats["updated"] == 2
        assert sync_service.jira.transition_issue.call_count == 2
        assert sync_service.jira.reassign_issue.call_count == 2

    def test_error_on_one_ticket_continues_to_next(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = {
            "SNYK-JS-LODASH-123": [
                {"jiraIssue": {"id": "10001", "key": "SEC-1"}},
                {"jiraIssue": {"id": "10002", "key": "SEC-2"}},
            ]
        }
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.side_effect = [
            Exception("Connection timeout"),
            make_jira_issue("SEC-2", "To Do", "new"),
        ]
        sync_service.jira.find_transition_id.return_value = "21"

        stats = self._run(sync_service)

        assert stats["errors"] == 1
        assert stats["updated"] == 1

    def test_non_list_jira_tickets_skipped(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = {
            "SNYK-JS-LODASH-123": "unexpected-string-value",
        }
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]

        stats = self._run(sync_service)

        assert stats["checked"] == 0
        sync_service.jira.get_issue.assert_not_called()

    def test_jira_ticket_missing_key_skipped(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = {
            "SNYK-JS-LODASH-123": [
                {"jiraIssue": {}},  # no "key"
            ]
        }
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]

        stats = self._run(sync_service)

        assert stats["checked"] == 1
        assert stats["updated"] == 0
        sync_service.jira.get_issue.assert_not_called()

    def test_mixed_resolved_and_open_issues(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
            ("SNYK-JS-EXPRESS-456", "SEC-2"),
            ("SNYK-JS-AXIOS-789", "SEC-3"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
            make_snyk_issue("SNYK-JS-EXPRESS-456", status="open"),
            make_snyk_issue("SNYK-JS-AXIOS-789", status="resolved"),
        ]
        sync_service.jira.get_issue.side_effect = [
            make_jira_issue("SEC-1", "To Do", "new"),
            make_jira_issue("SEC-3", "To Do", "new"),
        ]
        sync_service.jira.find_transition_id.return_value = "21"

        stats = self._run(sync_service)

        assert stats["checked"] == 3
        assert stats["resolved"] == 2
        assert stats["updated"] == 2
        jira_keys_fetched = [c[0][0] for c in sync_service.jira.get_issue.call_args_list]
        assert "SEC-2" not in jira_keys_fetched

    def test_transition_comment_contains_snyk_id(self, sync_service):
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "To Do", "new")
        sync_service.jira.find_transition_id.return_value = "21"

        self._run(sync_service)

        comment = sync_service.jira.transition_issue.call_args[1]["comment"]
        assert "SNYK-JS-LODASH-123" in comment
        assert "[Snyk-Jira Sync]" in comment


class TestRun:
    def test_processes_all_projects_when_no_filter(self, sync_service):
        sync_service.snyk.get_projects.return_value = [
            {"id": "p1", "attributes": {"name": "project-1"}},
            {"id": "p2", "attributes": {"name": "project-2"}},
        ]
        sync_service.snyk.get_jira_issues.return_value = {}

        sync_service.run(org_id="org-1", security_manager="sec.mgr")

        sync_service.snyk.get_projects.assert_called_once_with("org-1")
        assert sync_service.snyk.get_jira_issues.call_count == 2

    def test_filters_by_repo_name(self, sync_service):
        sync_service.snyk.get_projects.return_value = [
            {"id": "p1", "attributes": {"name": "my-repo"}},
        ]
        sync_service.snyk.get_jira_issues.return_value = {}

        sync_service.run(
            org_id="org-1", security_manager="sec.mgr", repo_filter="my-repo"
        )

        sync_service.snyk.get_projects.assert_called_once_with(
            "org-1", name_filter="my-repo"
        )

    def test_handles_multiple_comma_separated_repos(self, sync_service):
        sync_service.snyk.get_projects.return_value = []

        sync_service.run(
            org_id="org-1", security_manager="sec.mgr", repo_filter="repo-a, repo-b"
        )

        calls = sync_service.snyk.get_projects.call_args_list
        assert len(calls) == 2
        assert calls[0] == call("org-1", name_filter="repo-a")
        assert calls[1] == call("org-1", name_filter="repo-b")

    def test_no_projects_found(self, sync_service):
        sync_service.snyk.get_projects.return_value = []

        totals = sync_service.run(org_id="org-1", security_manager="sec.mgr")

        sync_service.snyk.get_jira_issues.assert_not_called()
        assert totals["checked"] == 0

    def test_returns_totals(self, sync_service):
        sync_service.snyk.get_projects.return_value = [
            {"id": "p1", "attributes": {"name": "project-1"}},
        ]
        sync_service.snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])
        sync_service.snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="resolved"),
        ]
        sync_service.jira.get_issue.return_value = make_jira_issue("SEC-1", "To Do", "new")
        sync_service.jira.find_transition_id.return_value = "21"

        totals = sync_service.run(org_id="org-1", security_manager="sec.mgr")

        assert totals["checked"] == 1
        assert totals["resolved"] == 1
        assert totals["updated"] == 1


class TestConfig:
    @patch.dict(
        "os.environ",
        {
            "SNYK_TOKEN": "tok",
            "SNYK_ORG_ID": "org-1",
            "JIRA_BASE_URL": "https://jira.example.gov",
            "JIRA_PAT": "pat",
            "JIRA_SECURITY_MANAGER_USERNAME": "sec.mgr",
        },
        clear=True,
    )
    def test_settings_loads_required_vars(self):
        from app.config import Settings

        settings = Settings()
        assert settings.snyk_token == "tok"
        assert settings.snyk_org_id == "org-1"
        assert settings.jira_base_url == "https://jira.example.gov"
        assert settings.jira_pat == "pat"
        assert settings.jira_security_manager_username == "sec.mgr"

    @patch.dict(
        "os.environ",
        {
            "SNYK_TOKEN": "tok",
            "SNYK_ORG_ID": "org-1",
            "JIRA_BASE_URL": "https://jira.example.gov",
            "JIRA_PAT": "pat",
            "JIRA_SECURITY_MANAGER_USERNAME": "sec.mgr",
        },
        clear=True,
    )
    def test_settings_defaults(self):
        from app.config import Settings

        settings = Settings()
        assert settings.snyk_base_url == "https://api.snyk.io"
        assert settings.snyk_repo_names is None
        assert settings.dry_run is False

    @patch.dict(
        "os.environ",
        {
            "SNYK_TOKEN": "tok",
            "SNYK_ORG_ID": "org-1",
            "JIRA_BASE_URL": "https://jira.example.gov",
            "JIRA_PAT": "pat",
            "JIRA_SECURITY_MANAGER_USERNAME": "sec.mgr",
            "DRY_RUN": "true",
            "SNYK_REPO_NAMES": "repo-a,repo-b",
            "SNYK_BASE_URL": "https://api.eu.snyk.io",
        },
        clear=True,
    )
    def test_settings_optional_vars(self):
        from app.config import Settings

        settings = Settings()
        assert settings.dry_run is True
        assert settings.snyk_repo_names == "repo-a,repo-b"
        assert settings.snyk_base_url == "https://api.eu.snyk.io"

    @patch.dict("os.environ", {}, clear=True)
    def test_settings_raises_on_missing_vars(self):
        from pydantic import ValidationError
        from app.config import Settings

        with pytest.raises(ValidationError):
            Settings()
