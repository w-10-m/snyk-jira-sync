from unittest.mock import MagicMock, patch

import pytest
import requests

from app.clients.jira import JiraClient, DEFAULT_TIMEOUT


class TestJiraClientInit:
    def test_sets_bearer_auth_header(self, jira_client):
        assert jira_client.session.headers["Authorization"] == "Bearer test-jira-pat"

    def test_sets_content_type_header(self, jira_client):
        assert jira_client.session.headers["Content-Type"] == "application/json"

    def test_builds_api_url(self, jira_client):
        assert jira_client.api_url == "https://jira.example.com/rest/api/2"

    def test_strips_trailing_slash(self):
        client = JiraClient("https://jira.example.com/", "pat")
        assert client.base_url == "https://jira.example.com"
        assert client.api_url == "https://jira.example.com/rest/api/2"


class TestJiraParseRetryAfter:
    def test_valid_integer(self, jira_client):
        assert jira_client._parse_retry_after("10") == 10

    def test_none_returns_default(self, jira_client):
        assert jira_client._parse_retry_after(None) == 60

    def test_empty_string_returns_default(self, jira_client):
        assert jira_client._parse_retry_after("") == 60

    def test_date_string_returns_default(self, jira_client):
        assert jira_client._parse_retry_after("Thu, 01 Jan 2026 00:00:00 GMT") == 60


class TestJiraRequest:
    def test_successful_get(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client._request("GET", "https://jira.example.com/rest/api/2/issue/SEC-1")

        assert result is mock_response
        mock_response.raise_for_status.assert_called_once()

    def test_sets_default_timeout(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client._request("GET", "https://jira.example.com/rest/api/2/issue/SEC-1")

        _, kwargs = jira_client.session.request.call_args
        assert kwargs["timeout"] == DEFAULT_TIMEOUT

    @patch("app.clients.jira.time.sleep")
    def test_retries_on_429(self, mock_sleep, jira_client):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "3"}

        success = MagicMock()
        success.status_code = 200

        jira_client.session.request = MagicMock(side_effect=[rate_limited, success])

        result = jira_client._request("GET", "https://jira.example.com/rest/api/2/issue/SEC-1")

        assert result is success
        mock_sleep.assert_called_once_with(3)

    @patch("app.clients.jira.time.sleep")
    def test_raises_after_4_retries(self, mock_sleep, jira_client):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {}

        jira_client.session.request = MagicMock(return_value=rate_limited)

        with pytest.raises(RuntimeError, match="rate limit exceeded after 4 retries"):
            jira_client._request("GET", "https://jira.example.com/rest/api/2/issue/SEC-1")

        assert jira_client.session.request.call_count == 4

    @patch("app.clients.jira.time.sleep")
    def test_429_without_retry_after_uses_default(self, mock_sleep, jira_client):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {}

        success = MagicMock()
        success.status_code = 200

        jira_client.session.request = MagicMock(side_effect=[rate_limited, success])

        jira_client._request("GET", "https://jira.example.com/rest/api/2/issue/SEC-1")

        mock_sleep.assert_called_once_with(60)

    def test_raises_on_http_error(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "403 Forbidden"
        )
        jira_client.session.request = MagicMock(return_value=mock_response)

        with pytest.raises(requests.exceptions.HTTPError, match="403"):
            jira_client._request("GET", "https://jira.example.com/rest/api/2/issue/SEC-1")


class TestGetIssue:
    def test_returns_parsed_json(self, jira_client):
        issue_data = {
            "key": "SEC-1",
            "fields": {
                "summary": "Test",
                "status": {"name": "To Do", "statusCategory": {"key": "new"}},
            },
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = issue_data
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.get_issue("SEC-1")

        assert result == issue_data

    def test_requests_correct_fields(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.get_issue("SEC-1")

        _, kwargs = jira_client.session.request.call_args
        assert "status" in kwargs["params"]["fields"]
        assert "assignee" in kwargs["params"]["fields"]
        assert "summary" in kwargs["params"]["fields"]
        assert "labels" in kwargs["params"]["fields"]


class TestGetTransitions:
    def test_returns_transitions_list(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "transitions": [
                {"id": "11", "name": "To Do"},
                {"id": "21", "name": "In Progress"},
                {"id": "31", "name": "Done"},
            ]
        }
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.get_transitions("SEC-1")

        assert len(result) == 3
        assert result[1]["name"] == "In Progress"

    def test_returns_empty_list_when_no_transitions(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.get_transitions("SEC-1")

        assert result == []


class TestSearchIssues:
    def test_returns_all_pages(self, jira_client):
        page1 = MagicMock()
        page1.status_code = 200
        page1.json.return_value = {
            "issues": [{"key": "SEC-1"}, {"key": "SEC-2"}],
            "total": 3,
        }
        page2 = MagicMock()
        page2.status_code = 200
        page2.json.return_value = {
            "issues": [{"key": "SEC-3"}],
            "total": 3,
        }

        jira_client.session.request = MagicMock(side_effect=[page1, page2])

        results = jira_client.search_issues("text ~ \"SNYK-\"", page_size=2)

        assert [r["key"] for r in results] == ["SEC-1", "SEC-2", "SEC-3"]
        assert jira_client.session.request.call_count == 2

    def test_returns_empty_when_no_matches(self, jira_client):
        page = MagicMock()
        page.status_code = 200
        page.json.return_value = {"issues": [], "total": 0}
        jira_client.session.request = MagicMock(return_value=page)

        results = jira_client.search_issues("text ~ \"SNYK-\"")

        assert results == []


class TestTransitionIssue:
    def test_sends_transition_payload(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.transition_issue("SEC-1", "21")

        _, kwargs = jira_client.session.request.call_args
        assert kwargs["json"]["transition"]["id"] == "21"

    def test_includes_comment_when_provided(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.transition_issue("SEC-1", "21", comment="Auto-resolved")

        _, kwargs = jira_client.session.request.call_args
        payload = kwargs["json"]
        assert payload["update"]["comment"][0]["add"]["body"] == "Auto-resolved"

    def test_no_comment_field_when_none(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.transition_issue("SEC-1", "21")

        _, kwargs = jira_client.session.request.call_args
        assert "update" not in kwargs["json"]

    def test_returns_none(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.transition_issue("SEC-1", "21")

        assert result is None


class TestReassignIssue:
    def test_sends_name_field(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.reassign_issue("SEC-1", "security.manager")

        call_args = jira_client.session.request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[1]["json"] == {"name": "security.manager"}

    def test_calls_assignee_endpoint(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.reassign_issue("SEC-1", "security.manager")

        call_url = jira_client.session.request.call_args[0][1]
        assert call_url.endswith("/rest/api/2/issue/SEC-1/assignee")

    def test_returns_none(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 204
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.reassign_issue("SEC-1", "security.manager")

        assert result is None


class TestAddComment:
    def test_sends_body(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "123", "body": "Hello"}
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.add_comment("SEC-1", "Hello")

        _, kwargs = jira_client.session.request.call_args
        assert kwargs["json"] == {"body": "Hello"}
        assert result["body"] == "Hello"

    def test_calls_comment_endpoint(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {}
        jira_client.session.request = MagicMock(return_value=mock_response)

        jira_client.add_comment("SEC-1", "test")

        call_url = jira_client.session.request.call_args[0][1]
        assert call_url.endswith("/rest/api/2/issue/SEC-1/comment")


class TestFindTransitionId:
    def test_finds_exact_match(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "transitions": [
                {"id": "11", "name": "To Do"},
                {"id": "21", "name": "In Progress"},
                {"id": "31", "name": "Done"},
            ]
        }
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.find_transition_id("SEC-1", "In Progress")

        assert result == "21"

    def test_case_insensitive(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "transitions": [{"id": "21", "name": "In Progress"}]
        }
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.find_transition_id("SEC-1", "in progress")

        assert result == "21"

    def test_partial_match(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "transitions": [{"id": "21", "name": "Move to In Progress"}]
        }
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.find_transition_id("SEC-1", "In Progress")

        assert result == "21"

    def test_returns_none_when_not_found(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "transitions": [
                {"id": "11", "name": "To Do"},
                {"id": "31", "name": "Done"},
            ]
        }
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.find_transition_id("SEC-1", "In Progress")

        assert result is None

    def test_returns_none_with_empty_transitions(self, jira_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"transitions": []}
        jira_client.session.request = MagicMock(return_value=mock_response)

        result = jira_client.find_transition_id("SEC-1", "In Progress")

        assert result is None
