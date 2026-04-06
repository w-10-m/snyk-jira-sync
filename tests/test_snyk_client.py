from unittest.mock import MagicMock, patch

import pytest
import requests

from app.clients.snyk import SnykClient, REST_API_VERSION, DEFAULT_TIMEOUT


class TestSnykClientInit:
    def test_sets_auth_header(self, snyk_client):
        assert snyk_client.session.headers["Authorization"] == "token test-snyk-token"

    def test_sets_accept_header(self, snyk_client):
        assert snyk_client.session.headers["Accept"] == "application/vnd.api+json"

    def test_strips_trailing_slash_from_base_url(self):
        client = SnykClient("tok", base_url="https://api.snyk.io/")
        assert client.base_url == "https://api.snyk.io"

    def test_default_base_url(self):
        client = SnykClient("tok")
        assert client.base_url == "https://api.snyk.io"

    def test_custom_base_url(self):
        client = SnykClient("tok", base_url="https://api.eu.snyk.io")
        assert client.base_url == "https://api.eu.snyk.io"


class TestParseRetryAfter:
    def test_valid_integer(self, snyk_client):
        assert snyk_client._parse_retry_after("30") == 30

    def test_none_returns_default(self, snyk_client):
        assert snyk_client._parse_retry_after(None) == 60

    def test_empty_string_returns_default(self, snyk_client):
        assert snyk_client._parse_retry_after("") == 60

    def test_date_string_returns_default(self, snyk_client):
        assert snyk_client._parse_retry_after("Wed, 21 Oct 2025 07:28:00 GMT") == 60

    def test_float_string_returns_default(self, snyk_client):
        assert snyk_client._parse_retry_after("3.5") == 60


class TestSnykRequest:
    def test_successful_request(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        result = snyk_client._request("GET", "https://api.snyk.io/rest/orgs")

        assert result == {"data": []}
        mock_response.raise_for_status.assert_called_once()

    def test_sets_default_timeout(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        snyk_client._request("GET", "https://api.snyk.io/rest/orgs")

        _, kwargs = snyk_client.session.request.call_args
        assert kwargs["timeout"] == DEFAULT_TIMEOUT

    def test_does_not_override_explicit_timeout(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        snyk_client._request("GET", "https://api.snyk.io/rest/orgs", timeout=90)

        _, kwargs = snyk_client.session.request.call_args
        assert kwargs["timeout"] == 90

    @patch("app.clients.snyk.time.sleep")
    def test_retries_on_429(self, mock_sleep, snyk_client):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "5"}

        success = MagicMock()
        success.status_code = 200
        success.json.return_value = {"ok": True}

        snyk_client.session.request = MagicMock(side_effect=[rate_limited, success])

        result = snyk_client._request("GET", "https://api.snyk.io/rest/orgs")

        assert result == {"ok": True}
        mock_sleep.assert_called_once_with(5)
        assert snyk_client.session.request.call_count == 2

    @patch("app.clients.snyk.time.sleep")
    def test_raises_after_4_retries(self, mock_sleep, snyk_client):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "1"}

        snyk_client.session.request = MagicMock(return_value=rate_limited)

        with pytest.raises(RuntimeError, match="rate limit exceeded after 4 retries"):
            snyk_client._request("GET", "https://api.snyk.io/rest/orgs")

        assert snyk_client.session.request.call_count == 4
        assert mock_sleep.call_count == 4

    def test_raises_on_http_error(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "500 Server Error"
        )
        snyk_client.session.request = MagicMock(return_value=mock_response)

        with pytest.raises(requests.exceptions.HTTPError):
            snyk_client._request("GET", "https://api.snyk.io/rest/orgs")

    def test_raises_on_404(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "404 Not Found"
        )
        snyk_client.session.request = MagicMock(return_value=mock_response)

        with pytest.raises(requests.exceptions.HTTPError):
            snyk_client._request("GET", "https://api.snyk.io/rest/orgs")


class TestRestGetAll:
    def test_single_page(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "1"}, {"id": "2"}],
            "links": {},
        }
        snyk_client.session.request = MagicMock(return_value=mock_response)

        result = snyk_client._rest_get_all("/orgs")

        assert result == [{"id": "1"}, {"id": "2"}]
        assert snyk_client.session.request.call_count == 1

    def test_multiple_pages(self, snyk_client):
        page1_response = MagicMock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            "data": [{"id": "1"}],
            "links": {"next": "/rest/orgs?starting_after=abc&version=2024-10-15"},
        }

        page2_response = MagicMock()
        page2_response.status_code = 200
        page2_response.json.return_value = {
            "data": [{"id": "2"}],
            "links": {},
        }

        snyk_client.session.request = MagicMock(
            side_effect=[page1_response, page2_response]
        )

        result = snyk_client._rest_get_all("/orgs")

        assert result == [{"id": "1"}, {"id": "2"}]
        assert snyk_client.session.request.call_count == 2

    def test_pagination_with_absolute_url(self, snyk_client):
        page1_response = MagicMock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            "data": [{"id": "1"}],
            "links": {
                "next": "https://api.snyk.io/rest/orgs?starting_after=abc&version=2024-10-15"
            },
        }

        page2_response = MagicMock()
        page2_response.status_code = 200
        page2_response.json.return_value = {"data": [{"id": "2"}], "links": {}}

        snyk_client.session.request = MagicMock(
            side_effect=[page1_response, page2_response]
        )

        result = snyk_client._rest_get_all("/orgs")

        second_call_url = snyk_client.session.request.call_args_list[1][1].get(
            "url"
        ) or snyk_client.session.request.call_args_list[1][0][1]
        assert "https://api.snyk.io/rest/orgs" in second_call_url

    def test_empty_data(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "links": {}}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        result = snyk_client._rest_get_all("/orgs")

        assert result == []

    def test_sets_version_and_limit_params(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "links": {}}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        snyk_client._rest_get_all("/orgs")

        _, kwargs = snyk_client.session.request.call_args
        assert kwargs["params"]["version"] == REST_API_VERSION
        assert kwargs["params"]["limit"] == 100

    def test_clears_params_on_subsequent_pages(self, snyk_client):
        page1_response = MagicMock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            "data": [{"id": "1"}],
            "links": {"next": "/rest/orgs?starting_after=abc&version=2024-10-15"},
        }

        page2_response = MagicMock()
        page2_response.status_code = 200
        page2_response.json.return_value = {"data": [], "links": {}}

        snyk_client.session.request = MagicMock(
            side_effect=[page1_response, page2_response]
        )

        snyk_client._rest_get_all("/orgs", params={"names": "my-repo"})

        first_call_params = snyk_client.session.request.call_args_list[0][1]["params"]
        assert first_call_params.get("names") == "my-repo"

        second_call_params = snyk_client.session.request.call_args_list[1][1]["params"]
        assert second_call_params == {}


class TestV1Get:
    def test_calls_correct_url(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"SNYK-123": []}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        snyk_client._v1_get("/org/org1/project/proj1/jira-issues")

        call_args = snyk_client.session.request.call_args
        assert call_args[0][1] == "https://api.snyk.io/v1/org/org1/project/proj1/jira-issues"


class TestGetOrgs:
    def test_calls_correct_path(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "org-1", "attributes": {"name": "My Org"}}],
            "links": {},
        }
        snyk_client.session.request = MagicMock(return_value=mock_response)

        result = snyk_client.get_orgs()

        assert len(result) == 1
        assert result[0]["id"] == "org-1"


class TestGetProjects:
    def test_without_filter(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "proj-1"}],
            "links": {},
        }
        snyk_client.session.request = MagicMock(return_value=mock_response)

        result = snyk_client.get_projects("org-1")

        assert len(result) == 1
        call_params = snyk_client.session.request.call_args[1]["params"]
        assert "names" not in call_params

    def test_with_name_filter(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "proj-1"}],
            "links": {},
        }
        snyk_client.session.request = MagicMock(return_value=mock_response)

        snyk_client.get_projects("org-1", name_filter="my-repo")

        call_params = snyk_client.session.request.call_args[1]["params"]
        assert call_params["names"] == "my-repo"


class TestGetIssues:
    def test_passes_scan_item_params(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "links": {}}
        snyk_client.session.request = MagicMock(return_value=mock_response)

        snyk_client.get_issues("org-1", "proj-1")

        call_params = snyk_client.session.request.call_args[1]["params"]
        assert call_params["scan_item.id"] == "proj-1"
        assert call_params["scan_item.type"] == "project"


class TestGetJiraIssues:
    def test_calls_v1_endpoint(self, snyk_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "SNYK-JS-LODASH-123": [{"jiraIssue": {"id": "10001", "key": "SEC-1"}}]
        }
        snyk_client.session.request = MagicMock(return_value=mock_response)

        result = snyk_client.get_jira_issues("org-1", "proj-1")

        assert "SNYK-JS-LODASH-123" in result
        call_url = snyk_client.session.request.call_args[0][1]
        assert "/v1/org/org-1/project/proj-1/jira-issues" in call_url
