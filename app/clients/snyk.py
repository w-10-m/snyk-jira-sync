import logging
import time

import requests

logger = logging.getLogger(__name__)

REST_API_VERSION = "2024-10-15"
DEFAULT_TIMEOUT = 30


class SnykClient:
    """Client for Snyk REST and V1 APIs."""

    def __init__(self, token: str, base_url: str = "https://api.snyk.io"):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.api+json",
        })

    def _rest_get_all(self, path: str, params: dict | None = None) -> list:
        """Paginate through all results from a REST API endpoint."""
        if params is None:
            params = {}
        params["version"] = REST_API_VERSION
        params.setdefault("limit", 100)

        all_data = []
        url = f"{self.base_url}/rest{path}"

        while url:
            response = self._request("GET", url, params=params)
            data = response.get("data", [])
            all_data.extend(data)

            next_link = response.get("links", {}).get("next")
            if next_link:
                url = (
                    next_link
                    if next_link.startswith("http")
                    else f"{self.base_url}{next_link}"
                )
                params = {}  # params are embedded in the next link
            else:
                url = None

        return all_data

    def _v1_get(self, path: str) -> dict:
        """Make a GET request to the V1 API."""
        url = f"{self.base_url}/v1{path}"
        return self._request("GET", url)

    def _parse_retry_after(self, value: str | None) -> int:
        """Parse Retry-After header, which may be seconds or a date string."""
        if not value:
            return 60
        try:
            return int(value)
        except ValueError:
            return 60

    def _request(self, method: str, url: str, **kwargs) -> dict:
        """Make an HTTP request with retry on rate limit."""
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)

        for attempt in range(4):
            response = self.session.request(method, url, **kwargs)

            if response.status_code == 429:
                retry_after = self._parse_retry_after(
                    response.headers.get("Retry-After")
                )
                logger.warning(
                    "Rate limited by Snyk, retrying in %ds (attempt %d/4)",
                    retry_after,
                    attempt + 1,
                )
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            return response.json()

        raise RuntimeError("Snyk API rate limit exceeded after 4 retries")

    def get_orgs(self) -> list:
        """List all organizations the token has access to."""
        return self._rest_get_all("/orgs")

    def get_projects(self, org_id: str, name_filter: str | None = None) -> list:
        """List projects in an org, optionally filtered by name."""
        params = {}
        if name_filter:
            params["names"] = name_filter
        return self._rest_get_all(f"/orgs/{org_id}/projects", params=params)

    def get_projects_by_tags(self, org_id: str, tags: list[str]) -> list:
        """List projects in an org filtered by tags.

        Args:
            org_id: Organization ID
            tags: List of tags to filter by (projects must have at least one tag in the list)

        Returns:
            List of projects that have at least one matching tag
        """
        all_projects = self._rest_get_all(f"/orgs/{org_id}/projects")

        # Filter projects by tags
        filtered_projects = []
        for project in all_projects:
            project_tags = project.get("attributes", {}).get("tags", [])
            project_tag_keys = [tag.get("key") for tag in project_tags]

            # Check if any of the desired tags match
            if any(tag in project_tag_keys for tag in tags):
                filtered_projects.append(project)

        return filtered_projects

    def get_projects_by_name_prefix(self, org_id: str, prefix: str) -> list:
        """List projects in an org filtered by name prefix.

        Args:
            org_id: Organization ID
            prefix: Name prefix to filter by (e.g., "xyz/")

        Returns:
            List of projects whose name starts with the prefix
        """
        all_projects = self._rest_get_all(f"/orgs/{org_id}/projects")

        # Filter projects by name prefix
        filtered_projects = []
        for project in all_projects:
            project_name = project.get("attributes", {}).get("name", "")
            if project_name.lower().startswith(prefix.lower()):
                filtered_projects.append(project)

        return filtered_projects

    def get_issues(self, org_id: str, project_id: str) -> list:
        """Get all issues for a project via REST API."""
        params = {
            "scan_item.id": project_id,
            "scan_item.type": "project",
        }
        return self._rest_get_all(f"/orgs/{org_id}/issues", params=params)

    def get_jira_issues(self, org_id: str, project_id: str) -> dict:
        """Get Snyk Issue ID -> Jira ticket mapping (V1 API).

        Returns a dict like:
            {"SNYK-JS-LODASH-123": [{"jiraIssue": {"id": "10001", "key": "PROJ-1"}}]}

        If the V1 endpoint is not available (406/404), returns empty dict.
        """
        try:
            # Try V1 API — this endpoint requires Jira integration to be configured in Snyk
            url = f"{self.base_url}/v1/org/{org_id}/project/{project_id}/jira-issues"
            return self._request("GET", url)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in (404, 406):
                # 404: Endpoint not found (may be disabled or not available in this Snyk version)
                # 406: Not Acceptable (may mean Jira integration not configured)
                logger.debug(
                    "Jira issues endpoint returned %d for project %s — "
                    "Jira integration may not be configured in Snyk. "
                    "Set SNYK_SKIP_JIRA_LOOKUP=true to suppress this warning.",
                    e.response.status_code,
                    project_id,
                )
                return {}
            # Re-raise other HTTP errors
            raise
