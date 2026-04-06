import logging
import time

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30


class JiraClient:
    """Client for Jira Server/Data Center REST API v2."""

    def __init__(self, base_url: str, pat: str):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/rest/api/2"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {pat}",
                "Content-Type": "application/json",
            }
        )

    def _parse_retry_after(self, value: str | None) -> int:
        """Parse Retry-After header, which may be seconds or a date string."""
        if not value:
            return 60
        try:
            return int(value)
        except ValueError:
            return 60

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with retry on rate limit."""
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)

        for attempt in range(4):
            response = self.session.request(method, url, **kwargs)

            if response.status_code == 429:
                retry_after = self._parse_retry_after(
                    response.headers.get("Retry-After")
                )
                logger.warning(
                    "Rate limited by Jira, retrying in %ds (attempt %d/4)",
                    retry_after,
                    attempt + 1,
                )
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            return response

        raise RuntimeError("Jira API rate limit exceeded after 4 retries")

    def get_issue(self, issue_key: str) -> dict:
        """Get issue details including status and assignee."""
        url = f"{self.api_url}/issue/{issue_key}"
        params = {"fields": "status,assignee,summary,labels"}
        response = self._request("GET", url, params=params)
        return response.json()

    def get_transitions(self, issue_key: str) -> list:
        """Get available transitions for an issue."""
        url = f"{self.api_url}/issue/{issue_key}/transitions"
        response = self._request("GET", url)
        return response.json().get("transitions", [])

    def transition_issue(
        self, issue_key: str, transition_id: str, comment: str | None = None
    ) -> None:
        """Transition an issue to a new status. Raises on failure."""
        url = f"{self.api_url}/issue/{issue_key}/transitions"
        payload = {"transition": {"id": transition_id}}

        if comment:
            payload["update"] = {
                "comment": [{"add": {"body": comment}}]
            }

        self._request("POST", url, json=payload)

    def reassign_issue(self, issue_key: str, username: str) -> None:
        """Reassign an issue to a user (Jira Server/DC uses 'name' field). Raises on failure."""
        url = f"{self.api_url}/issue/{issue_key}/assignee"
        self._request("PUT", url, json={"name": username})

    def add_comment(self, issue_key: str, body: str) -> dict:
        """Add a comment to an issue."""
        url = f"{self.api_url}/issue/{issue_key}/comment"
        response = self._request("POST", url, json={"body": body})
        return response.json()

    def find_transition_id(self, issue_key: str, target_name: str) -> str | None:
        """Find a transition ID by name (case-insensitive partial match)."""
        transitions = self.get_transitions(issue_key)
        target_lower = target_name.lower()
        for t in transitions:
            if target_lower in t["name"].lower():
                return t["id"]
        return None
