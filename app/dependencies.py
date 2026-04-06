from functools import lru_cache

from app.clients.jira import JiraClient
from app.clients.snyk import SnykClient
from app.config import Settings
from app.services.sync import SyncService


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_snyk_client() -> SnykClient:
    settings = get_settings()
    return SnykClient(settings.snyk_token, settings.snyk_base_url)


def get_jira_client() -> JiraClient:
    settings = get_settings()
    return JiraClient(settings.jira_base_url, settings.jira_pat)


def get_sync_service() -> SyncService:
    settings = get_settings()
    return SyncService(
        snyk=SnykClient(settings.snyk_token, settings.snyk_base_url),
        jira=JiraClient(settings.jira_base_url, settings.jira_pat),
    )
