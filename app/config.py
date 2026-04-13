from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    snyk_token: str
    snyk_org_id: str
    snyk_base_url: str = "https://api.snyk.io"
    snyk_repo_names: str | None = None
    snyk_project_tags: str | None = None  # Comma-separated tags to filter projects (e.g., "xyz")
    jira_snyk_jql: str = 'text ~ "SNYK-"'

    jira_base_url: str
    jira_pat: str
    jira_security_manager_username: str
    jira_target_status: str = "In Review"
    sync_report_dir: str = ".local/sync-reports"

    database_url: str = "postgresql://postgres:postgres@localhost:5530/snyk_jira_sync"

    dry_run: bool = False
