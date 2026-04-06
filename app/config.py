from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    snyk_token: str
    snyk_org_id: str
    snyk_base_url: str = "https://api.snyk.io"
    snyk_repo_names: str | None = None

    jira_base_url: str
    jira_pat: str
    jira_security_manager_username: str

    database_url: str = "postgresql://postgres:postgres@localhost:5530/snyk_jira_sync"

    dry_run: bool = False
