from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.dependencies import get_settings, get_sync_service
from app.main import app
from app.models import Base, SyncRun
from tests.conftest import make_snyk_issue, make_jira_map, make_jira_issue

# In-memory SQLite for tests — StaticPool ensures all connections share the same DB
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test, drop after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


def make_test_settings():
    """Create a mock Settings object for tests."""
    settings = MagicMock()
    settings.snyk_token = "tok"
    settings.snyk_org_id = "org-1"
    settings.snyk_base_url = "https://api.snyk.io"
    settings.snyk_repo_names = None
    settings.jira_base_url = "https://jira.example.gov"
    settings.jira_pat = "pat"
    settings.jira_security_manager_username = "sec.mgr"
    settings.database_url = "sqlite://"
    settings.dry_run = False
    return settings


@pytest.fixture
def client():
    """FastAPI test client with DB and settings overrides."""
    mock_service = MagicMock()
    mock_service.run.return_value = {
        "checked": 5,
        "resolved": 2,
        "updated": 2,
        "skipped": 1,
        "errors": 0,
    }
    mock_service.snyk = MagicMock()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = make_test_settings
    app.dependency_overrides[get_sync_service] = lambda: mock_service

    yield TestClient(app)

    app.dependency_overrides.clear()


@pytest.fixture
def client_with_snyk():
    """Test client with a controllable mock Snyk client for /projects endpoints."""
    mock_snyk = MagicMock()
    mock_service = MagicMock()
    mock_service.snyk = mock_snyk

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = make_test_settings

    # Override the snyk client dependency
    from app.dependencies import get_snyk_client
    app.dependency_overrides[get_snyk_client] = lambda: mock_snyk
    app.dependency_overrides[get_sync_service] = lambda: mock_service

    yield TestClient(app), mock_snyk

    app.dependency_overrides.clear()


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestSyncEndpoints:
    def test_trigger_sync(self, client):
        response = client.post("/sync", json={"dry_run": True})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["dry_run"] is True
        assert data["trigger"] == "api"
        assert data["total_checked"] == 5
        assert data["total_updated"] == 2

    def test_trigger_sync_with_repos(self, client):
        response = client.post("/sync", json={"repos": ["my-repo"]})

        assert response.status_code == 200
        data = response.json()
        assert data["repo_filter"] == "my-repo"

    def test_trigger_sync_default_body(self, client):
        response = client.post("/sync", json={})

        assert response.status_code == 200
        data = response.json()
        assert data["dry_run"] is False

    def test_get_sync_history(self, client):
        # Create a run first
        client.post("/sync", json={"dry_run": True})
        client.post("/sync", json={"dry_run": False})

        response = client.get("/sync/history")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        # Most recent first
        assert data[0]["dry_run"] is False
        assert data[1]["dry_run"] is True

    def test_get_sync_history_with_limit(self, client):
        client.post("/sync", json={})
        client.post("/sync", json={})
        client.post("/sync", json={})

        response = client.get("/sync/history?limit=2")

        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_get_sync_run_by_id(self, client):
        create_response = client.post("/sync", json={"dry_run": True})
        run_id = create_response.json()["id"]

        response = client.get(f"/sync/{run_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == run_id
        assert "actions" in data

    def test_get_sync_run_not_found(self, client):
        fake_id = str(uuid4())
        response = client.get(f"/sync/{fake_id}")

        assert response.status_code == 404

    def test_sync_run_records_failure(self, client):
        """When the sync service raises, the run should be marked as failed."""
        # Override sync service to raise
        mock_service = MagicMock()
        mock_service.run.side_effect = RuntimeError("Snyk API down")

        app.dependency_overrides[get_sync_service] = lambda: mock_service

        response = client.post("/sync", json={})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"


class TestProjectEndpoints:
    def test_list_projects(self, client_with_snyk):
        client, mock_snyk = client_with_snyk
        mock_snyk.get_projects.return_value = [
            {"id": "p1", "attributes": {"name": "my-repo", "origin": "github", "type": "npm"}},
        ]

        response = client.get("/projects")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == "p1"
        assert data[0]["name"] == "my-repo"
        assert data[0]["origin"] == "github"

    def test_list_projects_with_filter(self, client_with_snyk):
        client, mock_snyk = client_with_snyk
        mock_snyk.get_projects.return_value = []

        client.get("/projects?name=my-repo")

        mock_snyk.get_projects.assert_called_once_with("org-1", name_filter="my-repo")

    def test_get_project_issues(self, client_with_snyk):
        client, mock_snyk = client_with_snyk
        mock_snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="open"),
        ]
        mock_snyk.get_jira_issues.return_value = make_jira_map([
            ("SNYK-JS-LODASH-123", "SEC-1"),
        ])

        response = client.get("/projects/proj-1/issues")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["snyk_issue_id"] == "SNYK-JS-LODASH-123"
        assert data[0]["status"] == "open"
        assert data[0]["jira_keys"] == ["SEC-1"]

    def test_get_project_issues_no_jira_links(self, client_with_snyk):
        client, mock_snyk = client_with_snyk
        mock_snyk.get_issues.return_value = [
            make_snyk_issue("SNYK-JS-LODASH-123", status="open"),
        ]
        mock_snyk.get_jira_issues.return_value = {}

        response = client.get("/projects/proj-1/issues")

        assert response.status_code == 200
        data = response.json()
        assert data[0]["jira_keys"] == []
