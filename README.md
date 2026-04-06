# Snyk-Jira Sync

Automatically detects when Snyk vulnerabilities have been resolved and updates the corresponding Jira tickets — transitions them to "In Progress" and reassigns to the security manager for closure.

## Problem

Developers fix Snyk vulnerabilities (e.g., upgrade a dependency) but don't update the Jira tickets that Snyk auto-created. This leaves stale open tickets in Jira.

## How It Works

1. Fetches Snyk projects for your repo(s)
2. Gets the Snyk Issue → Jira ticket mapping (via Snyk V1 API)
3. Checks each Snyk issue's current status (via Snyk REST API)
4. For resolved issues with open Jira tickets:
   - Transitions the Jira ticket to "In Progress"
   - Adds a comment explaining the vulnerability was resolved
   - Reassigns to the security manager

## Setup

### Prerequisites

- **Snyk API token** — Service account (Enterprise) or personal token
- **Snyk Org ID** — Found in Snyk Org Settings → General
- **Jira Personal Access Token** — Generated in Jira profile → Personal Access Tokens
- **Security manager's Jira username**

### Configuration

```bash
cp .env.example .env
# Edit .env with your values
```

## API Usage

### Start the API

```bash
docker compose up
```

API runs on `http://localhost:8130`. Swagger docs at `http://localhost:8130/docs`.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/sync` | Trigger a sync run |
| `GET` | `/sync/history` | List past sync runs |
| `GET` | `/sync/{run_id}` | Get sync run details with actions |
| `GET` | `/projects` | List Snyk projects |
| `GET` | `/projects/{id}/issues` | Get issues with Jira links |

### Trigger a sync

```bash
# Dry run
curl -X POST http://localhost:8130/sync \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'

# Real run for specific repos
curl -X POST http://localhost:8130/sync \
  -H "Content-Type: application/json" \
  -d '{"repos": ["my-repo"]}'
```

## CLI Usage

```bash
# Dry run
python cli.py --dry-run

# Sync specific repos
python cli.py --repos my-repo,another-repo

# Via Docker
docker compose run --rm api python cli.py --dry-run
```

## Database Migrations

```bash
# Run migrations
alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "description"
```

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Cron Job

```bash
# Daily at 8am
0 8 * * * cd /path/to/snyk-jira-sync && docker compose run --rm api python cli.py >> /var/log/snyk-jira-sync.log 2>&1
```

## Architecture

```
app/
├── main.py              # FastAPI app
├── config.py            # Settings (pydantic-settings)
├── database.py          # SQLAlchemy session
├── models.py            # DB models (sync_runs, sync_actions)
├── schemas.py           # Pydantic request/response schemas
├── dependencies.py      # FastAPI dependency injection
├── clients/
│   ├── snyk.py          # Snyk REST + V1 API client
│   └── jira.py          # Jira Server/DC API client
├── services/
│   └── sync.py          # SyncService (core business logic)
└── routers/
    ├── health.py        # GET /health
    ├── sync.py          # POST /sync, GET /sync/history, GET /sync/{id}
    └── projects.py      # GET /projects, GET /projects/{id}/issues
```
