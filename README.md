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

### 1. Get a Snyk API Token

**Option A: Personal token (quick start)**
1. Log into [app.snyk.io](https://app.snyk.io)
2. Click your **avatar** (bottom-left) → **Account Settings**
3. Under **General** → **Auth Token**, click **"click to show"**
4. Copy the token

**Option B: Service account (recommended for automation)**
1. Go to **Snyk Org Settings** → **Service Accounts**
2. Click **"Create a service account"**
3. Name it (e.g., `jira-sync-bot`), select role **Org Viewer** (read-only is sufficient)
4. Copy the generated token

> Note: API access requires a paid Snyk plan. Service accounts require Enterprise.

**Verify it works:**
```bash
curl -H "Authorization: token YOUR_SNYK_TOKEN" \
  "https://api.snyk.io/rest/orgs?version=2024-10-15"
```

### 2. Get your Snyk Org ID

1. Log into [app.snyk.io](https://app.snyk.io)
2. Go to **Org Settings** → **General**
3. The **Organization ID** is displayed on this page (a UUID like `a1b2c3d4-...`)

Alternatively, use the token from step 1:
```bash
curl -H "Authorization: token YOUR_SNYK_TOKEN" \
  "https://api.snyk.io/rest/orgs?version=2024-10-15" | python3 -m json.tool
```
Look for your org's `id` field in the response.

### 3. Get a Jira Personal Access Token (PAT)

This is for **Jira Server / Data Center** (not Jira Cloud):

1. Log into your Jira instance (e.g., `https://jiraent.yourcompany.gov`)
2. Click your **avatar** (top-right) → **Profile**
3. Go to **Personal Access Tokens** (left sidebar)
4. Click **"Create token"**
5. Name it (e.g., `snyk-jira-sync`), set an expiration if required by policy
6. Copy the token immediately — it won't be shown again

> The PAT user needs permissions to: view issues, transition issues, reassign issues, and add comments in the relevant Jira projects.

**Verify it works:**
```bash
curl -H "Authorization: Bearer YOUR_JIRA_PAT" \
  "https://jiraent.yourcompany.gov/rest/api/2/myself"
```

### 4. Find the Security Manager's Jira Username

This is the Jira username (not display name) of the person who should close out resolved tickets. To find it:

1. Go to their Jira profile page
2. The username is in the URL: `https://jira.example.gov/secure/ViewProfile.jspa?name=THE_USERNAME`

Or search via API:
```bash
curl -H "Authorization: Bearer YOUR_JIRA_PAT" \
  "https://jiraent.yourcompany.gov/rest/api/2/user/search?username=smith"
```
Look for the `name` field in the response.

### 5. Configure

```bash
cp .env.example .env
```

Edit `.env` with the values you collected:

```bash
SNYK_TOKEN=your_snyk_token_from_step_1
SNYK_ORG_ID=your_org_id_from_step_2
JIRA_BASE_URL=https://jiraent.yourcompany.gov
JIRA_PAT=your_jira_pat_from_step_3
JIRA_SECURITY_MANAGER_USERNAME=the_username_from_step_4
```

### 6. Start

```bash
# Start the API + database
docker compose up -d

# Run database migrations
docker compose exec api alembic upgrade head

# Test with a dry run (no changes made)
curl -X POST http://localhost:8130/sync \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'
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
