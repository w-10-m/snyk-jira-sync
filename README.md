# Snyk-Jira Sync

Automatically detects when Snyk vulnerabilities have been resolved and updates the corresponding Jira tickets — transitions them to the configured review status and reassigns to the security manager for closure.

## Problem

Developers fix Snyk vulnerabilities (e.g., upgrade a dependency) but don't update the Jira tickets that Snyk auto-created. This leaves stale open tickets in Jira.

## How It Works

1. Fetches Snyk projects for your repo(s)
2. Fetches existing Jira tickets using JQL (default: `text ~ "SNYK-"`)
3. Extracts Snyk issue IDs from Jira ticket text (summary/description)
4. Checks each Snyk issue's current status (via Snyk REST API)
5. For resolved issues with open Jira tickets:
   - Transitions the Jira ticket to the configured review status (default: `In Review`)
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
curl -H "Authorization: token <TOKEN>" \
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

1. Log into your Jira instance (e.g., `https://jiraent.yourcompany.com`)
2. Click your **avatar** (top-right) → **Profile**
3. Go to **Personal Access Tokens** (left sidebar)
4. Click **"Create token"**
5. Name it (e.g., `snyk-jira-sync`), set an expiration if required by policy
6. Copy the token immediately — it won't be shown again

> The PAT user needs permissions to: view issues, transition issues, reassign issues, and add comments in the relevant Jira projects.

**Verify it works:**
```bash
curl -H "Authorization: Bearer YOUR_JIRA_PAT" \
  "https://jiraent.yourcompany.com/rest/api/2/myself"
```

### 4. Find the Security Manager's Jira Username

This is the Jira username (not display name) of the person who should close out resolved tickets. To find it:

1. Go to their Jira profile page
2. The username is in the URL: `https://jira.xyz.com/secure/ViewProfile.jspa?name=THE_USERNAME`

Or search via API:
```bash
curl -H "Authorization: Bearer YOUR_JIRA_PAT" \
  "https://jiraent.xyz.com/rest/api/2/user/search?username=smith"
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
JIRA_BASE_URL=https://jiraent.XYZ.com
JIRA_PAT=your_jira_pat_from_step_3
JIRA_SECURITY_MANAGER_USERNAME=the_username_from_step_4
JIRA_TARGET_STATUS=In Review

# Optional: narrow Snyk projects to only project-tag repos
SNYK_PROJECT_TAGS=project-tag/

# Optional: Jira query used to find Snyk-related tickets
JIRA_SNYK_JQL=text ~ "SNYK-"
```

### 6. Docker Quick Start

```bash
# Start the API and database
docker compose up -d

# Apply database migrations
docker compose exec api alembic upgrade head

# Verify the API is healthy
curl http://localhost:8130/health

# Run a full dry run
curl -X POST http://localhost:8130/sync \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'

# Run a targeted dry run for one Jira ticket
curl -X POST http://localhost:8130/sync/one \
  -H "Content-Type: application/json" \
  -d '{"jira_key":"HPT-1234","dry_run":true}'
```

Important:
- `docker compose up -d` by itself is not enough. You must run `docker compose exec api alembic upgrade head` before using the app.
- The API listens on `http://localhost:8130`.
- Swagger docs are at `http://localhost:8130/docs`.
- Sync reports are written to `.local/sync-reports/`.

After code changes:
```bash
# Rebuild and restart the API container
docker compose up -d --build api

# Re-run migrations if new Alembic migrations were added
docker compose exec api alembic upgrade head
```

## API Usage

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/sync` | Trigger a sync run |
| `POST` | `/sync/one` | Trigger a sync run for exactly one Jira ticket |
| `GET` | `/sync/history` | List past sync runs |
| `GET` | `/sync/{run_id}` | Get sync run details with actions |
| `GET` | `/projects` | List Snyk projects |
| `GET` | `/projects/{id}/issues` | Get issues with Jira links |

### Full Sync

```bash
# Dry run
curl -X POST http://localhost:8130/sync \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'

# Live run for specific repos
curl -X POST http://localhost:8130/sync \
  -H "Content-Type: application/json" \
  -d '{"repos": ["my-repo"]}'
```

### Targeted Sync For One Jira Ticket

```bash
# Dry run for one ticket
curl -X POST http://localhost:8130/sync/one \
  -H "Content-Type: application/json" \
  -d '{"jira_key":"HPT-1234","dry_run":true}'

# Live run for one ticket
curl -X POST http://localhost:8130/sync/one \
  -H "Content-Type: application/json" \
  -d '{"jira_key":"HPT-1234","dry_run":false}'
```

### Interpreting Dry-Run Results

The sync records actions at the `project + Snyk issue + Jira ticket` level.
Because one codebase can exist as multiple Snyk projects, the same Jira key may
appear more than once in a dry-run or sync report.

Common examples:
- a repo-level project such as `hpt/ace-api(master)`
- a manifest-specific project such as `hpt/ace-api(master):package.json`
- a container project such as `hpt/document-rendering-svc(master):Dockerfile`

If the same Jira ticket matches more than one of those Snyk projects, the report
will contain multiple `updated` actions for that Jira key. This is expected and
does not mean the database duplicated a row by mistake.

The sync also skips tickets in these cases:
- Jira is already in a `done` status category
- Jira is already in the configured target status and already assigned to `JIRA_SECURITY_MANAGER_USERNAME`

The full `/sync` path includes a guard against multi-project false positives:
- if the same `jira_key + Snyk issue ID` is still open in any matched Snyk project, the bulk run will not treat it as resolved from another sibling project that no longer reports it
- this keeps full-sync behavior aligned with `POST /sync/one` for ambiguous multi-project cases

### Inspecting Run Results

```bash
# List recent runs
curl http://localhost:8130/sync/history

# Get one run with full actions
curl http://localhost:8130/sync/<run_id>
```

Each run response includes:
- `total_checked`
- `total_resolved`
- `total_updated`
- `total_skipped`
- `total_errors`
- `actions[]` with `project_name`, `jira_key`, `snyk_issue_id`, `action`, and `detail`

Reports are also written locally as JSON files:
- `.local/sync-reports/sync-<run_id>.json`

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
# Run migrations locally
alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "description"

# Run migrations in Docker
docker compose exec api alembic upgrade head
```

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v

# Or in Docker
docker compose exec -T api pytest -q
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
