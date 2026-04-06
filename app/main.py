import logging

from fastapi import FastAPI

from app.routers import health, sync, projects

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

app = FastAPI(
    title="Snyk-Jira Sync API",
    description="Syncs resolved Snyk vulnerabilities to Jira tickets",
    version="1.0.0",
)

app.include_router(health.router)
app.include_router(sync.router)
app.include_router(projects.router)
