#!/usr/bin/env python3
"""CLI entry point for Snyk-Jira Sync."""

import argparse
import logging
import sys

from dotenv import load_dotenv

from app.clients.jira import JiraClient
from app.clients.snyk import SnykClient
from app.config import Settings
from app.services.sync import SyncService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Sync Snyk vulnerability status to Jira tickets"
    )
    parser.add_argument(
        "--repos",
        type=str,
        default=None,
        help="Comma-separated repo names to filter (overrides SNYK_REPO_NAMES env var)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log actions without making changes",
    )
    args = parser.parse_args()

    load_dotenv()

    try:
        settings = Settings()
    except Exception as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)

    dry_run = args.dry_run or settings.dry_run
    repo_filter = args.repos or settings.snyk_repo_names

    snyk = SnykClient(settings.snyk_token, settings.snyk_base_url)
    jira = JiraClient(settings.jira_base_url, settings.jira_pat)
    service = SyncService(snyk=snyk, jira=jira)

    service.run(
        org_id=settings.snyk_org_id,
        security_manager=settings.jira_security_manager_username,
        target_status=settings.jira_target_status,
        repo_filter=repo_filter,
        project_tags=settings.snyk_project_tags,
        jira_jql=settings.jira_snyk_jql,
        dry_run=dry_run,
    )


if __name__ == "__main__":
    main()
