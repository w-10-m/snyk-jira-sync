"""Sync service: detects resolved Snyk vulnerabilities and updates linked Jira tickets."""

import logging

from app.clients.jira import JiraClient
from app.clients.snyk import SnykClient

logger = logging.getLogger(__name__)


class SyncService:
    """Orchestrates syncing Snyk vulnerability status to Jira tickets."""

    def __init__(self, snyk: SnykClient, jira: JiraClient):
        self.snyk = snyk
        self.jira = jira

    @staticmethod
    def build_issue_status_map(issues: list) -> dict:
        """Build a map of Snyk vulnerability ID -> status.

        Maps problem IDs (e.g. SNYK-JS-LODASH-123) to "open" or "resolved".
        """
        status_map = {}
        for issue in issues:
            attrs = issue.get("attributes", {})
            status = attrs.get("status", "open")
            for problem in attrs.get("problems", []):
                problem_id = problem.get("id")
                if problem_id:
                    status_map[problem_id] = status
        return status_map

    def process_project(
        self,
        org_id: str,
        project_id: str,
        project_name: str,
        security_manager: str,
        dry_run: bool,
    ) -> dict:
        """Process a single Snyk project: check issues and update Jira tickets.

        Returns a summary dict with counts.
        """
        stats = {"checked": 0, "resolved": 0, "updated": 0, "skipped": 0, "errors": 0}

        # Get Snyk -> Jira mapping
        jira_map = self.snyk.get_jira_issues(org_id, project_id)
        if not jira_map:
            logger.info("  No Jira tickets linked for project %s", project_name)
            return stats

        # Get current issue statuses
        issues = self.snyk.get_issues(org_id, project_id)
        status_map = self.build_issue_status_map(issues)

        for snyk_issue_id, jira_tickets in jira_map.items():
            if not isinstance(jira_tickets, list):
                continue

            stats["checked"] += len(jira_tickets)
            issue_status = status_map.get(snyk_issue_id)

            # If the Snyk issue ID isn't in the status map, it may have been
            # fully removed (dependency dropped). Treat as resolved.
            if issue_status is None:
                logger.info(
                    "  Snyk issue %s not found in current scan — treating as resolved",
                    snyk_issue_id,
                )
                issue_status = "resolved"

            if issue_status != "resolved":
                continue

            stats["resolved"] += 1

            for ticket in jira_tickets:
                jira_key = ticket.get("jiraIssue", {}).get("key")
                if not jira_key:
                    continue

                try:
                    jira_issue = self.jira.get_issue(jira_key)
                    current_status = (
                        jira_issue.get("fields", {})
                        .get("status", {})
                        .get("statusCategory", {})
                        .get("key", "")
                    )

                    if current_status == "done":
                        logger.info("  %s already closed — skipping", jira_key)
                        stats["skipped"] += 1
                        continue

                    current_status_name = (
                        jira_issue.get("fields", {})
                        .get("status", {})
                        .get("name", "?")
                    )
                    logger.info(
                        "  %s (status: %s) — Snyk issue %s is resolved",
                        jira_key,
                        current_status_name,
                        snyk_issue_id,
                    )

                    if dry_run:
                        logger.info(
                            "  [DRY RUN] Would transition and reassign %s", jira_key
                        )
                        stats["updated"] += 1
                        continue

                    # Transition to "In Progress"
                    transition_id = self.jira.find_transition_id(
                        jira_key, "In Progress"
                    )
                    if transition_id:
                        comment = (
                            f"[Snyk-Jira Sync] Vulnerability {snyk_issue_id} has been "
                            f"resolved in Snyk. Reassigning to security manager for closure."
                        )
                        self.jira.transition_issue(
                            jira_key, transition_id, comment=comment
                        )
                        logger.info("  %s transitioned to In Progress", jira_key)
                    else:
                        logger.warning(
                            "  %s — 'In Progress' transition not available from current status '%s'",
                            jira_key,
                            current_status_name,
                        )
                        # Still add a comment even if we can't transition
                        self.jira.add_comment(
                            jira_key,
                            f"[Snyk-Jira Sync] Vulnerability {snyk_issue_id} has been "
                            f"resolved in Snyk. Could not auto-transition — please review.",
                        )

                    # Reassign to security manager
                    self.jira.reassign_issue(jira_key, security_manager)
                    logger.info("  %s reassigned to %s", jira_key, security_manager)

                    stats["updated"] += 1

                except Exception:
                    logger.exception("  Error processing Jira ticket %s", jira_key)
                    stats["errors"] += 1

        return stats

    def run(
        self,
        org_id: str,
        security_manager: str,
        repo_filter: str | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Run the full sync across projects.

        Returns totals dict with counts.
        """
        if dry_run:
            logger.info("=== DRY RUN MODE — no changes will be made ===")

        # Get projects
        if repo_filter:
            projects = []
            for name in repo_filter.split(","):
                name = name.strip()
                if name:
                    logger.info("Fetching Snyk projects matching '%s'...", name)
                    projects.extend(
                        self.snyk.get_projects(org_id, name_filter=name)
                    )
        else:
            logger.info("Fetching all Snyk projects in org...")
            projects = self.snyk.get_projects(org_id)

        logger.info("Found %d project(s) to process", len(projects))

        totals = {
            "checked": 0,
            "resolved": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
        }

        for project in projects:
            project_id = project["id"]
            project_name = project.get("attributes", {}).get("name", project_id)
            logger.info("Processing: %s", project_name)

            stats = self.process_project(
                org_id=org_id,
                project_id=project_id,
                project_name=project_name,
                security_manager=security_manager,
                dry_run=dry_run,
            )

            for k in totals:
                totals[k] += stats[k]

        logger.info("=== Sync Complete ===")
        logger.info(
            "Jira tickets checked: %d | Snyk issues resolved: %d | "
            "Jira tickets updated: %d | Already closed: %d | Errors: %d",
            totals["checked"],
            totals["resolved"],
            totals["updated"],
            totals["skipped"],
            totals["errors"],
        )

        return totals
