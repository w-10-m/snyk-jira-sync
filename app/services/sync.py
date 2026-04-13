"""Sync service: detects resolved Snyk vulnerabilities and updates linked Jira tickets."""

import logging
import re

from app.clients.jira import JiraClient
from app.clients.snyk import SnykClient

logger = logging.getLogger(__name__)


class SyncSelectionError(Exception):
    """Raised when a targeted sync request cannot be resolved safely."""

    def __init__(self, detail: str, status_code: int):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class SyncService:
    """Orchestrates syncing Snyk vulnerability status to Jira tickets."""

    def __init__(self, snyk: SnykClient, jira: JiraClient):
        self.snyk = snyk
        self.jira = jira

    SNYK_ID_PATTERN = re.compile(r"\bSNYK-[A-Z0-9-]+-\d+\b", re.IGNORECASE)

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

    @staticmethod
    def _extract_text_from_description(description: object) -> str:
        """Best-effort extraction of text from Jira description payloads."""
        if isinstance(description, str):
            return description
        if not isinstance(description, dict):
            return ""

        chunks = []

        def walk(node: object) -> None:
            if not isinstance(node, dict):
                return
            text = node.get("text")
            if isinstance(text, str):
                chunks.append(text)
            for child in node.get("content", []):
                walk(child)

        walk(description)
        return " ".join(chunks)

    @classmethod
    def extract_snyk_ids(cls, text: str) -> set[str]:
        """Extract Snyk issue IDs from arbitrary Jira text."""
        return {match.upper() for match in cls.SNYK_ID_PATTERN.findall(text or "")}

    @staticmethod
    def _project_aliases(project_name: str) -> set[str]:
        """Generate loose project aliases to match Jira ticket text."""
        aliases = {project_name.strip().lower()}
        before_branch = project_name.split("(", 1)[0].strip().lower()
        before_target = project_name.split(":", 1)[0].strip().lower()
        if before_branch:
            aliases.add(before_branch)
        if before_target:
            aliases.add(before_target)
        return {a for a in aliases if a}

    def build_project_jira_map(self, project_name: str, jira_issues: list[dict]) -> dict:
        """Build map of Snyk issue ID -> Jira tickets for one Snyk project."""
        aliases = self._project_aliases(project_name)
        jira_map = {}

        for issue in jira_issues:
            key = issue.get("key")
            fields = issue.get("fields", {})
            summary = fields.get("summary") or ""
            description = self._extract_text_from_description(fields.get("description"))
            searchable_text = f"{summary} {description}".strip()
            searchable_text_lc = searchable_text.lower()

            if aliases and not any(alias in searchable_text_lc for alias in aliases):
                continue

            snyk_ids = self.extract_snyk_ids(searchable_text)
            if not key or not snyk_ids:
                continue

            for snyk_issue_id in snyk_ids:
                jira_map.setdefault(snyk_issue_id, []).append(
                    {"jiraIssue": {"key": key}}
                )

        return jira_map

    @staticmethod
    def _empty_totals() -> dict:
        return {
            "checked": 0,
            "resolved": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "ticket_actions": [],
        }

    @staticmethod
    def _add_stats(totals: dict, stats: dict) -> None:
        for key in ("checked", "resolved", "updated", "skipped", "errors"):
            totals[key] += stats[key]
        totals["ticket_actions"].extend(stats.get("ticket_actions", []))

    def _get_projects_for_scope(
        self,
        org_id: str,
        repo_filter: str | None = None,
        project_tags: str | None = None,
    ) -> list[dict]:
        if repo_filter:
            projects = []
            for name in repo_filter.split(","):
                name = name.strip()
                if name:
                    logger.info("Fetching Snyk projects matching '%s'...", name)
                    projects.extend(self.snyk.get_projects(org_id, name_filter=name))
            return projects

        if project_tags:
            filters = [f.strip() for f in project_tags.split(",") if f.strip()]
            logger.info("Fetching Snyk projects with tags/prefixes: %s...", filters)

            all_matching_projects = []
            for filter_str in filters:
                prefix_projects = self.snyk.get_projects_by_name_prefix(org_id, filter_str)
                if prefix_projects:
                    all_matching_projects.extend(prefix_projects)
                    logger.info(
                        "  Found %d projects with prefix '%s'",
                        len(prefix_projects),
                        filter_str,
                    )
                else:
                    tag_projects = self.snyk.get_projects_by_tags(org_id, [filter_str])
                    if tag_projects:
                        all_matching_projects.extend(tag_projects)
                        logger.info(
                            "  Found %d projects with tag '%s'",
                            len(tag_projects),
                            filter_str,
                        )

            seen = set()
            projects = []
            for project in all_matching_projects:
                project_id = project.get("id")
                if project_id not in seen:
                    seen.add(project_id)
                    projects.append(project)
            return projects

        logger.info("Fetching all Snyk projects in org...")
        return self.snyk.get_projects(org_id)

    def process_project(
        self,
        org_id: str,
        project_id: str,
        project_name: str,
        security_manager: str,
        target_status: str,
        dry_run: bool,
        jira_issues: list[dict] | None = None,
        status_map: dict | None = None,
        jira_map: dict | None = None,
        globally_open_pairs: set[tuple[str, str]] | None = None,
    ) -> dict:
        """Process a single Snyk project: check issues and update Jira tickets.

        Returns a summary dict with counts.
        """
        stats = self._empty_totals()

        # Get current issue statuses from Snyk for this project
        if status_map is None:
            issues = self.snyk.get_issues(org_id, project_id)
            status_map = self.build_issue_status_map(issues)

        # Build Jira map from Jira tickets directly (skip Snyk jira-issues integration endpoint)
        if jira_map is None:
            if jira_issues is None:
                jira_issues = self.jira.search_issues(jql='text ~ "SNYK-"')
            if not isinstance(jira_issues, list):
                jira_issues = []
            jira_map = self.build_project_jira_map(project_name, jira_issues)
        if not jira_map:
            logger.info("  No Jira tickets linked for project %s", project_name)
            return stats

        for snyk_issue_id, jira_tickets in jira_map.items():
            if not isinstance(jira_tickets, list):
                continue

            stats["checked"] += len(jira_tickets)
            for ticket in jira_tickets:
                jira_key = ticket.get("jiraIssue", {}).get("key")
                if jira_key:
                    stats["ticket_actions"].append(
                        {
                            "project_name": project_name,
                            "snyk_issue_id": snyk_issue_id,
                            "jira_key": jira_key,
                            "action": "checked",
                            "detail": "Ticket considered during sync run",
                        }
                    )
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

            if globally_open_pairs:
                blocking_keys = [
                    ticket.get("jiraIssue", {}).get("key")
                    for ticket in jira_tickets
                    if (ticket.get("jiraIssue", {}).get("key"), snyk_issue_id)
                    in globally_open_pairs
                ]
                blocking_keys = [key for key in blocking_keys if key]
                if blocking_keys:
                    logger.info(
                        "  Snyk issue %s still open in another matched project for %s — skipping resolved handling",
                        snyk_issue_id,
                        ", ".join(blocking_keys),
                    )
                    continue

            stats["resolved"] += 1

            for ticket in jira_tickets:
                jira_key = ticket.get("jiraIssue", {}).get("key")
                if not jira_key:
                    continue

                try:
                    jira_issue = self.jira.get_issue(jira_key)
                    fields = jira_issue.get("fields", {})
                    assignee = fields.get("assignee") or {}
                    current_status = (
                        fields
                        .get("status", {})
                        .get("statusCategory", {})
                        .get("key", "")
                    )
                    current_status_name = (
                        fields
                        .get("status", {})
                        .get("name", "?")
                    )
                    current_assignee = assignee.get("name", "")

                    if current_status == "done":
                        logger.info("  %s already closed — skipping", jira_key)
                        stats["skipped"] += 1
                        stats["ticket_actions"].append(
                            {
                                "project_name": project_name,
                                "snyk_issue_id": snyk_issue_id,
                                "jira_key": jira_key,
                                "action": "skipped",
                                "detail": "Already closed in Jira",
                            }
                        )
                        continue

                    if (
                        current_status_name == target_status
                        and current_assignee == security_manager
                    ):
                        logger.info(
                            "  %s already in %s and assigned to %s — skipping",
                            jira_key,
                            target_status,
                            security_manager,
                        )
                        stats["skipped"] += 1
                        stats["ticket_actions"].append(
                            {
                                "project_name": project_name,
                                "snyk_issue_id": snyk_issue_id,
                                "jira_key": jira_key,
                                "action": "skipped",
                                "detail": (
                                    "Already in target status and assigned to "
                                    "security manager"
                                ),
                            }
                        )
                        continue

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
                        stats["ticket_actions"].append(
                            {
                                "project_name": project_name,
                                "snyk_issue_id": snyk_issue_id,
                                "jira_key": jira_key,
                                "action": "updated",
                                "detail": "Dry run: would transition and reassign",
                            }
                        )
                        continue

                    # Transition to the configured review status.
                    transition_id = self.jira.find_transition_id(
                        jira_key, target_status
                    )
                    if transition_id:
                        comment = (
                            f"[Snyk-Jira Sync] Vulnerability {snyk_issue_id} has been "
                            f"resolved in Snyk. Reassigning to security manager for closure."
                        )
                        self.jira.transition_issue(
                            jira_key, transition_id, comment=comment
                        )
                        logger.info("  %s transitioned to %s", jira_key, target_status)
                    else:
                        logger.warning(
                            "  %s — '%s' transition not available from current status '%s'",
                            jira_key,
                            target_status,
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
                    stats["ticket_actions"].append(
                        {
                            "project_name": project_name,
                            "snyk_issue_id": snyk_issue_id,
                            "jira_key": jira_key,
                            "action": "updated",
                            "detail": "Transitioned/reassigned",
                        }
                    )

                except Exception:
                    logger.exception("  Error processing Jira ticket %s", jira_key)
                    stats["errors"] += 1
                    stats["ticket_actions"].append(
                        {
                            "project_name": project_name,
                            "snyk_issue_id": snyk_issue_id,
                            "jira_key": jira_key,
                            "action": "errored",
                            "detail": "Error while processing Jira ticket",
                        }
                    )

        return stats

    def _build_project_context(
        self, org_id: str, project: dict, jira_issues: list[dict]
    ) -> dict:
        project_id = project["id"]
        project_name = project.get("attributes", {}).get("name", project_id)
        issues = self.snyk.get_issues(org_id, project_id)
        status_map = self.build_issue_status_map(issues)
        jira_map = self.build_project_jira_map(project_name, jira_issues)
        return {
            "project_id": project_id,
            "project_name": project_name,
            "status_map": status_map,
            "jira_map": jira_map,
        }

    @staticmethod
    def _collect_globally_open_pairs(project_contexts: list[dict]) -> set[tuple[str, str]]:
        open_pairs = set()
        for context in project_contexts:
            status_map = context.get("status_map", {})
            jira_map = context.get("jira_map", {})
            for snyk_issue_id, jira_tickets in jira_map.items():
                issue_status = status_map.get(snyk_issue_id)
                if issue_status in (None, "resolved"):
                    continue
                for ticket in jira_tickets:
                    jira_key = ticket.get("jiraIssue", {}).get("key")
                    if jira_key:
                        open_pairs.add((jira_key, snyk_issue_id))
        return open_pairs

    def run_one(
        self,
        org_id: str,
        jira_key: str,
        security_manager: str,
        target_status: str,
        repo_filter: str | None = None,
        project_tags: str | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Run the sync for exactly one Jira ticket."""
        if dry_run:
            logger.info("=== DRY RUN MODE — no changes will be made ===")

        jira_issue = self.jira.get_issue(jira_key)
        fields = jira_issue.get("fields", {})
        summary = fields.get("summary") or ""
        description = self._extract_text_from_description(fields.get("description"))
        searchable_text = f"{summary} {description}".strip()
        snyk_ids = self.extract_snyk_ids(searchable_text)

        if not snyk_ids:
            raise SyncSelectionError(
                f"Jira issue {jira_key} does not reference any SNYK issue IDs",
                status_code=400,
            )

        projects = self._get_projects_for_scope(
            org_id=org_id,
            repo_filter=repo_filter,
            project_tags=project_tags,
        )

        matching_projects = []
        matching_status_projects = []
        for project in projects:
            project_id = project["id"]
            project_name = project.get("attributes", {}).get("name", project_id)
            jira_map = self.build_project_jira_map(project_name, [jira_issue])
            if not any(snyk_id in jira_map for snyk_id in snyk_ids):
                continue

            matching_projects.append(project)
            issues = self.snyk.get_issues(org_id, project_id)
            status_map = self.build_issue_status_map(issues)
            if any(snyk_id in status_map for snyk_id in snyk_ids):
                matching_status_projects.append(project)

        candidates = matching_status_projects or matching_projects
        if not candidates:
            raise SyncSelectionError(
                f"Could not match Jira issue {jira_key} to a Snyk project",
                status_code=404,
            )
        if len(candidates) > 1:
            project_names = ", ".join(
                p.get("attributes", {}).get("name", p["id"]) for p in candidates
            )
            raise SyncSelectionError(
                f"Jira issue {jira_key} matched multiple Snyk projects: {project_names}",
                status_code=409,
            )

        project = candidates[0]
        project_id = project["id"]
        project_name = project.get("attributes", {}).get("name", project_id)
        logger.info("Processing single Jira issue %s against project %s", jira_key, project_name)
        return self.process_project(
            org_id=org_id,
            project_id=project_id,
            project_name=project_name,
            security_manager=security_manager,
            target_status=target_status,
            dry_run=dry_run,
            jira_issues=[jira_issue],
        )

    def run(
        self,
        org_id: str,
        security_manager: str,
        target_status: str,
        repo_filter: str | None = None,
        project_tags: str | None = None,
        jira_jql: str = 'text ~ "SNYK-"',
        dry_run: bool = False,
    ) -> dict:
        """Run the full sync across projects.

        Args:
            org_id: Snyk organization ID
            security_manager: Jira username for security manager
            repo_filter: Comma-separated project names to filter by
            project_tags: Comma-separated tags/prefixes to filter projects by.
                         Can be tag keys or name prefixes (e.g., "xyz/" for projects starting with "xyz/")
            jira_jql: Jira JQL used to discover existing Snyk-related Jira tickets
            dry_run: If True, no changes are made to Jira

        Returns:
            totals dict with counts.
        """
        if dry_run:
            logger.info("=== DRY RUN MODE — no changes will be made ===")

        projects = self._get_projects_for_scope(
            org_id=org_id,
            repo_filter=repo_filter,
            project_tags=project_tags,
        )

        logger.info("Found %d project(s) to process", len(projects))

        logger.info("Fetching Jira issues with JQL: %s", jira_jql)
        jira_issues = self.jira.search_issues(jql=jira_jql)
        logger.info("Found %d Jira ticket(s) matching Snyk query", len(jira_issues))

        project_contexts = [
            self._build_project_context(org_id, project, jira_issues)
            for project in projects
        ]
        globally_open_pairs = self._collect_globally_open_pairs(project_contexts)

        totals = self._empty_totals()

        for context in project_contexts:
            project_id = context["project_id"]
            project_name = context["project_name"]
            logger.info("Processing: %s", project_name)

            stats = self.process_project(
                org_id=org_id,
                project_id=project_id,
                project_name=project_name,
                security_manager=security_manager,
                target_status=target_status,
                dry_run=dry_run,
                jira_issues=jira_issues,
                status_map=context["status_map"],
                jira_map=context["jira_map"],
                globally_open_pairs=globally_open_pairs,
            )

            self._add_stats(totals, stats)

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
