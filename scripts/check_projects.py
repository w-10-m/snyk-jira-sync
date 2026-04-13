#!/usr/bin/env python3
"""Check Snyk projects and their tags."""

import os

import requests

token = os.getenv("SNYK_TOKEN")
org_id = os.getenv("SNYK_ORG_ID")

if not token or not org_id:
    print("Error: SNYK_TOKEN and SNYK_ORG_ID env vars not set")
    raise SystemExit(1)

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.api+json",
}

# Fetch all projects with pagination.
all_projects = []
url = f"https://api.snyk.io/rest/orgs/{org_id}/projects?version=2024-10-15&limit=100"

while url:
    response = requests.get(url, headers=headers)
    data = response.json()
    projects = data.get("data", [])
    all_projects.extend(projects)

    url = data.get("links", {}).get("next")
    if url and not url.startswith("http"):
        url = f"https://api.snyk.io{url}"

print(f"Found {len(all_projects)} total projects:\n")

for i, project in enumerate(all_projects, 1):
    name = project.get("attributes", {}).get("name", "N/A")
    tags = project.get("attributes", {}).get("tags", [])
    tag_keys = [tag.get("key") for tag in tags]

    print(f"{i}. {name}")
    if tag_keys:
        print(f"   Tags: {tag_keys}")
    else:
        print("   Tags: (none)")

print("\n" + "=" * 60)
print("Summary by tag:")
print("=" * 60)

tag_counts = {}
for project in all_projects:
    tags = project.get("attributes", {}).get("tags", [])
    for tag in tags:
        key = tag.get("key")
        if key:
            tag_counts[key] = tag_counts.get(key, 0) + 1

if tag_counts:
    for tag, count in sorted(tag_counts.items()):
        print(f"  {tag}: {count} project(s)")
else:
    print("  No projects have tags")
