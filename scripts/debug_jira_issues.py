#!/usr/bin/env python3
"""Debug the Snyk API jira-issues endpoint."""

import os

import requests

token = os.getenv("SNYK_TOKEN")
org_id = os.getenv("SNYK_ORG_ID")

if not token or not org_id:
    print("Error: SNYK_TOKEN and SNYK_ORG_ID env vars not set")
    raise SystemExit(1)

headers_rest = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.api+json",
}

url = f"https://api.snyk.io/rest/orgs/{org_id}/projects?version=2024-10-15&limit=1"
response = requests.get(url, headers=headers_rest)
data = response.json()
projects = data.get("data", [])

if not projects:
    print("No projects found")
    raise SystemExit(1)

project = projects[0]
project_id = project.get("id")
project_name = project.get("attributes", {}).get("name")

print(f"Testing with project: {project_name}")
print(f"Project ID: {project_id}\n")

print("=" * 60)
print("Testing V1 API: /org/{org_id}/project/{project_id}/jira-issues")
print("=" * 60)

v1_url = f"https://api.snyk.io/v1/org/{org_id}/project/{project_id}/jira-issues"

print("\n1. Testing with Accept: application/vnd.api+json")
response = requests.get(v1_url, headers=headers_rest)
print(f"   Status: {response.status_code}")
print(f"   Headers: {dict(response.headers)}")
if response.status_code != 200:
    print(f"   Error: {response.text[:200]}")

print("\n2. Testing with Accept: application/json")
headers_json = {"Authorization": f"token {token}", "Accept": "application/json"}
response = requests.get(v1_url, headers=headers_json)
print(f"   Status: {response.status_code}")
if response.status_code != 200:
    print(f"   Error: {response.text[:200]}")

print("\n3. Testing with no Accept header")
headers_no_accept = {"Authorization": f"token {token}"}
response = requests.get(v1_url, headers=headers_no_accept)
print(f"   Status: {response.status_code}")
if response.status_code != 200:
    print(f"   Error: {response.text[:200]}")

print("\n" + "=" * 60)
print("Testing REST API alternatives for issue data")
print("=" * 60)

print("\n1. GET /orgs/{org_id}/issues (all issues)")
rest_url = (
    "https://api.snyk.io/rest/orgs/"
    f"{org_id}/issues?version=2024-10-15&scan_item.id={project_id}"
    "&scan_item.type=project&limit=10"
)
response = requests.get(rest_url, headers=headers_rest)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    issues = response.json().get("data", [])
    print(f"   Found {len(issues)} issues")
    if issues:
        issue = issues[0]
        print(f"   Sample issue ID: {issue.get('id')}")
        print(
            "   Sample issue attributes keys: "
            f"{list(issue.get('attributes', {}).keys())}"
        )
else:
    print(f"   Error: {response.text[:200]}")

print("\n2. GET /orgs/{org_id}/projects/{project_id} (project details)")
project_detail_url = (
    f"https://api.snyk.io/rest/orgs/{org_id}/projects/{project_id}"
    "?version=2024-10-15"
)
response = requests.get(project_detail_url, headers=headers_rest)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    proj = response.json().get("data", {})
    attrs = proj.get("attributes", {})
    print(f"   Project attributes keys: {list(attrs.keys())}")
    for key in attrs.keys():
        if "jira" in key.lower() or "integration" in key.lower():
            print(f"   Found JIRA-related key: {key}")
else:
    print(f"   Error: {response.text[:200]}")

print("\n" + "=" * 60)
print("Summary: The 406 error suggests the V1 jira-issues endpoint")
print("may not be available in your Snyk instance. Consider using")
print("the REST issues API instead.")
print("=" * 60)
