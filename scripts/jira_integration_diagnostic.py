#!/usr/bin/env python3
"""Test Snyk Jira integration and debug issues."""

import os

import requests

token = os.getenv("SNYK_TOKEN")
org_id = os.getenv("SNYK_ORG_ID")

if not token or not org_id:
    print("Error: SNYK_TOKEN and SNYK_ORG_ID env vars not set")
    raise SystemExit(1)

print("=" * 70)
print("SNYK JIRA INTEGRATION DIAGNOSTIC")
print("=" * 70)

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.api+json",
}

print("\n1. Finding tagged projects...")
url = f"https://api.snyk.io/rest/orgs/{org_id}/projects?version=2024-10-15&limit=10"
response = requests.get(url, headers=headers)

if response.status_code != 200:
    print(f"   Failed to fetch projects: {response.status_code}")
    print(f"   Response: {response.text[:200]}")
    raise SystemExit(1)

projects = response.json().get("data", [])
tagged_projects = [
    p
    for p in projects
    if "project-tag/" in p.get("attributes", {}).get("name", "").lower()
]

if not tagged_projects:
    print("   No tagged projects found")
    raise SystemExit(1)

project = tagged_projects[0]
project_id = project.get("id")
project_name = project.get("attributes", {}).get("name")

print(f"   Found tagged project: {project_name}")
print(f"      ID: {project_id}\n")

print("2. Testing Snyk V1 API: /v1/org/{org_id}/project/{project_id}/jira-issues")
v1_url = f"https://api.snyk.io/v1/org/{org_id}/project/{project_id}/jira-issues"

response = requests.get(v1_url, headers=headers)
print(f"   Status: {response.status_code}")

if response.status_code == 200:
    print("   Endpoint is working")
    data = response.json()
    print(f"   Found {len(data)} issue mappings")
    if data:
        sample_key = list(data.keys())[0]
        print(f"   Sample mapping: {sample_key} -> {data[sample_key]}")
elif response.status_code == 406:
    print("   406 Not Acceptable")
    print("   Jira integration is not configured in your Snyk organization")
    print("   To fix: Go to Snyk Organization Settings -> Integrations -> Add Jira")
elif response.status_code == 404:
    print("   404 Not Found")
    print("   The endpoint may not be available in this Snyk version")
else:
    print(f"   Unexpected status: {response.status_code}")

print(f"\n   Response (first 300 chars): {response.text[:300]}")

print("\n3. Checking organization integrations...")
orgs_url = f"https://api.snyk.io/rest/orgs/{org_id}?version=2024-10-15"
response = requests.get(orgs_url, headers=headers)

if response.status_code == 200:
    org_data = response.json().get("data", {})
    attrs = org_data.get("attributes", {})
    print(f"   Organization: {attrs.get('name')}")

    integrations = attrs.get("integrations", {})
    if integrations:
        print("   Has integrations:")
        for name, config in integrations.items():
            print(f"      - {name}: {bool(config)}")
    else:
        print("   No integrations found in organization attributes")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("\nIf you see 406 error:")
print("  - Jira integration is not configured in Snyk")
print("  - Go to: https://app.snyk.io/org/your-org/settings/integrations")
print("  - Add Jira integration")
print("  - Authorize and connect your Jira instance")
print("  - Test again")
print("\nIf you see 200 OK:")
print("  - Integration is configured and working")
print("  - Link Snyk issues to Jira tickets in the Snyk UI")
print("  - Run sync again to pull mappings")
