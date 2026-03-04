#!/usr/bin/env python3
"""Cortex initial setup: create org, users, and API key for TheHive integration."""
import requests
import json
import sys
import os

# Auto-detect: use the directory where this script lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CORTEX_URL = "http://localhost:9001"
ADMIN_LOGIN = "admin@codesec.in"
ADMIN_PASS = "SocCortex@2025"

print("=== Cortex Initial Setup ===\n")

# Step 1: Login
print("1. Logging in as superadmin...")
session = requests.Session()

# First get a page to obtain CSRF token
resp = session.get(f"{CORTEX_URL}/")
csrf_token = session.cookies.get("CORTEX-XSRF-TOKEN", "")
if not csrf_token:
    # Try alternative cookie names
    for name, value in session.cookies.items():
        if "csrf" in name.lower() or "xsrf" in name.lower():
            csrf_token = value
            break
print(f"   CSRF token: {csrf_token[:20]}..." if csrf_token else "   No CSRF token found")
print(f"   Cookies: {dict(session.cookies)}")

# Set CSRF headers - Cortex uses CORTEX-XSRF-TOKEN cookie name
if csrf_token:
    session.headers.update({
        "X-CORTEX-XSRF-TOKEN": csrf_token,
        "X-XSRF-TOKEN": csrf_token,
        "CORTEX-XSRF-TOKEN": csrf_token
    })

resp = session.post(f"{CORTEX_URL}/api/login", json={"user": ADMIN_LOGIN, "password": ADMIN_PASS})
if resp.status_code != 200:
    print(f"   ERROR: Login failed: {resp.status_code} {resp.text}")
    sys.exit(1)
print(f"   OK: Logged in as {resp.json().get('name', 'unknown')}")

# Grab any new CSRF token after login
for name, value in session.cookies.items():
    if "csrf" in name.lower() or "xsrf" in name.lower():
        csrf_token = value
        session.headers.update({
            "X-CORTEX-XSRF-TOKEN": csrf_token,
            "X-XSRF-TOKEN": csrf_token,
            "CORTEX-XSRF-TOKEN": csrf_token
        })
        break

# Step 2: Create organization
print("\n2. Creating organization 'codesec'...")
resp = session.post(f"{CORTEX_URL}/api/organization", json={
    "name": "codesec",
    "description": "CodeSec SOC Organization",
    "status": "Active"
})
if resp.status_code == 201:
    print(f"   OK: Organization created - {resp.json().get('name')}")
elif resp.status_code == 400 and "already exists" in resp.text.lower():
    print("   OK: Organization already exists")
else:
    print(f"   WARN: {resp.status_code} {resp.text[:200]}")

# Step 3: Create org admin user
print("\n3. Creating organization admin user...")
resp = session.post(f"{CORTEX_URL}/api/user", json={
    "login": "orgadmin@codesec.in",
    "name": "Org Admin",
    "roles": ["read", "analyze", "orgadmin"],
    "organization": "codesec",
    "password": ADMIN_PASS
})
if resp.status_code == 201:
    print(f"   OK: Org admin created - {resp.json().get('id')}")
elif resp.status_code == 400 and "already exists" in resp.text.lower():
    print("   OK: Org admin already exists")
else:
    print(f"   WARN: {resp.status_code} {resp.text[:200]}")

# Step 4: Generate API key for org admin (needed for TheHive-Cortex integration)
print("\n4. Generating API key for org admin...")
resp = session.post(f"{CORTEX_URL}/api/user/orgadmin@codesec.in/key/renew")
if resp.status_code == 200:
    api_key = resp.text.strip().strip('"')
    print(f"   OK: API Key = {api_key}")

    # Save API key for TheHive integration
    key_path = os.path.join(BASE_DIR, ".cortex-api-key")
    with open(key_path, "w") as f:
        f.write(api_key)
    print(f"   Saved to {key_path}")
else:
    print(f"   WARN: {resp.status_code} {resp.text[:200]}")

print("\n=== Cortex Setup Complete ===")
print(f"\nLogin URL:  https://cortex.codesec.in")
print(f"SuperAdmin: {ADMIN_LOGIN} / {ADMIN_PASS}")
print(f"Org Admin:  orgadmin@codesec.in / {ADMIN_PASS}")
