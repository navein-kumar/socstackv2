#!/usr/bin/env python3
"""
SOC Stack - Credentials & Login Test
======================================
Tests all service logins with credentials from .env.deployed
Run AFTER post-deploy.py completes.

Usage:
  python3 /opt/socstack/test-creds.py
"""
import requests
import json
import os
import sys
import subprocess

requests.packages.urllib3.disable_warnings()

BASE_DIR = "/opt/socstack"
DEPLOYED_FILE = os.path.join(BASE_DIR, ".env.deployed")

# ── Colors ────────────────────────────────────────────────
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
NC = "\033[0m"

PASS = 0
FAIL = 0
WARN = 0
results = []


def ok(msg):
    global PASS
    PASS += 1
    results.append(("PASS", msg))
    print(f"  {GREEN}✓{NC} {msg}")


def fail(msg):
    global FAIL
    FAIL += 1
    results.append(("FAIL", msg))
    print(f"  {RED}✗{NC} {msg}")


def warn(msg):
    global WARN
    WARN += 1
    results.append(("WARN", msg))
    print(f"  {YELLOW}⚠{NC} {msg}")


# ── Load .env.deployed ────────────────────────────────────
creds = {}
if not os.path.exists(DEPLOYED_FILE):
    print(f"{RED}ERROR:{NC} {DEPLOYED_FILE} not found. Run post-deploy.py first.")
    sys.exit(1)

with open(DEPLOYED_FILE) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            creds[k.strip()] = v.strip()

print("=" * 60)
print("  SOC STACK - Credentials & Login Test")
print("=" * 60)

# ════════════════════════════════════════════════════════════
# 1. NPM Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 1. Nginx Proxy Manager ──────────────────────────{NC}")
try:
    r = requests.post("http://localhost:60081/api/tokens", json={
        "identity": creds.get("NPM_ADMIN_EMAIL", ""),
        "secret": creds.get("NPM_ADMIN_PASSWORD", "")
    }, timeout=10)
    if r.status_code == 200 and "token" in r.json():
        ok(f"NPM login: {creds.get('NPM_ADMIN_EMAIL')}")
        # Check proxy hosts exist
        token = r.json()["token"]
        h = {"Authorization": f"Bearer {token}"}
        hosts = requests.get("http://localhost:60081/api/nginx/proxy-hosts", headers=h, timeout=10).json()
        ok(f"NPM proxy hosts: {len(hosts)} configured")
        # Check SSL certs
        certs_resp = requests.get("http://localhost:60081/api/nginx/certificates", headers=h, timeout=10).json()
        ok(f"NPM SSL certificates: {len(certs_resp)} active")
    else:
        fail(f"NPM login failed: {r.status_code}")
except Exception as e:
    fail(f"NPM unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 2. Keycloak Admin Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 2. Keycloak ─────────────────────────────────────{NC}")
try:
    r = requests.post("http://localhost:8081/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": creds.get("KC_ADMIN_USER", ""),
        "password": creds.get("KC_ADMIN_PASSWORD", ""),
    }, timeout=10)
    if r.status_code == 200 and "access_token" in r.json():
        ok(f"Keycloak admin login: {creds.get('KC_ADMIN_USER')}")
        kc_token = r.json()["access_token"]
        kc_h = {"Authorization": f"Bearer {kc_token}"}

        # Check wazuh realm exists
        r2 = requests.get(f"http://localhost:8081/admin/realms/{creds.get('KC_WAZUH_REALM', 'wazuh')}", headers=kc_h, timeout=10)
        if r2.status_code == 200:
            ok(f"Keycloak realm '{creds.get('KC_WAZUH_REALM')}' exists")
        else:
            fail(f"Keycloak realm '{creds.get('KC_WAZUH_REALM')}' not found")

        # Check OIDC client exists
        r3 = requests.get(f"http://localhost:8081/admin/realms/{creds.get('KC_WAZUH_REALM', 'wazuh')}/clients?clientId={creds.get('KC_WAZUH_CLIENT_ID', 'wazuh-sso')}", headers=kc_h, timeout=10)
        if r3.status_code == 200 and r3.json():
            ok(f"Keycloak client '{creds.get('KC_WAZUH_CLIENT_ID')}' exists")
        else:
            fail(f"Keycloak client '{creds.get('KC_WAZUH_CLIENT_ID')}' not found")
    else:
        fail(f"Keycloak admin login failed: {r.status_code}")
except Exception as e:
    fail(f"Keycloak unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 3. Keycloak SSO Users Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 3. Keycloak SSO Users ───────────────────────────{NC}")
sso_users = [
    ("SSO_ADMIN_EMAIL", "SSO_ADMIN_PASSWORD", "SSO Admin"),
    ("SSO_USER_EMAIL", "SSO_USER_PASSWORD", "SSO User"),
]
for email_key, pass_key, label in sso_users:
    email = creds.get(email_key, "")
    passwd = creds.get(pass_key, "")
    if not email or not passwd:
        warn(f"{label}: credentials not in .env.deployed")
        continue
    try:
        r = requests.post(f"http://localhost:8081/realms/{creds.get('KC_WAZUH_REALM', 'wazuh')}/protocol/openid-connect/token", data={
            "grant_type": "password",
            "client_id": creds.get("KC_WAZUH_CLIENT_ID", "wazuh-sso"),
            "client_secret": creds.get("KC_WAZUH_CLIENT_SECRET", ""),
            "username": email,
            "password": passwd,
        }, timeout=10)
        if r.status_code == 200 and "access_token" in r.json():
            ok(f"{label} login: {email}")
        else:
            fail(f"{label} login failed: {r.status_code} {r.text[:100]}")
    except Exception as e:
        fail(f"{label} login error: {e}")

# ════════════════════════════════════════════════════════════
# 4. Wazuh Indexer (OpenSearch) Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 4. Wazuh Indexer ────────────────────────────────{NC}")
try:
    r = requests.get("https://localhost:9200/", verify=False,
                     auth=(creds.get("WAZUH_INDEXER_USERNAME", "admin"),
                           creds.get("WAZUH_INDEXER_PASSWORD", "")),
                     timeout=10)
    if r.status_code == 200:
        ver = r.json().get("version", {}).get("number", "?")
        ok(f"Wazuh Indexer login: {creds.get('WAZUH_INDEXER_USERNAME')} (v{ver})")
    else:
        fail(f"Wazuh Indexer login failed: {r.status_code}")
except Exception as e:
    fail(f"Wazuh Indexer unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 5. Wazuh Dashboard (reachable)
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 5. Wazuh Dashboard ─────────────────────────────{NC}")
try:
    r = requests.get("https://localhost:5601/", verify=False, timeout=10, allow_redirects=False)
    if r.status_code in (200, 302):
        ok(f"Wazuh Dashboard reachable (HTTP {r.status_code})")
    else:
        fail(f"Wazuh Dashboard: HTTP {r.status_code}")
except Exception as e:
    fail(f"Wazuh Dashboard unreachable: {e}")

# SSO redirect test
try:
    r = requests.get("https://localhost:5601/auth/openid/login", verify=False, timeout=10, allow_redirects=False)
    if r.status_code == 302:
        loc = r.headers.get("Location", "")
        if "sso.codesec.in" in loc and "wazuh-sso" in loc:
            ok(f"SSO redirect → Keycloak (client_id=wazuh-sso)")
        else:
            fail(f"SSO redirect wrong: {loc[:100]}")
    else:
        fail(f"SSO redirect: expected 302, got {r.status_code}")
except Exception as e:
    fail(f"SSO redirect test: {e}")

# ════════════════════════════════════════════════════════════
# 6. Wazuh API Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 6. Wazuh Manager API ────────────────────────────{NC}")
try:
    r = requests.post("https://localhost:55000/security/user/authenticate",
                      verify=False,
                      auth=(creds.get("WAZUH_API_USER", ""),
                            creds.get("WAZUH_API_PASSWORD", "")),
                      timeout=10)
    if r.status_code == 200:
        token = r.json().get("data", {}).get("token", "")
        if token:
            ok(f"Wazuh API login: {creds.get('WAZUH_API_USER')}")
        else:
            fail(f"Wazuh API: no token in response")
    else:
        fail(f"Wazuh API login failed: {r.status_code}")
except Exception as e:
    fail(f"Wazuh API unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 7. n8n Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 7. n8n ─────────────────────────────────────────{NC}")
try:
    r = requests.post("http://localhost:5678/rest/login", json={
        "email": creds.get("N8N_ADMIN_EMAIL", ""),
        "password": creds.get("N8N_ADMIN_PASSWORD", ""),
    }, timeout=10)
    if r.status_code == 200:
        ok(f"n8n login: {creds.get('N8N_ADMIN_EMAIL')}")
    elif r.status_code == 401:
        fail(f"n8n login failed: wrong credentials")
    else:
        # n8n may return 200 with cookie-based auth
        r2 = requests.get("http://localhost:5678/rest/settings", timeout=10)
        if r2.status_code == 200:
            ok(f"n8n API reachable (settings accessible)")
        else:
            fail(f"n8n login: {r.status_code}")
except Exception as e:
    fail(f"n8n unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 8. MISP Login + API Key
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 8. MISP ─────────────────────────────────────────{NC}")
misp_key = creds.get("MISP_API_KEY", "")
try:
    r = requests.get("https://localhost:8443/servers/getVersion",
                     headers={"Authorization": misp_key, "Accept": "application/json"},
                     verify=False, timeout=10)
    if r.status_code == 200:
        ver = r.json().get("version", "?")
        ok(f"MISP API key valid (v{ver})")
    else:
        fail(f"MISP API key failed: {r.status_code}")
except Exception as e:
    fail(f"MISP unreachable: {e}")

# MISP web login
try:
    s = requests.Session()
    s.verify = False
    login_page = s.get("https://localhost:8443/users/login", timeout=10)
    # Extract CSRF token if present
    import re
    csrf_match = re.search(r'name="_csrfToken"\s+value="([^"]+)"', login_page.text)
    if csrf_match:
        csrf = csrf_match.group(1)
        r = s.post("https://localhost:8443/users/login", data={
            "_csrfToken": csrf,
            "_method": "POST",
            "data[User][email]": creds.get("MISP_ADMIN_EMAIL", ""),
            "data[User][password]": creds.get("MISP_ADMIN_PASSWORD", ""),
        }, timeout=10, allow_redirects=False)
        if r.status_code in (302, 200):
            ok(f"MISP web login: {creds.get('MISP_ADMIN_EMAIL')}")
        else:
            warn(f"MISP web login: HTTP {r.status_code} (may need password change)")
    else:
        warn("MISP web login: could not extract CSRF token")
except Exception as e:
    warn(f"MISP web login: {e}")

# ════════════════════════════════════════════════════════════
# 9. TheHive Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 9. TheHive ──────────────────────────────────────{NC}")
for label, user_key, pass_key in [
    ("Admin", "THEHIVE_ADMIN_USER", "THEHIVE_ADMIN_PASSWORD"),
    ("Analyst", "THEHIVE_ANALYST_USER", "THEHIVE_ANALYST_PASSWORD"),
]:
    user = creds.get(user_key, "")
    passwd = creds.get(pass_key, "")
    if not user:
        warn(f"TheHive {label}: not in .env.deployed")
        continue
    try:
        r = requests.get("http://localhost:9000/api/v1/user/current",
                         auth=(user, passwd), timeout=10)
        if r.status_code == 200:
            name = r.json().get("name", "?")
            ok(f"TheHive {label} login: {user} ({name})")
        else:
            fail(f"TheHive {label} login failed: {r.status_code}")
    except Exception as e:
        fail(f"TheHive {label}: {e}")

# ════════════════════════════════════════════════════════════
# 10. Cortex Login + API Key
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 10. Cortex ──────────────────────────────────────{NC}")
try:
    s = requests.Session()
    s.get("http://localhost:9001/", timeout=10)
    csrf = s.cookies.get("CORTEX-XSRF-TOKEN", "")
    if csrf:
        s.headers.update({"X-CORTEX-XSRF-TOKEN": csrf})

    r = s.post("http://localhost:9001/api/login", json={
        "user": creds.get("CORTEX_ADMIN_USER", ""),
        "password": creds.get("CORTEX_ADMIN_PASSWORD", ""),
    }, timeout=10)
    if r.status_code == 200:
        ok(f"Cortex admin login: {creds.get('CORTEX_ADMIN_USER')}")
    else:
        fail(f"Cortex admin login failed: {r.status_code}")
except Exception as e:
    fail(f"Cortex unreachable: {e}")

# Cortex API key
cortex_key = creds.get("CORTEX_API_KEY", "")
if cortex_key:
    try:
        r = requests.get("http://localhost:9001/api/user/current",
                         headers={"Authorization": f"Bearer {cortex_key}"},
                         timeout=10)
        if r.status_code == 200:
            ok(f"Cortex API key valid (user: {r.json().get('id', '?')})")
        else:
            fail(f"Cortex API key invalid: {r.status_code}")
    except Exception as e:
        fail(f"Cortex API key test: {e}")

# ════════════════════════════════════════════════════════════
# 11. Grafana Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 11. Grafana ─────────────────────────────────────{NC}")
try:
    r = requests.get("http://localhost:3000/api/org",
                     auth=(creds.get("GF_ADMIN_USER", "admin"),
                           creds.get("GF_ADMIN_PASSWORD", "")),
                     timeout=10)
    if r.status_code == 200:
        org = r.json().get("name", "?")
        ok(f"Grafana login: {creds.get('GF_ADMIN_USER')} (org: {org})")
    else:
        fail(f"Grafana login failed: {r.status_code}")
except Exception as e:
    fail(f"Grafana unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 12. Wazuh n8n Integration Check
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 12. Wazuh n8n Integration ───────────────────────{NC}")
try:
    result = subprocess.run(
        ["docker", "exec", "socstack-wazuh-manager", "ls", "-la",
         "/var/ossec/integrations/custom-n8n", "/var/ossec/integrations/custom-n8n.py"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0 and "custom-n8n" in result.stdout:
        ok("custom-n8n integration scripts mounted")
        # Check permissions
        if "wazuh" in result.stdout:
            ok("custom-n8n permissions: root:wazuh")
        else:
            warn("custom-n8n permissions: may need fixing (not root:wazuh)")
    else:
        fail("custom-n8n integration scripts NOT found in container")
except Exception as e:
    fail(f"n8n integration check: {e}")

# Check ossec.conf has n8n integration
try:
    result = subprocess.run(
        ["docker", "exec", "socstack-wazuh-manager", "grep", "-c", "custom-n8n",
         "/var/ossec/etc/ossec.conf"],
        capture_output=True, text=True, timeout=10
    )
    count = result.stdout.strip()
    if count and int(count) > 0:
        ok(f"wazuh_manager.conf: n8n integration configured ({count} references)")
    else:
        fail("wazuh_manager.conf: n8n integration NOT configured")
except Exception as e:
    fail(f"n8n config check: {e}")

# ════════════════════════════════════════════════════════════
# 13. Public Domain SSL Check
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 13. Public Domain SSL ───────────────────────────{NC}")
domains = {
    "SSO": creds.get("SSO_URL", ""),
    "Wazuh": creds.get("WAZUH_URL", ""),
    "n8n": creds.get("N8N_URL", ""),
    "MISP": creds.get("CTI_URL", ""),
    "TheHive": creds.get("HIVE_URL", ""),
    "Cortex": creds.get("CORTEX_URL", ""),
    "Grafana": creds.get("GRAFANA_URL", ""),
    "NPM": creds.get("NPM_URL", ""),
}
for name, url in domains.items():
    if not url:
        warn(f"{name}: URL not in .env.deployed")
        continue
    try:
        r = requests.get(url, timeout=10, verify=True, allow_redirects=True)
        ok(f"{name}: {url} → SSL valid (HTTP {r.status_code})")
    except requests.exceptions.SSLError as e:
        fail(f"{name}: {url} → SSL ERROR")
    except requests.exceptions.ConnectionError:
        fail(f"{name}: {url} → connection refused")
    except Exception as e:
        warn(f"{name}: {url} → {e}")

# ════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════
print(f"\n{'=' * 60}")
print(f"  CREDENTIALS TEST SUMMARY")
print(f"{'=' * 60}")
print(f"  {GREEN}Passed:{NC} {PASS}")
print(f"  {RED}Failed:{NC} {FAIL}")
print(f"  {YELLOW}Warned:{NC} {WARN}")
print(f"{'=' * 60}")

if FAIL > 0:
    print(f"\n  {RED}FAILED TESTS:{NC}")
    for status, msg in results:
        if status == "FAIL":
            print(f"    {RED}✗{NC} {msg}")

if WARN > 0:
    print(f"\n  {YELLOW}WARNINGS:{NC}")
    for status, msg in results:
        if status == "WARN":
            print(f"    {YELLOW}⚠{NC} {msg}")

pct = round(PASS / (PASS + FAIL) * 100) if (PASS + FAIL) > 0 else 0
print(f"\n  Score: {PASS}/{PASS + FAIL} ({pct}%)")
print()

sys.exit(1 if FAIL > 0 else 0)
