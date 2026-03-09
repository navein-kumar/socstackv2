#!/usr/bin/env python3
"""
SOC Stack (IP-SSL) - Credentials & Login Test
================================================
Tests all service logins with credentials from .env.deployed
Run AFTER post-deploy.py completes.

Usage:
  python3 /any/folder/test-creds.py   (works from any deployment folder)
  cd /any/folder && python3 test-creds.py
"""
import requests
import json
import os
import sys
import subprocess
import re

requests.packages.urllib3.disable_warnings()

# Auto-detect: use script directory (works regardless of deploy folder name)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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


# ── Load .env then overlay .env.deployed (merge both) ──────
# .env has config params (SERVER_IP, ports, org names)
# .env.deployed has generated secrets (API keys, client secret)
ENV_FILE = os.path.join(BASE_DIR, ".env")
creds = {}
for ef in [ENV_FILE, DEPLOYED_FILE]:
    if os.path.exists(ef):
        with open(ef) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    creds[k.strip()] = v.strip()

if not os.path.exists(DEPLOYED_FILE):
    print(f"{RED}ERROR:{NC} {DEPLOYED_FILE} not found. Run post-deploy.py first.")
    sys.exit(1)

SERVER_IP    = creds.get("SERVER_IP",    "127.0.0.1")
WAZUH_PORT   = creds.get("WAZUH_PORT",   "8443")
SSO_PORT     = creds.get("SSO_PORT",     "8444")
N8N_PORT     = creds.get("N8N_PORT",     "8445")
MISP_PORT    = creds.get("MISP_PORT",    "8446")
THEHIVE_PORT = creds.get("THEHIVE_PORT", "8447")
CORTEX_PORT  = creds.get("CORTEX_PORT",  "8448")

print("=" * 60)
print("  SOC STACK (IP-SSL) - Credentials & Login Test")
print(f"  Server: {SERVER_IP}")
print("=" * 60)

# ════════════════════════════════════════════════════════════
# 1. Keycloak Admin Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 1. Keycloak ─────────────────────────────────────{NC}")
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
        r2 = requests.get(f"http://localhost:8081/admin/realms/{creds.get('KC_WAZUH_REALM', 'SOC')}", headers=kc_h, timeout=10)
        if r2.status_code == 200:
            ok(f"Keycloak realm '{creds.get('KC_WAZUH_REALM')}' exists")
        else:
            fail(f"Keycloak realm '{creds.get('KC_WAZUH_REALM')}' not found")

        # Check OIDC client exists
        r3 = requests.get(f"http://localhost:8081/admin/realms/{creds.get('KC_WAZUH_REALM', 'SOC')}/clients?clientId={creds.get('KC_WAZUH_CLIENT_ID', 'soc-sso')}", headers=kc_h, timeout=10)
        if r3.status_code == 200 and r3.json():
            ok(f"Keycloak client '{creds.get('KC_WAZUH_CLIENT_ID')}' exists")
        else:
            fail(f"Keycloak client '{creds.get('KC_WAZUH_CLIENT_ID')}' not found")
    else:
        fail(f"Keycloak admin login failed: {r.status_code}")
except Exception as e:
    fail(f"Keycloak unreachable: {e}")

# ════════════════════════════════════════════════════════════
# 2. Keycloak SSO Users Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 2. Keycloak SSO Users ───────────────────────────{NC}")
sso_users = [
    ("SSO_ADMIN_EMAIL",   "SSO_ADMIN_PASSWORD",   "SSO Admin"),
    # post-deploy.py saves analyst as SSO_ANALYST_EMAIL; fall back to SSO_USER_EMAIL from .env
    ("SSO_ANALYST_EMAIL", "SSO_ANALYST_PASSWORD", "SSO Analyst"),
]
for email_key, pass_key, label in sso_users:
    email = creds.get(email_key, "")
    passwd = creds.get(pass_key, "")
    if not email or not passwd:
        warn(f"{label}: credentials not in .env.deployed")
        continue
    try:
        r = requests.post(f"http://localhost:8081/realms/{creds.get('KC_WAZUH_REALM', 'SOC')}/protocol/openid-connect/token", data={
            "grant_type": "password",
            "client_id": creds.get("KC_WAZUH_CLIENT_ID", "soc-sso"),
            "client_secret": creds.get("KC_WAZUH_CLIENT_SECRET", "") or creds.get("SSO_CLIENT_SECRET", ""),
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
# 3. Wazuh Indexer (OpenSearch) Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 3. Wazuh Indexer ────────────────────────────────{NC}")
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
# 4. Wazuh Dashboard (reachable + SSO redirect)
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 4. Wazuh Dashboard ─────────────────────────────{NC}")
try:
    r = requests.get("https://localhost:5601/", verify=False, timeout=10, allow_redirects=False)
    if r.status_code in (200, 302):
        ok(f"Wazuh Dashboard reachable (HTTP {r.status_code})")
    else:
        fail(f"Wazuh Dashboard: HTTP {r.status_code}")
except Exception as e:
    fail(f"Wazuh Dashboard unreachable: {e}")

# SSO redirect test (redirect should contain SERVER_IP:SSO_PORT)
try:
    r = requests.get("https://localhost:5601/auth/openid/login", verify=False, timeout=10, allow_redirects=False)
    if r.status_code == 302:
        loc = r.headers.get("Location", "")
        if "soc-sso" in loc and (SSO_PORT in loc or SERVER_IP in loc):
            ok(f"SSO redirect → Keycloak at {SERVER_IP}:{SSO_PORT} (client_id=soc-sso)")
        else:
            fail(f"SSO redirect missing IP:PORT ({SERVER_IP}:{SSO_PORT}): {loc[:100]}")
    else:
        fail(f"SSO redirect: expected 302, got {r.status_code}")
except Exception as e:
    fail(f"SSO redirect test: {e}")

# ════════════════════════════════════════════════════════════
# 5. Wazuh Manager API
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 5. Wazuh Manager API ────────────────────────────{NC}")
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
# 6. n8n Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 6. n8n ─────────────────────────────────────────{NC}")
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
# 7. MISP Login + API Key (via direct container port 18443)
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 7. MISP ─────────────────────────────────────────{NC}")
misp_key = creds.get("MISP_API_KEY", "")
try:
    r = requests.get("https://localhost:18443/servers/getVersion",
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
    login_page = s.get("https://localhost:18443/users/login", timeout=10)
    csrf_match = re.search(r'name="_csrfToken"\s+value="([^"]+)"', login_page.text)
    if csrf_match:
        csrf = csrf_match.group(1)
        r = s.post("https://localhost:18443/users/login", data={
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
# 8. TheHive Login
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 8. TheHive ──────────────────────────────────────{NC}")
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
# 9. Cortex Login + API Key
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 9. Cortex ──────────────────────────────────────{NC}")
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
# 10. Wazuh n8n Integration Check
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 10. Wazuh n8n Integration ───────────────────────{NC}")
try:
    result = subprocess.run(
        ["docker", "exec", "socstack-wazuh-manager", "ls", "-la",
         "/var/ossec/integrations/custom-n8n", "/var/ossec/integrations/custom-n8n.py"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0 and "custom-n8n" in result.stdout:
        ok("custom-n8n integration scripts mounted")
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
# 11. IP:PORT SSL Verification (nginx self-signed cert)
# ════════════════════════════════════════════════════════════
print(f"\n{CYAN}── 11. IP:PORT SSL Verification ────────────────────{NC}")
print(f"  Checking nginx self-signed SSL on {SERVER_IP} ...")
ssl_ports = {
    "Wazuh Dashboard": WAZUH_PORT,
    "Keycloak SSO":    SSO_PORT,
    "n8n":             N8N_PORT,
    "MISP":            MISP_PORT,
    "TheHive":         THEHIVE_PORT,
    "Cortex":          CORTEX_PORT,
}
for name, port in ssl_ports.items():
    url = f"https://{SERVER_IP}:{port}/"
    try:
        r = requests.get(url, timeout=10, verify=False, allow_redirects=False)
        ok(f"{name}: https://{SERVER_IP}:{port}/ → HTTP {r.status_code} (self-signed SSL)")
    except requests.exceptions.ConnectionError:
        fail(f"{name}: https://{SERVER_IP}:{port}/ → connection refused")
    except requests.exceptions.SSLError as e:
        fail(f"{name}: https://{SERVER_IP}:{port}/ → SSL error: {e}")
    except Exception as e:
        warn(f"{name}: https://{SERVER_IP}:{port}/ → {e}")

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
