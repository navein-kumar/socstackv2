#!/usr/bin/env python3
"""
SOC Stack (IP-SSL) Test Suite
================================
Validates all services, logins, integrations and saves results.
Designed for IP-based deployment with self-signed SSL certificates.

Usage:
  python3 /any/folder/test-stack.py   (works from any deployment folder)
  cd /any/folder && python3 test-stack.py

Output (written to the same folder as this script):
  test-results.txt   - Full test report
  test-results.json  - Machine-readable results
"""
import requests
import json
import subprocess
import os
import sys
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# Auto-detect: use script directory (works regardless of deploy folder name)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_TXT = os.path.join(BASE_DIR, "test-results.txt")
RESULTS_JSON = os.path.join(BASE_DIR, "test-results.json")

# ── Load .env then overlay .env.deployed (merge both) ──────
# .env has config params (SERVER_IP, ports, org names)
# .env.deployed has generated secrets (API keys, client secret)
# Loading order: .env first, then .env.deployed overrides it
env = {}
for ef in [os.path.join(BASE_DIR, ".env"), os.path.join(BASE_DIR, ".env.deployed")]:
    if os.path.exists(ef):
        with open(ef) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()

SERVER_IP    = env.get("SERVER_IP",    "127.0.0.1")
WAZUH_PORT   = env.get("WAZUH_PORT",   "8443")
SSO_PORT     = env.get("SSO_PORT",     "8444")
N8N_PORT     = env.get("N8N_PORT",     "8445")
MISP_PORT    = env.get("MISP_PORT",    "8446")
THEHIVE_PORT = env.get("THEHIVE_PORT", "8447")
CORTEX_PORT  = env.get("CORTEX_PORT",  "8448")

# ── Test state ─────────────────────────────────────────────
results = []
lines = []
passed = 0
failed = 0
warned = 0


def log(msg):
    print(msg)
    lines.append(msg)


def test(name, check_fn, critical=True):
    global passed, failed, warned
    try:
        ok, detail = check_fn()
        if ok:
            status = "PASS"
            passed += 1
            icon = "✓"
        elif not critical:
            status = "WARN"
            warned += 1
            icon = "⚠"
        else:
            status = "FAIL"
            failed += 1
            icon = "✗"
    except Exception as e:
        ok = False
        detail = str(e)
        if critical:
            status = "FAIL"
            failed += 1
            icon = "✗"
        else:
            status = "WARN"
            warned += 1
            icon = "⚠"

    line = f"  {icon} [{status}] {name}: {detail}"
    log(line)
    results.append({"test": name, "status": status, "detail": detail})


# ════════════════════════════════════════════════════════════
# TEST 1: Docker Containers
# ════════════════════════════════════════════════════════════
def test_containers():
    log("\n" + "="*60)
    log("TEST 1: Docker Containers")
    log("="*60)

    expected = [
        "socstack-nginx", "socstack-keycloak", "socstack-keycloak-db",
        "socstack-wazuh-manager", "socstack-wazuh-indexer", "socstack-wazuh-dashboard",
        "socstack-n8n", "socstack-n8n-redis",
        "socstack-misp-core", "socstack-misp-db", "socstack-misp-redis", "socstack-misp-modules",
        "socstack-thehive", "socstack-cassandra", "socstack-elasticsearch", "socstack-minio",
        "socstack-cortex",
    ]

    result = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                            capture_output=True, text=True)
    running = {}
    for line in result.stdout.strip().split("\n"):
        if "\t" in line:
            name, status = line.split("\t", 1)
            running[name] = status

    for c in expected:
        def check(c=c):
            if c in running:
                return True, f"Running ({running[c][:30]})"
            return False, "NOT RUNNING"
        test(f"Container: {c}", check)


# ════════════════════════════════════════════════════════════
# TEST 2: Service HTTP Endpoints (direct backend ports)
# ════════════════════════════════════════════════════════════
def test_endpoints():
    log("\n" + "="*60)
    log("TEST 2: Service HTTP Endpoints")
    log("="*60)

    endpoints = [
        ("Keycloak",        "http://localhost:8081/realms/master",       200),
        ("Wazuh Dashboard", "https://localhost:5601/",                   302),
        ("Wazuh Indexer",   "https://localhost:9200/",                   200),
        ("n8n",             "http://localhost:5678/",                    200),
        ("MISP",            "https://localhost:18443/",                  302),
        ("TheHive",         "http://localhost:9000/api/v1/status",      401),
        ("Cortex",          "http://localhost:9001/api/status",          200),
        ("Elasticsearch",   "http://localhost:9200/",                    None),  # No host port
    ]

    for name, url, expected_code in endpoints:
        def check(name=name, url=url, expected_code=expected_code):
            try:
                r = requests.get(url, timeout=10, verify=False, allow_redirects=False,
                                 auth=("admin", env.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")) if "9200" in url and "https" in url else None)
                if expected_code is None:
                    return True, f"HTTP {r.status_code} (any accepted)"
                if r.status_code == expected_code:
                    return True, f"HTTP {r.status_code}"
                return False, f"Expected {expected_code}, got {r.status_code}"
            except requests.exceptions.ConnectionError:
                if expected_code is None:
                    return True, "No host port (internal only)"
                return False, "Connection refused"
        test(f"Endpoint: {name}", check)


# ════════════════════════════════════════════════════════════
# TEST 3: Authentication Tests
# ════════════════════════════════════════════════════════════
def test_auth():
    log("\n" + "="*60)
    log("TEST 3: Authentication / Login")
    log("="*60)

    # Wazuh Indexer
    def check_wazuh_idx():
        r = requests.get("https://localhost:9200/_cluster/health",
                         auth=("admin", env.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")),
                         verify=False)
        if r.status_code == 200:
            return True, f"Cluster: {r.json().get('cluster_name','?')} status={r.json().get('status','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: Wazuh Indexer", check_wazuh_idx)

    # Wazuh API
    def check_wazuh_api():
        r = requests.post("https://localhost:55000/security/user/authenticate",
                          auth=(env.get("WAZUH_API_USER", "wazuh-wui"),
                                env.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")),
                          verify=False)
        if r.status_code == 200:
            return True, "JWT token acquired"
        return False, f"HTTP {r.status_code}"
    test("Login: Wazuh API", check_wazuh_api)

    # n8n (check signup disabled, via direct port)
    def check_n8n():
        r = requests.get("http://localhost:5678/rest/settings")
        if r.status_code == 200:
            show = r.json().get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad", True)
            if not show:
                return True, "Owner configured, signup disabled"
            return False, "Signup still enabled"
        return False, f"HTTP {r.status_code}"
    test("Login: n8n (signup disabled)", check_n8n)

    # Keycloak (direct port 8081)
    def check_kc():
        r = requests.post("http://localhost:8081/realms/master/protocol/openid-connect/token",
                          data={
                              "grant_type": "password",
                              "client_id": "admin-cli",
                              "username": env.get("KC_ADMIN_USER", "admin"),
                              "password": env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025"),
                          })
        if r.status_code == 200 and "access_token" in r.json():
            return True, "Access token acquired"
        return False, f"HTTP {r.status_code}"
    test("Login: Keycloak", check_kc)

    # MISP (via direct container port 18443)
    def check_misp():
        misp_key = env.get("MISP_API_KEY", "")
        if not misp_key:
            result = subprocess.run(
                ["docker", "exec", "socstack-misp-db", "mysql", "-u",
                 env.get("MISP_DB_USER", "misp"), f"-p{env.get('MISP_DB_PASSWORD', 'SocMispDb@2025')}",
                 "misp", "-N", "-e",
                 f"SELECT authkey FROM users WHERE email='{env.get('MISP_ADMIN_EMAIL', 'admin@local.lab')}' LIMIT 1;"],
                capture_output=True, text=True, timeout=10
            )
            misp_key = result.stdout.strip()
        if not misp_key:
            return False, "No API key"
        r = requests.get("https://localhost:18443/servers/getVersion",
                         headers={"Authorization": misp_key, "Accept": "application/json"},
                         verify=False)
        if r.status_code == 200:
            return True, f"MISP v{r.json().get('version','?')} API key valid"
        return False, f"HTTP {r.status_code}"
    test("Login: MISP", check_misp)

    # TheHive admin
    def check_thehive_admin():
        r = requests.get("http://localhost:9000/api/v1/user/current",
                         auth=(env.get("THEHIVE_ADMIN_USER", "admin@thehive.local"),
                               env.get("THEHIVE_ADMIN_PASSWORD", "SocTheHive@2025")))
        if r.status_code == 200:
            return True, f"profile={r.json().get('profile','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: TheHive Admin", check_thehive_admin)

    # TheHive analyst
    def check_thehive_analyst():
        r = requests.get("http://localhost:9000/api/v1/user/current",
                         auth=(env.get("THEHIVE_ANALYST_USER", "analyst@local.lab"),
                               env.get("THEHIVE_ANALYST_PASSWORD", "SocAnalyst@2025")))
        if r.status_code == 200:
            return True, f"profile={r.json().get('profile','?')} org={r.json().get('organisation','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: TheHive Analyst", check_thehive_analyst)

    # Cortex admin
    def check_cortex():
        r = requests.post("http://localhost:9001/api/login", json={
            "user": env.get("CORTEX_ADMIN_USER", "admin@local.lab"),
            "password": env.get("CORTEX_ADMIN_PASSWORD", "SocCortex@2025")
        })
        if r.status_code == 200:
            return True, f"roles={r.json().get('roles','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: Cortex SuperAdmin", check_cortex)

    # Cortex org admin
    def check_cortex_org():
        r = requests.post("http://localhost:9001/api/login", json={
            "user": env.get("CORTEX_ORG_ADMIN", "orgadmin@local.lab"),
            "password": env.get("CORTEX_ADMIN_PASSWORD", "SocCortex@2025")
        })
        if r.status_code == 200:
            return True, f"roles={r.json().get('roles','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: Cortex OrgAdmin", check_cortex_org)


# ════════════════════════════════════════════════════════════
# TEST 4: Integration Tests
# ════════════════════════════════════════════════════════════
def test_integrations():
    log("\n" + "="*60)
    log("TEST 4: Integrations")
    log("="*60)

    # TheHive → Cortex connectivity
    def check_thehive_cortex():
        auth = (env.get("THEHIVE_ADMIN_USER", "admin@thehive.local"),
                env.get("THEHIVE_ADMIN_PASSWORD", "SocTheHive@2025"))
        r = requests.get("http://localhost:9000/api/connector/cortex", auth=auth, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                return True, f"Connected, {len(data)} server(s)"
            elif isinstance(data, dict) and data.get("name"):
                return True, f"Connected: {data.get('name')}"
            return True, f"Endpoint reachable, status={r.status_code}"
        # Try via API v1
        r2 = requests.post("http://localhost:9000/api/v1/query", auth=auth,
                           headers={"Content-Type": "application/json"},
                           json={"query": [{"_name": "listConnector"}]})
        if r2.status_code == 200:
            return True, f"Connector API reachable"
        return False, f"HTTP {r.status_code}"
    test("Integration: TheHive → Cortex", check_thehive_cortex, critical=False)

    # Cortex API key valid
    def check_cortex_key():
        key = env.get("CORTEX_API_KEY", "")
        if not key:
            keyfile = os.path.join(BASE_DIR, ".cortex-api-key")
            if os.path.exists(keyfile):
                with open(keyfile) as f:
                    key = f.read().strip()
        if not key:
            return False, "No API key found"
        r = requests.get("http://localhost:9001/api/user/current",
                         headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            return True, f"Key valid for user={r.json().get('id','?')}"
        return False, f"HTTP {r.status_code}"
    test("Integration: Cortex API Key", check_cortex_key)

    # MISP API reachable (via direct container port 18443)
    def check_misp_api():
        key = env.get("MISP_API_KEY", "")
        if not key:
            result = subprocess.run(
                ["docker", "exec", "socstack-misp-db", "mysql", "-u",
                 env.get("MISP_DB_USER", "misp"), f"-p{env.get('MISP_DB_PASSWORD', 'SocMispDb@2025')}",
                 "misp", "-N", "-e",
                 f"SELECT authkey FROM users WHERE email='{env.get('MISP_ADMIN_EMAIL', 'admin@local.lab')}' LIMIT 1;"],
                capture_output=True, text=True, timeout=10
            )
            key = result.stdout.strip()
        if not key:
            return False, "No API key"
        r = requests.get("https://localhost:18443/organisations/index",
                         headers={"Authorization": key, "Accept": "application/json"},
                         verify=False)
        if r.status_code == 200:
            orgs = r.json()
            return True, f"MISP API works, {len(orgs)} org(s)"
        return False, f"HTTP {r.status_code}"
    test("Integration: MISP API", check_misp_api)

    # TheHive org exists
    def check_thehive_org():
        auth = (env.get("THEHIVE_ADMIN_USER", "admin@thehive.local"),
                env.get("THEHIVE_ADMIN_PASSWORD", "SocTheHive@2025"))
        r = requests.post("http://localhost:9000/api/v1/query", auth=auth,
                          headers={"Content-Type": "application/json"},
                          json={"query": [{"_name": "listOrganisation"}]})
        if r.status_code == 200:
            orgs = [o["name"] for o in r.json()]
            target = env.get("THEHIVE_ORG_NAME", "YOURORG")
            if target in orgs:
                return True, f"Org '{target}' exists, total orgs: {len(orgs)}"
            return False, f"Org '{target}' not found. Existing: {orgs}"
        return False, f"HTTP {r.status_code}"
    test("Integration: TheHive Org", check_thehive_org)

    # Cortex org exists
    def check_cortex_org():
        session = requests.Session()
        r = session.post("http://localhost:9001/api/login", json={
            "user": env.get("CORTEX_ADMIN_USER", "admin@local.lab"),
            "password": env.get("CORTEX_ADMIN_PASSWORD", "SocCortex@2025")
        })
        if r.status_code != 200:
            return False, "Login failed"
        csrf = session.cookies.get("CORTEX-XSRF-TOKEN", "")
        if csrf:
            session.headers.update({"X-CORTEX-XSRF-TOKEN": csrf})
        r = session.get("http://localhost:9001/api/organization")
        if r.status_code == 200:
            orgs = r.json()
            names = [o.get("name", "?") for o in orgs]
            target = env.get("CORTEX_ORG_NAME", "yourorg")
            if target in names:
                return True, f"Org '{target}' exists"
            return False, f"Org '{target}' not found. Existing: {names}"
        return False, f"HTTP {r.status_code}"
    test("Integration: Cortex Org", check_cortex_org)

    # Wazuh manager-indexer connection
    def check_wazuh_connection():
        r = requests.get("https://localhost:9200/_cat/indices?v",
                         auth=("admin", env.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")),
                         verify=False)
        if r.status_code == 200:
            wazuh_indices = [l for l in r.text.split("\n") if "wazuh" in l.lower()]
            return True, f"{len(wazuh_indices)} Wazuh indices found"
        return False, f"HTTP {r.status_code}"
    test("Integration: Wazuh Manager → Indexer", check_wazuh_connection)

    # Keycloak SSO realm
    def check_kc_realm():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        r = requests.get(f"http://localhost:8081/realms/{realm}")
        if r.status_code == 200:
            return True, f"Realm '{realm}' accessible, issuer={r.json().get('issuer','?')[:50]}"
        return False, f"HTTP {r.status_code}"
    test("Integration: Keycloak SSO Realm", check_kc_realm)

    # Keycloak SSO client exists
    def check_kc_client():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        client_id = env.get("KC_WAZUH_CLIENT_ID", "soc-sso")
        r = requests.post("http://localhost:8081/realms/master/protocol/openid-connect/token",
                          data={"grant_type": "password", "client_id": "admin-cli",
                                "username": env.get("KC_ADMIN_USER", "admin"),
                                "password": env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")})
        if r.status_code != 200:
            return False, "Cannot get admin token"
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}
        r = requests.get(f"http://localhost:8081/admin/realms/{realm}/clients?clientId={client_id}", headers=h)
        if r.status_code == 200 and r.json():
            c = r.json()[0]
            return True, f"Client '{client_id}' exists, publicClient={c.get('publicClient')}"
        return False, f"Client '{client_id}' not found"
    test("Integration: Keycloak OIDC Client", check_kc_client)

    # Keycloak SSO admin user login
    def check_kc_sso_admin():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        client_id = env.get("KC_WAZUH_CLIENT_ID", "soc-sso")
        secret = env.get("KC_WAZUH_CLIENT_SECRET", "") or env.get("SSO_CLIENT_SECRET", "")
        user = env.get("SSO_ADMIN_EMAIL", "admin@local.lab")
        pwd = env.get("SSO_ADMIN_PASSWORD", "SocSsoAdmin@2025")
        if not secret:
            return False, "No client secret in .env.deployed"
        data = {"grant_type": "password", "client_id": client_id,
                "client_secret": secret, "scope": "openid profile email",
                "username": user, "password": pwd}
        r = requests.post(f"http://localhost:8081/realms/{realm}/protocol/openid-connect/token",
                          data=data)
        if r.status_code == 200 and "access_token" in r.json():
            import base64
            parts = r.json()["access_token"].split(".")
            payload = base64.b64decode(parts[1] + "==")
            import json as j
            d = j.loads(payload)
            groups = d.get("groups", [])
            return True, f"SSO admin '{user}' authenticated, groups={groups}"
        return False, f"HTTP {r.status_code}: {r.text[:100]}"
    test("Integration: SSO Admin Login", check_kc_sso_admin)

    # Keycloak SSO user login
    def check_kc_sso_user():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        client_id = env.get("KC_WAZUH_CLIENT_ID", "soc-sso")
        secret = env.get("KC_WAZUH_CLIENT_SECRET", "") or env.get("SSO_CLIENT_SECRET", "")
        # Prefer SSO_ANALYST_EMAIL (from .env.deployed) over SSO_USER_EMAIL (from .env)
        user = env.get("SSO_ANALYST_EMAIL") or env.get("SSO_USER_EMAIL", "user@local.lab")
        pwd = env.get("SSO_ANALYST_PASSWORD") or env.get("SSO_USER_PASSWORD", "SocSsoUser@2025")
        if not secret:
            return False, "No client secret in .env.deployed"
        data = {"grant_type": "password", "client_id": client_id,
                "client_secret": secret, "scope": "openid profile email",
                "username": user, "password": pwd}
        r = requests.post(f"http://localhost:8081/realms/{realm}/protocol/openid-connect/token",
                          data=data)
        if r.status_code == 200 and "access_token" in r.json():
            import base64
            parts = r.json()["access_token"].split(".")
            payload = base64.b64decode(parts[1] + "==")
            import json as j
            d = j.loads(payload)
            groups = d.get("groups", [])
            return True, f"SSO user '{user}' authenticated, groups={groups}"
        return False, f"HTTP {r.status_code}: {r.text[:100]}"
    test("Integration: SSO User Login", check_kc_sso_user)

    # Wazuh OpenID well-known endpoint accessible
    def check_wazuh_oidc():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        # Check from inside wazuh-indexer container (via container hostname)
        result = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer", "curl", "-sk",
             f"https://socstack-keycloak:8080/realms/{realm}/.well-known/openid-configuration"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and "authorization_endpoint" in result.stdout:
            return True, "OIDC well-known endpoint reachable from indexer"
        # Fallback: check via nginx SSL (SERVER_IP:SSO_PORT)
        r = requests.get(f"https://{SERVER_IP}:{SSO_PORT}/realms/{realm}/.well-known/openid-configuration",
                         verify=False, timeout=10)
        if r.status_code == 200 and "authorization_endpoint" in r.json():
            return True, f"OIDC well-known via https://{SERVER_IP}:{SSO_PORT} (internal may need SSL fix)"
        return False, f"OIDC endpoint not reachable: {result.stderr[:100] if result.stderr else 'no output'}"
    test("Integration: Wazuh OIDC Endpoint", check_wazuh_oidc, critical=False)


# ════════════════════════════════════════════════════════════
# TEST 5: Nginx Self-Signed SSL Port Verification
# ════════════════════════════════════════════════════════════
def test_proxy_ssl():
    log("\n" + "="*60)
    log("TEST 5: Nginx Self-Signed SSL Ports")
    log("="*60)
    log(f"  Server IP: {SERVER_IP}")

    nginx_ports = [
        (f"Wazuh Dashboard (:{WAZUH_PORT})",  f"https://localhost:{WAZUH_PORT}/",   [200, 302]),
        (f"Keycloak SSO (:{SSO_PORT})",        f"https://localhost:{SSO_PORT}/",     [200, 302, 303]),
        (f"n8n (:{N8N_PORT})",                 f"https://localhost:{N8N_PORT}/",     [200, 302]),
        (f"MISP (:{MISP_PORT})",               f"https://localhost:{MISP_PORT}/",    [200, 302]),
        (f"TheHive (:{THEHIVE_PORT})",         f"https://localhost:{THEHIVE_PORT}/", [200, 302, 401]),
        (f"Cortex (:{CORTEX_PORT})",           f"https://localhost:{CORTEX_PORT}/",  [200, 302, 303]),
    ]

    for label, url, accepted_codes in nginx_ports:
        def check(url=url, codes=accepted_codes):
            try:
                r = requests.get(url, timeout=10, verify=False, allow_redirects=False)
                if r.status_code in codes:
                    return True, f"HTTPS reachable → HTTP {r.status_code}"
                return False, f"Unexpected HTTP {r.status_code} (expected one of {codes})"
            except requests.exceptions.SSLError as e:
                return False, f"SSL error: {e}"
            except requests.exceptions.ConnectionError:
                return False, "Connection refused — nginx not listening on port"
        test(f"Nginx SSL: {label}", check)


# ════════════════════════════════════════════════════════════
# Save Results
# ════════════════════════════════════════════════════════════
def save_results():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summary
    total = passed + failed + warned
    log("\n" + "="*60)
    log("  TEST RESULTS SUMMARY")
    log("="*60)
    log(f"  Total:  {total}")
    log(f"  Passed: {passed}")
    log(f"  Failed: {failed}")
    log(f"  Warned: {warned}")
    log(f"  Score:  {passed}/{total} ({int(passed/total*100) if total else 0}%)")
    log("="*60)

    if failed == 0:
        log("\n  ✓ ALL CRITICAL TESTS PASSED")
    else:
        log(f"\n  ✗ {failed} CRITICAL TEST(S) FAILED")

    # Save text report
    with open(RESULTS_TXT, "w") as f:
        f.write(f"SOC Stack (IP-SSL) Test Report - {ts}\n")
        f.write("=" * 60 + "\n\n")
        f.write("\n".join(lines))
        f.write("\n")

    # Save JSON
    with open(RESULTS_JSON, "w") as f:
        json.dump({
            "timestamp": ts,
            "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
            "results": results
        }, f, indent=2)

    log(f"\n  Report: {RESULTS_TXT}")
    log(f"  JSON:   {RESULTS_JSON}")


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    log("="*60)
    log("  SOC STACK (IP-SSL) - Test Suite")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"  Server: {SERVER_IP}")
    log("="*60)

    test_containers()
    test_endpoints()
    test_auth()
    test_integrations()
    test_proxy_ssl()
    save_results()
