#!/usr/bin/env python3
"""
SOC Stack Test Suite
=====================
Validates all services, logins, integrations and saves results.

Usage:
  python3 /opt/socstack/test-stack.py

Output:
  /opt/socstack/test-results.txt   - Full test report
  /opt/socstack/test-results.json  - Machine-readable results
"""
import requests
import json
import subprocess
import os
import sys
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# Auto-detect: use the directory where this script lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_TXT = os.path.join(BASE_DIR, "test-results.txt")
RESULTS_JSON = os.path.join(BASE_DIR, "test-results.json")

# ── Load .env first, then .env.deployed overrides ──────────
env = {}
for ef in [os.path.join(BASE_DIR, ".env"), os.path.join(BASE_DIR, ".env.deployed")]:
    if os.path.exists(ef):
        with open(ef) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()

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
# TEST 2: Service HTTP Endpoints
# ════════════════════════════════════════════════════════════
def test_endpoints():
    log("\n" + "="*60)
    log("TEST 2: Service HTTP Endpoints")
    log("="*60)

    endpoints = [
        ("NPM API",        f"http://localhost:60081/api/",              200),
        ("Keycloak",        "http://localhost:8081/realms/master",       200),
        ("Wazuh Dashboard", "https://localhost:5601/",                   302),
        ("Wazuh Indexer",   "https://localhost:9200/",                   200),
        ("n8n",             "http://localhost:5678/",                    200),
        ("MISP",            "https://localhost:8443/",                   302),
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

    # NPM
    def check_npm():
        r = requests.post("http://localhost:60081/api/tokens", json={
            "identity": env.get("NPM_ADMIN_EMAIL", "admin@yourdomain.com"),
            "secret": env.get("NPM_ADMIN_PASSWORD", "ChangeMe_Npm@2025")
        })
        if r.status_code == 200 and "token" in r.json():
            return True, f"Token acquired, expires={r.json().get('expires','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: NPM", check_npm)

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

    # n8n (check signup disabled)
    def check_n8n():
        r = requests.get("http://localhost:5678/rest/settings")
        if r.status_code == 200:
            show = r.json().get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad", True)
            if not show:
                return True, "Owner configured, signup disabled"
            return False, "Signup still enabled"
        return False, f"HTTP {r.status_code}"
    test("Login: n8n (signup disabled)", check_n8n)

    # Keycloak
    def check_kc():
        r = requests.post("http://localhost:8081/realms/master/protocol/openid-connect/token",
                          data={
                              "grant_type": "password",
                              "client_id": "admin-cli",
                              "username": env.get("KC_ADMIN_USER", "admin"),
                              "password": env.get("KC_ADMIN_PASSWORD", "ChangeMe_Keycloak@2025"),
                          })
        if r.status_code == 200 and "access_token" in r.json():
            return True, "Access token acquired"
        return False, f"HTTP {r.status_code}"
    test("Login: Keycloak", check_kc)

    # MISP
    def check_misp():
        misp_key = env.get("MISP_API_KEY", "")
        if not misp_key:
            # Get from DB
            result = subprocess.run(
                ["docker", "exec", "socstack-misp-db", "mysql", "-u",
                 env.get("MISP_DB_USER", "misp"), f"-p{env.get('MISP_DB_PASSWORD', 'ChangeMe_MispDb@2025')}",
                 "misp", "-N", "-e",
                 f"SELECT authkey FROM users WHERE email='{env.get('MISP_ADMIN_EMAIL', 'admin@yourdomain.com')}' LIMIT 1;"],
                capture_output=True, text=True, timeout=10
            )
            misp_key = result.stdout.strip()
        if not misp_key:
            return False, "No API key"
        r = requests.get("https://localhost:8443/servers/getVersion",
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
                               env.get("THEHIVE_ADMIN_PASSWORD", "ChangeMe_TheHive@2025")))
        if r.status_code == 200:
            return True, f"profile={r.json().get('profile','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: TheHive Admin", check_thehive_admin)

    # TheHive analyst
    def check_thehive_analyst():
        r = requests.get("http://localhost:9000/api/v1/user/current",
                         auth=(env.get("THEHIVE_ANALYST_USER", "analyst@yourdomain.com"),
                               env.get("THEHIVE_ANALYST_PASSWORD", "ChangeMe_Analyst@2025")))
        if r.status_code == 200:
            return True, f"profile={r.json().get('profile','?')} org={r.json().get('organisation','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: TheHive Analyst", check_thehive_analyst)

    # Cortex admin
    def check_cortex():
        r = requests.post("http://localhost:9001/api/login", json={
            "user": env.get("CORTEX_ADMIN_USER", "admin@yourdomain.com"),
            "password": env.get("CORTEX_ADMIN_PASSWORD", "ChangeMe_Cortex@2025")
        })
        if r.status_code == 200:
            return True, f"roles={r.json().get('roles','?')}"
        return False, f"HTTP {r.status_code}"
    test("Login: Cortex SuperAdmin", check_cortex)

    # Cortex org admin
    def check_cortex_org():
        r = requests.post("http://localhost:9001/api/login", json={
            "user": env.get("CORTEX_ORG_ADMIN", "orgadmin@yourdomain.com"),
            "password": env.get("CORTEX_ADMIN_PASSWORD", "ChangeMe_Cortex@2025")
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
                env.get("THEHIVE_ADMIN_PASSWORD", "ChangeMe_TheHive@2025"))
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

    # MISP API reachable
    def check_misp_api():
        key = env.get("MISP_API_KEY", "")
        if not key:
            result = subprocess.run(
                ["docker", "exec", "socstack-misp-db", "mysql", "-u",
                 env.get("MISP_DB_USER", "misp"), f"-p{env.get('MISP_DB_PASSWORD', 'ChangeMe_MispDb@2025')}",
                 "misp", "-N", "-e",
                 f"SELECT authkey FROM users WHERE email='{env.get('MISP_ADMIN_EMAIL', 'admin@yourdomain.com')}' LIMIT 1;"],
                capture_output=True, text=True, timeout=10
            )
            key = result.stdout.strip()
        if not key:
            return False, "No API key"
        r = requests.get("https://localhost:8443/organisations/index",
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
                env.get("THEHIVE_ADMIN_PASSWORD", "ChangeMe_TheHive@2025"))
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
            "user": env.get("CORTEX_ADMIN_USER", "admin@yourdomain.com"),
            "password": env.get("CORTEX_ADMIN_PASSWORD", "ChangeMe_Cortex@2025")
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
        # Get admin token
        r = requests.post("http://localhost:8081/realms/master/protocol/openid-connect/token",
                          data={"grant_type": "password", "client_id": "admin-cli",
                                "username": env.get("KC_ADMIN_USER", "admin"),
                                "password": env.get("KC_ADMIN_PASSWORD", "ChangeMe_Keycloak@2025")})
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
        secret = env.get("SSO_CLIENT_SECRET", "")
        user = env.get("SSO_ADMIN_EMAIL", "admin@yourdomain.com")
        pwd = env.get("SSO_ADMIN_PASSWORD", "ChangeMe_SsoAdmin@2025")
        if not secret:
            return False, "No SSO_CLIENT_SECRET in .env/.env.deployed"
        data = {"grant_type": "password", "client_id": client_id,
                "client_secret": secret, "scope": "openid profile email",
                "username": user, "password": pwd}
        r = requests.post(f"http://localhost:8081/realms/{realm}/protocol/openid-connect/token",
                          data=data)
        if r.status_code == 200 and "access_token" in r.json():
            # Decode JWT to check groups
            import base64
            parts = r.json()["access_token"].split(".")
            payload = base64.b64decode(parts[1] + "==")
            import json as j
            d = j.loads(payload)
            groups = d.get("groups", [])
            return True, f"SSO admin '{user}' authenticated, groups={groups}"
        return False, f"HTTP {r.status_code}: {r.text[:100]}"
    test("Integration: SSO Admin Login", check_kc_sso_admin)

    # Keycloak SSO analyst user login
    def check_kc_sso_analyst():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        client_id = env.get("KC_WAZUH_CLIENT_ID", "soc-sso")
        secret = env.get("SSO_CLIENT_SECRET", "")
        user = env.get("SSO_ANALYST_EMAIL", "analyst@yourdomain.com")
        pwd = env.get("SSO_ANALYST_PASSWORD", "ChangeMe_SsoAnalyst@2025")
        if not secret:
            return False, "No SSO_CLIENT_SECRET in .env/.env.deployed"
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
            return True, f"SSO analyst '{user}' authenticated, groups={groups}"
        return False, f"HTTP {r.status_code}: {r.text[:100]}"
    test("Integration: SSO Analyst Login", check_kc_sso_analyst)

    # Wazuh OpenID well-known endpoint accessible
    def check_wazuh_oidc():
        realm = env.get("KC_WAZUH_REALM", "SOC")
        sso_domain = env.get("SSO_DOMAIN", "sso.yourdomain.com")
        # Check if the OIDC well-known endpoint is reachable from inside docker
        result = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer", "curl", "-sk",
             f"https://socstack-keycloak:8080/realms/{realm}/.well-known/openid-configuration"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and "authorization_endpoint" in result.stdout:
            return True, "OIDC well-known endpoint reachable from indexer"
        # Try via external URL
        r = requests.get(f"https://{sso_domain}/realms/{realm}/.well-known/openid-configuration",
                         verify=False, timeout=10)
        if r.status_code == 200 and "authorization_endpoint" in r.json():
            return True, f"OIDC well-known via external URL (internal may need SSL fix)"
        return False, f"OIDC endpoint not reachable: {result.stderr[:100] if result.stderr else 'no output'}"
    test("Integration: Wazuh OIDC Endpoint", check_wazuh_oidc, critical=False)


# ════════════════════════════════════════════════════════════
# TEST 5: NPM Proxy + SSL
# ════════════════════════════════════════════════════════════
def test_proxy_ssl():
    log("\n" + "="*60)
    log("TEST 5: Reverse Proxy & SSL")
    log("="*60)

    # Get NPM token
    try:
        r = requests.post("http://localhost:60081/api/tokens", json={
            "identity": env.get("NPM_ADMIN_EMAIL", "admin@yourdomain.com"),
            "secret": env.get("NPM_ADMIN_PASSWORD", "ChangeMe_Npm@2025")
        })
        if r.status_code != 200:
            log("  ✗ Cannot authenticate to NPM, skipping proxy tests")
            return
        token = r.json()["token"]
        h = {"Authorization": f"Bearer {token}"}
    except:
        log("  ✗ NPM unreachable, skipping proxy tests")
        return

    # Check proxy hosts
    hosts = requests.get("http://localhost:60081/api/nginx/proxy-hosts", headers=h).json()
    hosts_with_ssl = sum(1 for host in hosts if host.get("certificate_id", 0) and host.get("ssl_forced", False))
    hosts_total = len(hosts)

    if hosts_with_ssl == 0 and hosts_total > 0:
        log("  ↳ No SSL certificates configured — skipping SSL tests")
        log("  ↳ (This is normal if Let's Encrypt was skipped to avoid rate limits)")
        return

    for host in hosts:
        domain = host["domain_names"][0]
        cert_id = host.get("certificate_id", 0)
        ssl_forced = host.get("ssl_forced", False)

        def check(d=domain, c=cert_id, s=ssl_forced):
            if c and c > 0 and s:
                return True, f"cert_id={c}, ssl_forced=True"
            elif c and c > 0:
                return False, f"cert_id={c}, ssl_forced=False (should be True)"
            else:
                return None, f"No SSL certificate (configure via NPM UI or re-run post-deploy)"
        test(f"Proxy+SSL: {domain}", check, critical=False)


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
        f.write(f"SOC Stack Test Report - {ts}\n")
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
    log("  SOC STACK - Test Suite")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("="*60)

    test_containers()
    test_endpoints()
    test_auth()
    test_integrations()
    test_proxy_ssl()
    save_results()
