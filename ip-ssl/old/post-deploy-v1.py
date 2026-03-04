#!/usr/bin/env python3
"""
SOC Stack Post-Deploy Configuration
=====================================
Run AFTER 'docker-compose up -d' to configure all services.

Steps:
  1. NPM: Create proxy hosts + request SSL certs
  2. n8n: Create owner account (disables signup)
  3. Cortex: Migrate DB, create superadmin, org, users, API key
  4. TheHive: Change default password, create org + analyst user
  5. MISP ↔ TheHive Integration
  6. Keycloak SSO: Create realm, OIDC client, groups, users for Wazuh
  7. Apply Wazuh security configs (securityadmin)
  8. Save all deployed credentials to .env.deployed

Usage:
  python3 /opt/socstack/post-deploy.py
"""
import requests
import json
import time
import sys
import os
import subprocess
from datetime import datetime

requests.packages.urllib3.disable_warnings()

BASE_DIR = "/opt/socstack"
ENV_FILE = os.path.join(BASE_DIR, ".env")
DEPLOYED_FILE = os.path.join(BASE_DIR, ".env.deployed")
LOG_FILE = os.path.join(BASE_DIR, "post-deploy.log")

# ── Load .env ──────────────────────────────────────────────
env = {}
if os.path.exists(ENV_FILE):
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()

# ── Config ─────────────────────────────────────────────────
NPM_PORT = 60081
NPM_EMAIL = env.get("NPM_ADMIN_EMAIL", "admin@codesec.in")
NPM_PASS = env.get("NPM_ADMIN_PASSWORD", "SocNpm@2025")

N8N_EMAIL = env.get("N8N_ADMIN_EMAIL", "admin@codesec.in")
N8N_PASS = env.get("N8N_ADMIN_PASSWORD", "SocN8n@2025")

CORTEX_ADMIN = env.get("CORTEX_ADMIN_USER", "admin@codesec.in")
CORTEX_PASS = env.get("CORTEX_ADMIN_PASSWORD", "SocCortex@2025")
CORTEX_ORG = env.get("CORTEX_ORG_NAME", "codesec")
CORTEX_ORG_ADMIN = env.get("CORTEX_ORG_ADMIN", "orgadmin@codesec.in")

THEHIVE_USER = env.get("THEHIVE_ADMIN_USER", "admin@thehive.local")
THEHIVE_PASS = env.get("THEHIVE_ADMIN_PASSWORD", "SocTheHive@2025")
THEHIVE_DEFAULT = env.get("THEHIVE_DEFAULT_PASSWORD", "secret")
THEHIVE_ORG = env.get("THEHIVE_ORG_NAME", "CODESEC")
THEHIVE_ORG_DESC = env.get("THEHIVE_ORG_DESC", "CodeSec SOC Organization")
THEHIVE_ANALYST = env.get("THEHIVE_ANALYST_USER", "analyst@codesec.in")
THEHIVE_ANALYST_PASS = env.get("THEHIVE_ANALYST_PASSWORD", "SocAnalyst@2025")

MISP_ADMIN = env.get("MISP_ADMIN_EMAIL", "admin@codesec.in")
MISP_PASS = env.get("MISP_ADMIN_PASSWORD", "SocMisp@2025")
MISP_DB_USER = env.get("MISP_DB_USER", "misp")
MISP_DB_PASS = env.get("MISP_DB_PASSWORD", "SocMispDb@2025")

KC_USER = env.get("KC_ADMIN_USER", "admin")
KC_PASS = env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")
KC_WAZUH_REALM = env.get("KC_WAZUH_REALM", "wazuh")
KC_WAZUH_CLIENT = env.get("KC_WAZUH_CLIENT_ID", "wazuh-sso")
SSO_ADMIN_EMAIL = env.get("SSO_ADMIN_EMAIL", "admin@codesec.in")
SSO_ADMIN_PASS = env.get("SSO_ADMIN_PASSWORD", "SocSsoAdmin@2025")
SSO_ADMIN_FIRST = env.get("SSO_ADMIN_FIRST", "SOC")
SSO_ADMIN_LAST = env.get("SSO_ADMIN_LAST", "Admin")
SSO_USER_EMAIL = env.get("SSO_USER_EMAIL", "user@codesec.in")
SSO_USER_PASS = env.get("SSO_USER_PASSWORD", "SocSsoUser@2025")
SSO_USER_FIRST = env.get("SSO_USER_FIRST", "SOC")
SSO_USER_LAST = env.get("SSO_USER_LAST", "User")
WAZUH_DOMAIN = env.get("WAZUH_DOMAIN", "wazuh.codesec.in")
SSO_DOMAIN = env.get("SSO_DOMAIN", "sso.codesec.in")

DOMAINS = {
    "sso":     {"domain": env.get("SSO_DOMAIN", "sso.codesec.in"),     "host": "socstack-keycloak",         "port": 8080, "scheme": "http"},
    "wazuh":   {"domain": env.get("WAZUH_DOMAIN", "wazuh.codesec.in"), "host": "socstack-wazuh-dashboard",  "port": 5601, "scheme": "https"},
    "n8n":     {"domain": env.get("N8N_DOMAIN", "n8n.codesec.in"),     "host": "socstack-n8n",              "port": 5678, "scheme": "http"},
    "cti":     {"domain": env.get("MISP_DOMAIN", "cti.codesec.in"),    "host": "socstack-misp-core",        "port": 443,  "scheme": "https"},
    "hive":    {"domain": env.get("THEHIVE_DOMAIN", "hive.codesec.in"),"host": "socstack-thehive",          "port": 9000, "scheme": "http"},
    "cortex":  {"domain": env.get("CORTEX_DOMAIN", "cortex.codesec.in"),"host": "socstack-cortex",          "port": 9001, "scheme": "http"},
    "grafana": {"domain": env.get("GRAFANA_DOMAIN", "grafana.codesec.in"),"host": "socstack-grafana",       "port": 3000, "scheme": "http"},
    "npm":     {"domain": env.get("NPM_DOMAIN", "npm.codesec.in"),     "host": "socstack-nginx",            "port": 81,   "scheme": "http"},
}

deployed = {}  # Collect all deployed credentials
log_lines = []


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    log_lines.append(line)


def wait_for(name, url, timeout=120):
    log(f"  Waiting for {name}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code < 500:
                log(f"  ✓ {name} ready ({int(time.time()-start)}s)")
                return True
        except:
            pass
        time.sleep(3)
    log(f"  ✗ {name} TIMEOUT after {timeout}s")
    return False


# ════════════════════════════════════════════════════════════
# STEP 1: NPM - Proxy Hosts + SSL
# ════════════════════════════════════════════════════════════
def step_npm():
    log("\n" + "="*60)
    log("STEP 1: Nginx Proxy Manager → Proxy Hosts + SSL")
    log("="*60)

    NPM = f"http://localhost:{NPM_PORT}"
    if not wait_for("NPM", f"{NPM}/api/"):
        return

    # First-time setup or login
    resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
    if resp.status_code != 200:
        # Try legacy default credentials (NPM < 2.12)
        resp = requests.post(f"{NPM}/api/tokens", json={"identity": "admin@example.com", "secret": "changeme"})
        if resp.status_code == 200:
            t = resp.json()["token"]
            h = {"Authorization": f"Bearer {t}", "Content-Type": "application/json"}
            requests.put(f"{NPM}/api/users/1", headers=h, json={"email": NPM_EMAIL, "nickname": "Admin", "is_disabled": False, "roles": ["admin"]})
            requests.put(f"{NPM}/api/users/1/auth", headers=h, json={"type": "password", "current": "changeme", "secret": NPM_PASS})
            resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
        else:
            # NPM >= 2.14 starts with empty user table — create admin directly
            try:
                setup_check = requests.get(f"{NPM}/api/")
                if setup_check.status_code == 200 and not setup_check.json().get("setup", True):
                    log("  ↳ Fresh NPM (no users) — creating initial admin...")
                    create_resp = requests.post(f"{NPM}/api/users", json={
                        "name": "Administrator",
                        "nickname": "Admin",
                        "email": NPM_EMAIL,
                        "roles": ["admin"],
                        "is_disabled": False,
                        "auth": {"type": "password", "secret": NPM_PASS}
                    })
                    if create_resp.status_code in (200, 201):
                        log("  ✓ Initial admin user created")
                        resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
                    else:
                        log(f"  ✗ Failed to create admin: {create_resp.status_code} {create_resp.text[:200]}")
            except Exception as e:
                log(f"  ✗ Setup check failed: {e}")

    if resp.status_code != 200:
        log(f"  ✗ NPM login failed: {resp.status_code}")
        return

    token = resp.json()["token"]
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    log("  ✓ NPM authenticated")
    deployed["NPM_ADMIN_EMAIL"] = NPM_EMAIL
    deployed["NPM_ADMIN_PASSWORD"] = NPM_PASS

    # Nginx advanced config for all proxy hosts
    # Large headers needed for OIDC/SSO redirects (JWT tokens, cookies)
    NPM_ADVANCED = (
        "large_client_header_buffers 4 32k;\n"
        "proxy_buffer_size 16k;\n"
        "proxy_buffers 8 16k;\n"
        "proxy_busy_buffers_size 32k;\n"
        "proxy_ssl_verify off;\n"
        "proxy_connect_timeout 300s;\n"
        "proxy_send_timeout 300s;\n"
        "proxy_read_timeout 300s;\n"
        "send_timeout 300s;"
    )

    # SSO proxy needs larger buffers for Keycloak OIDC responses
    NPM_ADVANCED_SSO = (
        "large_client_header_buffers 4 32k;\n"
        "proxy_buffer_size 128k;\n"
        "proxy_buffers 4 256k;\n"
        "proxy_busy_buffers_size 256k;\n"
        "proxy_ssl_verify off;\n"
        "proxy_connect_timeout 300s;\n"
        "proxy_send_timeout 300s;\n"
        "proxy_read_timeout 300s;\n"
        "send_timeout 300s;"
    )

    # Create proxy hosts
    existing = requests.get(f"{NPM}/api/nginx/proxy-hosts", headers=h).json()
    existing_map = {x["domain_names"][0]: x["id"] for x in existing if x.get("domain_names")}

    for key, cfg in DOMAINS.items():
        d = cfg["domain"]
        # SSO (Keycloak) needs block_exploits=False and larger buffers
        is_sso = (key == "sso")
        adv = NPM_ADVANCED_SSO if is_sso else NPM_ADVANCED
        blk = False if is_sso else True
        if d in existing_map:
            log(f"  ↳ Proxy exists: {d} (ID={existing_map[d]})")
        else:
            r = requests.post(f"{NPM}/api/nginx/proxy-hosts", headers=h, json={
                "domain_names": [d], "forward_host": cfg["host"], "forward_port": cfg["port"],
                "forward_scheme": cfg["scheme"], "block_exploits": blk,
                "allow_websocket_upgrade": True, "access_list_id": 0,
                "certificate_id": 0, "ssl_forced": False, "meta": {},
                "advanced_config": adv, "locations": []
            })
            if r.status_code == 201:
                existing_map[d] = r.json()["id"]
                log(f"  ✓ Proxy created: {d} (ID={existing_map[d]})")
            else:
                log(f"  ✗ Proxy failed: {d}: {r.text[:100]}")

    # SSL certificates — skip requesting new certs if all already exist
    log("\n  Checking SSL certificates...")
    certs = requests.get(f"{NPM}/api/nginx/certificates", headers=h).json()
    cert_map = {}
    for c in certs:
        for d in c["domain_names"]:
            cert_map[d] = c["id"]

    all_domains = [cfg["domain"] for cfg in DOMAINS.values()]
    domains_with_certs = [d for d in all_domains if d in cert_map]
    domains_without_certs = [d for d in all_domains if d not in cert_map]

    if not domains_without_certs:
        log(f"  ✓ All {len(domains_with_certs)} domains already have SSL certificates — skipping")
    elif domains_with_certs:
        log(f"  ↳ {len(domains_with_certs)} domains have certs, {len(domains_without_certs)} need certs")

    for key, cfg in DOMAINS.items():
        d = cfg["domain"]
        if d in cert_map:
            log(f"  ↳ SSL exists: {d} (cert={cert_map[d]})")
            continue
        log(f"  Requesting SSL for {d}...")
        try:
            r = requests.post(f"{NPM}/api/nginx/certificates", headers=h, json={
                "domain_names": [d], "meta": {"dns_challenge": False}, "provider": "letsencrypt"
            }, timeout=120)
            if r.status_code == 201:
                cert_map[d] = r.json()["id"]
                log(f"  ✓ SSL cert: {d} (cert={cert_map[d]})")
            else:
                log(f"  ✗ SSL failed: {d}: {r.text[:120]}")
        except Exception as e:
            log(f"  ✗ SSL error: {d}: {e}")
        time.sleep(5)

    # Enable SSL on proxy hosts (only for domains that have certs)
    for key, cfg in DOMAINS.items():
        d = cfg["domain"]
        hid = existing_map.get(d)
        cid = cert_map.get(d)
        if not hid or not cid:
            continue
        is_sso = (key == "sso")
        adv = NPM_ADVANCED_SSO if is_sso else NPM_ADVANCED
        blk = False if is_sso else True
        cur = requests.get(f"{NPM}/api/nginx/proxy-hosts/{hid}", headers=h).json()
        if cur.get("certificate_id") == cid and cur.get("ssl_forced"):
            continue
        r = requests.put(f"{NPM}/api/nginx/proxy-hosts/{hid}", headers=h, json={
            "domain_names": [d], "forward_host": cfg["host"], "forward_port": cfg["port"],
            "forward_scheme": cfg["scheme"], "certificate_id": cid, "ssl_forced": True,
            "http2_support": True, "block_exploits": blk, "allow_websocket_upgrade": True,
            "access_list_id": 0, "advanced_config": adv, "meta": {}, "locations": []
        })
        if r.status_code == 200:
            log(f"  ✓ SSL enabled: {d}")


# ════════════════════════════════════════════════════════════
# STEP 2: n8n - Owner Setup (disables signup)
# ════════════════════════════════════════════════════════════
def step_n8n():
    log("\n" + "="*60)
    log("STEP 2: n8n → Owner Account (signup disabled)")
    log("="*60)

    if not wait_for("n8n", "http://localhost:5678"):
        return

    r = requests.get("http://localhost:5678/rest/settings")
    if r.status_code == 200:
        show = r.json().get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad", True)
        if not show:
            log("  ✓ Owner already configured, signup disabled")
            deployed["N8N_ADMIN_EMAIL"] = N8N_EMAIL
            deployed["N8N_ADMIN_PASSWORD"] = N8N_PASS
            return

    r = requests.post("http://localhost:5678/rest/owner/setup", json={
        "email": N8N_EMAIL, "firstName": "SOC", "lastName": "Admin", "password": N8N_PASS
    })
    if r.status_code == 200:
        log(f"  ✓ Owner created: {N8N_EMAIL}")
        log("  ✓ Signup now disabled (invite-only)")
    else:
        log(f"  ✗ Owner setup: {r.status_code} {r.text[:150]}")
    deployed["N8N_ADMIN_EMAIL"] = N8N_EMAIL
    deployed["N8N_ADMIN_PASSWORD"] = N8N_PASS


# ════════════════════════════════════════════════════════════
# STEP 3: Cortex - Migrate + SuperAdmin + Org + API Key
# ════════════════════════════════════════════════════════════
def step_cortex():
    log("\n" + "="*60)
    log("STEP 3: Cortex → Init, Org, Users, API Key")
    log("="*60)

    CURL = "http://localhost:9001"
    if not wait_for("Cortex", f"{CURL}/api/status"):
        return None

    session = requests.Session()

    # Get CSRF token first (Cortex/Play Framework requires this)
    session.get(f"{CURL}/")
    csrf = session.cookies.get("CORTEX-XSRF-TOKEN", "")
    if csrf:
        session.headers.update({"X-CORTEX-XSRF-TOKEN": csrf})

    # Try login first (already initialized?)
    r = session.post(f"{CURL}/api/login", json={"user": CORTEX_ADMIN, "password": CORTEX_PASS})
    if r.status_code != 200:
        # Fresh: migrate + create superadmin
        log("  Running DB migration...")
        session.post(f"{CURL}/api/maintenance/migrate", json={})
        time.sleep(3)
        log("  Creating superadmin...")
        session.post(f"{CURL}/api/user", json={
            "login": CORTEX_ADMIN, "name": "SOC Admin",
            "roles": ["superadmin"], "password": CORTEX_PASS
        })
        time.sleep(2)
        r = session.post(f"{CURL}/api/login", json={"user": CORTEX_ADMIN, "password": CORTEX_PASS})
        if r.status_code != 200:
            log(f"  ✗ Cortex login failed after init")
            return None
    log(f"  ✓ Logged in as {r.json().get('name')}")
    deployed["CORTEX_ADMIN_USER"] = CORTEX_ADMIN
    deployed["CORTEX_ADMIN_PASSWORD"] = CORTEX_PASS

    # Create org
    r = session.post(f"{CURL}/api/organization", json={
        "name": CORTEX_ORG, "description": "CodeSec SOC Organization", "status": "Active"
    })
    if r.status_code == 201:
        log(f"  ✓ Organization '{CORTEX_ORG}' created")
    else:
        log(f"  ↳ Organization: already exists or {r.status_code}")

    # Create org admin
    r = session.post(f"{CURL}/api/user", json={
        "login": CORTEX_ORG_ADMIN, "name": "Org Admin",
        "roles": ["read", "analyze", "orgadmin"],
        "organization": CORTEX_ORG, "password": CORTEX_PASS
    })
    if r.status_code == 201:
        log(f"  ✓ Org admin created: {CORTEX_ORG_ADMIN}")
    else:
        log(f"  ↳ Org admin: already exists or {r.status_code}")
    deployed["CORTEX_ORG_ADMIN"] = CORTEX_ORG_ADMIN

    # API key (json={} needed to set Content-Type for CSRF check)
    r = session.post(f"{CURL}/api/user/{CORTEX_ORG_ADMIN}/key/renew", json={})
    if r.status_code == 200:
        api_key = r.text.strip().strip('"')
        log(f"  ✓ API Key: {api_key}")
        with open(os.path.join(BASE_DIR, ".cortex-api-key"), "w") as f:
            f.write(api_key)
        deployed["CORTEX_API_KEY"] = api_key
        return api_key
    else:
        # Try get existing
        r = session.get(f"{CURL}/api/user/{CORTEX_ORG_ADMIN}/key")
        if r.status_code == 200:
            api_key = r.text.strip().strip('"')
            log(f"  ✓ Existing API Key: {api_key}")
            deployed["CORTEX_API_KEY"] = api_key
            return api_key
    log(f"  ✗ API key failed")
    return None


# ════════════════════════════════════════════════════════════
# STEP 4: TheHive - Password + Org + Analyst User
# ════════════════════════════════════════════════════════════
def step_thehive():
    log("\n" + "="*60)
    log("STEP 4: TheHive → Password, Org, Analyst User")
    log("="*60)

    TH = "http://localhost:9000"
    if not wait_for("TheHive", f"{TH}/api/v1/status", timeout=180):
        return

    # Determine current password
    auth = None
    r = requests.get(f"{TH}/api/v1/user/current", auth=(THEHIVE_USER, THEHIVE_PASS))
    if r.status_code == 200:
        log(f"  ✓ Admin password already set")
        auth = (THEHIVE_USER, THEHIVE_PASS)
    else:
        r = requests.get(f"{TH}/api/v1/user/current", auth=(THEHIVE_USER, THEHIVE_DEFAULT))
        if r.status_code == 200:
            log("  Changing default password...")
            r = requests.post(f"{TH}/api/v1/user/{THEHIVE_USER}/password/set",
                              auth=(THEHIVE_USER, THEHIVE_DEFAULT),
                              json={"password": THEHIVE_PASS})
            if r.status_code == 204:
                log(f"  ✓ Password changed for {THEHIVE_USER}")
                auth = (THEHIVE_USER, THEHIVE_PASS)
            else:
                log(f"  ✗ Password change failed: {r.status_code}")
                auth = (THEHIVE_USER, THEHIVE_DEFAULT)
        else:
            log("  ✗ Cannot login with default or new password")
            return

    deployed["THEHIVE_ADMIN_USER"] = THEHIVE_USER
    deployed["THEHIVE_ADMIN_PASSWORD"] = THEHIVE_PASS

    # Create organization
    log(f"\n  Creating organization '{THEHIVE_ORG}'...")
    r = requests.post(f"{TH}/api/v1/organisation", auth=auth,
                      headers={"Content-Type": "application/json"},
                      json={"name": THEHIVE_ORG, "description": THEHIVE_ORG_DESC})
    if r.status_code == 201:
        org_id = r.json().get("_id")
        log(f"  ✓ Organization created: {THEHIVE_ORG} (ID={org_id})")
    elif r.status_code == 400 or r.status_code == 409:
        log(f"  ↳ Organization already exists")
        # Get org ID
        r2 = requests.post(f"{TH}/api/v1/query", auth=auth,
                           headers={"Content-Type": "application/json"},
                           json={"query": [{"_name": "listOrganisation"}]})
        if r2.status_code == 200:
            for org in r2.json():
                if org["name"] == THEHIVE_ORG:
                    org_id = org["_id"]
                    break
            else:
                org_id = None
    else:
        log(f"  ✗ Org creation: {r.status_code} {r.text[:150]}")
        org_id = None

    # Create analyst user in the org
    if org_id or True:  # Try anyway
        log(f"\n  Creating analyst user: {THEHIVE_ANALYST}...")
        r = requests.post(f"{TH}/api/v1/user", auth=auth,
                          headers={"Content-Type": "application/json"},
                          json={
                              "login": THEHIVE_ANALYST,
                              "name": "SOC Analyst",
                              "profile": "analyst",
                              "organisation": THEHIVE_ORG,
                              "password": THEHIVE_ANALYST_PASS
                          })
        if r.status_code == 201:
            user_id = r.json().get("_id")
            log(f"  ✓ Analyst created: {THEHIVE_ANALYST} (ID={user_id})")
            # Set password
            r2 = requests.post(f"{TH}/api/v1/user/{THEHIVE_ANALYST}/password/set",
                               auth=auth, json={"password": THEHIVE_ANALYST_PASS})
            if r2.status_code == 204:
                log(f"  ✓ Analyst password set")
            else:
                log(f"  ✗ Analyst password: {r2.status_code}")
        elif "already exist" in r.text.lower() or r.status_code == 400:
            log(f"  ↳ Analyst already exists")
        else:
            log(f"  ✗ Analyst creation: {r.status_code} {r.text[:150]}")

        deployed["THEHIVE_ANALYST_USER"] = THEHIVE_ANALYST
        deployed["THEHIVE_ANALYST_PASSWORD"] = THEHIVE_ANALYST_PASS

    return auth


# ════════════════════════════════════════════════════════════
# STEP 5: MISP ↔ TheHive Integration
# ════════════════════════════════════════════════════════════
def step_misp_thehive(th_auth):
    log("\n" + "="*60)
    log("STEP 5: MISP ↔ TheHive Integration")
    log("="*60)

    TH = "http://localhost:9000"

    # Get MISP API key from DB
    log("  Retrieving MISP API key from database...")
    try:
        result = subprocess.run(
            ["docker", "exec", "socstack-misp-db", "mysql", "-u", MISP_DB_USER,
             f"-p{MISP_DB_PASS}", "misp", "-N", "-e",
             f"SELECT authkey FROM users WHERE email='{MISP_ADMIN}' LIMIT 1;"],
            capture_output=True, text=True, timeout=10
        )
        misp_key = result.stdout.strip()
    except Exception as e:
        log(f"  ✗ Failed to get MISP key: {e}")
        misp_key = None

    if not misp_key:
        log("  ✗ MISP API key not found")
        return

    log(f"  ✓ MISP API Key: {misp_key}")
    deployed["MISP_API_KEY"] = misp_key

    # Verify MISP key works
    r = requests.get("https://localhost:8443/servers/getVersion",
                      headers={"Authorization": misp_key, "Accept": "application/json"},
                      verify=False)
    if r.status_code == 200:
        ver = r.json().get("version", "?")
        log(f"  ✓ MISP API verified (v{ver})")
    else:
        log(f"  ✗ MISP API verification failed: {r.status_code}")
        return

    if not th_auth:
        log("  ✗ TheHive auth not available, skipping integration")
        return

    # Add MISP server to TheHive via custom config
    # TheHive 5.x uses the MISP connector in the Platform Management
    # We configure it via the API
    misp_url = f"https://{DOMAINS['cti']['host']}:443"
    log(f"\n  Configuring TheHive → MISP connector...")
    log(f"  MISP internal URL: {misp_url}")

    # Check if MISP connector already configured
    r = requests.post(f"{TH}/api/v1/query", auth=th_auth,
                      headers={"Content-Type": "application/json"},
                      json={"query": [{"_name": "listConnector"}]})

    if r.status_code == 200:
        connectors = r.json()
        misp_exists = any(c.get("name") == "MISP-CODESEC" for c in connectors)
        if misp_exists:
            log("  ↳ MISP connector already configured in TheHive")
            return

    # Create MISP connector in TheHive
    # TheHive 5.x uses the connector API
    r = requests.post(f"{TH}/api/connector/misp", auth=th_auth,
                      headers={"Content-Type": "application/json"},
                      json={
                          "name": "MISP-CODESEC",
                          "url": misp_url,
                          "auth": {"type": "key", "key": misp_key},
                          "wsConfig": {"ssl": {"loose.acceptAnyCertificate": True}},
                          "purpose": "ImportAndExport",
                          "includedTheHiveOrganisations": [THEHIVE_ORG],
                          "maxAttributes": 10000,
                          "maxAge": 365
                      })
    if r.status_code in (200, 201):
        log(f"  ✓ MISP connector added to TheHive")
    elif r.status_code == 404:
        # TheHive 5.2 may use different endpoint
        log(f"  ↳ MISP connector API not available (configure via UI)")
        log(f"    URL: {misp_url}")
        log(f"    API Key: {misp_key}")
        log(f"    → Go to TheHive UI → Platform Management → MISP Servers → Add")
    else:
        log(f"  ↳ MISP connector: {r.status_code} {r.text[:150]}")
        log(f"    Configure manually in TheHive UI:")
        log(f"    URL: {misp_url}")
        log(f"    API Key: {misp_key}")


# ════════════════════════════════════════════════════════════
# STEP 6: Keycloak SSO → Wazuh (Realm, Client, Groups, Users)
# ════════════════════════════════════════════════════════════
def step_keycloak_sso():
    log("\n" + "="*60)
    log("STEP 6: Keycloak SSO → Wazuh OIDC Setup")
    log("="*60)

    KC = "http://localhost:8081"
    if not wait_for("Keycloak", f"{KC}/realms/master"):
        return None

    # ── Get master token ────────────────────────────────────
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": KC_USER, "password": KC_PASS,
    })
    if r.status_code != 200:
        log(f"  ✗ Keycloak admin login failed: {r.status_code}")
        return None
    token = r.json()["access_token"]
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    log(f"  ✓ Keycloak admin authenticated")

    # ── Create realm ────────────────────────────────────────
    r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}", headers=h)
    if r.status_code == 200:
        log(f"  ↳ Realm '{KC_WAZUH_REALM}' already exists")
    else:
        r = requests.post(f"{KC}/admin/realms", headers=h, json={
            "realm": KC_WAZUH_REALM, "enabled": True,
            "displayName": "Wazuh SSO",
            "loginWithEmailAllowed": True,
            "sslRequired": "none",
        })
        if r.status_code == 201:
            log(f"  ✓ Realm '{KC_WAZUH_REALM}' created")
        else:
            log(f"  ✗ Realm creation failed: {r.status_code} {r.text[:150]}")
            return None

    # ── Re-authenticate against the new realm's admin ───────
    # (Master token works for admin/realms API)

    # ── Create OIDC client (confidential) ───────────────────
    wazuh_redirect = f"https://{WAZUH_DOMAIN}/*"
    # Check existing clients
    r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients?clientId={KC_WAZUH_CLIENT}", headers=h)
    existing_clients = r.json() if r.status_code == 200 else []
    client_uuid = None

    if existing_clients:
        client_uuid = existing_clients[0]["id"]
        log(f"  ↳ Client '{KC_WAZUH_CLIENT}' already exists (UUID={client_uuid[:8]}...)")
    else:
        r = requests.post(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients", headers=h, json={
            "clientId": KC_WAZUH_CLIENT,
            "name": "Wazuh Dashboard SSO",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False,
            "redirectUris": [wazuh_redirect],
            "webOrigins": [f"https://{WAZUH_DOMAIN}"],
            "attributes": {
                "post.logout.redirect.uris": f"https://{WAZUH_DOMAIN}/*",
            },
        })
        if r.status_code == 201:
            # Get the UUID from Location header
            loc = r.headers.get("Location", "")
            client_uuid = loc.rsplit("/", 1)[-1] if loc else None
            if not client_uuid:
                # Fetch it
                r2 = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients?clientId={KC_WAZUH_CLIENT}", headers=h)
                if r2.status_code == 200 and r2.json():
                    client_uuid = r2.json()[0]["id"]
            log(f"  ✓ Client '{KC_WAZUH_CLIENT}' created (UUID={client_uuid[:8]}...)")
        else:
            log(f"  ✗ Client creation failed: {r.status_code} {r.text[:150]}")
            return None

    # ── Add 'groups' protocol mapper to client ──────────────
    if client_uuid:
        # Check existing mappers
        r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients/{client_uuid}/protocol-mappers/models", headers=h)
        existing_mappers = [m["name"] for m in r.json()] if r.status_code == 200 else []
        if "groups" not in existing_mappers:
            r = requests.post(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients/{client_uuid}/protocol-mappers/models", headers=h, json={
                "name": "groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "consentRequired": False,
                "config": {
                    "full.path": "false",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "groups",
                    "userinfo.token.claim": "true",
                },
            })
            if r.status_code == 201:
                log(f"  ✓ Protocol mapper 'groups' added to client")
            else:
                log(f"  ✗ Mapper creation: {r.status_code} {r.text[:100]}")
        else:
            log(f"  ↳ Protocol mapper 'groups' already exists")

    # ── Get client secret ───────────────────────────────────
    client_secret = None
    if client_uuid:
        r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients/{client_uuid}/client-secret", headers=h)
        if r.status_code == 200:
            client_secret = r.json().get("value")
            if client_secret:
                log(f"  ✓ Client secret: {client_secret[:8]}...{client_secret[-4:]}")
                deployed["KC_WAZUH_CLIENT_SECRET"] = client_secret
            else:
                # Generate one
                r = requests.post(f"{KC}/admin/realms/{KC_WAZUH_REALM}/clients/{client_uuid}/client-secret", headers=h)
                if r.status_code == 200:
                    client_secret = r.json().get("value")
                    log(f"  ✓ Client secret generated: {client_secret[:8]}...{client_secret[-4:]}")
                    deployed["KC_WAZUH_CLIENT_SECRET"] = client_secret

    # ── Create groups ───────────────────────────────────────
    for group_name in ["wazuh_admin", "wazuh_user"]:
        r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/groups?search={group_name}&exact=true", headers=h)
        existing = r.json() if r.status_code == 200 else []
        if existing:
            log(f"  ↳ Group '{group_name}' already exists")
        else:
            r = requests.post(f"{KC}/admin/realms/{KC_WAZUH_REALM}/groups", headers=h, json={
                "name": group_name,
            })
            if r.status_code == 201:
                log(f"  ✓ Group '{group_name}' created")
            else:
                log(f"  ✗ Group '{group_name}': {r.status_code} {r.text[:100]}")

    # Helper: get group ID by name
    def get_group_id(name):
        r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/groups?search={name}&exact=true", headers=h)
        groups = r.json() if r.status_code == 200 else []
        for g in groups:
            if g["name"] == name:
                return g["id"]
        return None

    # ── Create SSO users ────────────────────────────────────
    sso_users = [
        {"email": SSO_ADMIN_EMAIL, "password": SSO_ADMIN_PASS,
         "first": SSO_ADMIN_FIRST, "last": SSO_ADMIN_LAST, "group": "wazuh_admin"},
        {"email": SSO_USER_EMAIL, "password": SSO_USER_PASS,
         "first": SSO_USER_FIRST, "last": SSO_USER_LAST, "group": "wazuh_user"},
    ]

    for u in sso_users:
        username = u["email"]
        # Check existing
        r = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/users?username={username}&exact=true", headers=h)
        existing_users = r.json() if r.status_code == 200 else []
        user_id = None

        if existing_users:
            user_id = existing_users[0]["id"]
            log(f"  ↳ User '{username}' already exists")
        else:
            r = requests.post(f"{KC}/admin/realms/{KC_WAZUH_REALM}/users", headers=h, json={
                "username": username,
                "email": username,
                "firstName": u["first"],
                "lastName": u["last"],
                "enabled": True,
                "emailVerified": True,
                "credentials": [{
                    "type": "password",
                    "value": u["password"],
                    "temporary": False,
                }],
            })
            if r.status_code == 201:
                loc = r.headers.get("Location", "")
                user_id = loc.rsplit("/", 1)[-1] if loc else None
                if not user_id:
                    r2 = requests.get(f"{KC}/admin/realms/{KC_WAZUH_REALM}/users?username={username}&exact=true", headers=h)
                    if r2.status_code == 200 and r2.json():
                        user_id = r2.json()[0]["id"]
                log(f"  ✓ User '{username}' created (group={u['group']})")
            else:
                log(f"  ✗ User '{username}': {r.status_code} {r.text[:100]}")

        # Assign to group
        if user_id:
            group_id = get_group_id(u["group"])
            if group_id:
                r = requests.put(f"{KC}/admin/realms/{KC_WAZUH_REALM}/users/{user_id}/groups/{group_id}", headers=h)
                if r.status_code == 204:
                    log(f"  ✓ User '{username}' → group '{u['group']}'")
                else:
                    log(f"  ✗ Group assignment: {r.status_code}")

    # ── Save SSO credentials ────────────────────────────────
    deployed["SSO_ADMIN_EMAIL"] = SSO_ADMIN_EMAIL
    deployed["SSO_ADMIN_PASSWORD"] = SSO_ADMIN_PASS
    deployed["SSO_USER_EMAIL"] = SSO_USER_EMAIL
    deployed["SSO_USER_PASSWORD"] = SSO_USER_PASS
    deployed["KC_WAZUH_REALM"] = KC_WAZUH_REALM
    deployed["KC_WAZUH_CLIENT_ID"] = KC_WAZUH_CLIENT

    # ── Inject client_secret into opensearch_dashboards.yml ─
    if client_secret:
        dash_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml")
        if os.path.exists(dash_yml):
            with open(dash_yml) as f:
                content = f.read()
            import re
            changed = False
            # Inject client secret
            if "WILL_BE_SET_BY_POST_DEPLOY" in content:
                content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
                changed = True
                log(f"  ✓ Client secret injected into opensearch_dashboards.yml")
            elif client_secret not in content:
                content = re.sub(
                    r'(opensearch_security\.openid\.client_secret:\s*)(".*?"|\'.*?\'|[^\s]+)',
                    f'\\1"{client_secret}"',
                    content
                )
                changed = True
                log(f"  ✓ Client secret updated in opensearch_dashboards.yml")
            else:
                log(f"  ↳ Client secret already in opensearch_dashboards.yml")
            if changed:
                with open(dash_yml, "w") as f:
                    f.write(content)
        else:
            log(f"  ✗ Dashboard config not found at {dash_yml}")

    return client_secret


# ════════════════════════════════════════════════════════════
# STEP 7: Apply Wazuh Security Configs (securityadmin)
# ════════════════════════════════════════════════════════════
def step_wazuh_security():
    log("\n" + "="*60)
    log("STEP 7: Wazuh Security → Apply configs (securityadmin)")
    log("="*60)

    # Wait for indexer to be available
    if not wait_for("Wazuh Indexer", "https://localhost:9200/",
                     timeout=60):
        log("  ⚠ Indexer not responding, trying anyway...")

    # ── Step 7a: Copy system CA into indexer (needed for OIDC SSL trust) ──────
    # system-ca.pem is bind-mounted from host (pre-deploy.sh creates it)
    # But we also copy it here as safety in case bind-mount wasn't present at start
    log("  Verifying system-ca.pem in indexer for OIDC SSL trust...")
    try:
        # Check if bind-mount is working (file should exist from pre-deploy)
        check = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer",
             "test", "-f", "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0:
            log("  ✓ system-ca.pem exists (bind-mounted from host)")
        else:
            # Fallback: copy from container's own system CA
            subprocess.run(
                ["docker", "exec", "-u", "root", "socstack-wazuh-indexer",
                 "cp", "/etc/ssl/certs/ca-certificates.crt",
                 "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
                capture_output=True, text=True, timeout=10
            )
            subprocess.run(
                ["docker", "exec", "-u", "root", "socstack-wazuh-indexer",
                 "chmod", "644", "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
                capture_output=True, text=True, timeout=10
            )
            log("  ✓ system-ca.pem copied from container (fallback)")
    except Exception as e:
        log(f"  ✗ system-ca.pem check failed: {e}")

    # ── Step 7b: Run securityadmin FIRST (before any restart) ───────────────
    # This pushes config.yml (with correct CA path) into the live security index
    # Must run BEFORE dashboard restart so SSO config is live when dashboard starts
    log("  Running securityadmin to apply security configs (config, roles, mappings)...")
    sa_cmd = (
        "JAVA_HOME=/usr/share/wazuh-indexer/jdk "
        "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh "
        "-cd /usr/share/wazuh-indexer/config/opensearch-security/ "
        "-nhnv "
        "-cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem "
        "-cert /usr/share/wazuh-indexer/config/certs/admin.pem "
        "-key /usr/share/wazuh-indexer/config/certs/admin-key.pem "
        "-icl -p 9200"
    )

    try:
        result = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer", "bash", "-c", sa_cmd],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            log(f"  ✓ securityadmin completed successfully")
            for line in result.stdout.split("\n"):
                if "Done" in line or "success" in line.lower() or "nodes" in line.lower():
                    log(f"    {line.strip()}")
        else:
            log(f"  ✗ securityadmin failed (exit={result.returncode})")
            if result.stderr:
                for line in result.stderr.strip().split("\n")[:5]:
                    log(f"    STDERR: {line.strip()}")
            if result.stdout:
                for line in result.stdout.strip().split("\n")[:5]:
                    log(f"    STDOUT: {line.strip()}")
    except subprocess.TimeoutExpired:
        log("  ✗ securityadmin timed out (120s)")
    except Exception as e:
        log(f"  ✗ securityadmin error: {e}")

    # ── Step 7c: Safety check client_secret in dashboard config ─────────────
    dash_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml")
    if os.path.exists(dash_yml):
        with open(dash_yml) as f:
            dash_content = f.read()
        if "WILL_BE_SET_BY_POST_DEPLOY" in dash_content:
            log("  ⚠ Dashboard config still has placeholder client_secret!")
            secret = deployed.get("KC_WAZUH_CLIENT_SECRET", "")
            if secret:
                dash_content = dash_content.replace("WILL_BE_SET_BY_POST_DEPLOY", secret)
                with open(dash_yml, "w") as f:
                    f.write(dash_content)
                log(f"  ✓ Client secret injected (safety check)")
            else:
                log("  ✗ No client secret available — SSO will fail!")

    # ── Step 7d: Restart indexer to reload security plugin with new config ───
    log("  Restarting wazuh-indexer to reload security plugin...")
    try:
        subprocess.run(["docker", "restart", "socstack-wazuh-indexer"],
                      capture_output=True, text=True, timeout=30)
        log("  ✓ Wazuh indexer restarting")
    except Exception as e:
        log(f"  ✗ Indexer restart failed: {e}")

    # Wait for indexer to come back fully
    log("  Waiting for indexer to come back...")
    time.sleep(20)
    wait_for("Wazuh Indexer", "https://localhost:9200/", timeout=90)

    # ── Step 7e: system-ca.pem is bind-mounted, so it survives restart ──────
    # No need to re-copy — bind mount handles it automatically
    log("  ✓ system-ca.pem persists via bind mount (no re-copy needed)")

    # ── Step 7f: Restart dashboard AFTER indexer is ready ───────────────────
    # Dashboard needs indexer+SSO both working before it starts
    log("  Restarting wazuh-dashboard (after indexer is ready)...")
    try:
        subprocess.run(["docker", "restart", "socstack-wazuh-dashboard"],
                      capture_output=True, text=True, timeout=30)
        log("  ✓ Wazuh dashboard restarting")
    except Exception as e:
        log(f"  ✗ Dashboard restart failed: {e}")
    time.sleep(15)
    wait_for("Wazuh Dashboard", "https://localhost:5601/", timeout=90)


# ════════════════════════════════════════════════════════════
# STEP 8: Save deployed credentials
# ════════════════════════════════════════════════════════════
def save_deployed():
    log("\n" + "="*60)
    log("STEP 8: Saving deployed credentials")
    log("="*60)

    # Add remaining known creds
    deployed["WAZUH_INDEXER_USERNAME"] = env.get("WAZUH_INDEXER_USERNAME", "admin")
    deployed["WAZUH_INDEXER_PASSWORD"] = env.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")
    deployed["WAZUH_API_USER"] = env.get("WAZUH_API_USER", "wazuh-wui")
    deployed["WAZUH_API_PASSWORD"] = env.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
    deployed["KC_ADMIN_USER"] = env.get("KC_ADMIN_USER", "admin")
    deployed["KC_ADMIN_PASSWORD"] = env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")
    deployed["MISP_ADMIN_EMAIL"] = env.get("MISP_ADMIN_EMAIL", "admin@codesec.in")
    deployed["MISP_ADMIN_PASSWORD"] = env.get("MISP_ADMIN_PASSWORD", "SocMisp@2025")
    deployed["GF_ADMIN_USER"] = env.get("GF_ADMIN_USER", "admin")
    deployed["GF_ADMIN_PASSWORD"] = env.get("GF_ADMIN_PASSWORD", "SocGrafana@2025")
    deployed["MINIO_ROOT_USER"] = env.get("MINIO_ROOT_USER", "socminioadmin")
    deployed["MINIO_ROOT_PASSWORD"] = env.get("MINIO_ROOT_PASSWORD", "SocMinio@2025")

    # Add domains
    for key, cfg in DOMAINS.items():
        deployed[f"{key.upper()}_URL"] = f"https://{cfg['domain']}"

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(DEPLOYED_FILE, "w") as f:
        f.write(f"# ============================================================\n")
        f.write(f"# SOC STACK - Deployed Credentials\n")
        f.write(f"# Generated: {ts}\n")
        f.write(f"# ============================================================\n\n")

        sections = {
            "URLS": ["SSO_URL", "WAZUH_URL", "N8N_URL", "CTI_URL", "HIVE_URL", "CORTEX_URL", "GRAFANA_URL", "NPM_URL"],
            "NPM": ["NPM_ADMIN_EMAIL", "NPM_ADMIN_PASSWORD"],
            "KEYCLOAK": ["KC_ADMIN_USER", "KC_ADMIN_PASSWORD"],
            "KEYCLOAK SSO (WAZUH)": ["KC_WAZUH_REALM", "KC_WAZUH_CLIENT_ID", "KC_WAZUH_CLIENT_SECRET",
                                      "SSO_ADMIN_EMAIL", "SSO_ADMIN_PASSWORD",
                                      "SSO_USER_EMAIL", "SSO_USER_PASSWORD"],
            "WAZUH": ["WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD", "WAZUH_API_USER", "WAZUH_API_PASSWORD"],
            "N8N": ["N8N_ADMIN_EMAIL", "N8N_ADMIN_PASSWORD"],
            "MISP": ["MISP_ADMIN_EMAIL", "MISP_ADMIN_PASSWORD", "MISP_API_KEY"],
            "THEHIVE": ["THEHIVE_ADMIN_USER", "THEHIVE_ADMIN_PASSWORD", "THEHIVE_ANALYST_USER", "THEHIVE_ANALYST_PASSWORD"],
            "CORTEX": ["CORTEX_ADMIN_USER", "CORTEX_ADMIN_PASSWORD", "CORTEX_ORG_ADMIN", "CORTEX_API_KEY"],
            "GRAFANA": ["GF_ADMIN_USER", "GF_ADMIN_PASSWORD"],
            "MINIO": ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"],
        }

        for section, keys in sections.items():
            f.write(f"# === {section} ===\n")
            for k in keys:
                v = deployed.get(k, "NOT_SET")
                f.write(f"{k}={v}\n")
            f.write("\n")

    log(f"  ✓ Saved to {DEPLOYED_FILE}")

    # Save log
    with open(LOG_FILE, "w") as f:
        f.write("\n".join(log_lines))
    log(f"  ✓ Log saved to {LOG_FILE}")


# ════════════════════════════════════════════════════════════
# Print Summary
# ════════════════════════════════════════════════════════════
def print_summary():
    log("\n" + "="*60)
    log("  SOC STACK - POST-DEPLOY COMPLETE")
    log("="*60)
    log("")
    svc = [
        ("NPM",      f"https://{DOMAINS['npm']['domain']}",     NPM_EMAIL, NPM_PASS),
        ("Keycloak",  f"https://{DOMAINS['sso']['domain']}",     env.get("KC_ADMIN_USER","admin"), env.get("KC_ADMIN_PASSWORD","SocKeycloak@2025")),
        ("Wazuh",     f"https://{DOMAINS['wazuh']['domain']}",   "admin", env.get("WAZUH_INDEXER_PASSWORD","SecretPassword")),
        ("  └ SSO Admin","",                                     SSO_ADMIN_EMAIL, SSO_ADMIN_PASS),
        ("  └ SSO User","",                                      SSO_USER_EMAIL, SSO_USER_PASS),
        ("n8n",       f"https://{DOMAINS['n8n']['domain']}",     N8N_EMAIL, N8N_PASS),
        ("MISP",      f"https://{DOMAINS['cti']['domain']}",     MISP_ADMIN, MISP_PASS),
        ("TheHive",   f"https://{DOMAINS['hive']['domain']}",    THEHIVE_USER, THEHIVE_PASS),
        ("  └ Analyst","",                                       THEHIVE_ANALYST, THEHIVE_ANALYST_PASS),
        ("Cortex",    f"https://{DOMAINS['cortex']['domain']}",  CORTEX_ADMIN, CORTEX_PASS),
        ("  └ OrgAdmin","",                                      CORTEX_ORG_ADMIN, CORTEX_PASS),
        ("Grafana",   f"https://{DOMAINS['grafana']['domain']}", "admin", env.get("GF_ADMIN_PASSWORD","SocGrafana@2025")),
    ]
    for name, url, user, pwd in svc:
        if url:
            log(f"  {name:12s} {url}")
        log(f"  {'':12s} {user} / {pwd}")
        log("")

    log(f"  Credentials: {DEPLOYED_FILE}")
    log(f"  Log:         {LOG_FILE}")

    cortex_key = deployed.get("CORTEX_API_KEY", "")
    misp_key = deployed.get("MISP_API_KEY", "")
    log("")
    log("=" * 60)
    log("  MANUAL STEPS REQUIRED (UI Configuration)")
    log("=" * 60)

    log("")
    log("  ─── A. TheHive UI ────────────────────────────────────")
    log("")
    log("  1. TheHive → Cortex Server")
    log("     Platform Management → Cortex Servers → Add")
    log(f"     - Server Name:                    Cortex-CODESEC")
    log(f"     - URL:                            http://socstack-cortex:9001")
    log(f"     - API Key:                        {cortex_key}")
    log(f"     - Check Certificate Authority:    DISABLE ✗")
    log(f"     - Disable hostname verification:  ENABLE  ✓")
    log("")
    log("  2. TheHive → MISP Server")
    log("     Platform Management → MISP Servers → Add")
    log(f"     - Server Name:  MISP-CODESEC")
    log(f"     - URL:          https://socstack-misp-core:443")
    log(f"     - API Key:      {misp_key}")
    log(f"     - Skip SSL:     Yes")
    log(f"     - Purpose:      Import and Export")

    log("")
    log("  ─── B. Cortex UI ─────────────────────────────────────")
    log("")
    log("  3. Cortex → Enable Analyzers")
    log("     Organization → Analyzers → Refresh → Enable needed")

    log("")
    log("  ─── C. MISP UI ──────────────────────────────────────")
    log("")
    log("  4. MISP → Initial password change on first login")
    log(f"     URL: https://{DOMAINS['cti']['domain']}")
    log(f"     Default: admin@admin.test / admin")
    log(f"     Change to: {MISP_ADMIN} / {MISP_PASS}")

    log("")
    log("  ─── D. Wazuh Dashboard UI ───────────────────────────")
    log("")
    log("  5. Wazuh App → SSO Role Mapping")
    log("     Dashboard → Security → Roles → Create role mapping")
    log("")
    log("     Role Map 1: wazuh_admin")
    log("       - Name:          wazuh_admin")
    log("       - Permissions:   admin (all permissions)")
    log("       - Rule:          backend_roles → Find → wazuh_admin")
    log("")
    log("     Role Map 2: wazuh_read_user")
    log("       - Name:          wazuh_read_user")
    log("       - Permissions:   readonly")
    log("       - Rule:          backend_roles → Find → wazuh_read_user")

    log("")
    log("  ─── E. n8n Workflow Setup ───────────────────────────")
    log("")
    log("  6. n8n → Import Wazuh Email Alert Workflow")
    log(f"     URL: https://{DOMAINS['n8n']['domain']}")
    log("     a) Create new workflow → Import from file")
    log("        File: 1_Wazuh_Email_Alert.json")
    log("     b) Fix Redis connection first:")
    log("        - Hostname: socstack-n8n-redis")
    log("        - Password: (leave empty / no password)")
    log("     c) Setup SMTP email credentials:")
    log("        - Configure SMTP host, port, user, password")
    log("        - Set 'To' email address")
    log("     d) Enable the workflow (toggle ON)")
    log("     e) Copy the webhook URL from the Webhook node")
    log("     f) Update webhook URL in wazuh_manager.conf:")
    log("        File: configs/wazuh/wazuh_cluster/wazuh_manager.conf")
    log("        Update <hook_url> in the n8n integration section")
    log("     g) Restart Wazuh manager:")
    log("        docker restart socstack-wazuh-manager")

    log("")
    log("=" * 60)
    log(f"  Credentials file: {DEPLOYED_FILE}")
    log("=" * 60)
    log("")


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    log("="*60)
    log("  SOC STACK - Post-Deploy Configuration")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("="*60)

    # Pre-step: Fix Keycloak data dir permissions (uid 1000 = keycloak user)
    # Keycloak needs /opt/keycloak/data/tmp writable for gzip theme cache
    kc_data = os.path.join(BASE_DIR, "data", "keycloak_data")
    kc_tmp = os.path.join(kc_data, "tmp")
    if os.path.isdir(kc_data):
        os.makedirs(kc_tmp, exist_ok=True)
        subprocess.run(["chown", "-R", "1000:0", kc_data],
                       capture_output=True, timeout=10)
        log("  ✓ Keycloak data dir permissions fixed (uid=1000)")

    # Pre-step: Stop Wazuh Dashboard before NPM/SSL is ready
    # Dashboard SSO connect_url needs public domain → NPM must be configured first
    subprocess.run(["docker", "stop", "socstack-wazuh-dashboard"],
                   capture_output=True, timeout=30)
    log("  ✓ Wazuh Dashboard stopped (will restart after NPM + SSL + SSO configured)")

    # Pre-step: Fix custom-n8n integration permissions inside Wazuh manager
    # Bind-mounted files get host permissions, but need root:wazuh (gid 101) + mode 750
    try:
        result = subprocess.run(
            ["docker", "exec", "socstack-wazuh-manager", "bash", "-c",
             "chmod --reference=/var/ossec/integrations/slack /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py 2>/dev/null && "
             "chown --reference=/var/ossec/integrations/slack /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py 2>/dev/null"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            log("  ✓ custom-n8n integration: permissions fixed (root:wazuh 750)")
        else:
            log("  ↳ custom-n8n integration: not found or permissions unchanged")
    except Exception:
        log("  ↳ custom-n8n integration: container not ready (will be fixed on restart)")

    step_npm()
    step_n8n()
    cortex_key = step_cortex()
    th_auth = step_thehive()
    step_misp_thehive(th_auth)
    step_keycloak_sso()
    step_wazuh_security()
    save_deployed()
    print_summary()
