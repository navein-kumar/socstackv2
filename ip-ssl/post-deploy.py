#!/usr/bin/env python3
"""
SOC Stack (IP-SSL) Post-Deploy Configuration
=============================================
IP-based deployment: self-signed SSL + per-service ports.
Run AFTER 'docker-compose up -d' to configure all services.

Steps:
  0. NPM: Set admin credentials + upload self-signed SSL cert
  1. n8n: Create owner account (disables signup)
  2. Cortex: Migrate DB, create superadmin, org, users, API key
  3. TheHive: Change default password, create org + analyst user
  4. MISP <-> TheHive Integration
  4b. MISP Feeds: Enable all feeds, cache/download all, daily cron update
  5. Keycloak SSO: Create SOC realm, soc-sso client, groups, users
  6. Apply Wazuh security configs (securityadmin)
  7. Wazuh API: SSO role mapping via run_as
  8. Save all deployed credentials to .env.deployed

Usage:
  python3 post-deploy.py                        (from inside your deploy folder)
  python3 /any/folder/post-deploy.py            (works from any location)
"""
import requests
import json
import time
import sys
import os
import subprocess
import base64
import secrets
import re
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# BASE_DIR: auto-detect from script location (works regardless of deploy folder name)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")
DEPLOYED_FILE = os.path.join(BASE_DIR, ".env.deployed")
LOG_FILE = os.path.join(BASE_DIR, "post-deploy.log")

# == Load .env ==============================================================
env = {}
if os.path.exists(ENV_FILE):
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()

# == Config ==================================================================
NPM_PORT  = 60081
NPM_EMAIL = env.get("NPM_ADMIN_EMAIL", "admin@local.lab")
NPM_PASS  = env.get("NPM_ADMIN_PASSWORD", "SocNpm@2025")

SERVER_IP    = env.get("SERVER_IP", "127.0.0.1")
WAZUH_PORT   = env.get("WAZUH_PORT",   "8443")
SSO_PORT     = env.get("SSO_PORT",     "8444")
N8N_PORT     = env.get("N8N_PORT",     "8445")
MISP_PORT    = env.get("MISP_PORT",    "8446")
THEHIVE_PORT = env.get("THEHIVE_PORT", "8447")
CORTEX_PORT  = env.get("CORTEX_PORT",  "8448")

N8N_EMAIL = env.get("N8N_ADMIN_EMAIL", "admin@local.lab")
N8N_PASS  = env.get("N8N_ADMIN_PASSWORD", "SocN8n@2025")

CORTEX_ADMIN    = env.get("CORTEX_ADMIN_USER", "admin@local.lab")
CORTEX_PASS     = env.get("CORTEX_ADMIN_PASSWORD", "SocCortex@2025")
CORTEX_ORG      = env.get("CORTEX_ORG_NAME", "yourorg")
CORTEX_ORG_ADMIN = env.get("CORTEX_ORG_ADMIN", "orgadmin@local.lab")

THEHIVE_USER     = env.get("THEHIVE_ADMIN_USER", "admin@thehive.local")
THEHIVE_PASS     = env.get("THEHIVE_ADMIN_PASSWORD", "SocTheHive@2025")
THEHIVE_DEFAULT  = env.get("THEHIVE_DEFAULT_PASSWORD", "secret")
THEHIVE_ORG      = env.get("THEHIVE_ORG_NAME", "YOURORG")
THEHIVE_ORG_DESC = env.get("THEHIVE_ORG_DESC", "SOC Organization")
THEHIVE_ANALYST  = env.get("THEHIVE_ANALYST_USER", "analyst@local.lab")
THEHIVE_ANALYST_PASS = env.get("THEHIVE_ANALYST_PASSWORD", "SocAnalyst@2025")

MISP_ADMIN   = env.get("MISP_ADMIN_EMAIL", "admin@local.lab")
MISP_PASS    = env.get("MISP_ADMIN_PASSWORD", "SocMisp@2025")
MISP_DB_USER = env.get("MISP_DB_USER", "misp")
MISP_DB_PASS = env.get("MISP_DB_PASSWORD", "SocMispDb@2025")

KC_USER = env.get("KC_ADMIN_USER", "admin")
KC_PASS = env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")

# SSO config -- reads KC_WAZUH_REALM / KC_WAZUH_CLIENT_ID from .env (falls back to SSO_REALM/SSO_CLIENT_ID)
SSO_REALM      = env.get("KC_WAZUH_REALM", env.get("SSO_REALM", "SOC"))
SSO_CLIENT_ID  = env.get("KC_WAZUH_CLIENT_ID", env.get("SSO_CLIENT_ID", "soc-sso"))

SSO_GROUP_ADMIN    = env.get("SSO_GROUP_ADMIN", "soc-admin")
SSO_GROUP_ANALYST  = env.get("SSO_GROUP_ANALYST", "soc-analyst")
SSO_GROUP_READONLY = env.get("SSO_GROUP_READONLY", "soc-readonly")

SSO_ADMIN_EMAIL = env.get("SSO_ADMIN_EMAIL", "admin@local.lab")
SSO_ADMIN_PASS  = env.get("SSO_ADMIN_PASSWORD", "SocSsoAdmin@2025")
SSO_ADMIN_FIRST = env.get("SSO_ADMIN_FIRST", "SOC")
SSO_ADMIN_LAST  = env.get("SSO_ADMIN_LAST", "Admin")

SSO_ANALYST_EMAIL = env.get("SSO_ANALYST_EMAIL", "analyst@local.lab")
SSO_ANALYST_PASS  = env.get("SSO_ANALYST_PASSWORD", "SocSsoAnalyst@2025")
SSO_ANALYST_FIRST = env.get("SSO_ANALYST_FIRST", "SOC")
SSO_ANALYST_LAST  = env.get("SSO_ANALYST_LAST", "Analyst")

SSO_READONLY_EMAIL = env.get("SSO_READONLY_EMAIL", "readonly@local.lab")
SSO_READONLY_PASS  = env.get("SSO_READONLY_PASSWORD", "SocSsoReadonly@2025")
SSO_READONLY_FIRST = env.get("SSO_READONLY_FIRST", "SOC")
SSO_READONLY_LAST  = env.get("SSO_READONLY_LAST", "Readonly")

WAZUH_API_USER = env.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = env.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")

# IP:PORT based service URLs (internal access for API calls)
MISP_INTERNAL = "https://localhost:18443"   # MISP container direct port

# Public-facing URLs (via nginx on SERVER_IP)
SERVICES = {
    "wazuh":   f"https://{SERVER_IP}:{WAZUH_PORT}",
    "sso":     f"https://{SERVER_IP}:{SSO_PORT}",
    "n8n":     f"https://{SERVER_IP}:{N8N_PORT}",
    "misp":    f"https://{SERVER_IP}:{MISP_PORT}",
    "thehive": f"https://{SERVER_IP}:{THEHIVE_PORT}",
    "cortex":  f"https://{SERVER_IP}:{CORTEX_PORT}",
}

deployed = {}
log_lines = []
results = {}


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
                log(f"  -> {name} ready ({int(time.time()-start)}s)")
                return True
        except:
            pass
        time.sleep(3)
    log(f"  X {name} TIMEOUT after {timeout}s")
    return False


# ====================================================================
# STEP 0: NPM - Set admin credentials + upload self-signed cert
# ====================================================================
def step_npm():
    log("\n" + "="*60)
    log("STEP 0: Nginx Proxy Manager -> Admin setup + SSL cert upload")
    log("="*60)

    NPM = f"http://localhost:{NPM_PORT}"
    if not wait_for("NPM", f"{NPM}/api/"):
        results["npm"] = "FAIL"
        return

    # Login — try configured creds first, then legacy defaults, then create fresh admin
    resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
    if resp.status_code != 200:
        resp = requests.post(f"{NPM}/api/tokens", json={"identity": "admin@example.com", "secret": "changeme"})
        if resp.status_code == 200:
            t = resp.json()["token"]
            h = {"Authorization": f"Bearer {t}", "Content-Type": "application/json"}
            requests.put(f"{NPM}/api/users/1", headers=h, json={"email": NPM_EMAIL, "nickname": "Admin", "is_disabled": False, "roles": ["admin"]})
            requests.put(f"{NPM}/api/users/1/auth", headers=h, json={"type": "password", "current": "changeme", "secret": NPM_PASS})
            resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
        else:
            # NPM >= 2.14: empty user table on first start
            try:
                create_resp = requests.post(f"{NPM}/api/users", json={
                    "name": "Administrator", "nickname": "Admin", "email": NPM_EMAIL,
                    "roles": ["admin"], "is_disabled": False,
                    "auth": {"type": "password", "secret": NPM_PASS}
                })
                if create_resp.status_code in (200, 201):
                    log("  -> Initial admin user created")
                    resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
            except Exception as e:
                log(f"  X NPM setup failed: {e}")

    if resp.status_code != 200:
        log(f"  X NPM login failed: {resp.status_code}")
        results["npm"] = "FAIL"
        return

    token = resp.json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    log("  -> NPM authenticated")
    deployed["NPM_ADMIN_EMAIL"] = NPM_EMAIL
    deployed["NPM_ADMIN_PASSWORD"] = NPM_PASS

    # Upload self-signed cert so it's visible in NPM UI
    cert_path = os.path.join(BASE_DIR, "certs", "server.crt")
    key_path  = os.path.join(BASE_DIR, "certs", "server.key")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Check if cert already uploaded
        certs = requests.get(f"{NPM}/api/nginx/certificates", headers=h).json()
        existing = [c for c in certs if c.get("nice_name") == "socstack-self-signed"]
        if existing:
            log(f"  -> Self-signed cert already uploaded (ID={existing[0]['id']})")
        else:
            with open(cert_path, "rb") as cf, open(key_path, "rb") as kf:
                r = requests.post(
                    f"{NPM}/api/nginx/certificates",
                    headers=h,
                    data={"nice_name": "socstack-self-signed", "provider": "other"},
                    files={"certificate": cf, "certificate_key": kf}
                )
            if r.status_code == 201:
                log(f"  -> Self-signed cert uploaded (ID={r.json()['id']})")
            else:
                log(f"  ~ Cert upload: {r.status_code} {r.text[:100]}")
    else:
        log(f"  ~ Cert files not found at {cert_path} — run pre-deploy.sh first")

    results["npm"] = "OK"
    log("  -> NPM step complete")


# ====================================================================
# STEP 1: n8n - Owner Setup (disables signup)
# ====================================================================
def step_n8n():
    log("\n" + "="*60)
    log("STEP 1: n8n -> Owner Account (signup disabled)")
    log("="*60)

    if not wait_for("n8n", "http://localhost:5678"):
        return

    r = requests.get("http://localhost:5678/rest/settings")
    if r.status_code == 200:
        show = r.json().get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad", True)
        if not show:
            log("  -> Owner already configured, signup disabled")
            deployed["N8N_ADMIN_EMAIL"] = N8N_EMAIL
            deployed["N8N_ADMIN_PASSWORD"] = N8N_PASS
            return

    r = requests.post("http://localhost:5678/rest/owner/setup", json={
        "email": N8N_EMAIL, "firstName": "SOC", "lastName": "Admin", "password": N8N_PASS
    })
    if r.status_code == 200:
        log(f"  -> Owner created: {N8N_EMAIL}")
        log("  -> Signup now disabled (invite-only)")
    else:
        log(f"  X Owner setup: {r.status_code} {r.text[:150]}")
    deployed["N8N_ADMIN_EMAIL"] = N8N_EMAIL
    deployed["N8N_ADMIN_PASSWORD"] = N8N_PASS


# ====================================================================
# STEP 2: Cortex - Migrate + SuperAdmin + Org + API Key
# ====================================================================
def step_cortex():
    log("\n" + "="*60)
    log("STEP 2: Cortex -> Init, Org, Users, API Key")
    log("="*60)

    CURL = "http://localhost:9001"
    if not wait_for("Cortex", f"{CURL}/api/status"):
        return None

    session = requests.Session()
    session.get(f"{CURL}/")
    csrf = session.cookies.get("CORTEX-XSRF-TOKEN", "")
    if csrf:
        session.headers.update({"X-CORTEX-XSRF-TOKEN": csrf})

    r = session.post(f"{CURL}/api/login", json={"user": CORTEX_ADMIN, "password": CORTEX_PASS})
    if r.status_code != 200:
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
            log(f"  X Cortex login failed after init")
            return None
    log(f"  -> Logged in as {r.json().get('name')}")
    deployed["CORTEX_ADMIN_USER"] = CORTEX_ADMIN
    deployed["CORTEX_ADMIN_PASSWORD"] = CORTEX_PASS

    r = session.post(f"{CURL}/api/organization", json={
        "name": CORTEX_ORG, "description": "SOC Organization", "status": "Active"
    })
    if r.status_code == 201:
        log(f"  -> Organization '{CORTEX_ORG}' created")
    else:
        log(f"  -> Organization: already exists or {r.status_code}")

    r = session.post(f"{CURL}/api/user", json={
        "login": CORTEX_ORG_ADMIN, "name": "Org Admin",
        "roles": ["read", "analyze", "orgadmin"],
        "organization": CORTEX_ORG, "password": CORTEX_PASS
    })
    if r.status_code == 201:
        log(f"  -> Org admin created: {CORTEX_ORG_ADMIN}")
    else:
        log(f"  -> Org admin: already exists or {r.status_code}")
    deployed["CORTEX_ORG_ADMIN"] = CORTEX_ORG_ADMIN

    r = session.post(f"{CURL}/api/user/{CORTEX_ORG_ADMIN}/key/renew", json={})
    if r.status_code == 200:
        api_key = r.text.strip().strip('"')
        log(f"  -> API Key: {api_key}")
        with open(os.path.join(BASE_DIR, ".cortex-api-key"), "w") as f:
            f.write(api_key)
        deployed["CORTEX_API_KEY"] = api_key
        return api_key
    else:
        r = session.get(f"{CURL}/api/user/{CORTEX_ORG_ADMIN}/key")
        if r.status_code == 200:
            api_key = r.text.strip().strip('"')
            log(f"  -> Existing API Key: {api_key}")
            deployed["CORTEX_API_KEY"] = api_key
            return api_key
    log(f"  X API key failed")
    return None


# ====================================================================
# STEP 3: TheHive - Password + Org + Analyst User
# ====================================================================
def step_thehive():
    log("\n" + "="*60)
    log("STEP 3: TheHive -> Password, Org, Analyst User")
    log("="*60)

    TH = "http://localhost:9000"
    if not wait_for("TheHive", f"{TH}/api/v1/status", timeout=180):
        return

    auth = None
    r = requests.get(f"{TH}/api/v1/user/current", auth=(THEHIVE_USER, THEHIVE_PASS))
    if r.status_code == 200:
        log(f"  -> Admin password already set")
        auth = (THEHIVE_USER, THEHIVE_PASS)
    else:
        r = requests.get(f"{TH}/api/v1/user/current", auth=(THEHIVE_USER, THEHIVE_DEFAULT))
        if r.status_code == 200:
            log("  Changing default password...")
            r = requests.post(f"{TH}/api/v1/user/{THEHIVE_USER}/password/set",
                              auth=(THEHIVE_USER, THEHIVE_DEFAULT),
                              json={"password": THEHIVE_PASS})
            if r.status_code == 204:
                log(f"  -> Password changed for {THEHIVE_USER}")
                auth = (THEHIVE_USER, THEHIVE_PASS)
            else:
                log(f"  X Password change failed: {r.status_code}")
                auth = (THEHIVE_USER, THEHIVE_DEFAULT)
        else:
            log("  X Cannot login with default or new password")
            return

    deployed["THEHIVE_ADMIN_USER"] = THEHIVE_USER
    deployed["THEHIVE_ADMIN_PASSWORD"] = THEHIVE_PASS

    log(f"\n  Creating organization '{THEHIVE_ORG}'...")
    r = requests.post(f"{TH}/api/v1/organisation", auth=auth,
                      headers={"Content-Type": "application/json"},
                      json={"name": THEHIVE_ORG, "description": THEHIVE_ORG_DESC})
    if r.status_code == 201:
        org_id = r.json().get("_id")
        log(f"  -> Organization created: {THEHIVE_ORG} (ID={org_id})")
    elif r.status_code in (400, 409):
        log(f"  -> Organization already exists")
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
        log(f"  X Org creation: {r.status_code} {r.text[:150]}")
        org_id = None

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
        log(f"  -> Analyst created: {THEHIVE_ANALYST}")
        r2 = requests.post(f"{TH}/api/v1/user/{THEHIVE_ANALYST}/password/set",
                           auth=auth, json={"password": THEHIVE_ANALYST_PASS})
        if r2.status_code == 204:
            log(f"  -> Analyst password set")
    elif "already exist" in r.text.lower() or r.status_code == 400:
        log(f"  -> Analyst already exists")
    else:
        log(f"  X Analyst creation: {r.status_code} {r.text[:150]}")

    deployed["THEHIVE_ANALYST_USER"] = THEHIVE_ANALYST
    deployed["THEHIVE_ANALYST_PASSWORD"] = THEHIVE_ANALYST_PASS
    return auth


# ====================================================================
# STEP 4: MISP <-> TheHive Integration
# ====================================================================
def step_misp_thehive(th_auth):
    log("\n" + "="*60)
    log("STEP 4: MISP <-> TheHive Integration")
    log("="*60)

    TH = "http://localhost:9000"

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
        log(f"  X Failed to get MISP key: {e}")
        misp_key = None

    if not misp_key:
        log("  X MISP API key not found")
        return

    log(f"  -> MISP API Key: {misp_key}")
    deployed["MISP_API_KEY"] = misp_key

    # Verify MISP key works (via direct container port)
    r = requests.get(f"{MISP_INTERNAL}/servers/getVersion",
                      headers={"Authorization": misp_key, "Accept": "application/json"},
                      verify=False)
    if r.status_code == 200:
        ver = r.json().get("version", "?")
        log(f"  -> MISP API verified (v{ver})")
    else:
        log(f"  X MISP API verification failed: {r.status_code}")
        return

    if not th_auth:
        log("  X TheHive auth not available, skipping integration")
        return

    # MISP internal URL (container-to-container)
    misp_url = "https://socstack-misp-core:443"
    log(f"\n  Configuring TheHive -> MISP connector...")
    log(f"  MISP internal URL: {misp_url}")

    r = requests.post(f"{TH}/api/v1/query", auth=th_auth,
                      headers={"Content-Type": "application/json"},
                      json={"query": [{"_name": "listConnector"}]})
    if r.status_code == 200:
        connectors = r.json()
        misp_exists = any(c.get("name") == "MISP-SOC" for c in connectors)
        if misp_exists:
            log("  -> MISP connector already configured in TheHive")
            return

    r = requests.post(f"{TH}/api/connector/misp", auth=th_auth,
                      headers={"Content-Type": "application/json"},
                      json={
                          "name": "MISP-SOC",
                          "url": misp_url,
                          "auth": {"type": "key", "key": misp_key},
                          "wsConfig": {"ssl": {"loose.acceptAnyCertificate": True}},
                          "purpose": "ImportAndExport",
                          "includedTheHiveOrganisations": [THEHIVE_ORG],
                          "maxAttributes": 10000,
                          "maxAge": 365
                      })
    if r.status_code in (200, 201):
        log(f"  -> MISP connector added to TheHive")
    elif r.status_code == 404:
        log(f"  -> MISP connector API not available (configure via UI)")
        log(f"    URL: {misp_url}")
        log(f"    API Key: {misp_key}")
        log(f"    -> Go to TheHive UI -> Platform Management -> MISP Servers -> Add")
    else:
        log(f"  -> MISP connector: {r.status_code} {r.text[:150]}")
        log(f"    Configure manually in TheHive UI:")
        log(f"    URL: {misp_url}")
        log(f"    API Key: {misp_key}")


# ====================================================================
# STEP 4b: MISP Feeds -> Load Defaults, Enable All, Cache All
# ====================================================================
def step_misp_feeds():
    log("\n" + "="*60)
    log("STEP 4b: MISP Feeds -> Load Defaults + Enable All + Cache All")
    log("="*60)

    MISP_URL = MISP_INTERNAL

    log("  Retrieving MISP API key...")
    misp_key = deployed.get("MISP_API_KEY")
    if not misp_key:
        try:
            result = subprocess.run(
                ["docker", "exec", "socstack-misp-db", "mysql", "-u", MISP_DB_USER,
                 f"-p{MISP_DB_PASS}", "misp", "-N", "-e",
                 f"SELECT authkey FROM users WHERE email='{MISP_ADMIN}' LIMIT 1;"],
                capture_output=True, text=True, timeout=10
            )
            misp_key = result.stdout.strip()
        except Exception as e:
            log(f"  X Failed to get MISP key: {e}")

    if not misp_key:
        log("  X MISP API key not available -- skipping feed setup")
        return

    mh = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        r = requests.get(f"{MISP_URL}/servers/getVersion", headers=mh, verify=False, timeout=10)
        if r.status_code != 200:
            log(f"  X MISP not responding ({r.status_code}) -- skipping feed setup")
            return
        log(f"  -> MISP API reachable (v{r.json().get('version','?')})")
    except Exception as e:
        log(f"  X MISP connection failed: {e}")
        return

    # Load default feeds
    log("\n  Loading default MISP feeds...")
    try:
        r = requests.post(f"{MISP_URL}/feeds/loadDefaultFeeds",
                          headers=mh, json={}, verify=False, timeout=60)
        if r.status_code == 200:
            log(f"  -> Default feeds loaded successfully")
        else:
            log(f"  -> Load defaults: {r.status_code} {r.text[:150]}")
    except Exception as e:
        log(f"  X Load defaults error: {e}")

    # List feeds
    log("  Fetching feed list...")
    try:
        r = requests.get(f"{MISP_URL}/feeds/index", headers=mh, verify=False, timeout=30)
        if r.status_code != 200:
            log(f"  X Feed list failed: {r.status_code}")
            return
        feeds = r.json()
        if isinstance(feeds, list) and feeds and "Feed" in feeds[0]:
            feed_list = [f["Feed"] for f in feeds]
        elif isinstance(feeds, list):
            feed_list = feeds
        else:
            log(f"  X Unexpected feed format: {type(feeds)}")
            return
        log(f"  -> Found {len(feed_list)} feeds total")
    except Exception as e:
        log(f"  X Feed list error: {e}")
        return

    # Enable all feeds
    disabled_feeds = [f for f in feed_list if not f.get("enabled")]
    already_enabled = len(feed_list) - len(disabled_feeds)
    log(f"  -> {already_enabled} already enabled, {len(disabled_feeds)} to enable")

    enabled_count = 0
    failed_count = 0
    for feed in disabled_feeds:
        fid = feed.get("id")
        fname = feed.get("name", f"Feed-{fid}")
        try:
            r = requests.post(f"{MISP_URL}/feeds/enable/{fid}",
                              headers=mh, json={}, verify=False, timeout=15)
            if r.status_code == 200:
                enabled_count += 1
            else:
                failed_count += 1
                if failed_count <= 3:
                    log(f"  X Enable failed: {fname} ({r.status_code})")
        except Exception as e:
            failed_count += 1

    if enabled_count > 0:
        log(f"  -> Enabled {enabled_count} feeds")

    # Enable caching
    log("\n  Enabling caching on all feeds...")
    cache_enabled = 0
    for feed in feed_list:
        fid = feed.get("id")
        if not feed.get("caching_enabled"):
            try:
                r = requests.post(f"{MISP_URL}/feeds/edit/{fid}",
                                  headers=mh, json={"Feed": {"caching_enabled": 1}},
                                  verify=False, timeout=15)
                if r.status_code == 200:
                    cache_enabled += 1
            except Exception:
                pass
    log(f"  -> Caching enabled on {cache_enabled} additional feeds")

    # Cache all feeds
    log("\n  Caching all enabled feeds (initial download)...")
    try:
        r = requests.post(f"{MISP_URL}/feeds/cacheFeeds/all",
                          headers=mh, json={}, verify=False, timeout=600)
        if r.status_code == 200:
            log(f"  -> Feed cache initiated successfully")
        else:
            log(f"  -> Feed cache response: {r.status_code} {r.text[:150]}")
    except requests.exceptions.Timeout:
        log("  -> Feed cache running (timed out, continues in background)")
    except Exception as e:
        log(f"  X Feed cache error: {e}")

    # Fetch from all feeds
    log("  Fetching data from all enabled feeds...")
    try:
        r = requests.post(f"{MISP_URL}/feeds/fetchFromAllFeeds",
                          headers=mh, json={}, verify=False, timeout=600)
        if r.status_code == 200:
            log(f"  -> Feed fetch initiated successfully")
        else:
            log(f"  -> Feed fetch response: {r.status_code} {r.text[:150]}")
    except requests.exceptions.Timeout:
        log("  -> Feed fetch running (timed out, continues in background)")
    except Exception as e:
        log(f"  X Feed fetch error: {e}")

    total_enabled = already_enabled + enabled_count
    log(f"\n  MISP Feeds Summary:")
    log(f"    Total feeds:   {len(feed_list)}")
    log(f"    Enabled:       {total_enabled}")
    log(f"    Daily updates: MISP built-in scheduler (every 86400s)")


# ====================================================================
# STEP 5: Keycloak SSO -> SOC Realm + Client + Groups + Users
# ====================================================================
def step_keycloak_sso():
    log("\n" + "="*60)
    log("STEP 5: Keycloak SSO -> SOC Realm + soc-sso Client")
    log("="*60)

    KC = "http://localhost:8081"
    if not wait_for("Keycloak", f"{KC}/realms/master"):
        return None

    # Get master token
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": KC_USER, "password": KC_PASS,
    })
    if r.status_code != 200:
        log(f"  X Keycloak admin login failed: {r.status_code}")
        return None
    token = r.json()["access_token"]
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    log(f"  -> Keycloak admin authenticated")

    # Create realm
    r = requests.get(f"{KC}/admin/realms/{SSO_REALM}", headers=h)
    if r.status_code == 200:
        log(f"  -> Realm '{SSO_REALM}' already exists")
    else:
        r = requests.post(f"{KC}/admin/realms", headers=h, json={
            "realm": SSO_REALM, "enabled": True,
            "displayName": "SOC SSO",
            "loginWithEmailAllowed": True,
            "sslRequired": "none",
        })
        if r.status_code == 201:
            log(f"  -> Realm '{SSO_REALM}' created")
        else:
            log(f"  X Realm creation failed: {r.status_code} {r.text[:150]}")
            return None

    # IP:PORT based redirect URIs (no domain names)
    wazuh_url   = f"https://{SERVER_IP}:{WAZUH_PORT}"
    cortex_url  = f"https://{SERVER_IP}:{CORTEX_PORT}"
    thehive_url = f"https://{SERVER_IP}:{THEHIVE_PORT}"
    n8n_url     = f"https://{SERVER_IP}:{N8N_PORT}"

    misp_url    = f"https://{SERVER_IP}:{MISP_PORT}"

    redirect_uris = [
        f"{wazuh_url}/*",
        f"{cortex_url}/api/ssoLogin",
        f"{thehive_url}/oauth2/callback",       # oauth2-proxy callback
        f"{thehive_url}/api/ssoLogin",           # legacy (kept for reference)
        f"{n8n_url}/oauth2/callback",
        f"{misp_url}/users/login",               # MISP native OIDC
        f"{misp_url}/*",
    ]
    web_origins = [wazuh_url, cortex_url, thehive_url, n8n_url, misp_url]
    post_logout_uris = "+".join([
        f"{wazuh_url}/*", f"{cortex_url}/*",
        f"{thehive_url}/*", f"{n8n_url}/*",
        f"{misp_url}/*",
    ])

    # Create / find client
    r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/clients?clientId={SSO_CLIENT_ID}", headers=h)
    existing_clients = r.json() if r.status_code == 200 else []
    client_uuid = None

    # Use static client secret from .env (generated by pre-deploy.sh)
    # This ensures oauth2-proxy containers start with the correct secret
    # on first boot — no chicken-and-egg dependency
    static_secret = env.get("SSO_CLIENT_SECRET", "")
    if not static_secret:
        log("  ! SSO_CLIENT_SECRET not set in .env — generating one")
        static_secret = secrets.token_urlsafe(32)

    if existing_clients:
        client_uuid = existing_clients[0]["id"]
        log(f"  -> Client '{SSO_CLIENT_ID}' already exists (UUID={client_uuid[:8]}...)")
        # Update redirect URIs, web origins, post-logout URIs, AND set static secret
        r = requests.put(f"{KC}/admin/realms/{SSO_REALM}/clients/{client_uuid}", headers=h, json={
            "clientId": SSO_CLIENT_ID,
            "secret": static_secret,
            "redirectUris": redirect_uris,
            "webOrigins": web_origins,
            "attributes": {
                "post.logout.redirect.uris": post_logout_uris,
            },
        })
        if r.status_code == 204:
            log(f"  -> Client updated (secret synced from .env)")
        else:
            log(f"  ! Client update returned: {r.status_code}")
    else:
        r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/clients", headers=h, json={
            "clientId": SSO_CLIENT_ID,
            "name": "SOC SSO Client",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": static_secret,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False,
            "redirectUris": redirect_uris,
            "webOrigins": web_origins,
            "attributes": {"post.logout.redirect.uris": post_logout_uris},
        })
        if r.status_code == 201:
            loc = r.headers.get("Location", "")
            client_uuid = loc.rsplit("/", 1)[-1] if loc else None
            if not client_uuid:
                r2 = requests.get(f"{KC}/admin/realms/{SSO_REALM}/clients?clientId={SSO_CLIENT_ID}", headers=h)
                if r2.status_code == 200 and r2.json():
                    client_uuid = r2.json()[0]["id"]
            log(f"  -> Client '{SSO_CLIENT_ID}' created (UUID={client_uuid[:8]}...)")
        else:
            log(f"  X Client creation failed: {r.status_code} {r.text[:150]}")
            return None

    # Add 'groups' protocol mapper
    if client_uuid:
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/clients/{client_uuid}/protocol-mappers/models", headers=h)
        existing_mappers = [m["name"] for m in r.json()] if r.status_code == 200 else []
        if "groups" not in existing_mappers:
            r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/clients/{client_uuid}/protocol-mappers/models", headers=h, json={
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
                log(f"  -> Protocol mapper 'groups' added")
        else:
            log(f"  -> Protocol mapper 'groups' already exists")

    # -- Client secret: use static value from .env -----------------------
    # The secret was already set during client creation/update above.
    # No need to read from Keycloak — .env is the single source of truth.
    client_secret = static_secret
    log(f"  -> Client secret (from .env): {client_secret[:8]}...{client_secret[-4:]}")
    deployed["SSO_CLIENT_SECRET"] = client_secret

    # Create groups
    for group_name in [SSO_GROUP_ADMIN, SSO_GROUP_ANALYST, SSO_GROUP_READONLY]:
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/groups?search={group_name}&exact=true", headers=h)
        existing = r.json() if r.status_code == 200 else []
        if existing:
            log(f"  -> Group '{group_name}' already exists")
        else:
            r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/groups", headers=h, json={"name": group_name})
            if r.status_code == 201:
                log(f"  -> Group '{group_name}' created")
            else:
                log(f"  X Group '{group_name}': {r.status_code} {r.text[:100]}")

    def get_group_id(name):
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/groups?search={name}&exact=true", headers=h)
        groups = r.json() if r.status_code == 200 else []
        for g in groups:
            if g["name"] == name:
                return g["id"]
        return None

    # Create SSO users
    sso_users = [
        {"email": SSO_ADMIN_EMAIL,    "password": SSO_ADMIN_PASS,
         "first": SSO_ADMIN_FIRST,    "last": SSO_ADMIN_LAST,    "group": SSO_GROUP_ADMIN},
        {"email": SSO_ANALYST_EMAIL,  "password": SSO_ANALYST_PASS,
         "first": SSO_ANALYST_FIRST,  "last": SSO_ANALYST_LAST,  "group": SSO_GROUP_ANALYST},
        {"email": SSO_READONLY_EMAIL, "password": SSO_READONLY_PASS,
         "first": SSO_READONLY_FIRST, "last": SSO_READONLY_LAST, "group": SSO_GROUP_READONLY},
    ]

    for u in sso_users:
        username = u["email"]
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/users?username={username}&exact=true", headers=h)
        existing_users = r.json() if r.status_code == 200 else []
        user_id = None

        if existing_users:
            user_id = existing_users[0]["id"]
            log(f"  -> User '{username}' already exists")
        else:
            r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/users", headers=h, json={
                "username": username, "email": username,
                "firstName": u["first"], "lastName": u["last"],
                "enabled": True, "emailVerified": True,
                "credentials": [{"type": "password", "value": u["password"], "temporary": False}],
            })
            if r.status_code == 201:
                loc = r.headers.get("Location", "")
                user_id = loc.rsplit("/", 1)[-1] if loc else None
                if not user_id:
                    r2 = requests.get(f"{KC}/admin/realms/{SSO_REALM}/users?username={username}&exact=true", headers=h)
                    if r2.status_code == 200 and r2.json():
                        user_id = r2.json()[0]["id"]
                log(f"  -> User '{username}' created (group={u['group']})")
            else:
                log(f"  X User '{username}': {r.status_code} {r.text[:100]}")

        if user_id:
            group_id = get_group_id(u["group"])
            if group_id:
                r = requests.put(f"{KC}/admin/realms/{SSO_REALM}/users/{user_id}/groups/{group_id}", headers=h)
                if r.status_code == 204:
                    log(f"  -> User '{username}' -> group '{u['group']}'")

    deployed["SSO_ADMIN_EMAIL"]    = SSO_ADMIN_EMAIL
    deployed["SSO_ADMIN_PASSWORD"] = SSO_ADMIN_PASS
    deployed["SSO_ANALYST_EMAIL"]   = SSO_ANALYST_EMAIL
    deployed["SSO_ANALYST_PASSWORD"] = SSO_ANALYST_PASS
    deployed["SSO_READONLY_EMAIL"]  = SSO_READONLY_EMAIL
    deployed["SSO_READONLY_PASSWORD"] = SSO_READONLY_PASS
    deployed["SSO_REALM"]           = SSO_REALM
    deployed["SSO_CLIENT_ID"]       = SSO_CLIENT_ID

    # Inject client_secret into config files
    if client_secret:
        sso_base     = f"https://{SERVER_IP}:{SSO_PORT}"
        wazuh_base   = f"https://{SERVER_IP}:{WAZUH_PORT}"
        oidc_url     = f"{sso_base}/realms/{SSO_REALM}/.well-known/openid-configuration"
        logout_url   = f"{sso_base}/realms/{SSO_REALM}/protocol/openid-connect/logout"

        # 1. opensearch_dashboards.yml
        dash_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml")
        if os.path.exists(dash_yml):
            with open(dash_yml) as f:
                content = f.read()
            changed = False
            if "WILL_BE_SET_BY_POST_DEPLOY" in content:
                content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
                changed = True
            # Update OIDC URLs to IP:PORT
            content = re.sub(
                r'(opensearch_security\.openid\.connect_url:\s*)(".*?"|[^\s]+)',
                f'\\1"{oidc_url}"', content
            )
            content = re.sub(
                r'(opensearch_security\.openid\.base_redirect_url:\s*)(".*?"|[^\s]+)',
                f'\\1"{wazuh_base}"', content
            )
            content = re.sub(
                r'(opensearch_security\.openid\.logout_url:\s*)(".*?"|[^\s]+)',
                f'\\1"{logout_url}"', content
            )
            changed = True
            with open(dash_yml, "w") as f:
                f.write(content)
            log(f"  -> opensearch_dashboards.yml updated (secret + OIDC URLs → IP:PORT)")

        # 2. config.yml (Wazuh Indexer OpenID)
        cfg_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_indexer/config.yml")
        if os.path.exists(cfg_yml):
            with open(cfg_yml) as f:
                content = f.read()
            content = re.sub(
                r'(openid_connect_url:\s*)"[^"]+"',
                f'\\1"{oidc_url}"', content
            )
            with open(cfg_yml, "w") as f:
                f.write(content)
            log(f"  -> config.yml updated (OIDC URL → IP:PORT)")

        # 3. cortex-application.conf (Cortex OAuth2 SSO)
        cortex_conf = os.path.join(BASE_DIR, "configs/thehive/cortex-application.conf")
        if os.path.exists(cortex_conf):
            with open(cortex_conf) as f:
                content = f.read()
            content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
            content = content.replace("YOUR_SERVER_IP", SERVER_IP)
            content = content.replace("YOUR_SSO_PORT", SSO_PORT)
            content = content.replace("YOUR_CORTEX_PORT", CORTEX_PORT)
            content = content.replace("YOUR_SSO_REALM", SSO_REALM)
            content = content.replace("YOUR_SSO_CLIENT_ID", SSO_CLIENT_ID)
            content = content.replace("YOUR_CORTEX_ORG_NAME", CORTEX_ORG)
            with open(cortex_conf, "w") as f:
                f.write(content)
            log(f"  -> cortex-application.conf updated (SSO secret + IP:PORT + org)")

        # 4. thehive-application.conf (TheHive OAuth2 SSO - reference config)
        thehive_conf = os.path.join(BASE_DIR, "configs/thehive/thehive-application.conf")
        if os.path.exists(thehive_conf):
            with open(thehive_conf) as f:
                content = f.read()
            content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
            content = content.replace("YOUR_SERVER_IP", SERVER_IP)
            content = content.replace("YOUR_SSO_PORT", SSO_PORT)
            content = content.replace("YOUR_THEHIVE_PORT", THEHIVE_PORT)
            content = content.replace("YOUR_SSO_REALM", SSO_REALM)
            content = content.replace("YOUR_SSO_CLIENT_ID", SSO_CLIENT_ID)
            content = content.replace("YOUR_THEHIVE_ORG_NAME", THEHIVE_ORG)
            with open(thehive_conf, "w") as f:
                f.write(content)
            log(f"  -> thehive-application.conf updated (SSO secret + IP:PORT + org)")

    # Save SSO_CLIENT_SECRET + OAUTH2_PROXY_COOKIE_SECRET to .env (single read/write)
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            env_content = f.read()

        # SSO_CLIENT_SECRET
        if client_secret:
            if re.search(r'^SSO_CLIENT_SECRET=', env_content, re.MULTILINE):
                env_content = re.sub(
                    r'^SSO_CLIENT_SECRET=.*$',
                    f'SSO_CLIENT_SECRET={client_secret}',
                    env_content, flags=re.MULTILINE
                )
            else:
                env_content = env_content.rstrip() + f"\nSSO_CLIENT_SECRET={client_secret}\n"
            log(f"  -> SSO_CLIENT_SECRET saved to .env")

        # OAUTH2_PROXY_COOKIE_SECRET (reuse existing, generate only if missing)
        cookie_secret = env.get("OAUTH2_PROXY_COOKIE_SECRET", "")
        if cookie_secret:
            log(f"  -> OAUTH2_PROXY_COOKIE_SECRET already in .env (reusing)")
        else:
            cookie_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
            env_content = env_content.rstrip() + f"\nOAUTH2_PROXY_COOKIE_SECRET={cookie_secret}\n"
            log(f"  -> OAUTH2_PROXY_COOKIE_SECRET generated and saved to .env")
        deployed["OAUTH2_PROXY_COOKIE_SECRET"] = cookie_secret

        with open(env_path, "w") as f:
            f.write(env_content)

    # Restart Cortex + TheHive so they reload their updated application.conf files
    log("  Restarting Cortex and TheHive to reload SSO application.conf...")
    for svc in ["socstack-cortex", "socstack-thehive"]:
        try:
            r = subprocess.run(
                ["docker", "compose", "-f", os.path.join(BASE_DIR, "docker-compose.yml"),
                 "up", "-d", "--no-deps", svc],
                capture_output=True, text=True, timeout=120, cwd=BASE_DIR
            )
            if r.returncode == 0:
                log(f"  -> {svc} restarted OK")
            else:
                r2 = subprocess.run(
                    ["docker-compose", "-f", os.path.join(BASE_DIR, "docker-compose.yml"),
                     "up", "-d", "--no-deps", svc],
                    capture_output=True, text=True, timeout=120, cwd=BASE_DIR
                )
                if r2.returncode == 0:
                    log(f"  -> {svc} restarted OK (via docker-compose)")
                else:
                    log(f"  ! {svc} restart failed: {r.stderr[:200]}")
        except Exception as e:
            log(f"  X {svc} restart error: {e}")

    # Restart oauth2-proxy containers so they pick up the new SSO_CLIENT_SECRET and cookie secret
    log("  Restarting oauth2-proxy containers with updated SSO credentials...")
    for svc in ["socstack-oauth2-proxy-hive", "socstack-oauth2-proxy-n8n"]:
        try:
            r = subprocess.run(
                ["docker", "compose", "-f", os.path.join(BASE_DIR, "docker-compose.yml"),
                 "up", "-d", "--no-deps", svc],
                capture_output=True, text=True, timeout=60, cwd=BASE_DIR
            )
            if r.returncode == 0:
                log(f"  -> {svc} restarted OK")
            else:
                # Fallback: try docker-compose (older CLI)
                r2 = subprocess.run(
                    ["docker-compose", "-f", os.path.join(BASE_DIR, "docker-compose.yml"),
                     "up", "-d", "--no-deps", svc],
                    capture_output=True, text=True, timeout=60, cwd=BASE_DIR
                )
                if r2.returncode == 0:
                    log(f"  -> {svc} restarted OK (via docker-compose)")
                else:
                    log(f"  ! {svc} restart failed: {r.stderr[:200]}")
        except Exception as e:
            log(f"  X {svc} restart error: {e}")

    return client_secret


# ====================================================================
# STEP 6: Apply Wazuh Security Configs (securityadmin)
# ====================================================================
def step_wazuh_security():
    log("\n" + "="*60)
    log("STEP 6: Wazuh Security -> Apply configs (securityadmin)")
    log("="*60)

    if not wait_for("Wazuh Indexer", "https://localhost:9200/", timeout=60):
        log("  ! Indexer not responding, trying anyway...")

    # Verify / copy self-signed CA as system-ca.pem for OIDC trust
    log("  Verifying system-ca.pem in indexer (self-signed CA for OIDC trust)...")
    try:
        check = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer",
             "test", "-f", "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0:
            log("  -> system-ca.pem exists (bind-mounted from host)")
        else:
            # Fallback: copy from container
            subprocess.run(
                ["docker", "exec", "-u", "root", "socstack-wazuh-indexer",
                 "cp", "/etc/ssl/certs/ca-certificates.crt",
                 "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
                capture_output=True, text=True, timeout=10
            )
            log("  -> system-ca.pem copied (fallback)")
    except Exception as e:
        log(f"  X system-ca.pem check failed: {e}")

    # Run securityadmin
    log("  Running securityadmin to apply security configs...")
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
            log(f"  -> securityadmin completed successfully")
            for line in result.stdout.split("\n"):
                if "Done" in line or "success" in line.lower() or "nodes" in line.lower():
                    log(f"    {line.strip()}")
        else:
            log(f"  X securityadmin failed (exit={result.returncode})")
    except subprocess.TimeoutExpired:
        log("  X securityadmin timed out (120s)")
    except Exception as e:
        log(f"  X securityadmin error: {e}")

    # Safety check client_secret in dashboard config
    dash_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml")
    if os.path.exists(dash_yml):
        with open(dash_yml) as f:
            dash_content = f.read()
        if "WILL_BE_SET_BY_POST_DEPLOY" in dash_content:
            log("  ! Dashboard config still has placeholder client_secret!")
            secret = deployed.get("SSO_CLIENT_SECRET", "")
            if secret:
                dash_content = dash_content.replace("WILL_BE_SET_BY_POST_DEPLOY", secret)
                with open(dash_yml, "w") as f:
                    f.write(dash_content)
                log(f"  -> Client secret injected (safety check)")

    # Restart indexer
    log("  Restarting wazuh-indexer to reload security plugin...")
    try:
        subprocess.run(["docker", "restart", "socstack-wazuh-indexer"],
                      capture_output=True, text=True, timeout=30)
        log("  -> Wazuh indexer restarting")
    except Exception as e:
        log(f"  X Indexer restart failed: {e}")

    log("  Waiting for indexer to come back...")
    time.sleep(20)
    wait_for("Wazuh Indexer", "https://localhost:9200/", timeout=90)

    # Restart dashboard after indexer is ready
    log("  Restarting wazuh-dashboard (after indexer is ready)...")
    try:
        subprocess.run(["docker", "restart", "socstack-wazuh-dashboard"],
                      capture_output=True, text=True, timeout=30)
        log("  -> Wazuh dashboard restarting")
    except Exception as e:
        log(f"  X Dashboard restart failed: {e}")
    time.sleep(15)
    wait_for("Wazuh Dashboard", "https://localhost:5601/", timeout=90)


# ====================================================================
# STEP 7: Wazuh API -> SSO Role Mapping (run_as)
# ====================================================================
def step_wazuh_api_role_mapping():
    log("\n" + "="*60)
    log("STEP 7: Wazuh API -> SSO Role Mapping (run_as)")
    log("="*60)

    WAZUH_API = "https://localhost:55000"

    if not wait_for("Wazuh API", WAZUH_API, timeout=90):
        log("  X Wazuh API not reachable -- skipping role mapping")
        results["wazuh_api_role_mapping"] = False
        return

    try:
        r = requests.post(
            f"{WAZUH_API}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False, timeout=15,
        )
        if r.status_code != 200:
            log(f"  X Wazuh API auth failed: {r.status_code} {r.text[:150]}")
            results["wazuh_api_role_mapping"] = False
            return
        token = r.json()["data"]["token"]
        log(f"  -> Wazuh API authenticated as {WAZUH_API_USER}")
    except Exception as e:
        log(f"  X Wazuh API auth error: {e}")
        results["wazuh_api_role_mapping"] = False
        return

    wh = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Resolve role IDs by name
    role_name_to_id = {}
    try:
        r = requests.get(f"{WAZUH_API}/security/roles?limit=100",
                         headers=wh, verify=False, timeout=15)
        if r.status_code == 200:
            for role in r.json().get("data", {}).get("affected_items", []):
                role_name_to_id[role["name"]] = role["id"]
            log(f"  -> Found {len(role_name_to_id)} Wazuh API roles")
    except Exception as e:
        log(f"  X Failed to fetch roles: {e}")

    def rid(name, fallback):
        return role_name_to_id.get(name, fallback)

    admin_role_ids = [
        rid("administrator", 1), rid("users_admin", 3),
        rid("agents_admin", 5),  rid("cluster_admin", 7),
    ]
    readonly_role_ids = [
        rid("readonly", 2), rid("agents_readonly", 4), rid("cluster_readonly", 6),
    ]

    role_mappings = [
        {"group": SSO_GROUP_ADMIN,    "rule_name": SSO_GROUP_ADMIN,
         "role_ids": admin_role_ids,    "desc": "administrator + users_admin + agents_admin + cluster_admin"},
        {"group": SSO_GROUP_ANALYST,  "rule_name": SSO_GROUP_ANALYST,
         "role_ids": admin_role_ids,    "desc": "administrator + users_admin + agents_admin + cluster_admin"},
        {"group": SSO_GROUP_READONLY, "rule_name": SSO_GROUP_READONLY,
         "role_ids": readonly_role_ids, "desc": "readonly + agents_readonly + cluster_readonly"},
    ]

    # Fetch existing rules
    try:
        r = requests.get(f"{WAZUH_API}/security/rules?limit=500",
                         headers=wh, verify=False, timeout=15)
        existing_rules = {}
        if r.status_code == 200:
            for rule in r.json().get("data", {}).get("affected_items", []):
                existing_rules[rule["name"]] = rule
    except Exception:
        existing_rules = {}

    all_ok = True
    for mapping in role_mappings:
        group    = mapping["group"]
        rule_name = mapping["rule_name"]
        role_ids = mapping["role_ids"]
        desc     = mapping["desc"]
        rule_id  = None

        if rule_name in existing_rules:
            rule_id = existing_rules[rule_name]["id"]
            log(f"  -> Rule '{rule_name}' already exists (id={rule_id})")
        else:
            try:
                r = requests.post(
                    f"{WAZUH_API}/security/rules",
                    headers=wh, verify=False, timeout=15,
                    json={"name": rule_name, "rule": {"FIND": {"backend_roles": group}}},
                )
                items = r.json().get("data", {}).get("affected_items", [])
                if r.status_code == 200 and items:
                    rule_id = items[0]["id"]
                    log(f"  -> Rule created: '{rule_name}' (id={rule_id})")
                else:
                    failed = r.json().get("data", {}).get("failed_items", [])
                    log(f"  X Rule '{rule_name}' failed: {failed or r.text[:150]}")
                    all_ok = False
                    continue
            except Exception as e:
                log(f"  X Rule '{rule_name}' error: {e}")
                all_ok = False
                continue

        if rule_id is not None:
            for role_id in role_ids:
                try:
                    r = requests.post(
                        f"{WAZUH_API}/security/roles/{role_id}/rules?rule_ids={rule_id}",
                        headers=wh, verify=False, timeout=15,
                    )
                    items  = r.json().get("data", {}).get("affected_items", [])
                    failed = r.json().get("data", {}).get("failed_items", [])
                    if items:
                        rname = items[0].get("name", f"role-{role_id}")
                        log(f"  -> Rule '{rule_name}' -> Role '{rname}'")
                    elif failed:
                        err_msg = str(failed)
                        if "already" in err_msg.lower():
                            log(f"  -> Rule '{rule_name}' already linked to role {role_id}")
                        else:
                            log(f"  X Link '{rule_name}' -> role {role_id}: {err_msg[:120]}")
                            all_ok = False
                except Exception as e:
                    log(f"  X Link error '{rule_name}' -> role {role_id}: {e}")
                    all_ok = False

    # Verify
    log("\n  Verifying Wazuh API role mappings...")
    try:
        r = requests.get(f"{WAZUH_API}/security/rules?limit=500",
                         headers=wh, verify=False, timeout=15)
        if r.status_code == 200:
            current = {rule["name"]: rule for rule in r.json()["data"]["affected_items"]}
            for m in role_mappings:
                found = m["rule_name"] in current
                status = "OK" if found else "MISSING"
                log(f"    {m['group']:20s} -> {m['desc'][:40]} [{status}]")
    except Exception as e:
        log(f"  X Verification error: {e}")

    results["wazuh_api_role_mapping"] = all_ok
    if all_ok:
        log("  -> All Wazuh API SSO role mappings configured successfully")
    else:
        log("  ! Some role mappings may need manual review")


# ====================================================================
# STEP 8: Save deployed credentials
# ====================================================================
def save_deployed():
    log("\n" + "="*60)
    log("STEP 8: Saving deployed credentials")
    log("="*60)

    deployed["WAZUH_INDEXER_USERNAME"] = env.get("WAZUH_INDEXER_USERNAME", "admin")
    deployed["WAZUH_INDEXER_PASSWORD"] = env.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")
    deployed["WAZUH_API_USER"]         = env.get("WAZUH_API_USER", "wazuh-wui")
    deployed["WAZUH_API_PASSWORD"]     = env.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
    deployed["KC_ADMIN_USER"]          = env.get("KC_ADMIN_USER", "admin")
    deployed["KC_ADMIN_PASSWORD"]      = env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")
    deployed["MISP_ADMIN_EMAIL"]       = env.get("MISP_ADMIN_EMAIL", "admin@local.lab")
    deployed["MISP_ADMIN_PASSWORD"]    = env.get("MISP_ADMIN_PASSWORD", "SocMisp@2025")
    deployed["MINIO_ROOT_USER"]        = "socminioadmin"
    deployed["MINIO_ROOT_PASSWORD"]    = "SocMinio@2025"

    # Add IP:PORT based service URLs
    for key, url in SERVICES.items():
        deployed[f"{key.upper()}_URL"] = url

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(DEPLOYED_FILE, "w") as f:
        f.write(f"# ============================================================\n")
        f.write(f"# SOC STACK (IP-SSL) - Deployed Credentials\n")
        f.write(f"# Generated: {ts}\n")
        f.write(f"# ============================================================\n\n")

        sections = {
            "URLS": ["WAZUH_URL", "SSO_URL", "N8N_URL", "MISP_URL", "THEHIVE_URL", "CORTEX_URL"],
            "KEYCLOAK": ["KC_ADMIN_USER", "KC_ADMIN_PASSWORD"],
            "KEYCLOAK SSO (SOC)": [
                "SSO_REALM", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET",
                "SSO_ADMIN_EMAIL", "SSO_ADMIN_PASSWORD",
                "SSO_ANALYST_EMAIL", "SSO_ANALYST_PASSWORD",
                "SSO_READONLY_EMAIL", "SSO_READONLY_PASSWORD",
            ],
            "WAZUH": ["WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD", "WAZUH_API_USER", "WAZUH_API_PASSWORD"],
            "N8N": ["N8N_ADMIN_EMAIL", "N8N_ADMIN_PASSWORD"],
            "MISP": ["MISP_ADMIN_EMAIL", "MISP_ADMIN_PASSWORD", "MISP_API_KEY"],
            "THEHIVE": ["THEHIVE_ADMIN_USER", "THEHIVE_ADMIN_PASSWORD", "THEHIVE_ANALYST_USER", "THEHIVE_ANALYST_PASSWORD"],
            "CORTEX": ["CORTEX_ADMIN_USER", "CORTEX_ADMIN_PASSWORD", "CORTEX_ORG_ADMIN", "CORTEX_API_KEY"],
            "MINIO": ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"],
        }

        for section, keys in sections.items():
            f.write(f"# === {section} ===\n")
            for k in keys:
                v = deployed.get(k, "NOT_SET")
                f.write(f"{k}={v}\n")
            f.write("\n")

    log(f"  -> Saved to {DEPLOYED_FILE}")

    with open(LOG_FILE, "w") as f:
        f.write("\n".join(log_lines))
    log(f"  -> Log saved to {LOG_FILE}")


# ====================================================================
# Print Summary
# ====================================================================
def print_summary():
    log("\n" + "="*60)
    log("  SOC STACK (IP-SSL) - POST-DEPLOY COMPLETE")
    log("="*60)
    log("")
    log("  ── Access URLs (import ca.crt into browser first) ──────────")
    log("")

    cortex_key = deployed.get("CORTEX_API_KEY", "NOT_SET")
    misp_key   = deployed.get("MISP_API_KEY",   "NOT_SET")

    svc = [
        ("Keycloak SSO",   SERVICES["sso"],     KC_USER, KC_PASS),
        ("Wazuh Dashboard",SERVICES["wazuh"],   "admin", env.get("WAZUH_INDEXER_PASSWORD","SecretPassword")),
        ("  > SSO Admin",  "",                  SSO_ADMIN_EMAIL,    SSO_ADMIN_PASS),
        ("  > SSO Analyst","",                  SSO_ANALYST_EMAIL,  SSO_ANALYST_PASS),
        ("  > SSO Readonly","",                 SSO_READONLY_EMAIL, SSO_READONLY_PASS),
        ("n8n",            SERVICES["n8n"],     N8N_EMAIL, N8N_PASS),
        ("MISP",           SERVICES["misp"],    MISP_ADMIN, MISP_PASS),
        ("TheHive",        SERVICES["thehive"], THEHIVE_USER, THEHIVE_PASS),
        ("  > Analyst",    "",                  THEHIVE_ANALYST, THEHIVE_ANALYST_PASS),
        ("Cortex",         SERVICES["cortex"],  CORTEX_ADMIN, CORTEX_PASS),
        ("  > OrgAdmin",   "",                  CORTEX_ORG_ADMIN, CORTEX_PASS),
    ]
    for name, url, user, pwd in svc:
        if url:
            log(f"  {name:18s} {url}")
        log(f"  {'':18s} {user} / {pwd}")
        log("")

    log(f"  SSL CA cert: {BASE_DIR}/certs/ca.crt")
    log(f"  Import into browser/OS to trust the self-signed SSL.")
    log("")
    log(f"  Credentials: {DEPLOYED_FILE}")
    log(f"  Log:         {LOG_FILE}")

    log("")
    log("=" * 60)
    log("  MANUAL STEPS REQUIRED (UI Configuration)")
    log("=" * 60)

    log("")
    log("  --- A. TheHive UI ----------------------------------------")
    log("")
    log("  1. TheHive -> Cortex Server")
    log("     Platform Management -> Cortex Servers -> Add")
    log(f"     - Server Name:                    Cortex-SOC")
    log(f"     - URL:                            http://socstack-cortex:9001")
    log(f"     - API Key:                        {cortex_key}")
    log(f"     - Check Certificate Authority:    DISABLE")
    log(f"     - Disable hostname verification:  ENABLE")
    log("")
    log("  2. TheHive -> MISP Server")
    log("     Platform Management -> MISP Servers -> Add")
    log(f"     - Server Name:  MISP-SOC")
    log(f"     - URL:          https://socstack-misp-core:443")
    log(f"     - API Key:      {misp_key}")
    log(f"     - Skip SSL:     Yes")
    log(f"     - Purpose:      Import and Export")

    log("")
    log("  --- B. Cortex UI -----------------------------------------")
    log("")
    log("  3. Cortex -> Enable Analyzers")
    log("     Organization -> Analyzers -> Refresh -> Enable needed")

    log("")
    log("  --- C. MISP UI ------------------------------------------")
    log("")
    log("  4. MISP -> Initial password change on first login")
    log(f"     URL: {SERVICES['misp']}")
    log(f"     Default: admin@admin.test / admin")
    log(f"     Change to: {MISP_ADMIN} / {MISP_PASS}")
    log("")
    log("  NOTE: MISP feeds are auto-loaded, enabled + cached by post-deploy.")

    log("")
    log("  --- D. Wazuh SSO Role Mapping (AUTOMATED) ----------------")
    log("")
    log("  5. Wazuh App SSO Role Mapping -> Done by Step 7 (API)")
    log(f"     {SSO_GROUP_ADMIN:20s} -> administrator (Wazuh API role)")
    log(f"     {SSO_GROUP_ANALYST:20s} -> administrator (Wazuh API role)")
    log(f"     {SSO_GROUP_READONLY:20s} -> readonly      (Wazuh API role)")
    log(f"     Indexer roles_mapping.yml also updated (securityadmin Step 6)")

    log("")
    log("  --- E. n8n Workflow Setup --------------------------------")
    log("")
    log("  6. n8n -> Import Wazuh Email Alert Workflow")
    log(f"     URL: {SERVICES['n8n']}")
    log("     a) Create new workflow -> Import from file")
    log("        File: 1_Wazuh_Email_Alert.json")
    log("     b) Fix Redis connection: Hostname = socstack-n8n-redis")

    log("")
    log("  --- F. Browser SSL Trust (self-signed CA) ----------------")
    log("")
    log("  7. Import self-signed CA into browser/OS")
    log(f"     CA file: {BASE_DIR}/certs/ca.crt")
    log("     Windows: certutil -addstore \"Root\" ca.crt")
    log("     Linux:   cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates")
    log("     macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt")
    log("     Firefox: Preferences -> Privacy -> View Certificates -> Authorities -> Import")


# ====================================================================
# MAIN
# ====================================================================
if __name__ == "__main__":
    log("=" * 60)
    log("  SOC STACK (IP-SSL) - Post-Deploy Configuration")
    log(f"  Server: {SERVER_IP}")
    log(f"  Ports:  Wazuh={WAZUH_PORT} SSO={SSO_PORT} n8n={N8N_PORT}")
    log(f"          MISP={MISP_PORT} TheHive={THEHIVE_PORT} Cortex={CORTEX_PORT}")
    log("=" * 60)

    step_npm()
    step_n8n()
    cortex_key = step_cortex()
    th_auth    = step_thehive()
    step_misp_thehive(th_auth)
    step_misp_feeds()
    client_secret = step_keycloak_sso()
    step_wazuh_security()
    step_wazuh_api_role_mapping()
    save_deployed()
    print_summary()
