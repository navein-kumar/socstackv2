# SOC Stack (IP-SSL) — IP-Based Self-Signed SSL Deployment

A fully automated Docker-based SOC stack designed for **internal/lab/air-gapped deployments** where no domain name or Let's Encrypt SSL is available. Deploys **22 containers** with **self-signed SSL certificates**, **dedicated ports per service** via nginx reverse proxy, and **Keycloak SSO for all services**.

```
  Wazuh Alert --> custom-n8n webhook --> n8n workflow --> Email + TheHive Alert
                                                              |
                                                    Incident Response Team
                                                    (Cases, Cortex Analysis, MISP Intel)
```

> **Use this when:** you don't have a domain name, or deploying on a private/internal network (192.168.x.x, 10.x.x.x), or any public IP without DNS records.
>
> **Use `domain-ssl/` instead when:** you have a domain name with DNS records pointing to your server.

---

## Table of Contents

- [Architecture](#architecture)
- [Services & Port Map](#services--port-map)
- [Server Requirements](#server-requirements)
- [Quick Start](#quick-start)
- [Post-Deployment (Automated)](#post-deployment-automated)
- [Post-Deployment UI Configuration (Manual)](#post-deployment-ui-configuration-manual)
- [SSO Roles & Permissions per Application](#sso-roles--permissions-per-application)
- [Credentials & API Keys](#credentials--api-keys)
- [Directory Structure](#directory-structure)
- [Management Commands](#management-commands)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
Client Browser
     |
     v (import ca.crt once to trust self-signed SSL)
     |
     +-- https://IP:8443  ->  Nginx  ->  Wazuh Dashboard  (SIEM)
     +-- https://IP:8444  ->  Nginx  ->  Keycloak          (SSO/IAM)
     +-- https://IP:8445  ->  Nginx  ->  oauth2-proxy-n8n  ->  n8n (Automation)
     +-- https://IP:8446  ->  Nginx  ->  MISP              (Threat Intel)
     +-- https://IP:8447  ->  Nginx  ->  oauth2-proxy-hive ->  TheHive (Cases)
     +-- https://IP:8448  ->  Nginx  ->  Cortex            (Analysis)

Direct ports (not proxied):
     +-- IP:1514   -> Wazuh Agent (TCP)
     +-- IP:1515   -> Wazuh Agent Enrollment
     +-- IP:514    -> Syslog (UDP)
     +-- IP:55000  -> Wazuh Manager API
```

### SSO Architecture

All services authenticate via a **single Keycloak realm (`SOC`)** and a **single OIDC client (`soc-sso`)**:

| Service | SSO Method | How It Works |
|---------|-----------|-------------|
| **Wazuh** | Native OIDC | OpenSearch Security plugin validates JWT tokens directly |
| **TheHive** | oauth2-proxy + hive-sso-bridge | Proxy authenticates via Keycloak, bridge maps SSO email to TheHive local credentials |
| **n8n** | oauth2-proxy + hooks.js | Proxy authenticates via Keycloak, hooks.js issues shared owner session |
| **MISP** | Native OIDC | Built-in OIDC support via environment variables |
| **Cortex** | Native OAuth2 | application.conf OAuth2 provider config |

### Integration Flow

| From | To | Method | Purpose |
|------|----|--------|---------|
| Wazuh Manager | n8n | custom-n8n webhook | Forward security alerts |
| n8n | Email (SMTP) | SMTP credentials | Email notifications |
| n8n | TheHive | TheHive API (analyst account) | Create alerts for incident response |
| TheHive | Cortex | Cortex API key | Observable analysis (VirusTotal, etc.) |
| Cortex | MISP | MISP API key (via analyzer) | On-demand threat intelligence lookups |
| All services | Keycloak | OpenID Connect (OIDC) | Single Sign-On authentication |

---

## Services & Port Map

| Port | Service | Container | Description |
|------|---------|-----------|-------------|
| 8443 | Wazuh Dashboard | `socstack-wazuh-dashboard` | SIEM + SSO login (Keycloak OIDC) |
| 8444 | Keycloak | `socstack-keycloak` | SSO Identity Provider |
| 8445 | n8n | `socstack-oauth2-proxy-n8n` | Workflow automation (SSO gated) |
| 8446 | MISP | `socstack-misp-core` | Threat Intelligence Platform |
| 8447 | TheHive | `socstack-oauth2-proxy-hive` | Case Management (SSO gated) |
| 8448 | Cortex | `socstack-cortex` | Observable Analysis Engine |
| 1514 | Wazuh Agent | `socstack-wazuh-manager` | Agent communication (TCP) |
| 1515 | Wazuh Enrollment | `socstack-wazuh-manager` | Agent auto-enrollment |
| 514 | Syslog | `socstack-wazuh-manager` | Log ingestion (UDP) |
| 55000 | Wazuh API | `socstack-wazuh-manager` | REST API (direct) |
| 9200 | OpenSearch API | `socstack-wazuh-indexer` | Index API (direct) |

### All 22 Containers

| # | Container | Purpose |
|---|-----------|---------|
| 1 | `socstack-nginx` | nginx:alpine reverse proxy (ports 8443-8448) |
| 2 | `socstack-keycloak` | Keycloak SSO Identity Provider |
| 3 | `socstack-keycloak-db` | Keycloak PostgreSQL database |
| 4 | `socstack-wazuh-manager` | Wazuh SIEM manager + agent listener |
| 5 | `socstack-wazuh-indexer` | OpenSearch indexer (OIDC auth) |
| 6 | `socstack-wazuh-dashboard` | Wazuh Dashboard UI (OIDC SSO) |
| 7 | `socstack-thehive` | Case management |
| 8 | `socstack-cortex` | Observable analysis (OAuth2 SSO) |
| 9 | `socstack-cassandra` | TheHive primary database |
| 10 | `socstack-elasticsearch` | Cortex + TheHive search index |
| 11 | `socstack-minio` | TheHive S3 file storage |
| 12 | `socstack-misp-core` | Threat intelligence (OIDC SSO) |
| 13 | `socstack-misp-db` | MISP MariaDB |
| 14 | `socstack-misp-redis` | MISP cache (Valkey) |
| 15 | `socstack-misp-modules` | MISP enrichment modules |
| 16 | `socstack-n8n` | Workflow automation |
| 17 | `socstack-n8n-redis` | n8n job queue |
| 18 | `socstack-hive-bridge` | TheHive SSO email-to-credentials bridge |
| 19 | `socstack-oauth2-proxy-hive` | TheHive SSO gateway |
| 20 | `socstack-oauth2-proxy-n8n` | n8n SSO gateway (soc-admin + soc-analyst) |

> **Note:** ip-ssl mode does not include Grafana (20 core + 2 SSO proxy = 22 containers).

---

## Server Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 50 GB free | 100 GB+ SSD |
| **Docker** | 24+ with Compose v2 | Latest stable |
| **OpenSSL** | Installed | Comes pre-installed on most distros |
| **Kernel** | `vm.max_map_count=262144` | Auto-set by pre-deploy.sh |
| **DNS** | Not required | Works with any IP (private or public) |

---

## Quick Start

### Step 1: Configure Environment

```bash
cp .env.example .env
nano .env
```

**Required changes:**
```env
SERVER_IP=192.168.1.100        # Your server's IP (private or public)
```

> `DEPLOY_DIR` is **not needed** -- both `pre-deploy.sh` and `post-deploy.py` auto-detect the deploy folder.

Change all `ChangeMe_*` passwords. The IP is embedded in the SSL certificate SAN -- it must be reachable from your browser.

### Step 2: Copy Files to Server

```bash
scp -r ip-ssl/* root@YOUR_SERVER_IP:/path/to/deploy/
```

> You can deploy to **any directory**. All scripts auto-detect the path.

### Step 3: Pre-Deployment Checks

```bash
ssh root@YOUR_SERVER_IP
cd /path/to/deploy
chmod +x pre-deploy.sh
sudo ./pre-deploy.sh
```

**pre-deploy.sh automatically handles:**

| Check | What It Does |
|-------|--------------|
| System | Validates OS, RAM (16GB+), disk (50GB+), root access |
| Docker | Verifies Docker + Compose installed, daemon running |
| Kernel | Sets `vm.max_map_count=262144` (persistent) |
| Ports | Checks 8443-8448, 1514, 1515, 514, 55000 available |
| SSL Certs | **Generates self-signed CA + server cert** with IP SAN |
| Wazuh Certs | Auto-generates Wazuh internal TLS certificates |
| Directories | Creates all data dirs + config dirs |
| CRLF Fix | Converts Windows `\r\n` to Unix `\n` on all files |
| Permissions | Fixes ownership: Keycloak (uid 1000), TheHive (uid 1000), n8n (uid 1000) |

> The `certs/ca.crt` file is created during this step -- you'll need it in Step 6.

### Step 4: Start the Stack

```bash
docker compose up -d
```

Wait **3-5 minutes** for all 22 containers to initialize:

```bash
docker compose ps
docker ps --filter "health=unhealthy"
```

### Step 5: Post-Deployment Configuration

```bash
python3 post-deploy.py
```

This takes **3-5 minutes**. See [details below](#post-deployment-automated).

### Step 6: Import CA Certificate

Before accessing any service, import the self-signed CA into your browser/OS:

```bash
# Copy from server
scp root@YOUR_SERVER_IP:/path/to/deploy/certs/ca.crt ./soc-ca.crt
```

**Windows (Chrome/Edge):**
```powershell
certutil -addstore "Root" soc-ca.crt
```

**Linux:**
```bash
sudo cp soc-ca.crt /usr/local/share/ca-certificates/soc-ca.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain soc-ca.crt
```

**Firefox (uses its own store):**
1. Preferences > Privacy & Security > View Certificates > Authorities > Import
2. Select `soc-ca.crt`, tick "Trust this CA to identify websites"

### Step 7: Verify

```bash
python3 test-stack.py
```

---

## Post-Deployment (Automated)

`post-deploy.py` configures all services after `docker compose up -d`:

| Step | Service | Action |
|------|---------|--------|
| 1 | **n8n** | Create owner account (disables public signup) |
| 2 | **Cortex** | DB migration, superadmin, org, org admin, API key |
| 3 | **TheHive** | Change default password, create org, analyst user |
| 4 | **MISP** | Retrieve API key, load 90+ threat feeds |
| 5 | **Keycloak SSO** | Create realm `SOC`, OIDC client `soc-sso`, 3 groups, 3 users, groups mapper |
| 5b | **Config Injection** | Inject client_secret + IP:PORT into Wazuh/Cortex/TheHive configs |
| 6 | **Wazuh Security** | Run `securityadmin.sh` to apply OIDC config + roles_mapping |
| 7 | **Wazuh API** | Create SSO-to-RBAC rules (soc-admin, soc-analyst, soc-readonly) |
| 8 | **Save** | Write all credentials + API keys to `.env.deployed` |

**Safety features:**
- **Idempotent** -- safe to re-run any number of times
- Keycloak client: creates if missing, **updates** redirect URIs if exists
- `client_secret`: reuses existing value on re-runs
- `OAUTH2_PROXY_COOKIE_SECRET`: reuses existing (preserves sessions)

---

## Post-Deployment UI Configuration (Manual)

After `post-deploy.py`, some tasks require manual UI configuration:

> **Full step-by-step guide:** See [`POST-DEPLOY-UI-GUIDE.md`](POST-DEPLOY-UI-GUIDE.md)

| Section | Task | Time |
|---------|------|------|
| **A** | TheHive: Add Cortex server + MISP server | 3 min |
| **B** | Cortex: Enable MISP analyzer + other analyzers | 5 min |
| **C** | MISP: Enable and fetch all threat feeds | 3 min |
| **D** | n8n: Import workflow, configure SMTP/TheHive/webhook | 10 min |

---

## SSO Roles & Permissions per Application

### Keycloak SSO Overview

| Setting | Value |
|---------|-------|
| Realm | `SOC` |
| Client ID | `soc-sso` |
| Client Type | Confidential (with secret) |
| Groups Mapper | `groups` claim in all tokens |

### SSO Groups & Users

| SSO User (.env key) | Keycloak Group | Role Level |
|---------------------|----------------|-----------|
| `SSO_ADMIN_EMAIL` | **soc-admin** | Full administrator |
| `SSO_ANALYST_EMAIL` | **soc-analyst** | Analyst (read/write/analyze) |
| `SSO_READONLY_EMAIL` | **soc-readonly** | Read-only viewer |

---

### 1. Wazuh SIEM

**SSO Method:** Native OpenID Connect (OIDC)

**Login URL:** `https://SERVER_IP:8443` > Click "Log in with single sign-on"

| SSO Group | OpenSearch Roles | Wazuh API Roles (port 55000) | Can Do |
|-----------|-----------------|------------------------------|--------|
| **soc-admin** | `all_access`, `kibana_user` | administrator, users_admin, agents_admin, cluster_admin | Full access: dashboards, agents, rules, decoders, settings, user management |
| **soc-analyst** | `all_access`, `kibana_user` | administrator, users_admin, agents_admin, cluster_admin | Same as admin (full access) |
| **soc-readonly** | `wazuh_user`, `kibana_user` | readonly, agents_readonly, cluster_readonly | View dashboards & alerts only. Cannot modify agents, rules, or settings |

> **Local login also available:** username `admin` / password from `WAZUH_INDEXER_PASSWORD`

---

### 2. TheHive (Case Management)

**SSO Method:** oauth2-proxy + hive-sso-bridge (Node.js)

**Login URL:** `https://SERVER_IP:8447` > Auto-redirects to Keycloak

**How it works:** TheHive 5.x Community Edition does not support native OIDC. Instead, oauth2-proxy handles Keycloak authentication, then the hive-sso-bridge maps the authenticated SSO email to a TheHive local account and logs in automatically.

| SSO Group | TheHive Local Account Mapped | TheHive Role | Can Do |
|-----------|------------------------------|-------------|--------|
| **soc-admin** | `THEHIVE_ADMIN_USER` (admin@thehive.local) | org-admin | Full access: cases, alerts, tasks, observables, org settings, user management |
| **soc-analyst** | `THEHIVE_ANALYST_USER` | analyst | Create/edit cases, manage tasks & observables. Cannot manage org settings or users |
| **soc-readonly** | read-only account (if configured) | read-only | View cases and alerts only |

> **Note:** The bridge requires matching TheHive local accounts. `post-deploy.py` creates the admin and analyst accounts automatically.

> **Local login also available:** `admin@thehive.local` / password from `THEHIVE_ADMIN_PASSWORD`

---

### 3. n8n (Workflow Automation / SOAR)

**SSO Method:** oauth2-proxy + hooks.js (shared owner session)

**Login URL:** `https://SERVER_IP:8445` > Auto-redirects to Keycloak

| SSO Group | Access | n8n Session | Can Do |
|-----------|--------|-------------|--------|
| **soc-admin** | Allowed | Owner session (full access) | All workflows, credentials, executions, settings |
| **soc-analyst** | Allowed | Owner session (full access) | Same as soc-admin (shared workspace) |
| **soc-readonly** | **Blocked** | N/A | Cannot access n8n (blocked at oauth2-proxy) |

**How it works (Shared Owner Session):**

n8n Community Edition does not support workflow sharing, RBAC, or team workspaces (these require Enterprise Edition). To work around this, `hooks.js` uses a **shared owner session** approach:

1. User clicks n8n URL > oauth2-proxy redirects to Keycloak
2. Keycloak authenticates and verifies group membership (soc-admin or soc-analyst)
3. oauth2-proxy passes the authenticated email to n8n via `X-Forwarded-Email` header
4. `hooks.js` receives the header but **does NOT create a per-user account**
5. Instead, it finds the **n8n owner account** (`N8N_ADMIN_EMAIL`) and issues a session cookie for that account
6. The SSO user now sees the owner's workspace -- all workflows, credentials, and executions

```
soc-admin@example.com   --+
                           +-- oauth2-proxy (Keycloak auth) --> hooks.js --> owner session
analyst@example.com     --+                                                      |
                                                                      All shared workflows
                                                                      (Wazuh alerts, SOAR, etc.)
```

> **Access control** is at the oauth2-proxy level -- only `soc-admin` and `soc-analyst` groups can reach n8n. `soc-readonly` is blocked with 403.
>
> **Audit trail:** n8n logs show which SSO email triggered each login: `SSO login: analyst@example.com -> owner session (admin@example.com)`

> **Local login also available:** `N8N_ADMIN_EMAIL` / `N8N_ADMIN_PASSWORD` (owner account)

---

### 4. MISP (Threat Intelligence)

**SSO Method:** Native OIDC (built-in)

**Login URL:** `https://SERVER_IP:8446` > Click "Login with OIDC"

| SSO Group | MISP Role | Can Do |
|-----------|----------|--------|
| **soc-admin** | Auto-created (default org member) | Access events, attributes, feeds, galaxies. Admin promotion requires manual UI config |
| **soc-analyst** | Auto-created (default org member) | Same as above (MISP CE creates with default role) |
| **soc-readonly** | Auto-created (default org member) | Same as above (MISP CE creates with default role) |

> **Note:** MISP auto-creates SSO users with default organization role. To promote to Org Admin or Site Admin, go to **Administration > List Users** and change role manually.

> **Local login also available:** `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD`

---

### 5. Cortex (Observable Analysis)

**SSO Method:** Native OAuth2 (application.conf)

**Login URL:** `https://SERVER_IP:8448` > Click "Login with SSO"

| SSO Group | Cortex Roles | Can Do |
|-----------|-------------|--------|
| **soc-admin** | `superadmin` | Full access: manage organizations, users, analyzers, responders. Run any analysis |
| **soc-analyst** | `read`, `analyze`, `orgadmin` | Run analyzers/responders, view results, manage org settings |
| **soc-readonly** | `read` | View analysis results only. Cannot run analyzers |

> **Local login also available:** `CORTEX_ADMIN_USER` / `CORTEX_ADMIN_PASSWORD`

---

### Quick Reference -- SSO Access Matrix

| Service | soc-admin | soc-analyst | soc-readonly | Local login |
|---------|:---------:|:-----------:|:------------:|:-----------:|
| **Wazuh** (:8443) | Full admin | Full admin | Read-only | admin / WAZUH_INDEXER_PASSWORD |
| **TheHive** (:8447) | Org admin (via bridge) | Analyst (via bridge) | Read-only | admin@thehive.local / THEHIVE_ADMIN_PASSWORD |
| **n8n** (:8445) | Owner session | Owner session | **Blocked** | N8N_ADMIN_EMAIL / N8N_ADMIN_PASSWORD |
| **MISP** (:8446) | Default member | Default member | Default member | MISP_ADMIN_EMAIL / MISP_ADMIN_PASSWORD |
| **Cortex** (:8448) | Superadmin | Analyst+orgadmin | Read-only | CORTEX_ADMIN_USER / CORTEX_ADMIN_PASSWORD |
| **Keycloak** (:8444) | N/A | N/A | N/A | admin / KC_ADMIN_PASSWORD |

### Adding More SSO Users

1. Login to Keycloak Admin at `https://SERVER_IP:8444`
2. Switch to realm **`SOC`**
3. **Users** > **Add user** > set username (use email), email, first name, last name
4. **Credentials** > set password (temporary: off)
5. **Groups** > join one of: `soc-admin`, `soc-analyst`, or `soc-readonly`
6. For TheHive: also create a matching local account in TheHive UI

---

## Credentials & API Keys

After `post-deploy.py`, all credentials are saved to `.env.deployed`.

### Service Logins

| Service | URL | Username | Password (.env key) |
|---------|-----|----------|---------------------|
| **Keycloak** | `https://IP:8444` | `admin` | `KC_ADMIN_PASSWORD` |
| **Wazuh** (local) | `https://IP:8443` | `admin` | `WAZUH_INDEXER_PASSWORD` |
| **n8n** (owner) | `https://IP:8445` | `N8N_ADMIN_EMAIL` | `N8N_ADMIN_PASSWORD` |
| **MISP** | `https://IP:8446` | `MISP_ADMIN_EMAIL` | `MISP_ADMIN_PASSWORD` |
| **TheHive** | `https://IP:8447` | `admin@thehive.local` | `THEHIVE_ADMIN_PASSWORD` |
| **Cortex** | `https://IP:8448` | `CORTEX_ADMIN_USER` | `CORTEX_ADMIN_PASSWORD` |

### SSO Logins

| User | Password (.env key) | Group |
|------|---------------------|-------|
| `SSO_ADMIN_EMAIL` | `SSO_ADMIN_PASSWORD` | soc-admin |
| `SSO_ANALYST_EMAIL` | `SSO_ANALYST_PASSWORD` | soc-analyst |
| `SSO_READONLY_EMAIL` | `SSO_READONLY_PASSWORD` | soc-readonly |

### Auto-Generated Keys

| Key | Generated By | Used For |
|-----|-------------|----------|
| `SSO_CLIENT_SECRET` | post-deploy.py (Keycloak) | All SSO integrations |
| `OAUTH2_PROXY_COOKIE_SECRET` | post-deploy.py | oauth2-proxy sessions (TheHive + n8n) |
| `CORTEX_API_KEY` | post-deploy.py | TheHive-Cortex integration |
| `MISP_API_KEY` | post-deploy.py (from MISP DB) | Cortex MISP analyzer |

---

## Directory Structure

```
ip-ssl/
|-- docker-compose.yml              # All 22 services + nginx:alpine
|-- .env                            # Your configuration (from .env.example)
|-- .env.example                    # Template with all variables
|-- .env.deployed                   # Auto-generated credentials (after post-deploy)
|-- pre-deploy.sh                   # Pre-deployment checks + cert generation
|-- post-deploy.py                  # Auto-configures everything after compose up
|-- test-stack.py                   # Full test suite
|-- test-creds.py                   # Credential validation tests
|-- README.md                       # This file
|-- POST-DEPLOY-UI-GUIDE.md        # Manual UI config guide
|
|-- nginx/
|   +-- nginx.conf                  # Port-based SSL reverse proxy (8443-8448)
|
|-- certs/                          # Auto-generated by pre-deploy.sh
|   |-- ca.key / ca.crt             # Self-signed CA (import ca.crt into browser)
|   +-- server.key / server.crt     # Server cert with IP SAN
|
|-- configs/
|   |-- wazuh/
|   |   |-- certs.yml                       # Cert generator config
|   |   |-- wazuh_indexer_ssl_certs/        # Generated TLS certificates
|   |   |-- wazuh_indexer/
|   |   |   |-- config.yml                  # Security config (OpenID auth domain)
|   |   |   |-- roles_mapping.yml           # Keycloak groups -> OpenSearch roles
|   |   |   +-- internal_users.yml          # Password hashes
|   |   |-- wazuh_dashboard/
|   |   |   +-- opensearch_dashboards.yml   # Dashboard OIDC config
|   |   +-- wazuh_cluster/
|   |       |-- wazuh_manager.conf          # Manager configuration
|   |       |-- custom-n8n                  # Webhook shell wrapper
|   |       +-- custom-n8n.py               # Webhook Python script
|   |-- thehive/
|   |   |-- cortex-application.conf         # Cortex config (SSO + elasticsearch)
|   |   |-- thehive-application.conf        # TheHive config
|   |   +-- hive-sso-bridge.js              # TheHive SSO email-to-credentials bridge
|   +-- n8n/
|       |-- hooks.js                        # n8n SSO shared owner session hook
|       +-- 1_Wazuh_Email_Alert.json        # n8n workflow template
|
+-- data/                                   # All persistent data volumes (auto-created)
```

---

## Management Commands

```bash
# All commands run from your deploy folder

# -- Start / Stop / Restart --
docker compose up -d                          # Start all containers
docker compose down                           # Stop all (preserves data)
docker restart socstack-<name>                # Restart single service

# -- Status --
docker compose ps
docker ps --filter "health=unhealthy"

# -- Logs --
docker logs socstack-wazuh-dashboard --tail 50
docker logs socstack-n8n --tail 20 | grep SSO

# -- Re-run Configuration (idempotent) --
python3 post-deploy.py
python3 test-stack.py

# -- Wazuh Security Admin (re-apply OIDC/roles after config changes) --
docker exec socstack-wazuh-indexer bash -c \
  "JAVA_HOME=/usr/share/wazuh-indexer/jdk \
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
   -cd /usr/share/wazuh-indexer/config/opensearch-security/ \
   -nhnv \
   -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
   -cert /usr/share/wazuh-indexer/config/certs/admin.pem \
   -key /usr/share/wazuh-indexer/config/certs/admin-key.pem \
   -h localhost -p 9200"

# -- Wazuh Agent Management --
docker exec socstack-wazuh-manager /var/ossec/bin/manage_agents -l
```

---

## Wazuh Agent Enrollment

Agents connect directly by IP (no domain needed):

```bash
# On the agent machine:
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.3-1_amd64.deb
sudo WAZUH_MANAGER=YOUR_SERVER_IP dpkg -i ./wazuh-agent_4.14.3-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

---

## Troubleshooting

### Browser shows SSL error (NET::ERR_CERT_AUTHORITY_INVALID)

Import `certs/ca.crt` into your OS/browser trust store (see Step 6).

### Wazuh SSO returns 401 "Authentication Exception"

1. **`client_secret` placeholder not replaced:**
   ```bash
   grep "WILL_BE_SET_BY_POST_DEPLOY" configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml
   # If found, re-run: python3 post-deploy.py
   ```

2. **Security config not applied** (securityadmin not re-run after config change):
   ```bash
   curl -sk -u admin:PASSWORD https://localhost:9200/_plugins/_security/api/securityconfig \
     | python3 -m json.tool | grep openid_connect_url
   # If wrong realm, re-run securityadmin.sh (see Management Commands)
   ```

### TheHive/n8n SSO not redirecting to Keycloak

Check nginx.conf routes through oauth2-proxy containers (ports 4180), not directly to services.

### n8n SSO shows 403 Forbidden

The user's Keycloak group is not allowed. Only `soc-admin` and `soc-analyst` can access n8n. `soc-readonly` is blocked at oauth2-proxy.

### Keycloak redirects to wrong URL

Ensure `SERVER_IP` in `.env` matches the IP you're accessing from.

### Services not starting

```bash
free -h                           # Need 16GB+ RAM
sysctl vm.max_map_count           # Needs 262144
docker compose logs SERVICE_NAME  # Check container logs
```

### Firewall blocking ports

```bash
ufw allow 8443:8448/tcp
# AWS/GCP/Azure: add inbound rules for 8443-8448
```

### Regenerate SSL certs for a new IP

```bash
rm -rf certs/
sudo ./pre-deploy.sh
docker compose restart socstack-nginx
```

---

## Security Notes

- `certs/ca.key` -- CA private key. Keep secret. Do not commit to Git.
- Self-signed CA is for internal/lab use only. For production, use `domain-ssl/` with Let's Encrypt.
- All services communicate internally over Docker network -- only nginx ports (8443-8448) are exposed.
- Wazuh agent ports (1514/1515/514) are exposed directly (not proxied through nginx).
- `NODE_EXTRA_CA_CERTS` is set on n8n container to trust the self-signed CA.

---

## License

Internal use. All third-party components retain their original licenses.
