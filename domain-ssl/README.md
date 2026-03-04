# SOC Stack (Domain-SSL) — Unified Security Operations Center

A production-ready, fully automated Docker-based SOC stack deploying **22 containers** on a single server with **Keycloak SSO for all services**, **Let's Encrypt SSL** via Nginx Proxy Manager, and **end-to-end integration** between Wazuh, TheHive, Cortex, MISP, and n8n.

```
  Wazuh Alert --> custom-n8n webhook --> n8n workflow --> Email + TheHive Alert
                                                              |
                                                    Incident Response Team
                                                    (Cases, Cortex Analysis, MISP Intel)
```

> **Use this when:** you have a domain with DNS records pointing to your server.
>
> **Use `ip-ssl/` instead when:** deploying on a private/internal network without a domain name.

---

## Table of Contents

- [Architecture](#architecture)
- [SSO Architecture](#sso-architecture)
- [Services (22 Containers)](#services-22-containers)
- [Server Requirements](#server-requirements)
- [Quick Start](#quick-start)
- [Post-Deployment (Automated)](#post-deployment-automated)
- [Post-Deployment UI Configuration (Manual)](#post-deployment-ui-configuration-manual)
- [SSO Roles & Permissions per Application](#sso-roles--permissions-per-application)
- [Credentials & API Keys](#credentials--api-keys)
- [n8n Wazuh Integration](#n8n-wazuh-integration)
- [Directory Structure](#directory-structure)
- [Management Commands](#management-commands)
- [Troubleshooting](#troubleshooting)
- [Re-Deployment / Updates](#re-deployment--updates)

---

## Architecture

```
                        Internet
                           |
                   +-------+--------+
                   |  Nginx Proxy   |  <-- SSL termination (Let's Encrypt)
                   |    Manager     |  <-- Reverse proxy for all services
                   +-------+--------+
       +------+------+-----+------+------+------+
       v      v      v     v      v      v      v
    Wazuh  Keycloak  n8n  MISP  TheHive Cortex Grafana
    SIEM    SSO    Workflow CTI  Cases  Analysis Metrics
      |       ^      ^     ^      ^       ^
      |       |      |     |      |       |
      +-------+------+-----+------+-------+
              |    Keycloak SSO (OpenID Connect)
              |    Single realm: SOC
              |    Single client: soc-sso
              |
              +--- Wazuh:   Native OIDC
              +--- TheHive:  oauth2-proxy + hive-sso-bridge
              +--- n8n:      oauth2-proxy + hooks.js (soc-admin only)
              +--- MISP:     Native OIDC
              +--- Cortex:   Native OAuth2
```

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

## SSO Architecture

All six services authenticate via a **single Keycloak realm (`SOC`)** and a **single OIDC client (`soc-sso`)**. Different services use different SSO integration methods:

| Service | SSO Method | How It Works |
|---------|-----------|-------------|
| **Wazuh** | Native OIDC | OpenSearch Security plugin validates JWT tokens directly |
| **TheHive** | oauth2-proxy + hive-sso-bridge | Proxy authenticates via Keycloak, bridge maps SSO email to TheHive local credentials |
| **n8n** | oauth2-proxy + hooks.js | Proxy authenticates via Keycloak (soc-admin only), hooks.js auto-creates/logs-in n8n users |
| **MISP** | Native OIDC | Built-in OIDC support via environment variables |
| **Cortex** | Native OAuth2 | application.conf OAuth2 provider config |
| **Grafana** | Native OAuth2 | Built-in Keycloak/OIDC integration |

```
Browser --> NPM (SSL) --> oauth2-proxy --> Keycloak (auth) --> upstream service
                            |                                       |
                            +-- TheHive: hive-sso-bridge (email->creds mapping)
                            +-- n8n: hooks.js (auto-create user from header)
```

---

## Services (22 Containers)

| # | Container | Image | Purpose |
|---|-----------|-------|---------|
| 1 | `socstack-nginx` | jc21/nginx-proxy-manager | Reverse proxy + Let's Encrypt SSL |
| 2 | `socstack-keycloak` | quay.io/keycloak/keycloak | SSO Identity Provider |
| 3 | `socstack-keycloak-db` | postgres:15-alpine | Keycloak database |
| 4 | `socstack-wazuh-manager` | wazuh/wazuh-manager | SIEM manager + agent listener |
| 5 | `socstack-wazuh-indexer` | wazuh/wazuh-indexer | OpenSearch indexer |
| 6 | `socstack-wazuh-dashboard` | wazuh/wazuh-dashboard | Wazuh Dashboard UI (OIDC SSO) |
| 7 | `socstack-thehive` | strangebee/thehive:5.2 | Case management |
| 8 | `socstack-cortex` | thehiveproject/cortex:3.1.8-1 | Observable analysis engine |
| 9 | `socstack-cassandra` | cassandra:4.1 | TheHive primary database |
| 10 | `socstack-elasticsearch` | elasticsearch:7.17.15 | Cortex + TheHive search index |
| 11 | `socstack-minio` | minio/minio | TheHive S3 file storage |
| 12 | `socstack-misp-core` | misp/misp-core | Threat intelligence platform |
| 13 | `socstack-misp-db` | mariadb:10.11 | MISP database |
| 14 | `socstack-misp-redis` | valkey:7.2 | MISP cache |
| 15 | `socstack-misp-modules` | misp/misp-modules | MISP enrichment modules |
| 16 | `socstack-n8n` | n8nio/n8n | Workflow automation |
| 17 | `socstack-n8n-redis` | redis:7-alpine | n8n job queue |
| 18 | `socstack-grafana` | grafana/grafana-oss | Metrics & dashboards |
| 19 | `socstack-grafana-renderer` | grafana/grafana-image-renderer | Image rendering for alerts |
| 20 | `socstack-hive-bridge` | node:22-alpine | TheHive SSO bridge (email-to-creds) |
| 21 | `socstack-oauth2-proxy-hive` | oauth2-proxy:v7.7.1 | TheHive SSO gateway |
| 22 | `socstack-oauth2-proxy-n8n` | oauth2-proxy:v7.7.1 | n8n SSO gateway (soc-admin only) |

All containers run on a single `socstack_net` Docker bridge network.

---

## Server Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 50 GB free | 100 GB+ SSD |
| **Docker** | 24+ with Compose v2 | Latest stable |
| **Ports** | 80, 443 open to internet | Firewall restricted |
| **Kernel** | `vm.max_map_count=262144` | Auto-set by pre-deploy.sh |
| **DNS** | 8 A records pointing to server IP | All pointing to same server |

### Required DNS A Records

Create these **before deployment** -- all pointing to your server's public IP:

| Domain | Service |
|--------|---------|
| `sso.yourdomain.com` | Keycloak SSO |
| `wazuh.yourdomain.com` | Wazuh Dashboard |
| `n8n.yourdomain.com` | n8n Workflows |
| `cti.yourdomain.com` | MISP CTI |
| `hive.yourdomain.com` | TheHive Cases |
| `cortex.yourdomain.com` | Cortex Analysis |
| `grafana.yourdomain.com` | Grafana Metrics |
| `npm.yourdomain.com` | Nginx Proxy Manager |

---

## Quick Start

### Step 1: Configure Environment

```bash
cp .env.example .env
nano .env     # Fill in ALL required fields
```

**Required changes in `.env`:**
- `SERVER_IP` -- your server's public IP address
- All `*_DOMAIN` fields -- your actual domain names
- All `*_PASSWORD` fields -- change every `ChangeMe_*` to strong passwords
- All `*_EMAIL` fields -- your actual email addresses
- `MISP_ORG` / `THEHIVE_ORG_NAME` / `CORTEX_ORG_NAME` -- your organization name

> `DEPLOY_DIR` is **not needed** -- both `pre-deploy.sh` and `post-deploy.py` auto-detect the deploy folder from their own location.

### Step 2: Copy Files to Server

```bash
scp -r domain-ssl/* root@YOUR_SERVER_IP:/path/to/deploy/
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
| Ports | Checks all required ports available |
| DNS | Verifies all 8 domain A records resolve to `SERVER_IP` |
| Directories | Creates all data dirs + config dirs |
| CRLF Fix | Converts Windows `\r\n` to Unix `\n` on all configs/scripts |
| Permissions | Fixes ownership: Keycloak (uid 1000), TheHive (uid 1000), n8n (uid 1000) |
| Wazuh Certs | Auto-generates Wazuh TLS certificates (if missing) |

Expected result: **All PASS, 0 FAIL**

### Step 4: Start the Stack

```bash
docker compose up -d
```

Wait **3-5 minutes** for all 22 containers to initialize:

```bash
docker compose ps
docker ps --filter "health=unhealthy"
```

> Cassandra and Elasticsearch take longest (1-2 min). TheHive and Cortex depend on them.

### Step 5: Post-Deployment Configuration

```bash
python3 post-deploy.py
```

This takes **3-5 minutes** and configures all services automatically. See [details below](#post-deployment-automated).

### Step 6: Run Tests

```bash
python3 test-stack.py
```

Then follow the [Post-Deployment UI Guide](#post-deployment-ui-configuration-manual) for remaining manual steps.

---

## Post-Deployment (Automated)

`post-deploy.py` configures all services after `docker compose up -d`:

| Step | Service | Action |
|------|---------|--------|
| Pre | Keycloak | Fix data dir permissions (uid 1000) |
| Pre | Wazuh Manager | Fix custom-n8n integration permissions |
| 1 | **NPM** | Create 8 proxy hosts + request Let's Encrypt SSL certs |
| 2 | **n8n** | Create owner account (disables public signup) |
| 3 | **Cortex** | DB migration, superadmin, org, org admin, API key |
| 4 | **TheHive** | Change default password, create org, analyst user |
| 5 | **MISP** | Retrieve API key, load threat feeds |
| 6 | **Keycloak SSO** | Create realm `SOC`, OIDC client `soc-sso`, 3 groups, 3 users, groups mapper |
| 6b | **Config Injection** | Inject client_secret into Wazuh/Cortex/TheHive configs, replace domain placeholders |
| 7 | **Wazuh Security** | Copy system CA, run `securityadmin.sh`, verify client_secret, restart dashboard |
| 8 | **Wazuh API** | Create SSO-to-RBAC rules (soc-admin, soc-analyst, soc-readonly) on port 55000 |
| 9 | **Save** | Write all credentials + API keys to `.env.deployed` |

**Safety features:**
- **Idempotent** -- safe to re-run any number of times
- SSL certificates: skips if already exist (avoids Let's Encrypt rate limits)
- Keycloak client: creates if missing, **updates** redirect URIs if exists
- `client_secret`: 3 layers of safety checks to prevent placeholder values
- `OAUTH2_PROXY_COOKIE_SECRET`: reuses existing value on re-runs (preserves sessions)

---

## Post-Deployment UI Configuration (Manual)

After `post-deploy.py` completes, some UI configurations must be done manually.

> **Full step-by-step guide:** See [`POST-DEPLOY-UI-GUIDE.md`](POST-DEPLOY-UI-GUIDE.md)

| Section | Task | Time |
|---------|------|------|
| **A** | TheHive: Add Cortex server integration | 2 min |
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

**Login URL:** `https://WAZUH_DOMAIN` > Click "Log in with single sign-on"

| SSO Group | OpenSearch Roles | Wazuh API Roles (port 55000) | Can Do |
|-----------|-----------------|------------------------------|--------|
| **soc-admin** | `all_access`, `kibana_user` | administrator, users_admin, agents_admin, cluster_admin | Full access: dashboards, agents, rules, decoders, settings, user management |
| **soc-analyst** | `all_access`, `kibana_user` | administrator, users_admin, agents_admin, cluster_admin | Same as admin (full access) |
| **soc-readonly** | `wazuh_user`, `kibana_user` | readonly, agents_readonly, cluster_readonly | View dashboards & alerts only. Cannot modify agents, rules, or settings |

> **Local login also available:** username `admin` / password from `WAZUH_INDEXER_PASSWORD`

---

### 2. TheHive (Case Management)

**SSO Method:** oauth2-proxy + hive-sso-bridge (Node.js)

**Login URL:** `https://THEHIVE_DOMAIN` > Auto-redirects to Keycloak

**How it works:** TheHive 5.x Community Edition does not support native OIDC. Instead, oauth2-proxy handles Keycloak authentication, then the hive-sso-bridge maps the authenticated SSO email to a TheHive local account and logs in automatically.

| SSO Group | TheHive Local Account Mapped | TheHive Role | Can Do |
|-----------|------------------------------|-------------|--------|
| **soc-admin** | `THEHIVE_ADMIN_USER` (admin@thehive.local) | org-admin | Full access: cases, alerts, tasks, observables, org settings, user management |
| **soc-analyst** | `THEHIVE_ANALYST_USER` (analyst@codesec.in) | analyst | Create/edit cases, manage tasks & observables. Cannot manage org settings or users |
| **soc-readonly** | read-only account (if configured) | read-only | View cases and alerts only. Cannot create or modify |

> **Note:** The bridge requires matching TheHive local accounts. `post-deploy.py` creates the admin and analyst accounts automatically. To add more SSO users, add them to a Keycloak group and create a matching local TheHive account.

> **Local login also available:** `admin@thehive.local` / password from `THEHIVE_ADMIN_PASSWORD`

---

### 3. n8n (Workflow Automation / SOAR)

**SSO Method:** oauth2-proxy + hooks.js (shared owner session)

**Login URL:** `https://N8N_DOMAIN` > Auto-redirects to Keycloak

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
6. The SSO user now sees the owner's workspace — all workflows, credentials, and executions

```
soc-admin@codesec.in   ──┐
                          ├── oauth2-proxy (Keycloak auth) ──> hooks.js ──> owner session
analyst@codesec.in     ──┘                                                     |
                                                                    All shared workflows
                                                                    (Wazuh alerts, SOAR, etc.)
```

> **Access control** is handled at the oauth2-proxy level — only `soc-admin` and `soc-analyst` Keycloak groups can reach n8n. `soc-readonly` is blocked with a 403 error.
>
> **All SSO users share one workspace** — any workflow created by one user is visible to all. This is by design for SOC team collaboration.
>
> **Audit trail:** n8n logs show which SSO email triggered each login: `SSO login: analyst@codesec.in -> owner session (admin@codesec.in)`

> **Local login also available:** `N8N_ADMIN_EMAIL` / `N8N_ADMIN_PASSWORD` (owner account)

---

### 4. MISP (Threat Intelligence)

**SSO Method:** Native OIDC (built-in)

**Login URL:** `https://MISP_DOMAIN` > Click "Login with OIDC"

| SSO Group | MISP Role | Can Do |
|-----------|----------|--------|
| **soc-admin** | Auto-created user (default org member) | Access events, attributes, feeds, galaxies. Admin promotion requires manual UI config |
| **soc-analyst** | Auto-created user (default org member) | Same as above (MISP CE auto-creates with default role) |
| **soc-readonly** | Auto-created user (default org member) | Same as above (MISP CE auto-creates with default role) |

> **Note:** MISP Community Edition auto-creates SSO users with the default organization role. To promote a user to Org Admin or Site Admin, go to **Administration > List Users** and change their role manually.

> **Local login also available:** `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD`

---

### 5. Cortex (Observable Analysis)

**SSO Method:** Native OAuth2 (application.conf)

**Login URL:** `https://CORTEX_DOMAIN` > Click "Login with SSO"

| SSO Group | Cortex Roles | Can Do |
|-----------|-------------|--------|
| **soc-admin** | `superadmin` | Full access: manage organizations, users, analyzers, responders. Run any analysis |
| **soc-analyst** | `read`, `analyze`, `orgadmin` | Run analyzers/responders, view results, manage org settings. Cannot manage other organizations |
| **soc-readonly** | `read` | View analysis results only. Cannot run analyzers or modify settings |

> **Role mapping** is configured in `configs/thehive/cortex-application.conf` under `auth.sso.groups.mappings`.

> **Local login also available:** `CORTEX_ADMIN_USER` / `CORTEX_ADMIN_PASSWORD`

---

### 6. Grafana (Metrics & Dashboards)

**SSO Method:** Native OAuth2/OIDC (environment variables)

**Login URL:** `https://GRAFANA_DOMAIN` > Click "Sign in with Keycloak"

| SSO Group | Grafana Role | Can Do |
|-----------|-------------|--------|
| **soc-admin** | Admin | Full access: create/edit dashboards, manage data sources, users, org settings |
| **soc-analyst** | Editor | Create/edit dashboards and panels. Cannot manage data sources or org settings |
| **soc-readonly** | Viewer | View dashboards only. Cannot edit or create |

> **Local login also available:** `GF_ADMIN_USER` / `GF_ADMIN_PASSWORD`

---

### 7. Keycloak (SSO Admin Console)

**URL:** `https://SSO_DOMAIN/admin`

| User | Access |
|------|--------|
| Keycloak master admin (`admin` / `KC_ADMIN_PASSWORD`) | Full Keycloak administration: realms, clients, users, groups, mappers |
| SSO users | No access to Keycloak admin console (they authenticate through it, not manage it) |

---

### Quick Reference — SSO Access Matrix

| Service | soc-admin | soc-analyst | soc-readonly | Local login |
|---------|:---------:|:-----------:|:------------:|:-----------:|
| **Wazuh** | Full admin | Full admin | Read-only | admin / WAZUH_INDEXER_PASSWORD |
| **TheHive** | Org admin (via bridge) | Analyst (via bridge) | Read-only | admin@thehive.local / THEHIVE_ADMIN_PASSWORD |
| **n8n** | Owner session | Owner session | **Blocked** | N8N_ADMIN_EMAIL / N8N_ADMIN_PASSWORD |
| **MISP** | Default member | Default member | Default member | MISP_ADMIN_EMAIL / MISP_ADMIN_PASSWORD |
| **Cortex** | Superadmin | Analyst+orgadmin | Read-only | CORTEX_ADMIN_USER / CORTEX_ADMIN_PASSWORD |
| **Grafana** | Admin | Editor | Viewer | GF_ADMIN_USER / GF_ADMIN_PASSWORD |
| **Keycloak** | N/A | N/A | N/A | admin / KC_ADMIN_PASSWORD |

### Adding More SSO Users

1. Login to Keycloak Admin at `https://SSO_DOMAIN/admin`
2. Switch to realm **`SOC`**
3. **Users** > **Add user** > set username (use email), email, first name, last name
4. **Credentials** > set password (temporary: off)
5. **Groups** > join one of: `soc-admin`, `soc-analyst`, or `soc-readonly`
6. For TheHive: also create a matching local account in TheHive UI

---

## Credentials & API Keys

After `post-deploy.py`, all credentials are saved to `.env.deployed` in the deploy folder.

### Service Logins

| Service | URL | Username | Password (.env key) |
|---------|-----|----------|---------------------|
| **NPM** | `https://NPM_DOMAIN` | `NPM_ADMIN_EMAIL` | `NPM_ADMIN_PASSWORD` |
| **Keycloak** | `https://SSO_DOMAIN/admin` | `admin` | `KC_ADMIN_PASSWORD` |
| **Wazuh** (local) | `https://WAZUH_DOMAIN` | `admin` | `WAZUH_INDEXER_PASSWORD` |
| **n8n** (owner) | `https://N8N_DOMAIN` | `N8N_ADMIN_EMAIL` | `N8N_ADMIN_PASSWORD` |
| **MISP** | `https://MISP_DOMAIN` | `MISP_ADMIN_EMAIL` | `MISP_ADMIN_PASSWORD` |
| **TheHive** | `https://THEHIVE_DOMAIN` | `admin@thehive.local` | `THEHIVE_ADMIN_PASSWORD` |
| **Cortex** | `https://CORTEX_DOMAIN` | `CORTEX_ADMIN_USER` | `CORTEX_ADMIN_PASSWORD` |
| **Grafana** | `https://GRAFANA_DOMAIN` | `GF_ADMIN_USER` | `GF_ADMIN_PASSWORD` |

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

## n8n Wazuh Integration

Wazuh alerts are forwarded to n8n via a custom webhook integration.

```
Wazuh Manager --[custom-n8n]--> n8n Webhook
                                    |
                          +---------+---------+
                          v                   v
                    Send Email          Create TheHive Alert
                   (via SMTP)          (via TheHive API)
                                            |
                                            v
                                  IR Team --> Cases --> Cortex
```

### Integration Files

| File | Purpose |
|------|---------|
| `configs/wazuh/wazuh_cluster/custom-n8n` | Shell wrapper (calls Python script) |
| `configs/wazuh/wazuh_cluster/custom-n8n.py` | Python script (formats alert, HTTP POST) |
| `configs/n8n/1_Wazuh_Email_Alert.json` | n8n workflow definition (import via UI) |

---

## Directory Structure

```
domain-ssl/
|-- docker-compose.yml              # All 22 services
|-- .env                            # Your configuration (from .env.example)
|-- .env.example                    # Template with all variables
|-- .env.deployed                   # Auto-generated credentials (after post-deploy)
|-- .gitattributes                  # Forces LF line endings in Git
|-- pre-deploy.sh                   # Pre-deployment checks & setup
|-- post-deploy.py                  # Auto-configures everything after compose up
|-- test-stack.py                   # Full test suite
|-- test-creds.py                   # Credential validation tests
|-- README.md                       # This file
|-- POST-DEPLOY-UI-GUIDE.md        # Manual UI config guide
|
|-- configs/
|   |-- wazuh/
|   |   |-- certs.yml                       # Cert generator hostname config
|   |   |-- wazuh_indexer_ssl_certs/        # Generated TLS certificates
|   |   |-- wazuh_indexer/
|   |   |   |-- wazuh.indexer.yml           # OpenSearch node config
|   |   |   |-- internal_users.yml          # Password hashes
|   |   |   |-- config.yml                  # Security config (OpenID auth domain)
|   |   |   |-- roles.yml                   # Role definitions
|   |   |   +-- roles_mapping.yml           # Keycloak groups -> OpenSearch roles
|   |   |-- wazuh_dashboard/
|   |   |   |-- opensearch_dashboards.yml   # Dashboard config (OIDC + client_secret)
|   |   |   +-- wazuh.yml                   # Wazuh API connection config
|   |   +-- wazuh_cluster/
|   |       |-- wazuh_manager.conf          # Manager configuration
|   |       |-- custom-n8n                  # Webhook shell wrapper
|   |       +-- custom-n8n.py               # Webhook Python script
|   |-- thehive/
|   |   |-- cortex-application.conf         # Cortex config (SSO + elasticsearch)
|   |   |-- thehive-application.conf        # TheHive config (SSO reference)
|   |   +-- hive-sso-bridge.js              # TheHive SSO email-to-credentials bridge
|   +-- n8n/
|       |-- hooks.js                        # n8n SSO auto-create user hook
|       +-- 1_Wazuh_Email_Alert.json        # n8n workflow template
|
+-- data/                                   # All persistent data volumes
    |-- nginx/                              # NPM data + Let's Encrypt certs
    |-- keycloak_postgres/                  # Keycloak PostgreSQL
    |-- keycloak_data/                      # Keycloak realm + theme cache
    |-- n8n/ n8n_redis/                     # n8n workflows + job queue
    |-- misp/                               # MISP data (configs, logs, mysql, etc.)
    +-- thehive/                            # TheHive ecosystem
        |-- cassandra_data/ cassandra_logs/
        |-- elasticsearch_data/ elasticsearch_logs/
        |-- minio_data/
        |-- thehive_data/ thehive_files/ thehive_index/
        +-- cortex_logs/
```

---

## Management Commands

```bash
# All commands run from your deploy folder (wherever you placed the files)

# -- Start / Stop / Restart --
docker compose up -d                          # Start all 22 containers
docker compose down                           # Stop all (preserves data)
docker compose restart                        # Restart all
docker restart socstack-<name>                # Restart single service

# -- Status & Health --
docker compose ps
docker ps --filter "health=unhealthy"

# -- Logs --
docker compose logs -f socstack-keycloak      # Tail specific service
docker logs socstack-wazuh-dashboard --tail 50

# -- Re-run Configuration (idempotent) --
python3 post-deploy.py
python3 test-stack.py
python3 test-creds.py

# -- Wazuh Agent Management --
docker exec socstack-wazuh-manager /var/ossec/bin/manage_agents -l
docker exec socstack-wazuh-manager /var/ossec/bin/wazuh-control status

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
```

---

## Troubleshooting

### Wazuh SSO returns 401 "Authentication Exception"

**Most common causes:**

1. **`client_secret` placeholder not replaced** in `opensearch_dashboards.yml`:
   ```bash
   grep "WILL_BE_SET_BY_POST_DEPLOY" configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml
   # If found, re-run: python3 post-deploy.py
   ```

2. **Security config not applied** (realm was changed but securityadmin not re-run):
   ```bash
   # Check runtime config:
   curl -sk -u admin:PASSWORD https://localhost:9200/_plugins/_security/api/securityconfig \
     | python3 -m json.tool | grep openid_connect_url
   # If it shows wrong realm, re-run securityadmin.sh (see Management Commands above)
   ```

3. **System CA bundle missing** (indexer can't verify Keycloak's Let's Encrypt cert):
   ```bash
   docker exec -u root socstack-wazuh-indexer \
     cp /etc/ssl/certs/ca-certificates.crt /usr/share/wazuh-indexer/config/certs/system-ca.pem
   # Then restart indexer + dashboard
   ```

### Keycloak GUI broken (CSS returns application/json)

```bash
chown -R 1000:0 data/keycloak_data/
docker restart socstack-keycloak
```

### TheHive/n8n SSO not redirecting to Keycloak

Check that NPM proxy routes through oauth2-proxy, not directly to the service:
- `hive.yourdomain.com` should forward to `socstack-oauth2-proxy-hive:4180`
- `n8n.yourdomain.com` should forward to `socstack-oauth2-proxy-n8n:4180`

### n8n SSO login shows "403 Forbidden"

This means the user's Keycloak group is not in the allowed list. Only **soc-admin** can access n8n. Users in soc-analyst or soc-readonly groups are blocked at the oauth2-proxy level.

### Wazuh custom-n8n "Couldn't execute command"

```bash
# Fix CRLF line endings
sed -i 's/\r$//' configs/wazuh/wazuh_cluster/custom-n8n \
                 configs/wazuh/wazuh_cluster/custom-n8n.py
docker restart socstack-wazuh-manager
```

### Container won't start

```bash
docker logs socstack-<name> --tail 100
docker inspect socstack-<name> --format='{{.State.ExitCode}} {{.State.Error}}'
```

### NPM SSL certificate issues

```bash
# Check certificate status in NPM UI at https://npm.yourdomain.com
# Re-request via: python3 post-deploy.py (Step 1 handles SSL)
```

---

## Re-Deployment / Updates

`post-deploy.py` is **idempotent** -- safe to re-run any number of times:

| Component | On Re-run |
|-----------|-----------|
| NPM proxy hosts | Skipped if already exist |
| SSL certificates | Skipped if already exist (avoids rate limits) |
| Keycloak SSO client | Creates if missing, **updates** redirect URIs if exists |
| SSO client_secret | Reuses existing value (preserves sessions) |
| Cookie secret | Reuses existing value (preserves oauth2-proxy sessions) |
| n8n/Cortex/TheHive | Skipped if already initialized |
| Wazuh security | Always re-applies (safe) |

### Fresh Re-Deploy

```bash
# 1. Stop everything
docker compose down

# 2. Copy updated files
scp -r domain-ssl/* root@YOUR_SERVER_IP:/path/to/deploy/

# 3. Run pre-deploy (fixes CRLF, permissions, certs)
sudo ./pre-deploy.sh

# 4. Start stack
docker compose up -d

# 5. Wait 3-5 minutes, then run post-deploy
python3 post-deploy.py

# 6. Verify
python3 test-stack.py
```

### Deploy from Git (Recommended)

```bash
# Clone directly on server (no CRLF issues)
git clone https://github.com/your-repo/socstack.git /path/to/deploy
cd /path/to/deploy/domain-ssl

cp .env.example .env
nano .env

sudo ./pre-deploy.sh
docker compose up -d
python3 post-deploy.py
```

---

## SSO Technical Details

### Config Files

| File | Purpose |
|------|---------|
| `configs/wazuh/wazuh_indexer/config.yml` | OpenID auth domain: validates JWT tokens, `roles_key: groups` |
| `configs/wazuh/wazuh_indexer/roles_mapping.yml` | Maps Keycloak groups to OpenSearch roles |
| `configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml` | Dashboard OIDC: client_id, client_secret, endpoints |
| `configs/thehive/cortex-application.conf` | Cortex OAuth2 SSO config + group-to-role mapping |
| `configs/thehive/thehive-application.conf` | TheHive OAuth2 config (reference; actual SSO via proxy) |
| `configs/thehive/hive-sso-bridge.js` | Node.js bridge: maps SSO email to TheHive local creds |
| `configs/n8n/hooks.js` | Express middleware: reads `X-Forwarded-Email`, auto-creates n8n users |

### Placeholder System

Config files use `YOUR_*` placeholders that `post-deploy.py` replaces at deploy time:

| Placeholder | Replaced With |
|-------------|---------------|
| `YOUR_SSO_DOMAIN` | SSO_DOMAIN from .env |
| `YOUR_SSO_REALM` | KC_WAZUH_REALM from .env |
| `YOUR_SSO_CLIENT_ID` | KC_WAZUH_CLIENT_ID from .env |
| `YOUR_CORTEX_DOMAIN` | CORTEX_DOMAIN from .env |
| `YOUR_THEHIVE_DOMAIN` | THEHIVE_DOMAIN from .env |
| `YOUR_CORTEX_ORG_NAME` | CORTEX_ORG_NAME from .env |
| `YOUR_THEHIVE_ORG_NAME` | THEHIVE_ORG_NAME from .env |
| `WILL_BE_SET_BY_POST_DEPLOY` | SSO_CLIENT_SECRET (auto-generated) |

---

## License

Internal use. All third-party components retain their original licenses.
