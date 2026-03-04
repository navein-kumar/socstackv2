# SOC Stack (IP-SSL) - Post-Deployment UI Configuration Guide

After running `post-deploy.py`, the following manual UI configurations are required.

All credentials are in `.env.deployed` inside your deployment folder on the server.
Replace `SERVER_IP` with your actual server IP (from `.env.deployed` → `SERVER_IP`).
Replace `DEPLOY_DIR` with your deployment folder path (wherever you placed the stack files, e.g. `/opt/socstack`, `/home/user/soc-stack`, etc.).

---

## 0. Browser Setup — Import Self-Signed CA Certificate

Before accessing any service, import the self-signed CA into your browser.
Without this, every service will show an SSL warning.

**Download the CA from the server:**
```bash
scp user@SERVER_IP:DEPLOY_DIR/certs/ca.crt ~/socstack-ca.crt
```

### Windows (Chrome / Edge)
1. Open **certmgr.msc** (Windows Certificate Manager)
2. Go to **Trusted Root Certification Authorities** → **Certificates**
3. Right-click → **All Tasks** → **Import**
4. Select `socstack-ca.crt` → Store in **Trusted Root Certification Authorities**
5. Restart browser

### macOS (Chrome / Safari / Edge)
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain socstack-ca.crt
```
Then restart the browser.

### Ubuntu / Debian (Chrome / Chromium)
```bash
sudo cp socstack-ca.crt /usr/local/share/ca-certificates/socstack-ca.crt
sudo update-ca-certificates
```
Restart browser.

### Firefox (All platforms)
1. Open **Settings** → **Privacy & Security** → **Certificates** → **View Certificates**
2. **Authorities** tab → **Import**
3. Select `socstack-ca.crt`
4. Check **Trust this CA to identify websites** → OK

---

## A. TheHive - Cortex Server Integration

1. Login to **TheHive** → `https://SERVER_IP:8447`
   - User: `admin@thehive.local` / *(see `.env.deployed` → `THEHIVE_ADMIN_PASSWORD`)*
2. Go to **Platform Management** → **Cortex Servers** → **Add Server**
3. Fill in:

| Field | Value |
|-------|-------|
| Server Name | `Cortex-SOC` |
| URL | `http://socstack-cortex:9001` |
| API Key | *(see `.env.deployed` → `CORTEX_API_KEY`)* |
| Check Certificate Authority | **DISABLE** (toggle OFF) |
| Disable hostname verification | **ENABLE** (toggle ON) |

4. Click **Confirm**

---

## B. Cortex - Enable & Configure Analyzers

1. Login to **Cortex** → `https://SERVER_IP:8448`
   - User: *(see `.env.deployed` → `CORTEX_ORG_ADMIN` / `CORTEX_ADMIN_PASSWORD`)*
2. Go to **Organization** → **Analyzers** → **Refresh** (click the refresh icon)
3. Wait for the analyzer list to load

### Configure MISP Analyzer (Primary)

1. In the Analyzers list, search for **MISP**
2. Click **Enable** on `MISP_2_1`
3. After enabling, click the **Edit** (pencil) icon on the analyzer
4. Fill in:

| Field | Value |
|-------|-------|
| url | `https://SERVER_IP:8446` |
| key | *(see `.env.deployed` → `MISP_API_KEY`)* |
| cert_check | `false` |

5. Click **Save**

> This uses your local MISP instance for threat intelligence lookups — **free, no external API key needed**. Cortex will query MISP for IOC matches (IPs, domains, hashes, URLs).

### All Recommended Analyzers

| Analyzer | Purpose | API Key | Cost |
|----------|---------|---------|------|
| **MISP_2_1** | Threat intel IOC lookup (local MISP) | `.env.deployed` → `MISP_API_KEY` | Free |
| URLhaus_2_0 | Malicious URL check | Not needed | Free |
| FileInfo_8_0 | File analysis (hash, type, size) | Not needed | Free |
| AbuseIPDB_1_0 | IP reputation check | https://www.abuseipdb.com | Free tier |
| OTXQuery_2_0 | AlienVault OTX threat intel | https://otx.alienvault.com | Free |
| VirusTotal_GetReport_3_1 | File/URL/IP scan reports | https://www.virustotal.com | Paid (free: 4 req/min) |

For each analyzer: **Enable** → **Edit** → enter API key (if needed) → **Save**

---

## C. MISP - Enable & Sync Threat Feeds

1. Login to **MISP** → `https://SERVER_IP:8446`
   - User: *(see `.env.deployed` → `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD`)*
2. Go to **Sync Actions** → **Feeds** → **List Feeds**
3. **Enable all feeds:**
   - Select all feeds (checkbox at top)
   - Click **Enable Selected**
4. **Fetch all feeds:**
   - Select all enabled feeds
   - Click **Fetch and store all feeds**
5. **Cache all feeds:**
   - Select all enabled feeds
   - Click **Cache all feeds**
6. Wait for the background jobs to complete (check **Administration** → **Jobs** for progress)

> **Why this matters:** MISP feeds provide the threat intelligence data that Cortex MISP analyzer uses for IOC lookups. Without enabled feeds, MISP has no data to search against.

---

## D. Wazuh Dashboard - SSO Role Mapping (AUTOMATED)

> **This step is now AUTOMATED by `post-deploy.py` Step 8.** No manual configuration is required.

The following Wazuh role mappings are created automatically during deployment:

| Role Mapping | Roles | Custom Rule |
|-------------|-------|-------------|
| `soc-admin` | administrator, users_admin, agents_admin, cluster_admin | `backend_roles` → Find → `soc-admin` |
| `soc-analyst` | administrator, users_admin, agents_admin, cluster_admin | `backend_roles` → Find → `soc-analyst` |
| `soc-readonly` | readonly, agents_readonly, cluster_readonly | `backend_roles` → Find → `soc-readonly` |

SSO users are assigned permissions based on their Keycloak group membership, which maps to the corresponding backend role above.

> **Note:** To verify or modify these mappings, go to **Wazuh** → **Security** → **Roles mapping** at `https://SERVER_IP:8443`.

---

## E. n8n - Import Wazuh Alert Workflow (Email + TheHive)

1. Login to **n8n** → `https://SERVER_IP:8445`
   - User: *(see `.env.deployed` → `N8N_ADMIN_EMAIL` / `N8N_ADMIN_PASSWORD`)*

2. **Create new workflow** → **Import from file**
   - File on server: `DEPLOY_DIR/configs/n8n/1_Wazuh_Email_Alert.json`

3. **Fix Redis connection** (do this first):
   - Click the Redis node → Edit credentials
   - **Host:** `socstack-n8n-redis`
   - **Port:** `6379`
   - **Password:** *(leave empty — no password)*
   - Save & test connection

4. **Setup SMTP email credentials:**
   - Click the **Send email** node → Edit SMTP credentials
   - Configure:
     - **SMTP Host:** your SMTP server
     - **Port:** 587 (or 465 for SSL)
     - **User:** your SMTP username
     - **Password:** your SMTP password
   - Set **From** email address
   - Set **To** email address(es)

### Configure TheHive Node (Alert Creation)

5. **Generate TheHive API Key for analyst account:**
   - Login to **TheHive** → `https://SERVER_IP:8447`
     - User: `admin@thehive.local` / *(see `.env.deployed` → `THEHIVE_ADMIN_PASSWORD`)*
   - Go to **Organisation** → **Users** → find the analyst user *(see `.env.deployed` → `THEHIVE_ANALYST_USER`)*
   - Click **Create API Key** → **Reveal** → copy the API key
   - ⚠️ **Save this key** — you cannot view it again after closing the dialog

6. **Configure TheHive credentials in n8n:**
   - Click the **TheHive** node in the workflow → Edit credentials
   - Click **Create New Credential** → select **TheHive API**
   - Fill in:

| Field | Value |
|-------|-------|
| API Key | *(TheHive analyst API key from step 5)* |
| URL | `http://socstack-thehive:9000` |
| Ignore SSL Issues | **ON** |

   - Click **Save** → test connection should succeed

7. **Verify TheHive node configuration:**
   - The TheHive node should be set to **Create Alert**
   - Key fields mapped from Wazuh alert data:
     - **Title** → Wazuh rule description
     - **Description** → Alert details (source IP, agent, rule info)
     - **Severity** → Mapped from Wazuh rule level
     - **Type** → `wazuh_alert`
     - **Source** → `Wazuh-SIEM`
   - The incident response team will pick up alerts in TheHive for further investigation

> **TheHive Analyst Account:**
> - User: *(see `.env.deployed` → `THEHIVE_ANALYST_USER` / `THEHIVE_ANALYST_PASSWORD`)*
> - Profile: `analyst` — can create/manage alerts & cases
> - Organisation: *(see `.env.deployed` → `THEHIVE_ORG_NAME`)*

### Enable Workflow & Connect Wazuh

8. **Enable the workflow** (toggle ON at top-right)

9. **Copy the Webhook URL:**
   - Click the **Webhook** node
   - Copy the **Production URL** (e.g., `https://SERVER_IP:8445/webhook/xxxxx`)

10. **Update Wazuh manager config with new webhook URL:**
    - Edit on server: `DEPLOY_DIR/configs/wazuh/wazuh_cluster/wazuh_manager.conf`
    - Find the `<integration>` section for `custom-n8n`
    - Replace the `<hook_url>` value with your new webhook URL:
    ```xml
    <integration>
      <name>custom-n8n</name>
      <hook_url>https://SERVER_IP:8445/webhook/YOUR-NEW-WEBHOOK-ID</hook_url>
      ...
    </integration>
    ```

11. **Restart Wazuh manager** to pick up the new webhook URL:
    ```bash
    docker restart socstack-wazuh-manager
    ```

12. **Test the full pipeline:**
    - Trigger a Wazuh alert (e.g., failed SSH login)
    - Verify **email notification** arrives
    - Verify **TheHive alert** is created at `https://SERVER_IP:8447` → **Alerts** page
    - Incident team can then promote alerts to **Cases** for investigation

---

## Quick Reference: Service URLs

Replace `SERVER_IP` with the value from `.env.deployed` → `SERVER_IP`.

| Service | URL | Purpose |
|---------|-----|---------|
| Wazuh Dashboard | `https://SERVER_IP:8443` | SIEM Dashboard |
| Keycloak SSO | `https://SERVER_IP:8444` | SSO Admin Console |
| n8n | `https://SERVER_IP:8445` | Workflow Automation |
| MISP | `https://SERVER_IP:8446` | Threat Intelligence |
| TheHive | `https://SERVER_IP:8447` | Case Management |
| Cortex | `https://SERVER_IP:8448` | Analysis Engine |

> **SSL Note:** All URLs use the self-signed CA from `certs/ca.crt`. Import the CA into your browser (see Section 0) to avoid SSL warnings.

---

## Quick Reference: Key Values from `.env.deployed`

| Key | Used In |
|-----|---------|
| `SERVER_IP` | All service URLs |
| `CORTEX_API_KEY` | TheHive → Cortex server config |
| `MISP_API_KEY` | Cortex MISP analyzer, TheHive → MISP (optional) |
| `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` | MISP login, feeds setup |
| `THEHIVE_ADMIN_PASSWORD` | TheHive admin login |
| `THEHIVE_ANALYST_USER` | TheHive analyst account (n8n API key) |
| `THEHIVE_ANALYST_PASSWORD` | TheHive analyst login |
| `CORTEX_ADMIN_PASSWORD` | Cortex login |
| `WAZUH_INDEXER_PASSWORD` | Wazuh Dashboard basic auth login |
| `N8N_ADMIN_EMAIL` / `N8N_ADMIN_PASSWORD` | n8n login |
