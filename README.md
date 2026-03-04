# SOC Stack v2

Automated deployment of a full Security Operations Center (SOC) stack with SSO integration.

## Deployment Modes

| Mode | Folder | Access | SSL |
|------|--------|--------|-----|
| **Domain-based** | `domain-ssl/` | Via domain names (e.g., `wazuh.example.com`) | Let's Encrypt certificates via Nginx Proxy Manager |
| **IP-based** | `ip-ssl/` | Via IP + ports (e.g., `https://1.2.3.4:8443`) | Self-signed CA + server certificate |

## Stack Components

- **Wazuh** — SIEM & XDR (Manager + Indexer + Dashboard)
- **Keycloak** — SSO & Identity Management
- **n8n** — SOAR / Workflow Automation
- **MISP** — Cyber Threat Intelligence Platform
- **TheHive** — Incident Response Platform
- **Cortex** — Observable Analysis & Active Response
- **Grafana** — Monitoring & Visualization (domain-ssl only)

## SSO Integration

Services use Keycloak SSO via oauth2-proxy or native OIDC. MISP and Cortex use their own local authentication.

| Role | Wazuh | n8n | TheHive | Grafana |
|------|-------|-----|---------|---------|
| `soc-admin` | Full admin | Full access (shared owner session) | Org-admin | Admin |
| `soc-analyst` | Read-only | Full access (shared owner session) | Analyst | Viewer |
| `soc-readonly` | Read-only | Blocked | Read-only | Viewer |

| Service | Auth Method |
|---------|------------|
| **MISP** | Local auth (email + password + API key) |
| **Cortex** | Local auth (username + password + API key) |
| **Keycloak** | Admin console (SSO provider itself) |

## Quick Start

1. Choose a deployment mode (`domain-ssl/` or `ip-ssl/`)
2. Copy `.env.example` to `.env` and fill in your values
3. Run `pre-deploy.sh` to generate certificates and configs
4. Run `docker-compose up -d` to start all services
5. Run `post-deploy.py` to configure SSO, users, and integrations

See the README inside each folder for detailed instructions.
