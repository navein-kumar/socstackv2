/**
 * n8n Community Edition SSO Hook (v4.0 - Stable for n8n 1.109.x)
 *
 * Bypasses n8n CE's workflow sharing limitation by logging ALL SSO users
 * into the single owner account. This way everyone sees the same workflows,
 * credentials, and executions.
 *
 * Flow:
 *   Browser -> Nginx -> oauth2-proxy (Keycloak auth) -> n8n
 *   oauth2-proxy verifies Keycloak token and group membership
 *   This hook reads the trusted header, then issues a session cookie
 *   for the n8n OWNER account (not the SSO user's email)
 *
 * Why:
 *   n8n Community Edition does not support workflow sharing, RBAC, or
 *   team workspaces. Each user gets an isolated workspace. By mapping
 *   all SSO logins to the owner account, the entire SOC team shares
 *   one workspace with all workflows (Wazuh alerts, SOAR playbooks, etc.)
 *
 * Access control is handled at the oauth2-proxy level:
 *   - soc-admin AND soc-analyst Keycloak group members can reach n8n
 *   - soc-readonly is blocked before reaching this hook
 *   - Both groups get the same owner session (full workflow access)
 *
 * Origin header fix:
 *   oauth2-proxy strips the Origin header when proxying to the upstream.
 *   n8n's push endpoint (/rest/push) requires a valid Origin header for
 *   SSE/WebSocket connections. This hook reconstructs it from
 *   X-Forwarded-Host + X-Forwarded-Proto that oauth2-proxy sets.
 *
 * Version history:
 *   v3.1 — Initial version with Origin fix
 *   v3.2 — Attempted n8n 2.7+ role relation fix (createQueryBuilder)
 *   v3.3 — Two-query merge for n8n 2.7.5 TypeORM bug
 *   v4.0 — Downgraded to n8n 1.109.2 (role is string, no TypeORM bug)
 *          + Defensive caching (don't cache owner if email is null)
 *          + Lazy owner lookup (works even if n8n starts before post-deploy)
 *
 * Environment variables:
 *   N8N_FORWARD_AUTH_HEADER  - Header name from oauth2-proxy (default: X-Forwarded-Email)
 *   N8N_OWNER_EMAIL          - Owner account email (default: from DB, first user)
 *   SSO_LOGOUT_URL           - Logout redirect (default: /oauth2/sign_out)
 */
module.exports = {
  n8n: {
    ready: [
      async function (server, config) {
        const headerName = (process.env.N8N_FORWARD_AUTH_HEADER || "X-Forwarded-Email").toLowerCase();
        const app = server.app;

        // Use Module.createRequire to resolve n8n internal dependencies
        const { createRequire } = require("module");
        const n8nRequire = createRequire("/usr/local/lib/node_modules/n8n/package.json");

        const Layer = n8nRequire("router/lib/layer");
        const { issueCookie } = require("/usr/local/lib/node_modules/n8n/dist/auth/jwt.js");

        const log = (level, msg) => {
          try { server.logger?.[level]?.(msg); } catch {}
          console.log(`[SSO] ${msg}`);
        };

        log("info", `Initializing SSO middleware (shared owner session), header: ${headerName}`);

        app.set("trust proxy", 1);

        const ignoreAuth = /^\/(assets|healthz|webhook|rest\/oauth2-credential|health|favicon|icons)/;
        const cookieName = "n8n-auth";
        const UserRepo = this.dbCollections.User;

        // ── Find the n8n owner account ──
        // The owner is the first user created by post-deploy.py with role "global:owner".
        // n8n 1.109.x stores role as a simple string column on the User entity.
        //
        // DEFENSIVE CACHING: Only cache the owner if the user has a valid email.
        // On fresh deploy, n8n may start BEFORE post-deploy creates the owner.
        // Without this check, a null/broken owner gets cached permanently and
        // SSO never works until n8n is manually restarted.
        let ownerUser = null;
        const ownerEmail = process.env.N8N_OWNER_EMAIL || "";

        async function findOwner() {
          // Only return cached owner if it has a valid email
          if (ownerUser?.email) return ownerUser;
          ownerUser = null; // Clear any broken cached result

          try {
            // Strategy 1: Find by configured email (most reliable)
            if (ownerEmail) {
              const user = await UserRepo.findOneBy({ email: ownerEmail.toLowerCase() });
              if (user?.email) {
                ownerUser = user;
                log("info", `Owner found by email: ${user.email} (role: ${user.role}, id: ${user.id})`);
                return ownerUser;
              }
            }

            // Strategy 2: Find by role (n8n 1.109.x — role is a string column)
            try {
              const byRole = await UserRepo.findOneBy({ role: "global:owner" });
              if (byRole?.email) {
                ownerUser = byRole;
                log("info", `Owner found by role: ${byRole.email} (role: ${byRole.role}, id: ${byRole.id})`);
                return ownerUser;
              }
            } catch {
              // role query might fail on n8n 2.x where role is a relation — ignore
            }

            // Strategy 3: First user in DB (always the owner in n8n CE)
            const first = await UserRepo.findOne({ where: {}, order: { createdAt: "ASC" } });
            if (first?.email) {
              ownerUser = first;
              log("info", `Owner fallback (first user): ${first.email} (role: ${first.role}, id: ${first.id})`);
              return ownerUser;
            }

            // No users yet (n8n started before post-deploy ran)
            log("warn", "No users found in database — owner will be resolved on first request");
          } catch (err) {
            log("error", `Owner lookup error: ${err.message}`);
          }

          return ownerUser;
        }

        // Pre-warm the owner lookup (may be null if post-deploy hasn't run yet)
        await findOwner();

        // ── Middleware stack injection ──
        const { stack } = app._router || app.router;
        const idx = stack.findIndex((l) => l?.name === "cookieParser");

        if (idx === -1) {
          log("error", "cookieParser not found in middleware stack, trying fallback position");
        }

        // ── FIX: Reconstruct missing Origin header ──
        // oauth2-proxy strips the Origin header when proxying to the upstream.
        // n8n's push endpoint (/rest/push) may require a valid Origin header for
        // SSE/WebSocket connections. We reconstruct it from X-Forwarded-Host +
        // X-Forwarded-Proto that oauth2-proxy sets (with --reverse-proxy=true).
        const originFixLayer = new Layer("/", { strict: false, end: false }, (req, res, next) => {
          if (!req.headers.origin) {
            const fwdHost = req.headers["x-forwarded-host"] || req.headers.host;
            const fwdProto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
            if (fwdHost) {
              const host = fwdHost.split(",")[0].trim();
              req.headers.origin = `${fwdProto}://${host}`;
            }
          }
          next();
        });
        originFixLayer.name = "ssoOriginFix";

        // ── SSO session middleware ──
        const ssoLayer = new Layer("/", { strict: false, end: false }, async (req, res, next) => {
          try {
            if (ignoreAuth.test(req.url)) return next();

            // Skip if already authenticated via n8n-auth cookie
            if (req.cookies?.[cookieName]) return next();

            // Read email from trusted proxy header (proves Keycloak auth passed)
            const emailHeader = req.headers[headerName];
            if (!emailHeader) return next();

            const ssoEmail = String(emailHeader).trim().toLowerCase();
            if (!ssoEmail || !ssoEmail.includes("@")) return next();

            // Find the owner account (re-tries DB if not yet cached)
            const owner = await findOwner();
            if (!owner || !owner.email) {
              log("error", `Cannot issue session — owner account not found. SSO user: ${ssoEmail}`);
              return next();
            }

            // Issue session cookie for the OWNER account (not the SSO user)
            await issueCookie(res, owner);
            log("info", `SSO login: ${ssoEmail} -> owner session (${owner.email})`);
            return next();
          } catch (error) {
            log("error", `Middleware error: ${error.message}`);
            return next();
          }
        });
        ssoLayer.name = "ssoSessionIssuer";

        // Insert both middleware after cookieParser (or at position 2 as fallback)
        // Order: ... cookieParser -> originFix -> ssoSession -> ... (rest of n8n stack)
        const insertIdx = idx !== -1 ? idx + 1 : 2;
        stack.splice(insertIdx, 0, originFixLayer, ssoLayer);
        log("info", `Origin fix middleware installed at stack position ${insertIdx}`);
        log("info", `SSO session middleware installed at stack position ${insertIdx + 1}`);

        // ── Logout: clear n8n cookie + redirect through oauth2-proxy logout ──
        const ssoLogoutUrl = process.env.SSO_LOGOUT_URL || "/oauth2/sign_out";

        // Intercept n8n's native logout (POST /rest/logout)
        // Without this, n8n only clears its own cookie but oauth2-proxy's
        // session (_n8n_oauth2 cookie) stays alive, so the user is immediately
        // auto-logged back in. We redirect through the full chain:
        //   POST /rest/logout -> 303 -> /oauth2/sign_out -> Keycloak logout -> /
        app.post("/rest/logout", (req, res) => {
          res.clearCookie(cookieName, { path: "/" });
          res.redirect(303, ssoLogoutUrl);
        });

        // SSO logout helper (GET)
        app.get("/sso-logout", (req, res) => {
          res.clearCookie(cookieName, { path: "/" });
          res.redirect(ssoLogoutUrl);
        });

        log("info", "SSO hook initialization complete (shared owner session mode)");
      }
    ]
  }
};
