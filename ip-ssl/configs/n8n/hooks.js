/**
 * n8n Community Edition SSO Hook (v2 - n8n 2.7.5 compatible)
 * Auto-login users via trusted proxy headers (oauth2-proxy + Keycloak)
 *
 * Flow: Browser -> NPM -> oauth2-proxy (Keycloak auth) -> n8n
 * oauth2-proxy sets X-Auth-Request-Email header after successful Keycloak login
 * This hook reads that header and auto-creates/logs-in the user
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
        const { randomBytes } = require("crypto");
        const { hash } = n8nRequire("bcryptjs");
        const { issueCookie } = require("/usr/local/lib/node_modules/n8n/dist/auth/jwt.js");

        const log = (level, msg) => {
          try { server.logger?.[level]?.(msg); } catch {}
          console.log(`[SSO] ${msg}`);
        };

        log("info", `Initializing SSO middleware, header: ${headerName}`);

        app.set("trust proxy", 1);

        const ignoreAuth = /^\/(assets|healthz|webhook|rest\/oauth2-credential|health|favicon|icons)/;
        const cookieName = "n8n-auth";
        const UserRepo = this.dbCollections.User;

        const { stack } = app._router || app.router;
        const idx = stack.findIndex((l) => l?.name === "cookieParser");

        if (idx === -1) {
          log("error", "cookieParser not found in middleware stack, trying fallback position");
        }

        const layer = new Layer("/", { strict: false, end: false }, async (req, res, next) => {
          try {
            if (ignoreAuth.test(req.url)) return next();

            // Skip if already authenticated via n8n-auth cookie
            if (req.cookies?.[cookieName]) return next();

            // Read email from trusted proxy header
            const emailHeader = req.headers[headerName];
            if (!emailHeader) return next();

            const userEmail = String(emailHeader).trim().toLowerCase();
            if (!userEmail || !userEmail.includes("@")) return next();

            // Extract names from JWT access token if available
            let firstName = "";
            let lastName = "";
            const accessToken = req.headers["x-forwarded-access-token"] || req.headers["x-auth-request-access-token"] || "";
            if (accessToken) {
              try {
                const parts = String(accessToken).split(".");
                if (parts.length === 3) {
                  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
                  firstName = payload.given_name || "";
                  lastName = payload.family_name || "";
                }
              } catch {}
            }

            // Find or create user
            let user = await UserRepo.findOne({ where: { email: userEmail } });

            if (!user) {
              log("info", `Creating new SSO user: ${userEmail}`);
              const hashed = await hash(randomBytes(16).toString("hex"), 10);
              try {
                const result = await UserRepo.createUserWithProject({
                  email: userEmail,
                  firstName: firstName || userEmail.split("@")[0],
                  lastName: lastName || "SSO",
                  password: hashed,
                  role: "global:member",
                });
                user = result.user;
              } catch (createErr) {
                log("error", `Failed to create user ${userEmail}: ${createErr.message}`);
                return next();
              }
            } else {
              // Update name if changed
              let changed = false;
              if (firstName && user.firstName !== firstName) { user.firstName = firstName; changed = true; }
              if (lastName && user.lastName !== lastName) { user.lastName = lastName; changed = true; }
              if (changed) {
                try { await UserRepo.save(user); } catch {}
              }
            }

            // Reload user with role relation (required for issueCookie which accesses user.role.slug)
            user = await UserRepo.findOne({
              where: { id: user.id },
              relations: ["role", "authIdentities"],
            });

            if (!user) {
              log("error", `Failed to reload user ${userEmail}`);
              return next();
            }

            // Issue session cookie
            await issueCookie(res, user);
            log("info", `SSO login successful: ${userEmail}`);
            return next();
          } catch (error) {
            log("error", `Middleware error: ${error.message}`);
            return next();
          }
        });

        // Insert middleware after cookieParser (or at position 2 as fallback)
        const insertIdx = idx !== -1 ? idx + 1 : 2;
        stack.splice(insertIdx, 0, layer);
        log("info", `Middleware installed at stack position ${insertIdx}`);

        // Logout endpoints
        const ssoLogoutUrl = process.env.SSO_LOGOUT_URL || "/oauth2/sign_out";

        // Intercept n8n's native logout (POST /rest/logout).
        // Without this, n8n only clears its own cookie but oauth2-proxy's
        // session (_n8n_oauth2 cookie) stays alive, so the user is immediately
        // auto-logged back in. We redirect the browser through the full chain:
        //   POST /rest/logout → 303 → /oauth2/sign_out → Keycloak logout → /
        app.post("/rest/logout", (req, res) => {
          res.clearCookie(cookieName, { path: "/" });
          res.redirect(303, ssoLogoutUrl);
        });

        // SSO logout helper (GET) — used by /sso-logout links or manual calls
        app.get("/sso-logout", (req, res) => {
          res.clearCookie(cookieName, { path: "/" });
          res.redirect(ssoLogoutUrl);
        });

        log("info", "SSO hook initialization complete");
      }
    ]
  }
};
