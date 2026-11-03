# proxy-header-auth

HFS plugin that trusts reverse-proxy identity headers and logs users into their HFS account.

## What it does

- Reads an identity header (default: `X-Forwarded-User`).
- Trusts it only when the request comes from configured `trustedProxies`.
- Optionally requires a shared-secret header/value pair.
- Resolves identity to an HFS account by:
  - direct username match,
  - optional email local-part fallback,
  - optional email field lookup (`emailFieldPath`, default `plugin.email`),
  - optional explicit mapping table (`mapping`).
- Includes a safety bypass for login API endpoints (enabled by default).
- Supports optional logout redirect (`logoutRedirect`): browser requests get HTTP redirect, API requests receive `x-proxy-header-auth-logout`.
- Also exposes `x-proxy-header-auth-logout` on explicit HFS logout API calls (`/~/api/logout`) when `logoutRedirect` is configured.
- Calls HFS internal `setLoggedIn()` through `api.require('./auth')`.

## Recommended setup

1. Put HFS behind a reverse proxy.
2. Make sure direct access to HFS is blocked from untrusted networks.
3. Configure proxy auth (OIDC/SAML/whatever), enforce it on protected routes, and forward headers only after successful auth.
4. Configure this plugin:
   - `trustedProxies`: proxy IP/netmask(es)
   - `userHeader`: header carrying identity
   - optionally `requiredHeaderName` + `_requiredHeaderValue` (shown as "Required header value")
5. Configure proxy/client logout behavior:
   - browser flow: follow HTTP redirects;
   - API flow: consume `x-proxy-header-auth-logout` and redirect/logout on that value.

## Scope and standards

- This plugin follows a common reverse-proxy pattern: proxy authenticates users, then forwards trusted identity headers to the upstream app.
- That pattern is widely used, but there is no single formal standard that defines every header name and flow in the same way.
- The `x-proxy-header-auth-logout` response header is plugin-specific integration behavior, not a cross-platform auth standard.
- In practice, this plugin covers the HFS side. The other half must be implemented in your reverse proxy/client setup (auth enforcement, header forwarding, and logout handling).

## Example

If proxy sends:

- `X-Forwarded-User: alice@example.com`

you can map to account `alice` by enabling `allowEmailLocalPart`, or with explicit mapping:

`alice@example.com = alice`

## Notes

- This plugin is meant for trusted reverse-proxy deployments.
- If you enable `autoCreateAccounts`, created users are marked as plugin-auth accounts.

## Production notes

- Keep `trustedProxies` strict: include only your reverse-proxy IPs/networks (avoid `*`).
- Set `requiredHeaderName` + `_requiredHeaderValue` to add a shared-secret check between proxy and HFS.
- On upgrade, `requiredHeaderValue` is automatically migrated to `_requiredHeaderValue` and the old key is removed. An already configured `_requiredHeaderValue` takes precedence. The leading underscore excludes the secret from HFS's "Export without passwords".
- Choose `logoutWhenHeaderMissing` based on your proxy behavior:
  - `true` keeps HFS session aligned with proxy auth state;
  - `false` avoids unexpected logout if some routes are missing auth headers.
