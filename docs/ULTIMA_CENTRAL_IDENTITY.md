# ULTIMA Central Identity – staged rollout

## Current state

The production membership API currently stores a separate `Member` for each `site_id`. Existing bearer tokens also contain the site ID. This is site-scoped authentication, not shared identity. Do not label the current service as SSO.

The companion `sso-rollout.json` is a policy manifest only. It explicitly allows the approved portfolio sites and denies unknown sites. It does not activate authentication or change the production database.

## Required target model

- `Identity`: global immutable user ID, normalized verified email, account status, password hash (or external identity provider), token/session version.
- `Profile`: display name, avatar URL, biography and user-editable profile fields.
- `SiteMembership`: identity ID + site ID, status and site-specific role.
- `RolePermission`: centrally managed role/permission grants with explicit site scope.
- `OAuthClient`: registered site slug, exact redirect URIs, allowed scopes and client status.
- `AuthorizationCode`: hashed, one-time, short-lived code bound to client, redirect URI and PKCE S256 challenge.
- `RefreshSession`: hashed rotating refresh token, expiry, revocation and device metadata.

## Cross-domain login flow

1. A participating site redirects to the ULTIMA identity service with a registered client ID, exact redirect URI, state, nonce and PKCE S256 challenge.
2. ULTIMA authenticates the user on its own origin and checks that the site is explicitly enabled in the allowlist.
3. ULTIMA issues a short-lived, one-time authorization code bound to the client and PKCE challenge.
4. The site backend exchanges the code server-to-server and verifies the PKCE verifier.
5. ULTIMA returns a minimal identity assertion and site-scoped permissions. The participating site creates its own secure session.
6. Logout and revocation are coordinated through the identity/session endpoints. No cross-domain cookie sharing is used.

## Migration safety

- Back up PostgreSQL and test restore before schema changes.
- Create new identity and membership tables additively; do not drop or rewrite the existing Member table in the first migration.
- Produce a dry-run report of duplicate normalized emails and conflicting credentials.
- Never merge accounts solely because their email strings match. Require verified email ownership and a safe account-linking procedure.
- Preserve site-scoped credits, orders, audit history, and payment references. These remain scoped to their original site.
- Migrate one pilot site first, verify registration/login/logout/profile/role checks, then expand in controlled batches.
- Keep a rollback path and retain legacy authentication until all pilot checks pass.
- Do not enable real-money/payment changes as part of identity migration.

## Permanent exclusions

Rothshild properties, Lyca, all webshops, the Parfum shop, and Rea Signature are excluded. The manifest uses an explicit allowlist and denies unknown sites by default.

## Activation gate

SSO must remain disabled until:
- the target schema and migrations are implemented and tested;
- account-linking conflicts have been reviewed;
- exact redirect URIs and client secrets are configured outside GitHub;
- CSRF/state/nonce/PKCE, token expiry, rotation, revocation and rate limits are tested;
- database backup and restore have been verified;
- the pilot site has passed end-to-end tests.
