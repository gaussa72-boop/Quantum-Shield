# ULTIMA Membership Core

Central administration and membership API for the user's Render portfolio.

## Architecture
- Every website has a distinct slug and isolated member namespace (site_id). No cross-site single sign-on.
- Members register and authenticate separately for each website.
- Central admin can register websites, view membership counts, and manage members per website.
- A site administrator role is scoped to one website.
- Passwords are stored as scrypt hashes; API tokens are signed and expire after 12 hours; logout revokes the current token version.
- Admin sessions use secure, HttpOnly, SameSite cookies and CSRF tokens.
- Audit log stores administrative actions, never passwords or tokens.

## Required Render environment
- DATABASE_URL: persistent PostgreSQL connection string (use Render's Internal Database URL).
- SECRET_KEY: long random secret.
- ADMIN_SETUP_TOKEN: one-time bootstrap token; remove it after first admin is created.
- ALLOWED_ORIGINS: comma-separated exact origins for connected sites.
- RATELIMIT_STORAGE_URI: Redis URL for multi-instance rate limiting; memory backend is only a single-instance fallback.

## Routes
- /setup one-time first-admin setup
- /admin/login, /admin central admin
- /admin/site/<slug> central member management
- /api/<slug>/register, /login, /me, /profile, /logout
- /health

## Website widget
Include membership-widget.js in each website and initialize it with that website's unique slug:
<script src="https://ultima-membership-core.onrender.com/membership-widget.js"></script>
<script>UltimaMembership.init({siteSlug:"my-site",brand:"My Site"});</script>

The widget uses sessionStorage (not persistent localStorage) for its short-lived bearer token. Each site's users are isolated by its slug.

## Production gate
The first Render Postgres instance created for evaluation is free and expires on 2026-12-13. Do not use it for production or real member records. Before production, upgrade/create a persistent paid PostgreSQL database, configure its internal URL, Redis-backed rate limiting, email verification and password reset, administrator MFA, and exact allowed origins. The API currently provides registration/login/profile/logout and central member administration; it is not yet a complete production identity provider.
