# ULTIMA Membership & Credit Core

Central membership and credit API for the complete registered Render portfolio, including the Rothshild properties.

## Membership architecture
- Every website, including each Rothshild property, has a distinct slug and isolated member namespace (site_id). No cross-site single sign-on; the central ULTIMA owner manages the portfolio, while member accounts, tokens, credits, and orders remain site-scoped.
- Members register and authenticate separately for each website.
- Central admin can register websites, view membership counts, and manage members per website.
- A site administrator role is scoped to one website.
- Passwords are stored as scrypt hashes; API tokens are signed and expire after 12 hours; logout revokes the current token version.
- Admin sessions use secure, HttpOnly, SameSite cookies and CSRF tokens.
- Audit log stores administrative actions, never passwords or tokens.

## Credit wallet and Bitcoin top-ups
- Each member has a separate credit balance per website.
- 1 credit = 1 USD. Minimum top-up: 5 USD, whole-dollar increments.
- Bitcoin network: Bitcoin mainnet.
- Receiving wallet: configured only through Render environment variable BTC_RECEIVE_ADDRESS; no address is hardcoded.
- A member submits the amount and 64-character Bitcoin transaction ID. The payment remains pending.
- The central administrator must independently verify the transaction, destination, confirmations and USD-equivalent amount before approving it. Approval credits the member's balance once; duplicate TXIDs are rejected.
- No automatic on-chain verification or live BTC/USD pricing is claimed in this version.
- Real top-ups are deliberately disabled in Render with CRYPTO_TOPUPS_ENABLED=false while the test database is temporary. Do not accept real Bitcoin payments until a persistent production database and verification workflow are ready.

## Default per-generation prices
- ai_generation: 1 credit
- image_generation: 2 credits
- video_generation: 5 credits
- music_generation: 3 credits
- game_generation: 25 credits
- dlc_generation: 15 credits
- mod_generation: 10 credits

These are server-side prices in GENERATION_PRICES; configure them to match actual model/API costs. Apps should call /api/<slug>/credits/consume only after the generation has succeeded, with a unique request_id. Failed generations should not be charged. The endpoint is idempotent for a given member, site and request ID.

## Required Render environment
- DATABASE_URL: persistent PostgreSQL connection string (use Render's Internal Database URL).
- SECRET_KEY: long random secret.
- ADMIN_SETUP_TOKEN: one-time bootstrap token; remove it after first admin is created.
- ALLOWED_ORIGINS: comma-separated exact origins for connected sites.
- RATELIMIT_STORAGE_URI: Redis URL for multi-instance rate limiting; memory backend is only a single-instance fallback.

## Routes
- /setup one-time first-admin setup
- /admin/login, /admin central admin and pending payment approval
- /admin/site/<slug> central member management
- /api/<slug>/register, /login, /me, /profile, /logout
- /api/<slug>/credits/balance, /credits/history, /credits/purchase, /credits/consume
- /health

## Website widget
Include the widget on each non-Rothshild website:
<script src="https://ultima-membership-api.onrender.com/membership-widget.js"></script>
<script>UltimaMembership.init({siteSlug:"my-site",brand:"My Site"});</script>

The widget uses sessionStorage for its short-lived bearer token. Each site's members and credit balance are isolated by its slug.

## Important deployment and security status
The initial Render test database is free and expires on 2026-12-13. Do not use it for production or real member balances. Before real payments: use a persistent paid database, Redis-backed rate limiting, email verification and password reset, MFA for administrators, strict origins, operational backups, and an independent Bitcoin transaction verification procedure. The app currently records TXIDs and supports manual review; it does not independently query the Bitcoin network or determine fiat exchange value.

## ULTIMA autonomy and publishing policy
- `ULTIMA_AI_MODE=multi` selects the multi-provider integration mode. This is a routing/configuration mode, not proof that providers are connected.
- Provider adapters and credentials must be configured separately in Render as secret environment variables. Never commit API keys to GitHub.
- `ULTIMA_PUBLISH_MODE=approval` is the safe default: generated content remains a draft until the owner explicitly approves it. Do not grant an agent unrestricted access to publish, alter prices, change checkout/payment settings, or deploy production code.
- The current core exposes the active AI and publishing policy in `/health`. It does not itself generate content, train model weights, crawl the internet continuously, or publish to third-party sites.
- Recommended workflow: research/source capture -> draft -> malware/copyright/privacy/policy checks -> owner approval -> publish via the target platform's official API -> audit log and notification.
- For Shopify/Printful and order integrations, configure each site's `ULTIMA_ORDER_TOKEN` only after obtaining its site-specific token in the authenticated central admin. BullRun additionally requires a Shopify webhook secret and a verified Shopify webhook. Never reuse tokens across sites.
- Do not enable automatic payment approval or automatic deployment from AI-generated code.
