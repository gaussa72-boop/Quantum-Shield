# ULTIMA Telegram Support Rollout

## Public support destination
- Telegram username: @Ari_phenex
- Link: https://t.me/Ari_phenex
- Central widget asset: https://ultima-membership-api.onrender.com/support-widget.js

## Website integration
Add this script immediately before the closing body tag on each eligible website:
```html
<script src="https://ultima-membership-api.onrender.com/support-widget.js" defer></script>
```
The widget creates a small fixed Telegram support link. It does not collect customer data, read page content, or send messages automatically.

## Exclusions
Do not add the widget to Rothshild, Lyca, or BullRun websites unless the owner explicitly changes this scope.

## Actual bot status
This integration currently links visitors to the public Telegram username. It does not create a Telegram bot, send bot messages, or provide a private ticket inbox. A Telegram bot must first be created/owned in Telegram via the official BotFather flow. Store its token only as a Render secret (never commit or paste it in chat). A webhook endpoint, secret validation, ticket persistence, admin replies, rate limits, and privacy notice are required before automated bot handling is enabled.

## Deployment checklist
1. Deploy the ULTIMA service; the static script is served from the repository root.
2. Add the script tag to each eligible website frontend repository and deploy each site.
3. Verify widget visibility, link destination, mobile layout, and excluded sites.
4. If a bot is later provisioned, implement signed webhook handling and a protected admin inbox before accepting messages.
