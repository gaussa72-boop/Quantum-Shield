# ULTIMA Central Billing & Checkout Rollout

Status: preparation/specification only. No payment provider has been activated and no private Wise account details are published.

## Scope
Central ULTIMA order, payment and invoice management for every active registered site except:
- Rothshild properties
- Lyca properties
- BullRun Apparel

Keep the existing per-site isolation: each order is permanently associated with its originating site. Do not merge customer accounts or credentials across sites.

## Existing foundation
- `StoreOrder` stores site, external order ID, order number, customer, currency, total, payment/fulfillment state, item snapshot and invoice URL.
- `POST /api/integrations/<slug>/orders` accepts authenticated order-sync requests using a per-site `X-ULTIMA-ORDER-TOKEN`.
- `/admin/order/<id>/invoice` renders a printable invoice view.
- `/admin/site/<slug>/integration-token` issues a one-time integration token.

## Required implementation before production
1. Extend order ingestion so every eligible order receives an immutable ULTIMA invoice number, invoice issue timestamp and a snapshot of seller/customer/address/tax/item data.
2. Add a central invoice register with search/filter/export and downloadable PDF invoices. Never overwrite a finalized invoice; use credit notes for refunds/corrections.
3. Add email delivery and delivery status/retry tracking. Do not mark an email as sent unless SMTP/provider confirms acceptance.
4. Keep payment state separate from fulfillment state. New orders start pending/unpaid. Only verified provider webhooks or an authorized admin reconciliation action may mark an order paid.
5. Add provider-neutral payment records and idempotency keys. Verify webhook signatures, replay windows and event IDs. Never trust a browser redirect or customer-entered TXID as proof of payment.
6. Add SEPA bank-transfer instructions only after a business-eligible receiving account and seller details are approved. Include a unique order reference. Reconcile via an authorized bank feed/API or manual bank-statement review; no automatic activation from an uploaded receipt.
7. Add Apple Pay and Google Pay through a payment service provider that has approved the merchant, domain and payment methods. Wallet availability must be checked per domain/device/country. Payout destination must be a provider-approved business bank account.
8. Keep all payment secrets server-side in Render environment variables. Never commit secrets or put them in frontend code.

## Wise account handling
The Wise details currently supplied belong to a personal account. Do not publish the IBAN in merchant checkout pages, do not use it as a shared commercial settlement destination and do not represent Apple Pay/Google Pay as enabled. Revisit only after Wise confirms the intended business use in writing or a suitable Wise Business account is established.

## Required Render configuration (placeholders only)
- `ULTIMA_SELLER_LEGAL_NAME`
- `ULTIMA_SELLER_ADDRESS`
- `ULTIMA_SELLER_TAX_ID` (only where applicable)
- `ULTIMA_SELLER_VAT_ID` (only where applicable)
- `ULTIMA_INVOICE_PREFIX`
- `ULTIMA_PUBLIC_URL`
- SMTP provider credentials, stored only as Render secrets
- Payment provider API/webhook secrets, stored only as Render secrets

Do not enable production invoicing until legal seller details, tax treatment, invoice numbering policy and retention requirements have been reviewed for the actual seller and jurisdiction.

## Acceptance tests
- Duplicate order webhook does not create a second order or invoice.
- Order from excluded site is rejected from central billing ingestion.
- Unpaid order cannot produce a paid invoice state.
- Invalid/replayed payment webhook is rejected.
- Verified payment event is idempotent and updates exactly one order.
- Refund/correction produces a credit note/reference, not a rewritten invoice.
- Invoice PDF includes seller, customer, issue date, sequential number, line items, currency, tax treatment and totals as applicable.
- Customer email delivery failure is visible and retryable.
- Each site's orders remain isolated in the admin UI and API.
