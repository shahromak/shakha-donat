# SHAKHA DONAT API

Initial server scaffold only. No real payments, receipt uploads, Telegram OTP or order persistence yet.

## Deploy on Render
1. New > Web Service > connect GitHub repository shahromak/shakha-donat.
2. Runtime Node, build command npm install, start command npm start.
3. Add secret environment variable TELEGRAM_BOT_TOKEN in Render dashboard (never commit token).
4. Set ADMIN_TELEGRAM_ID to 8465117749 and ALLOWED_ORIGINS to https://shahromak.github.io (add https://shakha.tj once domain is live).
5. Confirm GET /health returns JSON ok:true.

## Auth
GET /api/me and /api/admin/check require Authorization: tma <Telegram WebApp.initData>. The server verifies Telegram signature and auth_date. Admin permission is checked server-side.

## Before taking payments
Implement durable database, bot webhook, optional server-issued OTP, session handling, orders, receipt storage, reconciliation and admin audit logs. Never trust a receipt screenshot as proof of payment. Avoid storing tokens or payment details in public files.
