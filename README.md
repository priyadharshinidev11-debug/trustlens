# TrustLens

Check it before you trust it. Paste a link, SMS/WhatsApp message, UPI ID, phone number or QR code and get a
verdict (safe / suspicious / dangerous), a 0-100 risk score, the exact reasons, and what to do next.

Full stack: **Node.js API + SQLite/PostgreSQL database + framework-free web frontend**. No build step.

## Run it

Requires **Node.js 22.13 or newer**.

```bash
cp .env.example .env        # optional for local use
npm run seed                # optional: demo community reports
npm start                   # http://localhost:3000
```

With no `DATABASE_URL`, data is stored in `data/trustlens.db` (SQLite), so it works with zero setup.
Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` to get a moderator account.

### Use PostgreSQL
```bash
docker compose up -d
npm install                 # installs the optional "pg" driver
# in .env:
# DATABASE_URL=postgres://trustlens:trustlens@localhost:5432/trustlens
npm run migrate && npm start
```
The same `server/db/schema.sql` runs on both databases (UUID text ids, ISO timestamps, JSON as text).

### Tests
```bash
npm test     # 12 detection-engine tests + 6 API tests (in-memory database)
```

## Features
| Area | What it does |
|---|---|
| Scanner | Auto-detects link / message / UPI ID / phone / QR image. Marks up the exact scam phrases in a message and breaks a link into parts so you can see the *real* website. |
| Engine | Brand look-alikes and typosquats, raw IPs, `@` tricks, punycode, risky TLDs, shorteners, `.apk` links, 18 message scam patterns (KYC, OTP theft, UPI collect, digital arrest, parcel, utility, task jobs...), English + starter Hindi/Tamil, UPI-ID and payment-link checks. Genuine OTP notices are not flagged. |
| Community | Report scams, confirm/dispute reports. Enough net confirmations (`BLOCKLIST_THRESHOLD`) or a moderator verification puts it on the blocklist used by every scan. |
| Accounts | Sign up / sign in (scrypt passwords, JWT), history with filters and delete, personal dashboard. |
| Moderation | Admin queue: verify, reject, reopen reports. |
| Public API | Create API keys, call `POST /api/v1/scan` with `X-API-Key` (120 req/min per key). |
| Learn | Eight scam playbooks and what to do if money is lost (1930, cybercrime.gov.in). |
| Optional | Google Safe Browsing lookup when `GOOGLE_SAFE_BROWSING_KEY` is set. |

## Layout
```
server/
  index.js, app.js         HTTP server, routing, static files, security headers, rate limits
  routes/index.js          all API endpoints
  engine/                  detection: url.js, message.js, upi.js, text.js, data.js, index.js (orchestrator)
  db/                      schema.sql, adapter (SQLite or PostgreSQL), migrate, seed
  lib/                     auth (scrypt, JWT), http helpers
web/                       index.html, css/app.css, js/ (router, api, views/*)
test/                      engine.test.js, api.test.js
```

## API quick reference
`POST /api/scan {input}` · `GET /api/scans` · `GET|DELETE /api/scans/:id` · `GET /api/stats/me` ·
`GET /api/stats/community` · `GET|POST /api/reports` · `POST /api/reports/:id/vote {vote: 1|-1|0}` ·
`POST /api/auth/signup|login` · `GET|POST|DELETE /api/keys` · `GET /api/admin/reports` ·
`POST /api/admin/reports/:id/status` · `POST /api/v1/scan` (API key)

## Before you deploy
- Set `NODE_ENV=production` and a long random `JWT_SECRET` (the server refuses to start without it).
- Put it behind HTTPS and set `TRUST_PROXY=1` if behind a reverse proxy.
- Rate limiting is in-memory (one instance). Use Redis if you scale to several.
- The scanner is rule-based guidance, not a guarantee. Keep extending `engine/data.js` and the rules with real examples.
- The QR reader loads `jsQR` from cdnjs on browsers without the built-in `BarcodeDetector`.

## Ideas to build next
Browser extension, WhatsApp/Telegram bot using the public API, full Tamil/Hindi UI translation, email/push
alerts for trending scams, ML scoring on top of the rules, Redis rate limiting, admin user management.
