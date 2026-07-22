# NetGuard Pro Platform v3.5.1

Platform v3.5.1 fixes the shared Render API quota that could disable dashboard buttons and sign-in. It gives every verified JWT its own protected request bucket, keeps health/Google OAuth/admin recovery outside the shared quota, preserves sessions during temporary 429/network failures, and deduplicates API error notifications. The Chrome extension remains v3.5.0 with its blurred unsafe-site interstitial, 10-second safety return, Continue/Back decisions, and server-side administrator recovery login.

NetGuard Pro is a Chrome Manifest V3 browser-security project with an optional cloud dashboard.

## Included modules

- Heuristic URL scanner and known-domain matching
- Declarative Net Request blocklist
- DOM checks for hidden iframes, insecure password forms, XSS-like URL payloads, redirects, and crypto-miner scripts
- Privacy-preserving HIBP Pwned Passwords check using the k-Anonymity range endpoint
- Server-side TLS certificate, negotiated protocol, cipher, expiry, and HSTS inspection
- Google OAuth and local username-or-email/password authentication
- MongoDB-backed threat dashboard and admin panel
- Public extension installer and sign-in-independent update notifications
- Privacy-preserving domain-level browsing analytics (no normal browsing paths or queries)
- One-click PDF security reports for 7, 30, or 90 day periods
- Gemini security assistant with continuous chat and screenshot analysis
- Owner-only admin controls with a local demo administrator and optional Google owner `ADMIN_EMAIL`
- Separate Web Browsing and Protected Website report filters with full PDF export
- Real protected-website telemetry stored in MongoDB
- Origin-bound website SDK with form shield, repeat detection, rate analysis, bot signals, reCAPTCHA, throttling, and temporary blocks
- Privacy-safe HMAC network-source labels instead of stored raw IP or impossible browser MAC collection
- Per-site protection toggles and configurable 1/5-second-style detection windows
- Per-user website registration with independent Balanced, Strict, or Custom controls
- Automatic public TLS/header scan on registration and recurring scans from verified live traffic
- Honest activation states: public scan ready, integration required, connected, paused, or live protection running

## Project layout

```text
frontend/   React + Vite website and dashboard (Vercel)
backend/    Express + MongoDB API (Render)
extension/  Chrome Manifest V3 extension
render.yaml Render Blueprint
```

## Local development

1. Copy `backend/.env.example` to `backend/.env` and fill the values.
2. Copy `frontend/.env.example` to `frontend/.env`.
3. In `backend`, run `npm ci` and `npm run dev`.
4. In `frontend`, run `npm ci` and `npm run dev`.
5. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `extension/`.

For the production sequence and all environment variables, follow `DEPLOYMENT_GUIDE.md`.
For the current live-site repair, follow `DEPLOY_V3_5_1_HOTFIX.md`.
For website installation, testing, privacy, and DDoS boundaries, follow `WEBSITE_PROTECTION_GUIDE.md`.

## Important distribution limitation

A normal website cannot silently install an unpacked Chrome extension. The public `/install` page provides the ZIP and correct Developer Mode steps. Publish the final extension in the Chrome Web Store when one-click **Add to Chrome** installation and automatic browser-managed updates are required.
