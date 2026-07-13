# NetGuard Pro v3.1

NetGuard Pro is a Chrome Manifest V3 browser-security project with an optional cloud dashboard.

## Included modules

- Heuristic URL scanner and known-domain matching
- Declarative Net Request blocklist
- DOM checks for hidden iframes, insecure password forms, XSS-like URL payloads, redirects, and crypto-miner scripts
- Privacy-preserving HIBP Pwned Passwords check using the k-Anonymity range endpoint
- Server-side TLS certificate, negotiated protocol, cipher, expiry, and HSTS inspection
- Google OAuth and local email/password authentication
- MongoDB-backed threat dashboard and admin panel
- Public extension installer and sign-in-independent update notifications

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

## Important distribution limitation

A normal website cannot silently install an unpacked Chrome extension. The public `/install` page provides the ZIP and correct Developer Mode steps. Publish the final extension in the Chrome Web Store when one-click **Add to Chrome** installation and automatic browser-managed updates are required.
