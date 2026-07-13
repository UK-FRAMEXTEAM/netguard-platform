# NetGuard Pro repair summary

## Confirmed root causes

1. The Google buttons existed in React, but the backend only implemented local authentication. No Google strategy or OAuth routes were active.
2. Production Google sign-in navigated to `/api/auth/google` on the Vercel frontend instead of the Render API.
3. OAuth callback and local login stored a JWT without immediately populating the React user state, causing protected-route redirects back to `/login`.
4. The extension API and dashboard URLs were hard-coded to localhost.
5. The extension had no working method to receive the signed-in dashboard token, so cloud sync remained offline.
6. The provided standalone install-page text ended in the middle of a CSS rule and was not a complete HTML document.
7. A normal public website cannot directly install an unpacked Chrome extension. The working assessment flow must download a ZIP and use Chrome Developer Mode, unless the extension is published in the Chrome Web Store.
8. No update feed or version comparison existed, and the dashboard was protected by sign-in.
9. The proposal-required HIBP password-breach module and TLS certificate inspector were absent from the extension.
10. The uploaded project contained duplicate project trees, `node_modules`, and a real backend `.env`, making GitHub deployment unsafe and unnecessarily large.

## Implemented repairs

- Added Google OAuth 2.0 with state validation, exact callback configuration, JWT issuance, and account linking by verified email.
- Fixed production API routing and auth state handling for both Google and local login.
- Added a public `/install` route, stable Vercel-hosted ZIP path, public `release.json`, and no-cache headers.
- Added extension update checks on startup and every six hours, with a popup badge and download banner that work without signing in.
- Added signed-in dashboard release information.
- Added automatic dashboard-to-extension cloud pairing through an origin-restricted page message and isolated content script.
- Added configurable production URLs in one file: `extension/js/config.js`.
- Added HIBP k-Anonymity password checks and local strength scoring.
- Added a public, SSRF-restricted backend TLS inspection endpoint for protocol, cipher, certificate, expiry, and HSTS.
- Made the master protection toggle control both detection and the declarative ruleset.
- Added JSON threat-log export, improved duplicate-event handling, and removed false-positive URL matching cases.
- Removed the committed `.env`, added `.gitignore`, cleaned the project structure, and added Vercel/Render deployment instructions.

## Required user configuration before the live deployment

- Vercel production URL
- Render production URL
- MongoDB Atlas connection string
- Google OAuth client ID and client secret
- Admin email
- The three production URLs in `extension/js/config.js`, followed by rebuilding the public extension ZIP
