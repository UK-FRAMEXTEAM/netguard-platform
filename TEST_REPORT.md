# NetGuard Pro v3.4 verification report

Verification date: 2026-07-21

## Automated results

| Check | Result |
| --- | --- |
| Backend Node test suite | Pass — 9/9 |
| Site URL normalization and exact-origin validation | Pass |
| Keyed HMAC network-source label behavior | Pass |
| Normal request decision | Pass |
| Repeated-submission reCAPTCHA decision | Pass |
| Extreme-pattern temporary-block decision | Pass |
| Per-site Balanced/Strict/Custom setting normalization | Pass |
| Per-site setting range clamping | Pass |
| Automatic posture-scan due/disabled decisions | Pass |
| Backend route/module syntax and load checks | Pass |
| Website SDK JavaScript syntax | Pass |
| Frontend Vite 8.1.5 production build | Pass |
| Backend dependency audit | Pass — 0 vulnerabilities |
| Frontend dependency audit | Pass — 0 vulnerabilities |
| Secret-pattern scan of release source | Pass — no embedded credentials found |
| Extension archive root contains `manifest.json` | Pass |
| Extension manifest/release version | Pass — 3.4.0 |
| Extension release SHA-256 | `1cc89e5063fcabf855dfb8683792051a0f80f5706ebda8890762234372905104` |

## Code-level controls verified

- Browser and protected-website report routes require an authenticated user and scope MongoDB queries to that user's ID.
- Protected-site updates, network scans, and reports require ownership of the selected site ID.
- Each registered website has independent profile, master switch, feature toggles, thresholds, automation interval, counters, and report scope.
- Website registration runs an automatic SSRF-safe public posture scan without falsely marking live application protection as connected.
- Live traffic triggers a due posture scan only for its origin-bound site code; an in-process queue prevents duplicate concurrent scans.
- Admin navigation remains role-gated and admin APIs remain owner-email gated by `ADMIN_EMAIL`.
- Website telemetry accepts only the exact registered origin.
- Public protection codes identify a site but do not bypass origin validation.
- Raw IP addresses and MAC addresses are not stored. Reports receive short labels derived from server-side HMAC values.
- Form values are not sent; non-secret values are converted to a browser SHA-256 digest and keyed again on the backend.
- reCAPTCHA secrets and Gemini keys remain backend environment variables.
- Screenshot bytes sent to the assistant remain transient and are not stored in MongoDB.
- Network scans resolve and reject private/reserved address ranges before connecting, reducing SSRF risk.
- The website SDK fails open when its remote telemetry service is unavailable; the guide explicitly requires the protected origin's own rate limits and an edge WAF/CDN.

## Deployment acceptance checks

Complete these after pushing v3.4 and deploying Render/Vercel:

1. Confirm `/api/health` returns `version: "3.4.0"`, `websiteProtection: true`, `perSiteProtectionControls: true`, `automaticSitePostureScans: true`, and the expected Gemini/reCAPTCHA booleans.
2. Sign in using the configured `ADMIN_EMAIL` and confirm **Admin Panel** appears only for that owner account.
3. Confirm **Reports** opens and switches between **Web Browsing Report** and **Protected Website Report**.
4. Add a live HTTPS website, choose its profile/toggles, and confirm the initial TLS/header scan is stored while live protection still says **Integration required**.
5. Paste its generated script, open the site, refresh **Protected Sites**, and confirm **Live protection: Running**.
6. Submit the same safe test form twice within five seconds and confirm a challenge/throttle event is stored.
7. With valid reCAPTCHA v3 keys/domains, confirm a passed challenge permits the form to continue and failed challenges are counted.
8. Confirm no raw form values, query strings, raw IPs, or MAC addresses appear in MongoDB or the PDF.
9. Click a report recommendation and confirm the Gemini agent continues with the selected issue context.
10. Reload the unpacked v3.4 extension, verify Cloud Synced, and confirm the public release feed/hash match the packaged ZIP.

Live Google OAuth, MongoDB Atlas, Gemini, reCAPTCHA, Vercel, Render, and a registered external website require the user's private production environment and therefore cannot be exercised from the local release build.
