# Changelog

## 3.4.0 — 2026-07-21

- Corrected the protected-site architecture so every signed-in user configures their own registered website rather than the NetGuard dashboard.
- Added protection profiles and feature-by-feature ON/OFF choices directly to website registration.
- Added an automatic SSRF-safe public posture scan immediately after registration.
- Added recurring per-site posture scans triggered by verified live website traffic.
- Added explicit integration-required, connected, paused, and live-protection states.
- Added a per-site master protection switch and independent automatic-scan settings.
- Clarified the owner-authorized one-time script installation and reCAPTCHA domain boundary.
- Updated the extension and release feed to 3.4.0.

## 3.3.0 — 2026-07-21

- Added a separate **Reports** tab with Web Browsing and Protected Website filters.
- Added 7/30/90-day filters, protected-site selection, full PDF evidence, charts, recommendations, and AI remediation actions.
- Added real MongoDB protected-website events and anonymized network-source analysis.
- Added an exact-origin website SDK with page/form telemetry, local message hashing, repeat detection, burst/minute rate decisions, bot signals, reCAPTCHA v3, throttling, and temporary blocks.
- Added per-site master protection, individual protection toggles, and threshold controls.
- Added Connected/Pending/Offline integration verification.
- Added server-side TLS, certificate, HSTS, CSP, frame, MIME, referrer, and permissions-policy scans saved to MongoDB and included in reports.
- Extended the Gemini assistant with protected-website findings and proactive issue prompts.
- Upgraded the frontend build toolchain to Vite 8.1.5 and cleared dependency audit findings.
- Updated the extension/release feed to 3.3.0.

## 3.2.0

- Added domain-only browsing analytics, PDF reports, Gemini chat/image guidance, and owner-only admin controls.
