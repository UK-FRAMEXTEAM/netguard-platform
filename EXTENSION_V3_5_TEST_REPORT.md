# NetGuard Pro v3.5 Verification Report

Date: 22 July 2026

## Verified outcomes

- Shared URL risk engine loads in the popup, content script, and service worker.
- Known phishing and malware domains are classified as critical danger.
- Brand spoofing, unencrypted credential pages, and XSS-like query values trigger danger.
- Risky top-level domains alone remain warning-only to reduce false positives.
- The warning injects over the live page, applies blur, and displays a 10-second countdown.
- Continue Anyway removes the warning and sends a continued-by-user decision.
- Go Back sends a protected navigation decision to the service worker.
- Auto-back is wired to the zero-second countdown state.
- Known malicious subframes, scripts, and XHR requests remain blocked.
- Main-frame requests are available to the content script so the warning is visible instead of a blank network error.
- Administrator recovery login is independent of Google OAuth and the shared API quota.
- The administrator password must be configured on the backend and is not bundled in client code.

## Automated verification

| Check | Result |
| --- | --- |
| Extension JavaScript syntax | Pass |
| Extension URL/warning contract tests | 10/10 pass |
| Browser-like warning DOM test | Pass |
| Backend test suite | 17/17 pass |
| Frontend production build | Pass |
| Extension ZIP integrity | Pass |
| Extension-only scope scan | Pass |

The frontend build reports only the existing advisory that one generated JavaScript chunk is larger than 500 kB; the build completes successfully.
