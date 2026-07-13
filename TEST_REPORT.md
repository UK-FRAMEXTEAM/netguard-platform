# NetGuard Pro v3.1 verification report

Date: 2026-07-13

## Automated results

| Test | Result |
| --- | --- |
| React/Vite production build | Pass |
| SPA route smoke test (`/`, `/install`, `/login`, `/dashboard`) | Pass - HTTP 200 |
| Public `release.json` response | Pass - HTTP 200 |
| Stable extension ZIP response | Pass - HTTP 200 |
| Extension manifest and rules JSON parsing | Pass |
| Referenced manifest files exist | Pass |
| Popup JavaScript DOM ID references exist | Pass |
| Extension JavaScript syntax checks | Pass |
| Backend JavaScript syntax checks | Pass |
| Private/reserved IP rejection unit checks | Pass |
| Frontend production dependency audit | Pass - 0 known vulnerabilities |
| Backend production dependency audit | Pass - 0 known vulnerabilities |
| Secret scan of the clean project | Pass - no real `.env`, private key, or connection secret found |

## Deployment-dependent acceptance tests

Complete these after the real Vercel, Render, MongoDB, and Google values are configured:

1. Google OAuth completes and returns the user to `/dashboard`.
2. A page refresh on `/dashboard` remains in the React application.
3. The extension popup changes from **Offline Mode** to **Cloud Synced** after web sign-in.
4. A controlled test threat is stored in MongoDB and appears in the dashboard.
5. HIBP returns a known breach count for a deliberately weak test password without sending the complete hash.
6. TLS inspection returns certificate details for a public HTTPS host and rejects localhost/private hosts.
7. Raising `release.json.latestVersion` above the manifest version displays the popup update banner without dashboard sign-in.
8. The new extension ZIP downloads from the same stable URL after replacement.

Do not test malware or phishing behavior against uncontrolled third-party systems. Use local fixtures or domains you own.
