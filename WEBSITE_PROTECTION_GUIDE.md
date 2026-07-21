# NetGuard per-site protection integration

NetGuard v3.4 protects websites added by signed-in users. It does not apply these controls to the NetGuard dashboard itself. Every registered origin receives independent profiles, ON/OFF controls, telemetry, counters, scans, and reports.

## Automatic onboarding flow

1. The user adds the exact HTTPS website URL in **Protected Sites**.
2. The user selects **Balanced** or **Strict**, then turns any individual protection layer ON or OFF.
3. NetGuard stores those per-site settings and immediately runs an SSRF-safe public TLS, certificate, and security-header scan.
4. NetGuard generates an origin-bound integration script for that website.
5. The site owner installs that script once. The first verified request changes the status to **Connected**.
6. Live form/rate/bot decisions, MongoDB evidence, reports, heartbeats, and due posture scans continue automatically.

Adding a URL cannot silently edit a remote website. The one-time script installation is the owner-authorized connection that lets NetGuard observe and protect that site. Without it, the public posture scan works, but live application-layer protection remains **Integration required**.

## What the integration does

- Verifies that the protection code is used only from the exact registered website origin.
- Records page views, form submissions, client errors, challenge results, and protection actions as MongoDB events.
- Detects bursts over a configurable 1–60 second window.
- Detects identical form submissions over a configurable 1–30 second window without storing the form values.
- Challenges suspicious visitors with reCAPTCHA v3 when keys are configured.
- Temporarily throttles or blocks extreme application-layer patterns.
- Reports anonymized network-source labels, allowed/challenged/throttled/blocked totals, reCAPTCHA outcomes, client errors, bot signals, and average page-load time.
- Sends relevant report findings to the Gemini security assistant for step-by-step remediation.
- Repeats public posture scans automatically at the interval configured for that website whenever live site traffic connects to NetGuard.

## Privacy model

The browser cannot expose a visitor's MAC address to a public website. NetGuard does not attempt to collect it.

The backend observes the request IP temporarily, converts it to a site-specific HMAC-SHA-256 label, and stores only that keyed label. NetGuard also stores only the route path, never its query string or hash. Form values are hashed in the browser and then keyed again on the server; passwords, tokens, secrets, keys, cookies, and session fields are excluded before hashing. The report exposes only short labels such as `source-a1b2c3d4e5`.

## Install the website script

1. Open **Protected Sites** and select **Add Site**.
2. Enter the exact production HTTPS URL, for example `https://example.com`.
3. Choose the per-site profile and ON/OFF controls. NetGuard registers and scans the site automatically.
4. Copy the generated integration script.
5. Paste it once before the closing `</body>` tag of the protected website.

Example:

```html
<script
  src="https://YOUR-RENDER-SERVICE.onrender.com/api/site/sdk.js"
  data-netguard-key="netguard_YOUR_SITE_CODE"
  defer
></script>
```

6. Deploy and open the registered website.
7. Return to **Protected Sites**, select **Refresh**, and confirm **Live protection: Running**.

For a React/Vite website, put the tag in the root `index.html`. For a normal HTML website, add it to every layout through the shared footer/template rather than duplicating it on individual pages.

## Content Security Policy

If the site uses a strict Content Security Policy, allow the NetGuard backend in `script-src` and `connect-src`. When reCAPTCHA is enabled, also allow the Google reCAPTCHA script/frame/connect origins required by the reCAPTCHA documentation. A blocked script or connection produces a **Pending** or **Offline** integration state.

## Configure reCAPTCHA v3

Create a reCAPTCHA v3 key pair and register every protected production hostname. A single NetGuard platform key works only for hostnames that the NetGuard owner has authorized in the Google console; adding an arbitrary URL cannot register that domain with Google automatically. Store both values only in the Render backend environment:

```env
RECAPTCHA_SITE_KEY=your_public_v3_site_key
RECAPTCHA_SECRET_KEY=your_private_v3_secret_key
```

Never place the secret key in the frontend, protected website, extension, GitHub repository, or screenshots. Redeploy Render and confirm `/api/health` shows:

```json
{
  "recaptchaProtection": true
}
```

If keys are absent, NetGuard remains in safe throttle/block mode and does not pretend that a reCAPTCHA challenge was completed.

## Protection controls

Each website has independent controls:

| Control | Effect |
| --- | --- |
| Network telemetry | Saves privacy-safe MongoDB events for reports |
| Request rate detection | Detects bursts and minute-level event volume |
| Repeated message protection | Detects identical non-secret form content by hash |
| Bot signal detection | Flags webdriver/headless/automated signals |
| Form shield | Pauses suspicious browser form submissions |
| reCAPTCHA challenge | Verifies suspicious form submissions when configured |
| Client error monitoring | Saves a one-way error signature, not the raw error text |
| Automatic temporary block | Blocks extreme patterns for the configured period |
| Automatic posture scans | Rechecks TLS, certificate expiry, and response security headers every 1–168 hours |

The **Balanced** profile uses eight monitored events per five seconds, a 60-event minute limit, a 15-minute block, and a 24-hour posture scan. **Strict** uses five events per five seconds, a 30-event minute limit, a 30-minute block, and a 12-hour scan. Changing any control creates a **Custom** profile for that site only.

Balanced defaults challenge/throttle two identical submissions or eight monitored events within five seconds. Extreme repeated/rate patterns are blocked for 15 minutes. Adjust thresholds carefully to avoid blocking legitimate fast users.

## Test safely

1. Use a test website and test form that you control.
2. Submit the same non-sensitive message twice within five seconds.
3. Confirm the second request is challenged or throttled.
4. Repeat until the configured extreme threshold is reached and confirm the temporary block.
5. Open **Reports → Protected Website Report**, choose the site and period, and verify the event, anonymized source, challenge, and block evidence.
6. Select a recommended action to open the Gemini fixing agent with that report issue.

Do not test against websites you do not own or have permission to assess.

## DDoS boundary

The integration script and NetGuard API controls mitigate application-layer form abuse and generate network-analysis evidence. A malicious client can bypass browser JavaScript, and a volumetric DDoS attack reaches the network before this script can run. Production deployment therefore also requires:

- an edge CDN/WAF with DDoS protection;
- rate limiting on the protected website's own server/API;
- request/body-size limits and timeouts;
- origin access restricted to the edge provider where practical;
- monitoring and alerts at the hosting/network layer.

The NetGuard report intentionally states this boundary instead of claiming that client-side JavaScript alone stops DDoS traffic.
