# NetGuard Pro deployment guide

Use this architecture:

- Frontend and public download: Vercel Hobby
- Backend API: Render free web service
- Database: MongoDB Atlas
- Login: Google OAuth 2.0 Web Application

Never commit a real `.env` file. The original archive contained a backend `.env`; rotate any MongoDB or JWT credentials that were used there before publishing the repository.

## 1. Push the clean project to GitHub

Create a new GitHub repository and push the contents of this `netguard-platform` folder. The repository root must contain `frontend/`, `backend/`, `extension/`, and `render.yaml` directly.

## 2. Create the MongoDB database

Create an Atlas deployment, a database user, and a Network Access rule suitable for Render. Copy the connection string and replace its username, password, and database name. Keep it for `MONGODB_URI`.

## 3. First Vercel deployment

1. Import the GitHub repository in Vercel.
2. Set **Root Directory** to `frontend`.
3. Framework preset: **Vite**.
4. Build command: `npm run build`.
5. Output directory: `dist`.
6. For the first deployment, set `VITE_API_URL` to the future Render URL if known; otherwise deploy once and add it after step 4.
7. Record the production URL, for example `https://netguard-pro.vercel.app`.

## 4. Render backend deployment

Create a Blueprint from the same repository and select `render.yaml`, or create a Web Service manually with root directory `backend`, build command `npm ci`, and start command `npm start`.

Set these environment variables:

| Variable | Value |
| --- | --- |
| `NODE_ENV` | `production` |
| `MONGODB_URI` | MongoDB Atlas connection string |
| `JWT_SECRET` | Long random secret (Render can generate this) |
| `FRONTEND_URL` | Exact Vercel production URL, without a trailing slash |
| `CORS_ORIGINS` | Exact Vercel production URL; add extra exact origins separated by commas only if needed |
| `ADMIN_EMAIL` | Email that should receive the admin role |
| `GOOGLE_CLIENT_ID` | Added after step 5 |
| `GOOGLE_CLIENT_SECRET` | Added after step 5 |
| `GOOGLE_CALLBACK_URL` | `https://YOUR-RENDER-SERVICE.onrender.com/api/auth/google/callback` |

Record the Render URL and confirm `https://YOUR-RENDER-SERVICE.onrender.com/api/health` returns JSON.

## 5. Configure Google OAuth

1. Open Google Cloud Console and create/select a project.
2. Configure the Google Auth Platform consent screen. During testing, add your Google account as a test user.
3. Create an OAuth Client with application type **Web application**.
4. Add the exact Vercel URL under **Authorized JavaScript origins**.
5. Add this exact **Authorized redirect URI**:

   `https://YOUR-RENDER-SERVICE.onrender.com/api/auth/google/callback`

6. Copy the client ID and client secret into Render.
7. Set `GOOGLE_CALLBACK_URL` to the same exact callback URI and redeploy Render.

The redirect URI must match character-for-character. Do not use the Vercel URL as the callback; Google returns to the backend first, and the backend then sends the user to the frontend.

## 6. Finish Vercel configuration

Set `VITE_API_URL=https://YOUR-RENDER-SERVICE.onrender.com` in Vercel for Production, Preview, and Development as required. Redeploy, then test:

- `/install` opens without signing in.
- Google sign-in ends at `/dashboard`.
- Refreshing `/dashboard` does not return 404.
- The dashboard API calls reach Render, not the Vercel domain.

## 7. Configure and package the extension

Edit only `extension/js/config.js`:

```js
self.NETGUARD_CONFIG = Object.freeze({
  API_BASE: 'https://YOUR-RENDER-SERVICE.onrender.com',
  DASHBOARD_URL: 'https://YOUR-VERCEL-PROJECT.vercel.app',
  RELEASE_URL: 'https://YOUR-VERCEL-PROJECT.vercel.app/release.json',
  ALLOWED_DASHBOARD_ORIGINS: ['https://YOUR-VERCEL-PROJECT.vercel.app'],
});
```

Create a ZIP whose root contains `manifest.json`, `popup.html`, `blocked.html`, `rules.json`, `icons/`, and `js/`. Do not wrap those files in an extra parent folder for the public release ZIP.

Place it at `frontend/public/downloads/netguard-pro-extension.zip`.

Update `frontend/public/release.json`, commit, and push. Vercel will redeploy, while the public download URL remains unchanged.

## 8. Test cloud pairing

1. Load the configured extension through `chrome://extensions`.
2. Open the live NetGuard website and sign in.
3. Open the extension popup. It should show **Cloud Synced**.
4. Browse a safe test page and a locally controlled test page containing one of the detection patterns.
5. Confirm new events appear in the signed-in dashboard.

## Update workflow

1. Increase the version in `extension/manifest.json`.
2. Replace the extension ZIP at the same Vercel path.
3. Set the same version in `frontend/public/release.json` and update the changelog and SHA-256 value.
4. Commit and push.

The extension checks `release.json` every six hours and on service-worker start. This check is public and does not require dashboard sign-in. Developer Mode users still install the update manually. Chrome Web Store users receive browser-managed updates after the extension is published there.

## Google Drive alternative

Google Drive is optional. The Vercel file path above is already a stable URL. If Drive is preferred, upload a new version of the existing Drive file instead of creating a new file, and set `downloadUrl` in `release.json` to its direct-download URL. The update notification still comes from `release.json`; Drive only stores the ZIP.
