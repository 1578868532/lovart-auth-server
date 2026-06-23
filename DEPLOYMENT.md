# Render deployment checklist

## Required environment variables

Set ALL of the following in Render → Environment (never commit real values to source control):

| Variable | Value | Notes |
|---|---|---|
| `NODE_ENV` | `production` | **REQUIRED** — disables dev-only fallbacks |
| `ADMIN_SECRET` | a long random secret | e.g. `openssl rand -hex 32`. All `/api/admin/*` routes require this header |
| `OTP_EMAIL` | your 163 mailbox address | e.g. `yourname@163.com` |
| `OTP_PASS` | IMAP authorization code | This is NOT the login password — generate it in 163 mail settings |
| `OTP_IMAP_HOST` | `imap.163.com` | |
| `OTP_IMAP_PORT` | `993` | |
| `OTP_IMAP_SECURE` | `true` | |
| `DATA_DIR` | persistent disk mount path | e.g. `/var/data`. `db.json` will be written here |

**WARNING:** If `NODE_ENV` is not set to `production`, the server will start a local dev-only admin secret that must NOT be used in production. Always set `NODE_ENV=production` on Render.

**WARNING:** If `ADMIN_SECRET` is not set in production, all admin endpoints return 503. Set it before distributing any build.

## Service settings

- **Build command:** `npm install`
- **Start command:** `npm start`
- **Health endpoint:** `GET /api/health` — returns `{ success: true }` when running
- **Persistent disk:** Attach a Render Persistent Disk and set `DATA_DIR` to its mount directory (e.g. `/var/data`) so `db.json` survives restarts and deployments.

## Desktop (Electron) setting

Set `LOVART_AUTH_SERVER_URL` to the deployed HTTPS base URL **before** packaging or running the Electron application. The desktop falls back to `http://127.0.0.1:3000` for local dev only.

```text
LOVART_AUTH_SERVER_URL=https://your-service.onrender.com
```

Never ship a production Electron build without this env var pointing to the Render HTTPS address.

## Existing-license transition

The current desktop installation uses a legacy local license and has no cloud session. Before replacing the running desktop build:

1. Deploy the backend on Render and configure all environment variables above.
2. Create a new cloud license: `POST /api/admin/create-license` with header `x-admin-secret: <ADMIN_SECRET>`.
   ```json
   { "days": 30, "maxSlots": 3, "maxAccounts": 100, "plan": "monthly" }
   ```
3. Note the returned `licenseKey`.
4. Set `LOVART_AUTH_SERVER_URL` in the desktop build environment.
5. Activate the machine: `POST /api/activate` with `{ licenseKey, machineId }`.
6. Test `POST /api/verify` and `POST /api/otp/get` before distributing the new build.

The pre-migration local license is backed up in the desktop project's `.private-backup` directory and must **not** be uploaded or deleted.

## API reference (quick)

| Route | Auth required | Description |
|---|---|---|
| `GET /api/health` | none | Liveness check |
| `POST /api/activate` | none | Activate a license key on a machine |
| `POST /api/verify` | none (uses body sessionToken + machineId) | Periodic license check |
| `POST /api/otp/get` | `Authorization: Bearer <sessionToken>` + `x-machine-id` | Fetch latest Lovart OTP code |
| `POST /api/otp/mark-baseline` | same as otp/get | Mark current inbox state so next get only returns new messages |
| `POST /api/admin/create-license` | `x-admin-secret` | Create a new license key |
| `GET /api/admin/licenses` | `x-admin-secret` | List all licenses |
| `POST /api/admin/block-license` | `x-admin-secret` | Block (revoke) a license |
| `POST /api/admin/unbind-license` | `x-admin-secret` | Unbind license from machine |
