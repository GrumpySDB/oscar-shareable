# OSCAR Secure Uploader

Hardened web app for uploading OSCAR SD card files through Docker.

## Security highlights
- Runs in Docker with non-root UID:GID `911:911` and hardened compose settings.
- Login required for upload/delete actions and before reaching the OSCAR UI.
- Credentials loaded from `.env`.
- Strict file validation (`.crc`, `.tgt`, `.edf`, max 10MB each).
- Folder name validation and server-side path safety.
- Security headers with Helmet and API rate limiting.
- Upload directory ownership is enforced to `911:911` by startup/runtime checks in the uploader container.
- Server refuses to run if upload directory ownership is not `911:911`.
- A Traefik reverse proxy is the **only** exposed service and it must publish on a high random port (49152-65535).
- CrowdSec protects the reverse proxy via forward-auth middleware (`crowdsec-bouncer`).

## Required environment variables
Create a `.env` file:

```env
JWT_SECRET=change-this-to-a-long-random-secret
APP_USERNAME=shared-user
APP_PASSWORD=change-me
REQUIRE_DOCKER=true
CROWDSEC_BOUNCER_API_KEY=change-this-to-a-long-random-secret

# Optional overrides
HTTP_PORT=3000
HTTPS_PORT=3443
SSL_KEY_PATH=/app/certs/key.pem
SSL_CERT_PATH=/app/certs/cert.pem
OSCAR_BASE_URL=http://oscar:3000
```

## Run
Start with the helper script (recommended):

```bash
./scripts/start-secure-uploader.sh
```

The script picks a random high port (49152-65535), launches Compose, and prints the URL.

Manual run (if you want to pin a specific high port):

```bash
SECURE_UPLOADER_PORT=55443 docker compose up --build -d
```

If uploads still fail due to host filesystem ACLs or root-squash, fix ownership on the host:

```bash
sudo mkdir -p secure-uploader/data/uploads
sudo chown -R 911:911 secure-uploader/data/uploads
sudo chmod 750 secure-uploader/data/uploads
```

> Because the certificate is self-signed, your browser will show a trust warning on first load.

## Workflow behavior
- Frontend scans selected SD folder.
- Frontend compares filenames against server files for the target folder (no hashing).
- Only new filenames are uploaded, except these are always uploaded every time:
  - `Identification.crc`
  - `Identification.tgt`
  - `STR.edf`
- Non-required files must be within selected date range and no older than 1 year.
- Users can delete all uploaded data for a folder.

## Integrated OSCAR service
- `docker-compose.yml` runs the uploader and `rogerrum/docker-oscar:latest` together.
- The upload page includes a large **Proceed to OSCAR** button.
- Clicking it calls an authenticated API endpoint that issues a short-lived launch URL, then sets an HttpOnly gate cookie under `/oscar` before proxying traffic to the OSCAR container.
- Direct access to `/oscar/*` without the gate cookie returns `401 Unauthorized`.
- Requests under `/oscar/*` bypass the uploader's Helmet CSP so OSCAR can serve its own scripts/styles without browser CSP violations.
- The proxy rewrites OSCAR's `Content-Security-Policy` `frame-ancestors` directive to `'self'` so the embedded VNC view can load under the shared app origin.
- WebSocket upgrades under `/oscar/*` are proxied (with the same gate cookie check), which restores OSCAR audio/socket connectivity.
- Upload and OSCAR launch share a single service lock: if another user is actively using one flow, new upload/OSCAR attempts receive `423 Locked` plus a gentle "temporarily in use" message and retry hint.
