# OSCAR Secure Uploader

Hardened web app for uploading OSCAR SD card files through Docker.

## Security highlights
- Runs in Docker with non-root UID:GID `911:911` and hardened compose settings.
- Login required for upload/delete actions and before reaching the OSCAR UI.
- Auth sessions time out after 30 minutes by default (configurable with `AUTH_SESSION_TTL_SECONDS`).
- Credentials loaded from `.env`.
- Strict file validation (`.crc`, `.tgt`, `.edf`, max 10MB each).
- Folder name validation and server-side path safety.
- Security headers with Helmet and API rate limiting.
- HTTPS-only serving with a self-signed certificate.
- Upload directory ownership is enforced to `911:911` by startup/runtime checks in the uploader container.
- Server refuses to run if upload directory ownership is not `911:911`.

## Required environment variables
Create a `.env` file:

```env
JWT_SECRET=change-this-to-a-long-random-secret
APP_USERNAME=shared-user
APP_PASSWORD=change-me
REQUIRE_DOCKER=true

# Optional overrides
HTTPS_PORT=50710
SSL_KEY_PATH=/app/certs/key.pem
SSL_CERT_PATH=/app/certs/cert.pem
OSCAR_BASE_URL=http://oscar:3000
OSCAR_DNS_FAMILY=4
AUTH_SESSION_TTL_SECONDS=1800
```

## Run
```bash
docker compose up --build
```

If uploads still fail due to host filesystem ACLs or root-squash, fix ownership on the host:

```bash
sudo mkdir -p secure-uploader/data/uploads
sudo chown -R 911:911 secure-uploader/data/uploads
sudo chmod 750 secure-uploader/data/uploads
```

App URL: `https://localhost:50710`

> Because the certificate is self-signed, your browser will show a trust warning on first load.

## Workflow behavior
- Frontend automatically scans selected SD folder as soon as it is chosen.
- Frontend compares filenames against server files for the target folder (no hashing).
- Only new filenames are uploaded, except these are always uploaded every time:
  - `Identification.crc`
  - `STR.edf`
- `Identification.tgt` and `journal.nl` are optional: upload them when present, but they are not required.
- Non-required files must be within selected date range and no older than 6 months.
- Uploads are capped at 5,000 files per request; choose a later start date if scan finds more.
- If selected uploads exceed Cloudflare's per-request gateway limits, the frontend automatically splits uploads into multiple smaller batches.
- Users can delete all uploaded data for a folder.
- `.spo2` uploads are auto-detected as oximetry data and stored under `<folder>/Oximetry/`; only `.spo2` files up to 200KB are accepted.
- Wellue/Viatom oximetry uploads are auto-detected when `db_o2.db` is present; the `db_o2.db` file is ignored and files from sibling numbered folders are stored under `<folder>/Oximetry/<number>/` when they have no extension and are <=200KB.
- Oximetry uploads are rejected unless SD-card baseline files (`Identification.crc` and `STR.edf`) already exist in the destination folder.

## Integrated OSCAR service
- `docker-compose.yml` now runs the uploader and `rogerrum/docker-oscar:latest` together.
- The upload page includes a large **Proceed to OSCAR** button.
- Clicking it calls an authenticated API endpoint that issues a short-lived launch URL and opens OSCAR in a new browser tab/window, then sets an HttpOnly gate cookie under `/oscar` before proxying traffic to the OSCAR container.
- Direct access to `/oscar/*` without the gate cookie returns `401 Unauthorized`.
- Requests under `/oscar/*` bypass the uploader's Helmet CSP so OSCAR can serve its own scripts/styles without browser CSP violations.
- The proxy rewrites OSCAR's `Content-Security-Policy` `frame-ancestors` directive to `'self'` so the embedded VNC view can load under the shared app origin.
- WebSocket upgrades under `/oscar/*` are now proxied (with the same gate cookie check), which restores OSCAR audio/socket connectivity.
- If your Docker network resolves `oscar` to an unreachable IPv6 address first, set `OSCAR_DNS_FAMILY=4` so the proxy always connects over IPv4.
