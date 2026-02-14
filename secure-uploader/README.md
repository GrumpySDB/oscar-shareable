# OSCAR Secure Uploader

Hardened web app for uploading OSCAR SD card files through Docker.

## Security highlights
- Runs in Docker with non-root UID:GID `911:911` and hardened compose settings.
- Login required for upload/delete actions.
- Credentials loaded from `.env`.
- Strict file validation (`.crc`, `.tgt`, `.edf`, max 10MB each).
- Folder name validation and server-side path safety.
- Security headers with Helmet and API rate limiting.
- HTTPS-only serving with a self-signed certificate.
- HTTP listener only redirects to HTTPS (308).
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
HTTP_PORT=3000
HTTPS_PORT=3443
SSL_KEY_PATH=/app/certs/key.pem
SSL_CERT_PATH=/app/certs/cert.pem
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

App URL: `https://localhost:3443`

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
