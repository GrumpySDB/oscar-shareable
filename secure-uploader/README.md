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

## Cloudflare tunnel and end-to-end encryption considerations
- Cloudflare Tunnel protects transport, but Cloudflare still terminates TLS at its edge for normal proxied HTTP(S) traffic.
- If your goal is to prevent Cloudflare from decrypting file contents, use client-side encryption in the browser **before upload** so only ciphertext traverses the tunnel.
- With that model, your origin server receives encrypted blobs and can only decrypt them if it has the keys.
- To keep Cloudflare blind to data, decryption keys must never be sent to Cloudflare and should be managed outside the tunnel path.

### Practical model for this app
- Upload page now includes an opt-in toggle: **Tinfoil Hat Mode (End-to-End Encryption)**.
- When enabled:
  1. Browser encrypts each upload batch with a per-batch AES-256-GCM key (WebCrypto).
  2. Browser wraps that batch key with the server RSA-OAEP public key from `/api/upload-encryption-key`.
  3. Browser uploads only ciphertext files plus metadata (`wrappedKey`, `fileMetadata`, `keyId`).
  4. Origin unwraps and decrypts after the tunnel, then writes plaintext files for OSCAR ingestion.
- When disabled:
  - Upload behavior remains the original plaintext-over-TLS flow.

### Important trade-offs
- This is not pure end-to-end encryption if the server decrypts for OSCAR; it is best described as **application-layer encryption through Cloudflare**.
- If you need strict E2EE where server cannot decrypt, OSCAR ingestion workflow must be redesigned because OSCAR needs plaintext files.

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

## Integrated OSCAR service
- `docker-compose.yml` now runs the uploader and `rogerrum/docker-oscar:latest` together.
- The upload page includes a large **Proceed to OSCAR** button.
- Clicking it calls an authenticated API endpoint that issues a short-lived launch URL and opens OSCAR in a new browser tab/window, then sets an HttpOnly gate cookie under `/oscar` before proxying traffic to the OSCAR container.
- Direct access to `/oscar/*` without the gate cookie returns `401 Unauthorized`.
- Requests under `/oscar/*` bypass the uploader's Helmet CSP so OSCAR can serve its own scripts/styles without browser CSP violations.
- The proxy rewrites OSCAR's `Content-Security-Policy` `frame-ancestors` directive to `'self'` so the embedded VNC view can load under the shared app origin.
- WebSocket upgrades under `/oscar/*` are now proxied (with the same gate cookie check), which restores OSCAR audio/socket connectivity.
- If your Docker network resolves `oscar` to an unreachable IPv6 address first, set `OSCAR_DNS_FAMILY=4` so the proxy always connects over IPv4.
