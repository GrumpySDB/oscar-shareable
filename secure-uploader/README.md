# OSCAR Secure Uploader

Hardened web app for uploading OSCAR SD card files through Docker.

## Security highlights
- Runs in Docker with non-root user and hardened compose settings.
- Login required for upload/delete actions.
- Credentials loaded from `.env`.
- Strict file validation (`.crc`, `.tgt`, `.edf`, max 10MB each).
- Folder name validation and server-side path safety.
- Security headers with Helmet and API rate limiting.

## Required environment variables
Create a `.env` file:

```env
PORT=3000
JWT_SECRET=change-this-to-a-long-random-secret
APP_USERNAME=shared-user
APP_PASSWORD=change-me
REQUIRE_DOCKER=true
```

## Run
```bash
docker compose up --build
```

App URL: `http://localhost:3000`

## Workflow behavior
- Frontend scans selected SD folder.
- Frontend compares filenames against server files for the target folder (no hashing).
- Only new filenames are uploaded, except these are always uploaded every time:
  - `Identification.crc`
  - `Identification.tgt`
  - `STR.edf`
- Non-required files must be within selected date range and no older than 1 year.
- Users can delete all uploaded data for a folder.
