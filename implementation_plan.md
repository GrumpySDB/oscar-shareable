# Implementation Plan - API Key Management System

This plan outlines the steps to implement an API key system that allows trusted applications to upload SD card or oximetry data on behalf of a user.

## Proposed Changes

### [Backend] secure-uploader-rs

#### [MODIFY] [db.rs](file:///config/dev/oscar-shareable/secure-uploader-rs/src/db.rs)
- Add a new table `api_keys`:
- `id` (INTEGER PRIMARY KEY)
- `key_hash` (TEXT NOT NULL UNIQUE) - Salted Argon2 hash
- `user_uuid` (TEXT NOT NULL)
- `label` (TEXT)
- `created_at` (INTEGER NOT NULL)
- `last_used_at` (INTEGER)
- `scopes` (TEXT) - e.g., "upload_only"
- Add methods:
  - `create_api_key(user_uuid, key_hash, label)`
  - `list_api_keys(user_uuid)`
  - `revoke_api_key(id, user_uuid)`
  - `verify_api_key(key_plaintext)` - Returns the associated `User` if valid

#### [MODIFY] [auth.rs](file:///config/dev/oscar-shareable/secure-uploader-rs/src/auth.rs)
- Update `auth_middleware` to handle `X-API-Key` headers.
- Implement API key generation logic:
  - Generate a secure random string (e.g., `sk_live_...`).
  - Hash it using Argon2.
  - Store the hash and return the plaintext to the user (ONLY once).
- Add handlers:
  - `GET /api/me`: Returns current user info (username, role) - helpful for verifying API keys.
  - `GET /api/account/api-keys`: List keys
  - `POST /api/account/api-keys`: Create a key
  - `DELETE /api/account/api-keys/:id`: Revoke a key

- Update `handle_upload` to support a new optimized flow:
  - **Endpoint**: `POST /api/upload`
  - **Header**: `X-API-Key: <key>`
  - **Header**: `X-File-Path: /DATALOG/20231027/BRP.edf` (Standardized SD path)
  - **Header**: `X-Device-Id`: Optional identifier for the source device (e.g., "resmed_as10", "wellue_o2ring").
  - **Header**: `X-Content-MD5: <hash>` (If provided, server verifies and skips if already matched)
- **New Endpoint**: `POST /api/upload/check`
  - **Payload**: `{"device_id": "...", "files": [{"path": "/...", "size": 123, "md5": "..."}]}`
  - **Response**: `{"status": [{"path": "/...", "action": "UPLOAD|SKIP|INVALID"}]}`
  - This allows tools like **CPAP-AutoSync** to perform a bulk "diff" before transmitting data.
- **Path Sanitization**: Ensure that absolute paths like `/DATALOG` are safely mapped to the user's `SD_CARD` directory in their persistent storage.

### [Frontend] frontend

#### [NEW] API Key Management UI
- Create a new section in the account settings or a dedicated "Integrations" page.
- Allow users to generate new keys and see existing ones (labels and masked keys).
- Provide a clear "Copy to Clipboard" for newly generated keys.

## Verification Plan

### Automated Tests
- Test API key generation and ensure the plaintext is not stored in the database.
- Test uploading files using an API key in the `X-API-Key` header.
- Test that revoked or expired keys are rejected.

### Manual Verification
- Use `curl` to simulate an external application upload:
  - First, call `/api/upload/check` with a file list.
  - Then, upload only the missing files.
- Verify the uploaded files appear in the user's OSCAR session.
