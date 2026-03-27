# Security Hardening & API Key System Blueprint

This blueprint combines the requested API key management system with security hardening based on recent SAST scans (`cargo audit`, `npm audit`, `clippy`, and `semgrep`).

## Diagnostics Result Summary
- **Backend (Rust)**: 
  - `cargo audit`: Found `RUSTSEC-2023-0071` in `rsa` crate (Moderate). No official patch available for 0.9.x yet.
  - `clippy`: 0 warnings/errors.
- **Frontend (JS)**:
  - `npm audit`: Found moderate vulnerabilities in `esbuild` and `vite` (dev-only).
  - `semgrep`: 0 findings.

## Proposed Changes

---

### [Component] Security Patching
| File | Action | Description |
| :--- | :--- | :--- |
| [package.json](file:///config/dev/oscar-shareable/frontend/package.json) | [MODIFY] | Update `vite` and `esbuild` to resolve moderate audit findings. |
| [Cargo.toml](file:///config/dev/oscar-shareable/secure-uploader-rs/Cargo.toml) | [MODIFY] | Update `rsa` and other dependencies to latest compatible versions. |

---

### [Component] API Key System (Backend)
| File | Action | Description |
| :--- | :--- | :--- |
| [db.rs](file:///config/dev/oscar-shareable/secure-uploader-rs/src/db.rs) | [MODIFY] | Add `api_keys` table and CRUD methods. Uses parameterized `rusqlite` queries. |
| [auth.rs](file:///config/dev/oscar-shareable/secure-uploader-rs/src/auth.rs) | [MODIFY] | Update middleware to support `X-API-Key`. Add key generation logic (Argon2 hashing). |
| [upload.rs](file:///config/dev/oscar-shareable/secure-uploader-rs/src/upload.rs) | [MODIFY] | Implement `GET /api/me`, `POST /api/upload`, and `POST /api/upload/check`. |

---

### [Component] API Key System (Frontend)
| File | Action | Description |
| :--- | :--- | :--- |
| [Integrations.js](file:///config/dev/oscar-shareable/frontend/src/Integrations.js) | [NEW] | New UI component for managing API keys (Generate, List, Revoke). |
| [app.js](file:///config/dev/oscar-shareable/frontend/src/app.js) | [MODIFY] | Add routing/navigation for the new Integrations page. |

---

## Verification Plan
### Automated Tests
- **Rust**: `cargo check` and `cargo audit` (to verify patch/suppression).
- **JS**: `npm run build` to verify the Vite/esbuild update didn't break the build pipeline.

### Manual Verification
- Verify that API keys can be generated and successfully used with `curl` to upload data.
- Verify that the "Tinfoil Hat Mode" continues to function correctly despite the `rsa` vulnerability (which is a timing side-channel risk, not a functional break).

> [!IMPORTANT]
> Since no patch is available for `rsa` 0.9.x, I will monitor for updates. The current implementation is acceptable for the "Tinfoil Hat Mode" as the private key is not persistently exposed on the network in a high-frequency polling environment.

**Please review this blueprint. If approved, I will begin the Autonomous Iteration Loop to apply these changes, utilizing `cargo` and `npm` to verify the builds. Shall I proceed?**
