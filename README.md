# oscar-shareable

## secure-uploader TLS cert behavior

The Docker image generates a self-signed certificate at build time, stored in:

- `/app/certs/key.pem`
- `/app/certs/cert.pem`

This avoids host bind-mount permission/path issues for TLS startup.

If you need custom cert locations, you can still override in-container paths with:

- `SSL_KEY_PATH`
- `SSL_CERT_PATH`

## Reverse proxy + CrowdSec hardening

`secure-uploader/docker-compose.yml` now places NGINX in front of the uploader and publishes **only** the NGINX HTTPS listener.

- Exposed host port is fixed at `50710`.
- CrowdSec (`crowdsecurity/crowdsec`) parses NGINX access logs and blocks abusive requests through a forward-auth bouncer gate.

### Run securely

```bash
cd secure-uploader
docker compose up --build -d
```

Open `https://localhost:50710`.

### If files exist but startup still fails

If startup still fails with certificate errors, it is usually a permissions or host security-label issue.

Quick checks:

```bash
# from secure-uploader/
docker compose exec uploader sh -lc 'id && ls -l /app/certs && namei -l /app/certs/key.pem /app/certs/cert.pem'
```

What to look for:

- Container runs as `911:911`, so that user must be able to read both files.
- Parent directories also need execute (`x`) permission so the container user can traverse to the files.
- On SELinux hosts, bind mounts may need relabeling (for example `:z` / `:Z`) so container access is allowed.
