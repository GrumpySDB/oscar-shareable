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

`secure-uploader/docker-compose.yml` now places Traefik in front of the uploader and publishes **only** the Traefik HTTPS entrypoint.

- Exposed host port is provided by `SECURE_UPLOADER_PORT` and must be high-numbered.
- `secure-uploader/scripts/start-secure-uploader.sh` automatically picks a random port from `49152-65535`.
- CrowdSec (`crowdsecurity/crowdsec`) parses Traefik access logs and the Traefik CrowdSec bouncer protects requests through forward auth.

### Run securely

```bash
cd secure-uploader
./scripts/start-secure-uploader.sh
```

The script prints the selected URL, for example `https://localhost:55321`.

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
