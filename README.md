# oscar-shareable

## secure-uploader TLS cert behavior

The Docker image now generates a self-signed certificate at build time, stored in:

- `/app/certs/key.pem`
- `/app/certs/cert.pem`

This avoids host bind-mount permission/path issues for TLS startup.

If you need custom cert locations, you can still override in-container paths with:

- `SSL_KEY_PATH`
- `SSL_CERT_PATH`

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


## Service port

The secure uploader is exposed only on HTTPS port `50710` in the compose setup.
