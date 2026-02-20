# CrowdSec ingestion for `nginx-internal`

This repository now exposes Nginx logs on the host at `./logs/nginx` via Docker bind mount and provides host CrowdSec acquisition/collection config.

For the containerized CrowdSec service in `docker-compose.yml`, `acquis.yaml` is bind-mounted directly to `/etc/crowdsec/acquis.yaml`. The base CrowdSec `config.yaml` is provided by the upstream image (it is no longer masked by a full `/etc/crowdsec` volume mount).

## 1) Log source setup

Two supported ingestion paths are provided in `crowdsec/acquis.yaml`:

- **Docker source** (`source: docker`) for `container_name: nginx-internal`
- **File source** (`filenames`) for host-mounted files:
  - `/workspace/oscar-shareable/logs/nginx/access.log`
  - `/workspace/oscar-shareable/logs/nginx/error.log`

Use one or both depending on your host CrowdSec deployment.

## 2) Enable parser collections / scenarios

On the host CrowdSec instance:

```bash
sudo cscli collections install crowdsecurity/nginx
sudo cscli collections install crowdsecurity/http-cve
sudo cscli collections install crowdsecurity/base-http-scenarios
```

(Equivalent one-shot install)

```bash
sudo xargs -n1 cscli collections install < /workspace/oscar-shareable/crowdsec/collections.txt
```

## 3) Apply acquisition to host CrowdSec

```bash
sudo cp /workspace/oscar-shareable/crowdsec/acquis.yaml /etc/crowdsec/acquis.yaml
sudo systemctl restart crowdsec
```

## 4) Confirm parsing as Nginx HTTP and decision creation

Generate some HTTP traffic against Nginx, then verify:

```bash
# Confirm parser hits on nginx logs
sudo cscli metrics | sed -n '/Acquisition Metrics/,$p'

# Confirm nginx/http scenarios are running and producing alerts/decisions
sudo cscli alerts list -n 20
sudo cscli decisions list -n 20
```

You should see events labeled `type: nginx`, parsed by nginx/http parsers, and decisions with attacker client IPs under `Value`/`IP`.
