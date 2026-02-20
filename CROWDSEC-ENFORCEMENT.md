# CrowdSec enforcement strategy for tunnel-only ingress

This stack uses **Cloudflare Tunnel** (`cloudflared`) as the only public ingress path to `nginx-internal`. To enforce CrowdSec decisions as close to the attacker as possible, the preferred control is the **CrowdSec Cloudflare bouncer** at the Cloudflare edge.

## Strategy decision

### Preferred (enabled by default)
- Deploy `crowdsec` (LAPI + parser engine) and `crowdsec-cloudflare-bouncer` in `docker-compose.yml`.
- The Cloudflare bouncer reads `crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml` (mounted at `/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml`) and uses a **least-privilege API token** (`CF_API_TOKEN`) plus account/zone scoping (`CF_ACCOUNT_ID`, `CF_ZONE_ID`) to create CrowdSec-driven deny/challenge rules at Cloudflare edge.
- Default action is `managed_challenge` so suspicious traffic is challenged before reaching the tunnel origin.

### Optional defense-in-depth (disabled by default)
- `crowdsec-nginx-bouncer` is included under compose profile `defense-in-depth`.
- Enable with:
  ```bash
  docker compose --profile defense-in-depth up -d crowdsec-nginx-bouncer
  ```
- This gives an additional local enforcement point in front of `nginx-internal`, backed by host LAPI (`crowdsec:8080`).

## Fail-open / fail-closed behavior

### Cloudflare bouncer (preferred)
- **Recommended mode: fail-open** for availability.
  - If LAPI or Cloudflare API is temporarily unavailable, existing edge rules stay in place until their expiration.
  - New decisions may be delayed, but tunnel/app availability is preserved.
- **Fail-closed option** can be chosen for high-security posture.
  - Any inability to refresh/apply decisions should be treated as enforcement failure and trigger immediate operations alerting and incident handling.

> This deployment records the selected mode in `.env` via `CROWDSEC_BOUNCER_MODE` (set to `fail-open` by default).

### Nginx bouncer (optional)
- For defense-in-depth, keep the local bouncer **fail-open** unless strict outage policies require otherwise.
- Fail-closed locally can block legitimate traffic if LAPI connectivity breaks.

## Decision TTLs and refresh intervals

- Default decision TTL is documented in `.env` as `CROWDSEC_DECISION_TTL=4h`.
- Cloudflare bouncer pulls decisions every `10s` (`BOUNCER_UPDATE_FREQUENCY: 10s`).
- Operational guideline:
  - Keep TTL long enough to survive brief control-plane outages (e.g., 1h–24h).
  - Keep pull interval short enough for rapid reaction (e.g., 10s–60s).

## Required secrets and permissions

Add/set these in `.env`:
- `CF_API_TOKEN`: Cloudflare token scoped to the target zone with only permissions needed to manage WAF/custom rules for decisions.
- `CF_ACCOUNT_ID`: Cloudflare account ID that owns the target zone.
- `CF_ZONE_ID`: target zone ID.
- `CROWDSEC_BOUNCER_KEY`: API key registered in CrowdSec for Cloudflare bouncer.
- `CROWDSEC_NGINX_BOUNCER_KEY`: API key for optional nginx bouncer.

## End-to-end verification procedure (test decision)

1. Start services:
   ```bash
   docker compose up -d crowdsec crowdsec-cloudflare-bouncer cloudflared nginx uploader oscar
   ```
2. Register bouncer keys (if not pre-provisioned) in CrowdSec:
   ```bash
   docker compose exec crowdsec cscli bouncers add cloudflare-bouncer -k "$CROWDSEC_BOUNCER_KEY"
   docker compose exec crowdsec cscli bouncers add nginx-bouncer -k "$CROWDSEC_NGINX_BOUNCER_KEY"
   ```
3. Inject a test ban/challenge decision for a known test IP:
   ```bash
   docker compose exec crowdsec cscli decisions add --ip 198.51.100.23 --duration "$CROWDSEC_DECISION_TTL" --reason "e2e-test"
   ```
4. Confirm decision exists in CrowdSec:
   ```bash
   docker compose exec crowdsec cscli decisions list | grep 198.51.100.23
   ```
5. Wait for bouncer sync (`10s`) and confirm Cloudflare rule appears (Dashboard/API).
6. Perform request through the real public hostname with test source IP `198.51.100.23`.
   - Expected result with current default policy: Cloudflare **Managed Challenge** (or deny if policy changed).
7. Cleanup test decision:
   ```bash
   docker compose exec crowdsec cscli decisions delete --ip 198.51.100.23
   ```

## Notes
- Because ingress is tunnel-only, edge enforcement is materially stronger than origin-only blocking.
- Keep optional nginx bouncer for layered defense, not as primary control.
