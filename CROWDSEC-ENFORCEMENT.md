# CrowdSec enforcement strategy for tunnel-only ingress

This stack uses **Cloudflare Tunnel** (`cloudflared`) as the only public ingress path to `nginx-internal`. CrowdSec enforcement is now done at the origin through the **CrowdSec Nginx bouncer**.

## Strategy decision

### Primary enforcement (enabled by default)
- Deploy `crowdsec` (LAPI + parser engine) and `crowdsec-nginx-bouncer` in `docker-compose.yml`.
- The Nginx bouncer pulls decisions from CrowdSec LAPI (`http://crowdsec:8080`) and enforces local block/challenge behavior at the Nginx layer.
- This avoids Cloudflare API/WAF dependencies that are not available in Cloudflare free-tier plans.

## Fail-open / fail-closed behavior

### Nginx bouncer (primary)
- **Recommended mode: fail-open** for availability.
  - If LAPI is temporarily unavailable, new decisions may be delayed, but service availability is preserved.
- **Fail-closed option** can be chosen for stricter posture.
  - If LAPI cannot be reached, enforcement should be considered degraded and trigger alerting.

## Decision TTLs and refresh intervals

- Default decision TTL is documented in `.env` as `CROWDSEC_DECISION_TTL=4h`.
- Operational guideline:
  - Keep TTL long enough to survive brief control-plane outages (e.g., 1h–24h).
  - Keep pull interval short enough for rapid reaction (e.g., 10s–60s).

## Required secrets and permissions

Add/set these in `.env`:
- `CROWDSEC_NGINX_BOUNCER_KEY`: API key for nginx bouncer.

## End-to-end verification procedure (test decision)

1. Start services:
   ```bash
   docker compose up -d crowdsec crowdsec-nginx-bouncer cloudflared nginx uploader oscar
   ```
2. Register bouncer key (if not pre-provisioned) in CrowdSec:
   ```bash
   docker compose exec crowdsec cscli bouncers add nginx-bouncer -k "$CROWDSEC_NGINX_BOUNCER_KEY"
   ```
3. Inject a test decision for a known test IP:
   ```bash
   docker compose exec crowdsec cscli decisions add --ip 198.51.100.23 --duration "$CROWDSEC_DECISION_TTL" --reason "e2e-test"
   ```
4. Confirm decision exists in CrowdSec:
   ```bash
   docker compose exec crowdsec cscli decisions list | grep 198.51.100.23
   ```
5. Perform request through the real public hostname with test source IP `198.51.100.23`.
   - Expected result: request is blocked/challenged by the nginx bouncer policy.
6. Cleanup test decision:
   ```bash
   docker compose exec crowdsec cscli decisions delete --ip 198.51.100.23
   ```

## Notes
- With tunnel-only ingress, origin enforcement still protects app access even without Cloudflare edge/WAF automation.
