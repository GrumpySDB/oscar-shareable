#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${PROJECT_DIR}/debug"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${OUTPUT_DIR}/traefik-debug-${STAMP}"

mkdir -p "${RUN_DIR}"

run() {
  local title="$1"
  shift
  {
    echo "### ${title}"
    echo "\$ $*"
    "$@"
  } >"${RUN_DIR}/$(echo "${title}" | tr ' ' '_' | tr -cd '[:alnum:]_-').txt" 2>&1 || true
}

cd "${PROJECT_DIR}"

run "docker_compose_ps" docker compose ps
run "reverse_proxy_logs" docker compose logs --no-color --tail=400 reverse-proxy
run "uploader_logs" docker compose logs --no-color --tail=200 uploader
run "crowdsec_logs" docker compose logs --no-color --tail=200 crowdsec
run "crowdsec_bouncer_logs" docker compose logs --no-color --tail=200 crowdsec-bouncer
run "traefik_static_config" docker compose exec -T reverse-proxy cat /etc/traefik/traefik.yml
run "traefik_dynamic_config" docker compose exec -T reverse-proxy cat /etc/traefik/dynamic.yml
run "traefik_version" docker compose exec -T reverse-proxy traefik version
run "traefik_access_log_tail" docker compose exec -T reverse-proxy sh -lc 'tail -n 200 /var/log/traefik/access.log'
run "traefik_main_log_tail" docker compose exec -T reverse-proxy sh -lc 'tail -n 200 /var/log/traefik/traefik.log'
run "service_health_check" docker compose exec -T reverse-proxy sh -lc 'apk add --no-cache curl >/dev/null 2>&1 || true; curl -vk https://uploader:3443/ || true'
run "crowdsec_bouncer_health" docker compose exec -T reverse-proxy sh -lc 'apk add --no-cache curl >/dev/null 2>&1 || true; curl -sv http://crowdsec-bouncer:8080/api/v1/forwardAuth || true'
run "local_tls_probe" sh -lc 'curl -vk https://localhost:50710/ || true'

cat >"${RUN_DIR}/README.txt" <<TXT
Traefik troubleshooting bundle generated at: ${STAMP}

Files:
- docker_compose_ps.txt: Container status and restart loops.
- reverse_proxy_logs.txt: Traefik startup/runtime errors.
- uploader_logs.txt: Backend TLS/app errors.
- crowdsec_logs.txt + crowdsec_bouncer_logs.txt: auth-blocking failures.
- traefik_*_config.txt: live config mounted inside Traefik.
- traefik_*_log_tail.txt: last log lines from file logs.
- service_health_check.txt: reverse-proxy -> uploader HTTPS probe.
- crowdsec_bouncer_health.txt: reverse-proxy -> bouncer connectivity probe.
- local_tls_probe.txt: host -> Traefik TLS probe.
TXT

echo "Wrote diagnostics to ${RUN_DIR}"
