#!/usr/bin/env bash
# All Docker mutations belong to a fresh project. Logs intentionally survive it.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
source "$root/e2e/exporter.env"
export E2E_EXPORTER_IMAGE E2E_EXPORTER_VERSION
mkdir -p "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}"
run_dir=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/endlessh-e2e.XXXXXXXX")
project=$(basename "$run_dir" | tr '[:upper:].' '[:lower:]-')-$$
export E2E_DASHBOARD_IMAGE=${E2E_DASHBOARD_IMAGE:-endlessh-dashboard-e2e:$project}
compose=(docker compose --env-file /dev/null -p "$project" -f "$root/e2e/docker-compose.e2e.yml")
if [[ -n ${E2E_COMPOSE_OVERRIDE:-} ]]; then compose+=(-f "$E2E_COMPOSE_OVERRIDE"); fi
printf '%s\n' "$project" > "$run_dir/project"
printf 'E2E project: %s\nLogs: %s\n' "$project" "$run_dir"
owned=0
child=
ids() {
 case "$1" in
 container) docker ps -aq --filter "label=com.docker.compose.project=$project" ;;
 volume) docker volume ls -q --filter "label=com.docker.compose.project=$project" ;;
 network) docker network ls -q --filter "label=com.docker.compose.project=$project" ;;
 esac
}
cleanup() {
 local status=$? failed=0 kind remaining
 trap - EXIT
 trap '' INT TERM
 set +e
 if [[ -n $child ]]; then kill -TERM -- "-$child" 2>/dev/null; wait "$child" 2>/dev/null; fi
 if (( owned )); then
  timeout 20s "${compose[@]}" logs --no-color > "$run_dir/containers.log" 2>&1
  timeout 60s "${compose[@]}" down --volumes --remove-orphans --timeout 10 > "$run_dir/cleanup.log" 2>&1
  # A failed/partial Compose teardown is not enough: remove and verify only
  # resources labelled with this invocation's preflight-checked project.
  for kind in container volume network; do
   remaining=$(ids "$kind")
   if (( $? != 0 )); then failed=1; continue; fi
   if [[ -n $remaining ]]; then
    readarray -t owned_ids <<< "$remaining"
    case "$kind" in
    container) timeout 30s docker rm -fv "${owned_ids[@]}" >> "$run_dir/cleanup.log" 2>&1 ;;
    volume) timeout 30s docker volume rm "${owned_ids[@]}" >> "$run_dir/cleanup.log" 2>&1 ;;
    network) timeout 30s docker network rm "${owned_ids[@]}" >> "$run_dir/cleanup.log" 2>&1 ;;
    esac
   fi
  done
  : > "$run_dir/remaining.log"
  for kind in container volume network; do
   remaining=$(ids "$kind")
   if (( $? != 0 )); then failed=1; fi
   printf '%s: %s\n' "$kind" "$remaining" >> "$run_dir/remaining.log"
   if [[ -n $remaining ]]; then failed=1; fi
  done
 fi
 if (( failed )); then
  echo "ERROR: project cleanup could not be verified; see $run_dir" >&2
  if (( status == 0 )); then status=1; fi
 else
  printf 'Cleanup verified for %s; logs retained at %s\n' "$project" "$run_dir"
 fi
 exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_step() {
 local name=$1 limit=$2 status=0
 shift 2
 printf 'Running %s\n' "$name"
 setsid timeout --signal=TERM --kill-after=10s "$limit" "$@" > "$run_dir/$name.log" 2>&1 &
 child=$!
 wait "$child" || status=$?
 child=
 if (( status )); then cat "$run_dir/$name.log" >&2; return "$status"; fi
}
# Do not claim ownership of any pre-existing project, even on a name collision.
for kind in container volume network; do
 remaining=$(ids "$kind")
 [[ -z $remaining ]] || { echo "Project collision: $project" >&2; exit 1; }
done
owned=1
run_step config 30s "${compose[@]}" config
if [[ ${E2E_SKIP_BUILD:-0} != 1 ]]; then run_step build 15m "${compose[@]}" build dashboard; fi
run_step startup 5m "${compose[@]}" up --no-build -d
container=$("${compose[@]}" ps -q tarpit)
actual=$(docker inspect --format '{{.Config.Image}}' "$container")
[[ $actual == "$E2E_EXPORTER_IMAGE" ]] || { echo 'Unexpected exporter image' >&2; exit 1; }
docker image inspect "$E2E_EXPORTER_IMAGE" --format '{{.Id}} {{json .RepoDigests}} {{json .Config.Labels}}' > "$run_dir/exporter-identity.log"
port=$("${compose[@]}" port dashboard 18222)
[[ $port =~ ^127\.0\.0\.1:[0-9]+$ ]] || { echo "Dashboard is not loopback-only: $port" >&2; exit 1; }
export E2E_BASE_URL=http://$port
export E2E_TARPIT_ADDR
E2E_TARPIT_ADDR=$("${compose[@]}" port tarpit 2222)
[[ $E2E_TARPIT_ADDR =~ ^127\.0\.0\.1:[0-9]+$ ]] || { echo "Tarpit is not loopback-only: $E2E_TARPIT_ADDR" >&2; exit 1; }
port=$("${compose[@]}" port tarpit 2112)
[[ $port =~ ^127\.0\.0\.1:[0-9]+$ ]] || { echo "Metrics are not loopback-only: $port" >&2; exit 1; }
export E2E_METRICS_URL=http://$port/metrics E2E_FIXTURE_PATH=$run_dir/exporter.prom E2E=1
if (( $# )); then
 run_step test 10m "$@"
else
 run_step test 10m go test -count=1 -v -tags e2e -timeout 9m ./e2e/...
fi
