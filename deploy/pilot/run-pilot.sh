#!/usr/bin/env bash
# Convenience wrapper for the containerised pilot topology.
#
# `pnpm pilot` runs the acceptance rehearsal in-process against real
# components (real CA, real mTLS, real IPP, real TSAs) and is the canonical
# acceptance run. This script brings up the docker-compose topology instead,
# which additionally exercises real CUPS servers and the container images.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed on this host." >&2
  echo "Run the in-process acceptance rehearsal instead:  pnpm pilot" >&2
  exit 2
fi

echo "Building images..."
docker compose build

echo "Starting pilot topology (1 authority, 3 centres, 3 CUPS servers)..."
docker compose up -d

echo
echo "Topology is up. Follow runbooks/exam-day.md, or tear down with:"
echo "  docker compose -f deploy/pilot/docker-compose.yml down -v"
