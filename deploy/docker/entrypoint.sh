#!/bin/sh
# ZERO-WINDOW container entrypoint.
#
# Selects the service CLI by first argument. Everything after it is passed
# through, so `docker run zero-window authority status --dir /var/lib/...`
# behaves exactly like the same command on a systemd host.
set -eu

SERVICE="${1:-help}"
shift 2>/dev/null || true

case "$SERVICE" in
  authority)
    exec node /opt/zero-window/authority/dist/cli.js "$@"
    ;;
  centre)
    exec node /opt/zero-window/centre/dist/cli.js "$@"
    ;;
  verify)
    exec node /opt/zero-window/verifier/dist/cli.js "$@"
    ;;
  ca)
    exec node /opt/zero-window/ca/dist/cli.js "$@"
    ;;
  help|--help|-h)
    cat <<'USAGE'
ZERO-WINDOW container

  docker run ... zero-window <service> [args]

SERVICES
  authority   zw-authority — provisioning, ceremony, release
  centre      zw-centre    — custody, check-in, T-0 printing
  verify      zw-verify    — independent audit
  ca          zw-ca        — internal PKI

The container runs unprivileged as uid 10001. Mount a writable volume at
/var/lib/zero-window for service state, and pass the vault passphrase via
ZW_VAULT_PASSPHRASE (docker secret / systemd LoadCredential), never on the
command line.
USAGE
    exit 0
    ;;
  *)
    echo "unknown service '$SERVICE' (expected: authority, centre, verify, ca)" >&2
    exit 1
    ;;
esac
