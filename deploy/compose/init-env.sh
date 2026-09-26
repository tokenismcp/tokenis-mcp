#!/bin/sh
# Writes .env with fresh random secrets for the Compose stack. Refuses to
# overwrite an existing .env: the keystore passphrase in it unlocks the
# keystore created on first start.
set -eu
cd "$(dirname "$0")"
if [ -e .env ]; then
  echo ".env already exists; delete it only together with the volumes (docker compose down -v)" >&2
  exit 1
fi
secret() { openssl rand -hex 24; }
umask 077
cat > .env <<EOF
POSTGRES_PASSWORD=$(secret)
TOKENIS_DB_PASSWORD=$(secret)
CRM_READER_PASSWORD=$(secret)
TOKENIS_KEYSTORE_PASSPHRASE=$(secret)
TOKENIS_ADMIN_TOKEN=$(secret)
GRAFANA_ADMIN_PASSWORD=$(secret)
EOF
echo "wrote $(pwd)/.env (mode 600). Admin dashboard password: see TOKENIS_ADMIN_TOKEN." >&2
