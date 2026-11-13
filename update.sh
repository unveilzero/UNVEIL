#!/usr/bin/env bash
# Update a cloud-hosted UNVEIL to the latest code and restart it.
#   bash update.sh
set -euo pipefail
cd "$(dirname "$0")"
ENV_FILE=deploy/cloud/.env
if [ ! -f "$ENV_FILE" ]; then
  echo "$ENV_FILE not found. Run deploy/cloud/setup.sh first." >&2
  exit 1
fi
if [ "${1:-}" != "--pulled" ]; then
  git pull --ff-only
  # Carry on with the version of this script that was just pulled.
  exec bash "$0" --pulled
fi
# The app and the command room share a secret. Make one the first time.
if ! grep -Eq '^UNVEIL_ROOM_TOKEN=.{32,}' "$ENV_FILE"; then
  token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf '\n# Shared secret between the app and the command room.\nUNVEIL_ROOM_TOKEN=%s\n' "$token" >> "$ENV_FILE"
  echo "Created the command room secret."
fi
docker compose --env-file "$ENV_FILE" -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml up -d --build
echo "UNVEIL is updated and running."
