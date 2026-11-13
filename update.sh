#!/usr/bin/env bash
# Update a cloud-hosted UNVEIL to the latest code and restart it.
#   bash update.sh
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f deploy/cloud/.env ]; then
  echo "deploy/cloud/.env not found. Run deploy/cloud/setup.sh first." >&2
  exit 1
fi
git pull --ff-only
docker compose --env-file deploy/cloud/.env -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml up -d --build
echo "UNVEIL is updated and running."
