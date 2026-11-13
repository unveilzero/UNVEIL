#!/usr/bin/env bash
# One-step setup for UNVEIL on a fresh cloud server.
#
#   git clone https://github.com/unveilzero/UNVEIL.git && cd UNVEIL
#   bash deploy/cloud/setup.sh
#
# Asks for the domain, creates the admin password and the audit key, writes
# deploy/cloud/.env (readable only by you), and starts everything.
set -euo pipefail

cd "$(dirname "$0")/../.."
ENV_FILE="deploy/cloud/.env"

if [ -e "$ENV_FILE" ]; then
  echo "$ENV_FILE already exists. To start with the existing settings, run:"
  echo "  docker compose --env-file $ENV_FILE -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml up -d --build"
  exit 1
fi
if [ -z "${UNVEIL_SETUP_DRY_RUN:-}" ]; then
  command -v docker >/dev/null 2>&1 || { echo "Docker is not installed on this server."; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "Docker Compose is not available (need 'docker compose')."; exit 1; }
fi
command -v openssl >/dev/null 2>&1 || { echo "openssl is not installed on this server."; exit 1; }

DOMAIN="${UNVEIL_DOMAIN:-}"
if [ -z "$DOMAIN" ]; then
  read -r -p "Address people will open (for example app.unveilresearch.com): " DOMAIN
fi
DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]' | sed -e 's#^https\?://##' -e 's#/.*$##')"
if ! printf '%s' "$DOMAIN" | grep -Eq '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'; then
  echo "That does not look like a domain name: $DOMAIN"
  exit 1
fi

ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
AUDIT_KEY="$(openssl rand -hex 32)"
ROOM_TOKEN="$(openssl rand -hex 32)"

umask 077
cat > "$ENV_FILE" <<ENV
UNVEIL_DOMAIN=$DOMAIN
ODYSSEUS_ADMIN_PASSWORD=$ADMIN_PASSWORD
UNVEIL_AUDIT_KEY=$AUDIT_KEY
UNVEIL_ROOM_TOKEN=$ROOM_TOKEN
ENV
chmod 600 "$ENV_FILE"

echo
echo "Settings written to $ENV_FILE"
if [ -z "${UNVEIL_SETUP_DRY_RUN:-}" ]; then
  echo "Building and starting UNVEIL. The first build takes several minutes."
  docker compose --env-file "$ENV_FILE" -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml up -d --build
fi

cat <<DONE

UNVEIL is starting at:  https://$DOMAIN
Sign in as:             admin
First password:         $ADMIN_PASSWORD

Write these down now. They are not shown again.
  Audit key:            $AUDIT_KEY

Keep a copy of the audit key somewhere other than this server.
Change the admin password after your first sign-in.
The address must already point at this server, or the HTTPS certificate cannot be issued.
DONE
