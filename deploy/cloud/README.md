# Hosting UNVEIL in the cloud

This runs UNVEIL on a rented Linux server so it is always on and reachable from a phone or any browser over HTTPS.

## What you need

- A Linux server with Docker installed. 2 CPU cores and 4 GB of memory is a workable minimum.
- A domain or subdomain whose DNS record points at the server's IP address.
- Ports 80 and 443 open to the internet. Nothing else needs to be open.
- An AI model provider account, since a small server cannot run a large model itself.

## Start it

The short way, which asks for your domain and creates the password and audit key for you:

```bash
git clone https://github.com/unveilzero/UNVEIL.git
cd UNVEIL
bash deploy/cloud/setup.sh
```

It prints the address, the first admin password and the audit key once. Write them down.

Or by hand:

```bash
cp deploy/cloud/.env.example deploy/cloud/.env
# edit deploy/cloud/.env: domain, admin password, audit key
docker compose --env-file deploy/cloud/.env \
  -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml up -d --build
```

Open `https://your-domain`. Sign in as `admin`, then change the password.

The start is refused if the domain, the admin password or the audit key is missing.

## What this setup fixes in place

- Login is required for everything, and there is no loopback bypass.
- Session cookies are only sent over HTTPS.
- The app listens on the server's loopback address. Only the HTTPS front door is public.
- The security layer always enforces, with its audit key supplied from outside the data volume.

## On a phone

Open the address in the phone's browser and choose "Add to Home Screen". UNVEIL then opens full screen from its own icon. The agents and the security layer keep running on the server when the phone is closed.

## Public website

The page in `site/` can be served from the same server. Point the website's
DNS record at this server, add `UNVEIL_SITE_DOMAIN` to `deploy/cloud/.env`
(see `.env.example`), and start again with the command above. Leave it unset
and the website stays off the internet.

## Updating

```bash
git pull
docker compose --env-file deploy/cloud/.env \
  -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml up -d --build
```

## Keep in mind

- Chats, files and the audit log live in `./data` on the server. Back it up.
- Keep a copy of `UNVEIL_AUDIT_KEY` off the server. Without the original key the audit log cannot be verified.
- Anyone on the internet can reach the login page. Use a long password and keep the server's system updates on.
