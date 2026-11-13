#!/usr/bin/env bash
# Check the command room on a cloud-hosted UNVEIL: the separate container that
# agent commands run in.
#   bash deploy/cloud/check-box.sh
# It sends one harmless command the same way the app does and reports what
# that command could see. Nothing is changed.
set -uo pipefail
cd "$(dirname "$0")/../.."
compose=(docker compose --env-file deploy/cloud/.env -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml)

"${compose[@]}" exec -T odysseus python - <<'PY'
import os, subprocess, sys

from src import containment
from src.command_room import client

settings = containment._room_settings()
if settings is None:
    print("RESULT: the command room is not set up yet (no secret). Run: bash update.sh")
    sys.exit(1)
answer = client.ping(*settings, timeout=5)
if answer is None:
    print("RESULT: the command room did not answer. It may still be starting; try again in a minute.")
    sys.exit(1)
if not answer.get("room"):
    print("RESULT: the command room is running but cannot build a private space for commands.")
    print("Agent commands stay refused. Send this output for the next step.")
    sys.exit(1)

workspace = (answer.get("workspaces") or [""])[0]
probe = (
    "echo files-at-top: $(ls / | tr '\\n' ' ');"
    "echo app-folder: $( [ -e /app/app.py ] && echo VISIBLE || echo hidden );"
    "echo database-and-keys: $( ls /app/data 2>/dev/null | grep -Eqv '^agent_workspace$' && echo VISIBLE || echo hidden );"
    "echo settings-in-environment: $(env | grep -Ec 'UNVEIL|ODYSSEUS|KEY|TOKEN|PASSWORD|SECRET');"
    "echo other-processes: $(ls /proc 2>/dev/null | grep -c '^[0-9]');"
)
env = {"PATH": os.environ.get("PATH", ""), "UNVEIL_ROOM_URL": settings[0], "UNVEIL_ROOM_TOKEN": settings[1]}
done = subprocess.run(
    [sys.executable, "-I", containment._ROOM_CLIENT, "--workspace", workspace, "--timeout", "20",
     "--", "/bin/sh", "-c", probe],
    env=env, capture_output=True, text=True, timeout=40)
if done.returncode != 0:
    print("RESULT: the test command did not run.")
    print((done.stderr or "").strip()[:400])
    sys.exit(1)

print(done.stdout.strip())
lines = done.stdout
exposed = "VISIBLE" in lines or "settings-in-environment: 0" not in lines
print("RESULT:", "PROBLEM, the room can see more than it should. Send this output." if exposed
      else "the command room works. Commands run with no app files, no database, no keys and no settings.")
sys.exit(1 if exposed else 0)
PY
