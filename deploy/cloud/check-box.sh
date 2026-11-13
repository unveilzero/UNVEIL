#!/usr/bin/env bash
# Check the room that agent commands run in on a cloud-hosted UNVEIL.
#   bash deploy/cloud/check-box.sh
# It starts one harmless command the same way the app does and reports what
# that command could see. Nothing is changed.
set -uo pipefail
cd "$(dirname "$0")/../.."
compose=(docker compose --env-file deploy/cloud/.env -f docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml)

"${compose[@]}" exec -T odysseus python - <<'PY'
import os, shutil, subprocess, sys, tempfile

if not shutil.which("bwrap"):
    print("RESULT: no box. The sandbox tool is not installed in this image.")
    print("Agent commands are refused until it is. Run: bash update.sh")
    sys.exit(1)

from src import containment

workspace = tempfile.mkdtemp(prefix="boxcheck-")
spec = containment.agent_spec(workspace, {}, 20)
probe = (
    "echo files-at-top: $(ls / | tr '\\n' ' ');"
    "echo app-folder: $( [ -e /app ] && echo VISIBLE || echo hidden );"
    "echo data-folder: $( [ -e /app/data ] && echo VISIBLE || echo hidden );"
    "echo settings-in-environment: $(env | wc -l);"
    "echo other-processes: $(ls /proc | grep -c '^[0-9]');"
)
try:
    argv = containment._bwrap_prefix(spec) + ["/bin/sh", "-c", probe]
    done = subprocess.run(argv, env={}, capture_output=True, text=True, timeout=20)
except Exception as error:
    print(f"RESULT: the box could not start ({type(error).__name__}: {error}).")
    sys.exit(1)
finally:
    shutil.rmtree(workspace, ignore_errors=True)

if done.returncode != 0:
    print("RESULT: the box could not start in this container.")
    print((done.stderr or "").strip()[:400])
    print("Agent commands stay refused. Send this output for the next step.")
    sys.exit(1)

print(done.stdout.strip())
exposed = "VISIBLE" in done.stdout
print("RESULT:", "PROBLEM, the box can see application files." if exposed
      else "the box works. Commands run with no app files, no data and no settings.")
sys.exit(1 if exposed else 0)
PY
