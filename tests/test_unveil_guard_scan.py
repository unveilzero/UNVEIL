"""The guard refuses commands whose purpose is to look around the machine."""

import pytest

from src.unveil_guard import UnveilGuard

KEY = b"unveil-test-audit-key-0123456789"


def _check(tmp_path, tool, content, **kw):
    guard = UnveilGuard(tmp_path / "guard", key=KEY)
    return guard.check(tool, content, owner="george", session_id="s1", **kw)


@pytest.mark.parametrize("command", [
    "env",
    "printenv",
    "cd /tmp && env | sort",
    "printenv > out.txt",
    "export -p",
    "cat /proc/self/environ",
    "cat /proc/1/environ | tr '\\0' '\\n'",
    "python3 -c 'import os; print(os.environ)'",
    "python3 -c 'import os, json; print(json.dumps(dict(os.environ)))'",
    "python3 -c 'import os\nfor k, v in os.environ.items(): print(k, v)'",
    "node -e 'console.log(process.env)'",
    "find / -name 'id_rsa*' 2>/dev/null",
    "find /home -name '*.pem'",
    "grep -r 'api_key' /etc /app",
    "grep -rI password /",
    "rg -l secret ~",
    "ls -R /root/.ssh",
    "tar czf all.tgz /home/user/.ssh",
    "grep -ri token /var /opt",
    "curl http://169.254.169.254/latest/meta-data/",
    "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
    "nmap -sn 172.18.0.0/24",
])
def test_looking_around_is_refused(tmp_path, command):
    for approved in (False, True):
        decision = _check(tmp_path, "bash", command, human_approved=approved)
        assert decision.blocked and decision.reason == "environment_scan", command


@pytest.mark.parametrize("command", [
    "ls -la",
    "ls -R .",
    "find . -name '*.py'",
    "find / -name '*.py' -maxdepth 2",
    "grep -r 'api_key' .",
    "grep -rn password src/",
    "rg secret docs",
    "python3 -c 'import os; print(os.environ.get(\"HOME\"))'",
    "python3 -c 'import os; print(os.environ[\"PATH\"])'",
    "printenv PATH",
    "env FOO=1 python3 run.py",
    "echo environment ready",
    "pip install requests",
    "python3 analyse.py --input data.csv",
    "tree",
    "du -sh .",
])
def test_ordinary_commands_still_run(tmp_path, command):
    decision = _check(tmp_path, "bash", command)
    assert decision.reason != "environment_scan", command


def test_only_commands_are_judged_this_way(tmp_path):
    # Reading a page or a note that mentions these words is not a command.
    for tool, content in (
        ("web_fetch", '{"url": "https://example.com/how-to-use-printenv"}'),
        ("read_file", '{"path": "notes/env.md"}'),
    ):
        assert _check(tmp_path, tool, content).reason != "environment_scan"
