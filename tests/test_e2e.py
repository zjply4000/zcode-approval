"""End-to-End integration tests for ZCode hook evaluator subprocess piping."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "scripts" / "zcode_evaluator.py"


def _popen_env(extra_env: dict | None = None) -> dict:
    env = dict(os.environ)
    # Keep tests deterministic and network-free
    env.pop("TYPESAFE_API_KEY", None)
    env.pop("JEV_API_KEY", None)
    if extra_env:
        env.update(extra_env)
    return env


def run_evaluator(
    payload: str | dict | None,
    args: list[str] | None = None,
    extra_env: dict | None = None,
    cwd: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    """Execute zcode_evaluator.py as a subprocess, piping payload to stdin."""
    cmd_args = ["--event", "PreToolUse"] if args is None else args
    cmd = [sys.executable, str(EVALUATOR), *cmd_args]

    if isinstance(payload, dict):
        stdin_data = json.dumps(payload)
    elif isinstance(payload, str):
        stdin_data = payload
    elif payload is None:
        stdin_data = ""
    else:
        stdin_data = str(payload)

    proc = subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_popen_env(extra_env),
        cwd=cwd or str(ROOT),
        timeout=30,
    )
    assert proc.returncode == 0, f"Evaluator exited with non-zero code {proc.returncode}. Stderr: {proc.stderr}"
    out_stripped = proc.stdout.strip()
    data = json.loads(out_stripped) if out_stripped else {}
    return proc, data


def assert_zcode_hook_output(data: dict, expected_decision: str | None = None) -> dict:
    """Validate that stdout conforms strictly to ZCode hookSpecificOutput schema."""
    assert "hookSpecificOutput" in data, f"Missing 'hookSpecificOutput' root key in: {data}"
    hook_out = data["hookSpecificOutput"]
    assert hook_out.get("hookEventName") == "PreToolUse", f"Unexpected hookEventName: {hook_out}"
    decision = hook_out.get("permissionDecision")
    assert decision in ("allow", "deny", "ask"), f"Invalid permissionDecision: {decision}"
    assert "permissionDecisionReason" in hook_out, "Missing permissionDecisionReason"
    assert isinstance(hook_out["permissionDecisionReason"], str), "Reason must be string"
    if expected_decision is not None:
        assert decision == expected_decision, (
            f"Expected decision {expected_decision!r}, got {decision!r}. "
            f"Reason: {hook_out.get('permissionDecisionReason')}"
        )
    return hook_out


def test_e2e_whitelisted_bash_allows(tmp_path):
    """Whitelisted read-only command (Bash with git status): decision == 'allow'."""
    log_file = tmp_path / "audit.log"
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": str(tmp_path),
        "session_id": "e2e-session-whitelist",
    }
    proc, data = run_evaluator(payload, extra_env={"JEV_LOG_FILE": str(log_file)})
    hook_out = assert_zcode_hook_output(data, expected_decision="allow")
    assert "whitelist" in hook_out["permissionDecisionReason"]


def test_e2e_blocklisted_bash_denies(tmp_path):
    """Dangerous blocklist command (Bash with rm -rf /): decision == 'deny'."""
    log_file = tmp_path / "audit.log"
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "e2e-session-blocklist",
    }
    proc, data = run_evaluator(payload, extra_env={"JEV_LOG_FILE": str(log_file)})
    hook_out = assert_zcode_hook_output(data, expected_decision="deny")
    assert "blocklist" in hook_out["permissionDecisionReason"]


def test_e2e_system_path_write_denies(tmp_path):
    """High-risk system path write: decision == 'deny' under Strategy C."""
    system_target = "C:/Windows/System32/evil.dll" if sys.platform == "win32" else "/etc/evil.conf"
    log_file = tmp_path / "audit.log"
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": system_target, "content": "exploit"},
        "cwd": str(tmp_path),
        "session_id": "e2e-session-syspath",
    }
    proc, data = run_evaluator(payload, extra_env={"JEV_LOG_FILE": str(log_file)})
    hook_out = assert_zcode_hook_output(data, expected_decision="deny")
    assert any(term in hook_out["permissionDecisionReason"] for term in ("system directory", "sensitive credential"))


def test_e2e_credential_path_write_denies(tmp_path):
    """High-risk credential write (~/.ssh/authorized_keys): decision == 'deny' under Strategy C."""
    log_file = tmp_path / "audit.log"
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-rsa AAAAB3NzaC1yc2E..."},
        "cwd": str(tmp_path),
        "session_id": "e2e-session-cred",
    }
    proc, data = run_evaluator(payload, extra_env={"JEV_LOG_FILE": str(log_file)})
    hook_out = assert_zcode_hook_output(data, expected_decision="deny")
    assert any(term in hook_out["permissionDecisionReason"] for term in ("system directory", "sensitive credential"))


def test_e2e_outside_workspace_write_asks(tmp_path):
    """Benign outside-workspace write: decision == 'ask' under Strategy C."""
    ws = tmp_path / "workspace"
    os.makedirs(ws / ".git", exist_ok=True)
    outside_file = tmp_path / "outside_temp" / "notes.txt"
    log_file = tmp_path / "audit.log"

    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": str(outside_file), "content": "some notes"},
        "cwd": str(ws),
        "session_id": "e2e-session-outside",
    }
    proc, data = run_evaluator(payload, extra_env={"JEV_LOG_FILE": str(log_file)})
    hook_out = assert_zcode_hook_output(data, expected_decision="ask")
    assert "outside workspace" in hook_out["permissionDecisionReason"]


def test_e2e_empty_payload_fails_closed():
    """Empty payload fails closed with decision == 'ask' and exit code 0."""
    proc, data = run_evaluator(None)
    hook_out = assert_zcode_hook_output(data, expected_decision="ask")
    assert "empty input" in hook_out["permissionDecisionReason"] or "timeout" in hook_out["permissionDecisionReason"]


def test_e2e_broken_json_payload_fails_closed():
    """Malformed/broken JSON payload fails closed with decision == 'ask' and exit code 0."""
    proc, data = run_evaluator("{invalid json without closing brace")
    hook_out = assert_zcode_hook_output(data, expected_decision="ask")
    assert "malformed" in hook_out["permissionDecisionReason"]


def test_e2e_non_pretooluse_event_cli():
    """Non-PreToolUse event passed via CLI returns {} with exit code 0."""
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
    proc, data = run_evaluator(payload, args=["--event", "PostToolUse"])
    assert data == {}


def test_e2e_non_pretooluse_event_payload():
    """Non-PreToolUse event passed in payload returns {} with exit code 0."""
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    }
    proc, data = run_evaluator(payload, args=[])
    assert data == {}


def test_e2e_stdout_purity():
    """Stdout must contain exactly one JSON object line with no stray debug logs."""
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    }
    proc, data = run_evaluator(payload)
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, f"Expected exactly 1 line on stdout, got: {lines}"
    assert "hookSpecificOutput" in lines[0]


def test_e2e_zcode_camelcase_fields():
    """Payload using ZCode camelCase field names (toolName, toolInput, sessionId)."""
    payload = {
        "toolName": "Bash",
        "toolInput": {"command": "git status"},
        "sessionId": "camel-session",
    }
    proc, data = run_evaluator(payload)
    hook_out = assert_zcode_hook_output(data, expected_decision="allow")
    assert hook_out["permissionDecision"] == "allow"
