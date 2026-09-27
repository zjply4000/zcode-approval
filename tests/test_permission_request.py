# tests/test_permission_request.py
# PermissionRequest event: deterministic-only evaluation and output mapping.
from __future__ import annotations

import json
import sys

import pytest

from zcode_evaluator import (
    format_permission_request_output,
    handle_permission_request,
    main,
)


def _ws(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / ".git").mkdir()
    return ws


def test_format_permission_request_allow_carries_no_message():
    out = format_permission_request_output("allow", "some reason")
    assert out["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert out["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


def test_format_permission_request_deny_carries_message():
    out = format_permission_request_output("deny", "blocklist: rm recursive force")
    assert out["hookSpecificOutput"]["decision"] == {
        "behavior": "deny",
        "message": "blocklist: rm recursive force",
    }


def test_format_permission_request_passthrough_is_empty():
    assert format_permission_request_output("ask", "whatever") == {}
    assert format_permission_request_output("force_ask", "whatever") == {}
    assert format_permission_request_output("", "whatever") == {}


def test_handle_permission_request_edit_in_workspace_allows(tmp_path):
    ws = _ws(tmp_path)
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Edit",
        "cwd": str(ws),
        "session_id": "sess-pr-1",
        "tool_input": {"file_path": str(ws / "src" / "core" / "utils" / "dates.ts"),
                       "old_string": "a", "new_string": "b"},
    }
    out = handle_permission_request(payload)
    assert out["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert out["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


def test_handle_permission_request_sensitive_file_prompts(tmp_path):
    ws = _ws(tmp_path)
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Edit",
        "cwd": str(ws),
        "session_id": "sess-pr-2",
        "tool_input": {"file_path": str(ws / "pyproject.toml"),
                       "old_string": "a", "new_string": "b"},
    }
    assert handle_permission_request(payload) == {}


def test_handle_permission_request_outside_workspace_prompts(tmp_path):
    ws = _ws(tmp_path)
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Write",
        "cwd": str(ws),
        "session_id": "sess-pr-3",
        "tool_input": {"file_path": str(tmp_path / "outside.txt"), "content": "hi"},
    }
    assert handle_permission_request(payload) == {}


def test_handle_permission_request_blocklist_denies(tmp_path):
    ws = _ws(tmp_path)
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "cwd": str(ws),
        "session_id": "sess-pr-4",
        "tool_input": {"command": "rm -rf /"},
    }
    out = handle_permission_request(payload)
    decision = out["hookSpecificOutput"]["decision"]
    assert decision["behavior"] == "deny"
    assert decision["message"]


def test_handle_permission_request_whitelisted_command_allows(tmp_path):
    ws = _ws(tmp_path)
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "cwd": str(ws),
        "session_id": "sess-pr-5",
        "tool_input": {"command": "git status"},
    }
    out = handle_permission_request(payload)
    assert out["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


def test_handle_permission_request_tier2_command_prompts(tmp_path):
    ws = _ws(tmp_path)
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "cwd": str(ws),
        "session_id": "sess-pr-6",
        "tool_input": {"command": "git add src/a.ts && git commit -m 'x'"},
    }
    # Tier-2 LLM evaluation is intentionally skipped on this event.
    assert handle_permission_request(payload) == {}


def test_handle_permission_request_audit_records_event(tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("JEV_LOG_FILE", str(log_file))
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Edit",
        "cwd": str(ws),
        "session_id": "sess-pr-7",
        "tool_input": {"file_path": str(ws / "a.ts"), "old_string": "a", "new_string": "b"},
    }
    handle_permission_request(payload)
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert any(r.get("event") == "PermissionRequest" and r["decision"] == "allow"
               for r in records)


def test_main_dispatches_permission_request_payload(monkeypatch, capsys, tmp_path):
    import zcode_evaluator

    ws = _ws(tmp_path)
    payload = json.dumps({
        "hook_event_name": "PermissionRequest",
        "tool_name": "Edit",
        "cwd": str(ws),
        "session_id": "sess-pr-8",
        "tool_input": {"file_path": str(ws / "dates.ts"), "old_string": "a", "new_string": "b"},
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py", "--event", "PermissionRequest"])

    assert main() == 0
    data = json.loads(capsys.readouterr().out.strip())
    assert data["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert data["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


def test_main_permission_request_empty_payload_falls_through(monkeypatch, capsys):
    import zcode_evaluator

    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: None)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py", "--event", "PermissionRequest"])

    assert main() == 0
    assert json.loads(capsys.readouterr().out.strip()) == {}


def test_main_permission_request_crash_falls_through(monkeypatch, capsys):
    import zcode_evaluator

    payload = json.dumps({"hook_event_name": "PermissionRequest", "tool_name": "Bash"})
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py", "--event", "PermissionRequest"])
    monkeypatch.setattr(zcode_evaluator, "find_workspace_root",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))

    assert main() == 0
    assert json.loads(capsys.readouterr().out.strip()) == {}
