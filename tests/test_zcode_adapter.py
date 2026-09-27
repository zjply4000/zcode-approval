import json
import os
import sys
from pathlib import Path
import pytest

from zcode_evaluator import (
    format_zcode_output,
    main,
    normalize_zcode_tool_call,
)


def test_normalize_bash():
    norm = normalize_zcode_tool_call("Bash", {"command": "git status"}, "C:/demo")
    assert norm["tool_name"] == "run_command"
    assert norm["command"] == "git status"
    assert norm["target"] == ""
    assert norm["cwd"] == "C:/demo"


def test_normalize_write_resolves_relative_path():
    norm = normalize_zcode_tool_call("Write", {"file_path": "src/a.ts"}, "C:/demo")
    assert norm["tool_name"] == "write_to_file"
    assert norm["command"] == ""
    assert Path(norm["target"]).is_absolute()
    assert norm["target"] == str((Path("C:/demo") / "src/a.ts").resolve())


def test_normalize_write_preserves_absolute_path(tmp_path):
    abs_path = str((tmp_path / "out.txt").resolve())
    norm = normalize_zcode_tool_call("Write", {"file_path": abs_path}, "C:/demo")
    assert norm["tool_name"] == "write_to_file"
    assert norm["command"] == ""
    assert norm["target"] == abs_path


def test_normalize_edit():
    norm = normalize_zcode_tool_call("Edit", {"file_path": "foo/bar.py"}, "C:/demo")
    assert norm["tool_name"] == "replace_file_content"
    assert norm["command"] == ""
    assert norm["target"] == str((Path("C:/demo") / "foo/bar.py").resolve())


def test_normalize_apply_patch():
    norm = normalize_zcode_tool_call("ApplyPatch", {"path": "src/patch.diff"}, "C:/demo")
    assert norm["tool_name"] == "replace_file_content"
    assert norm["command"] == ""
    assert norm["target"] == str((Path("C:/demo") / "src/patch.diff").resolve())


def test_normalize_unmapped_tool_safe():
    norm = normalize_zcode_tool_call("UnknownTool", {}, "C:/demo")
    assert norm["tool_name"] == "UnknownTool"
    assert norm["command"] == ""
    assert norm["target"] == ""


def test_normalize_none_input_safe():
    norm = normalize_zcode_tool_call("Bash", None, "C:/demo")
    assert norm["tool_name"] == "run_command"
    assert norm["command"] == ""
    assert norm["target"] == ""


def test_format_zcode_output_maps_force_ask_to_ask():
    out = format_zcode_output("force_ask", "network disallowed")
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "network disallowed"


def test_format_zcode_output_allow_and_deny():
    out_allow = format_zcode_output("allow", "whitelist: read-only command")
    assert out_allow["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out_allow["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert out_allow["hookSpecificOutput"]["permissionDecisionReason"] == "whitelist: read-only command"

    out_deny = format_zcode_output("deny", "blocklist: rm recursive force")
    assert out_deny["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out_deny["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out_deny["hookSpecificOutput"]["permissionDecisionReason"] == "blocklist: rm recursive force"


def test_format_zcode_output_default_reason():
    out = format_zcode_output("allow", "")
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "evaluated by jev"


def test_main_empty_input_fails_closed(monkeypatch, capsys):
    import zcode_evaluator

    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: None)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "timeout" in data["hookSpecificOutput"]["permissionDecisionReason"]


def test_main_malformed_json_fails_closed(monkeypatch, capsys):
    import zcode_evaluator

    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: "{not valid json")
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "malformed" in data["hookSpecificOutput"]["permissionDecisionReason"]


def test_main_ignores_non_pretooluse(monkeypatch, capsys):
    import zcode_evaluator

    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}})
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py", "--event", "PostToolUse"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data == {}


def test_main_bash_git_status_allowed(monkeypatch, capsys, tmp_path):
    import zcode_evaluator

    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("JEV_LOG_FILE", str(log_file))

    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": str(tmp_path),
        "session_id": "test-session-1",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert log_file.exists()


def test_main_bash_rm_rf_denied(monkeypatch, capsys, tmp_path):
    import zcode_evaluator

    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("JEV_LOG_FILE", str(log_file))

    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "test-session-2",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_write_outside_workspace_strategy_c_asks(monkeypatch, capsys, tmp_path):
    import zcode_evaluator

    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("JEV_LOG_FILE", str(log_file))

    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / ".git").mkdir()
    outside_file = tmp_path / "outside" / "test.txt"

    payload = json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": str(outside_file), "content": "hello"},
        "cwd": str(ws),
        "session_id": "test-session-3",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "outside workspace" in data["hookSpecificOutput"]["permissionDecisionReason"]


def test_main_logging_failure_does_not_break_decision(monkeypatch, capsys, tmp_path):
    import zcode_evaluator

    # Force build_audit_logger to fail
    monkeypatch.setattr(zcode_evaluator, "build_audit_logger", lambda _: (_ for _ in ()).throw(PermissionError("Blocked")))

    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": str(tmp_path),
        "session_id": "test-session-4",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_main_write_system_path_strategy_c_denied(monkeypatch, capsys, tmp_path):
    import zcode_evaluator
    ws = tmp_path / "ws"
    ws.mkdir()
    system_target = "C:/Windows/System32/drivers/etc/hosts" if sys.platform == "win32" else "/etc/hosts"
    payload = json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": system_target, "content": "127.0.0.1 evil.local"},
        "cwd": str(ws),
        "session_id": "test-session-5",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "system directory" in data["hookSpecificOutput"]["permissionDecisionReason"]


def test_main_write_zcode_memories_auto_allowed(monkeypatch, capsys, tmp_path):
    import zcode_evaluator
    ws = tmp_path / "ws"
    ws.mkdir()

    # Point memories root to a tmp dir to avoid touching user real home
    memories_dir = tmp_path / "custom_memories"
    memories_file = memories_dir / "projects" / "photos-123" / "memory" / "MEMORY.md"
    memories_file.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(zcode_evaluator, "DEFAULT_MEMORIES_ROOT", memories_dir)

    payload = json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": str(memories_file), "content": "# Project Memories"},
        "cwd": str(ws),
        "session_id": "test-session-mem",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py"])

    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "artifact" in data["hookSpecificOutput"]["permissionDecisionReason"]

    # Also verify non-memory sibling path under ~/.zcode/cli is NOT auto-allowed
    non_memory = tmp_path / "custom_memories" / ".." / "config.json"
    payload2 = json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": str(non_memory.resolve()), "content": "{}"},
        "cwd": str(ws),
        "session_id": "test-session-mem-2",
    })
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: payload2)
    code = main()
    assert code == 0
    captured = capsys.readouterr()
    data2 = json.loads(captured.out.strip())
    assert data2["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "outside workspace" in data2["hookSpecificOutput"]["permissionDecisionReason"]

