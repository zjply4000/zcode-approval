# tests/test_crash_fallback.py
"""Fault-injection coverage for the PermissionRequest fallback design.

Contract under test: when the PreToolUse evaluation is unavailable (crash in
this process, or a host-side timeout kill), the call degrades to a prompt
(fail-closed), and the PermissionRequest invocation — a fresh, stateless
process — still delivers the deterministic Tier-1 verdict for that same call:
workspace source edits are rescued to allow, blocklist commands are denied,
everything else keeps prompting. Tier-2 must never run on the
PermissionRequest path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import zcode_evaluator
from zcode_evaluator import handle_permission_request, main


def _ws(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / ".git").mkdir()
    return ws


def _run_pretooluse_crash(monkeypatch, capsys, payload):
    """Simulate a PreToolUse invocation crashing mid-evaluation."""
    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated evaluator crash")

    monkeypatch.setattr(zcode_evaluator, "evaluate_tool_call", boom)
    monkeypatch.setattr(zcode_evaluator, "read_stdin_payload", lambda: json.dumps(payload))
    monkeypatch.setattr(sys, "argv", ["zcode_evaluator.py", "--event", "PreToolUse"])
    assert main() == 0
    return json.loads(capsys.readouterr().out.strip())


def test_pretooluse_crash_fails_closed_and_audits(monkeypatch, capsys, tmp_path):
    ws = _ws(tmp_path)
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(ws),
               "session_id": "crash-1",
               "tool_input": {"file_path": str(ws / "a.ts"),
                              "old_string": "a", "new_string": "b"}}

    out = _run_pretooluse_crash(monkeypatch, capsys, payload)

    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "评估器异常" in out["hookSpecificOutput"]["permissionDecisionReason"]

    # The fault moment itself must be visible in the audit trail.
    last = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["event"] == "PreToolUse"
    assert last["tier"] == "crash_fallback"
    assert last["decision"] == "ask"
    assert "simulated evaluator crash" in last["reason"]


def test_fallback_rescues_workspace_source_edit(monkeypatch, capsys, tmp_path):
    ws = _ws(tmp_path)
    pre_payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(ws),
                   "session_id": "rescue-1",
                   "tool_input": {"file_path": str(ws / "src" / "util.ts"),
                                  "old_string": "a", "new_string": "b"}}
    pr_payload = {**pre_payload, "hook_event_name": "PermissionRequest"}

    pre = _run_pretooluse_crash(monkeypatch, capsys, pre_payload)
    assert pre["hookSpecificOutput"]["permissionDecision"] == "ask"

    monkeypatch.undo()  # act 2 runs in a fresh, unpatched process in production

    out = handle_permission_request(pr_payload)
    assert out["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert out["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


def test_fallback_blocks_blocklist_command(monkeypatch, capsys, tmp_path):
    ws = _ws(tmp_path)
    pre_payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(ws),
                   "session_id": "rescue-2",
                   "tool_input": {"command": "rm -rf jev-pr-deny-test"}}
    pr_payload = {**pre_payload, "hook_event_name": "PermissionRequest"}

    pre = _run_pretooluse_crash(monkeypatch, capsys, pre_payload)
    assert pre["hookSpecificOutput"]["permissionDecision"] == "ask"

    monkeypatch.undo()

    out = handle_permission_request(pr_payload)
    decision = out["hookSpecificOutput"]["decision"]
    assert decision["behavior"] == "deny"
    assert "拦截" in decision["message"]


def test_permission_request_never_runs_tier2(monkeypatch, tmp_path):
    def no_tier2(*_args, **_kwargs):
        raise AssertionError("tier-2 LLM evaluation must not run on PermissionRequest")

    monkeypatch.setattr(zcode_evaluator, "evaluate_command", no_tier2)
    ws = _ws(tmp_path)
    payload = {"hook_event_name": "PermissionRequest", "tool_name": "Bash", "cwd": str(ws),
               "session_id": "rescue-3",
               "tool_input": {"command": "git add -A && git commit -m x"}}

    # A tier-2-classified command must pass through without touching the LLM.
    assert handle_permission_request(payload) == {}


def test_permission_request_decides_in_fresh_process(tmp_path):
    """Production semantics: every hook invocation is a fresh interpreter, so
    the fallback must work with no in-process state from PreToolUse."""
    ws = _ws(tmp_path)
    payload = {"hook_event_name": "PermissionRequest", "tool_name": "Edit", "cwd": str(ws),
               "session_id": "rescue-4",
               "tool_input": {"file_path": str(ws / "dates.ts"),
                              "old_string": "a", "new_string": "b"}}
    env = {**os.environ, "JEV_LOG_FILE": str(tmp_path / "subprocess-audit.log")}

    proc = subprocess.run(
        [sys.executable, zcode_evaluator.__file__, "--event", "PermissionRequest"],
        input=json.dumps(payload), capture_output=True, text=True, timeout=60, env=env)

    assert proc.returncode == 0
    out = json.loads(proc.stdout.strip())
    assert out["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert out["hookSpecificOutput"]["decision"] == {"behavior": "allow"}
