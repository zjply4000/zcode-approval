#!/usr/bin/env python3
"""ZCode PreToolUse hook evaluator: prints exactly one strict JSON decision on stdout."""
from __future__ import annotations

import json
import logging
import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
logging.basicConfig(stream=sys.stderr, level=logging.ERROR, force=True)

try:
    from jev_eval.config import load_settings
    from jev_eval.decide import Decision, finalize_tier2
    from jev_eval.deterministic import evaluate_tool_call
    from jev_eval.formatter import format_fallback_reason
    from jev_eval.jev_client import evaluate_command
    from jev_eval.logging_setup import audit, build_audit_logger
    from jev_eval.reader import read_stdin_payload
except ImportError:
    _env_src = os.environ.get("JEV_EVAL_SRC")
    if _env_src and Path(_env_src).exists() and _env_src not in sys.path:
        sys.path.insert(0, _env_src)
    else:
        _alt_src = Path(__file__).resolve().parents[2] / "antigravity-approval" / "src"
        if _alt_src.exists() and str(_alt_src) not in sys.path:
            sys.path.insert(0, str(_alt_src))
    from jev_eval.config import load_settings
    from jev_eval.decide import Decision, finalize_tier2
    from jev_eval.deterministic import evaluate_tool_call
    from jev_eval.formatter import format_fallback_reason
    from jev_eval.jev_client import evaluate_command
    from jev_eval.logging_setup import audit, build_audit_logger
    from jev_eval.reader import read_stdin_payload

_TOOL_MAP = {
    "Bash": "run_command",
    "Write": "write_to_file",
    "Edit": "replace_file_content",
    "ApplyPatch": "replace_file_content",
}

DEFAULT_MEMORIES_ROOT = Path(os.environ.get("ZCODE_MEMORIES_DIR") or (Path.home() / ".zcode" / "cli" / "memories"))


def find_workspace_root(cwd: str | None = None) -> str:
    """Find the workspace root directory by searching upwards for .git or .zcode markers.

    Guards against swallowing user home if dotfiles repo exists at home boundary.
    """
    cur = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    home = Path.home().resolve()
    for parent in [cur, *cur.parents]:
        if parent == home and cur != home:
            break
        if (parent / ".git").exists() or (parent / ".zcode").exists():
            return str(parent)
    return str(cur)


def normalize_zcode_tool_call(tool_name: str, tool_input: dict | None, cwd: str) -> dict:
    """Normalize ZCode tool names and inputs to standard jev_eval format."""
    canonical = _TOOL_MAP.get(tool_name, tool_name)
    tool_input = tool_input or {}
    command = ""
    target = ""
    if canonical == "run_command":
        command = tool_input.get("command") or ""
    elif canonical in ("write_to_file", "replace_file_content"):
        target = tool_input.get("file_path") or tool_input.get("path") or ""
        if target:
            if target.startswith("~"):
                target = str(Path(target).expanduser())
            elif not Path(target).is_absolute():
                base_cwd = Path(cwd).resolve() if cwd else Path.cwd().resolve()
                target = str((base_cwd / target).resolve())
    return {"tool_name": canonical, "command": command, "cwd": cwd, "target": target}


def format_zcode_output(decision: str, reason: str) -> dict:
    """Format decision and reason into ZCode hook JSON schema."""
    zcode_decision = "ask" if decision in ("ask", "force_ask") else decision
    if zcode_decision not in ("allow", "deny"):
        zcode_decision = "ask"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": zcode_decision,
            "permissionDecisionReason": reason or "evaluated by jev",
        }
    }


def format_permission_request_output(behavior: str, message: str) -> dict:
    """PermissionRequest envelope: decision.behavior allow/deny, or {} (no
    decision) to fall through to the host prompt. The allow branch of the
    host schema carries no message field, so only deny carries one."""
    if behavior not in ("allow", "deny"):
        return {}
    decision: dict = {"behavior": behavior}
    if behavior == "deny" and message:
        decision["message"] = message
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": decision,
        }
    }


def extract_hook_context(payload: dict) -> tuple[str, dict, str, str]:
    """Pull tool_name/tool_input/cwd/session_id from either naming convention."""
    tool_name = payload.get("tool_name") or payload.get("toolName") or ""
    tool_input = payload.get("tool_input") if "tool_input" in payload else payload.get("toolInput") or {}
    cwd = payload.get("cwd") or os.getcwd()
    session_id = payload.get("session_id") or payload.get("sessionId") or ""
    return tool_name, tool_input, cwd, session_id


def _audit_crash(event: str, payload: object, exc: Exception) -> None:
    """Best-effort audit line for a crashed evaluation so fault moments leave a
    trace; logging failures are swallowed (must never break the fallback)."""
    try:
        settings = load_settings(host="zcode", workspace_dir=os.getcwd())
        logger = build_audit_logger(settings.log_file)
        record = payload if isinstance(payload, dict) else {}
        audit(logger, event=event,
              conversationId=str(record.get("session_id") or record.get("sessionId") or ""),
              tool=str(record.get("tool_name") or record.get("toolName") or ""),
              input="", tier="crash_fallback",
              decision="ask" if event == "PreToolUse" else "pass",
              reason=str(exc)[:200], category=None, confidence=None,
              latency_ms=None, fail_mode=settings.fail_mode)
    except Exception:
        pass


def handle_permission_request(payload: dict) -> dict:
    """Deterministic Tier-1 evaluation for the PermissionRequest event.

    The host fires this hook only when a tool call is about to prompt the
    user. Subagent tool calls never reach PreToolUse, so this is their only
    jev evaluation; main-session calls land here only after PreToolUse
    returned ask (or ran no evaluation). Tier-2 LLM evaluation is therefore
    deliberately skipped: replaying it could flip a main-session PreToolUse
    ask into an allow on a second, differently-scored verdict. Allow/deny
    come from Tier 1 alone; everything else returns no decision and the
    host prompt proceeds.
    """
    try:
        tool_name, tool_input, cwd, session_id = extract_hook_context(payload)

        ws_root = find_workspace_root(cwd)
        norm = normalize_zcode_tool_call(tool_name, tool_input, cwd)

        settings = load_settings(host="zcode", workspace_dir=ws_root)
        try:
            logger = build_audit_logger(settings.log_file)
        except Exception:
            logger = None

        extra_roots = [str(DEFAULT_MEMORIES_ROOT)]

        t1 = evaluate_tool_call(norm["tool_name"], norm["command"], norm["cwd"],
                                norm["target"], [ws_root], settings.allow_network_commands,
                                extra_write_roots=extra_roots,
                                path_policy=settings.path_policy)

        behavior = ""
        if t1 is not None and t1.decision in ("allow", "deny"):
            behavior = t1.decision

        if logger is not None:
            audit(logger, event="PermissionRequest", conversationId=session_id,
                  tool=tool_name, input=(norm["command"] or norm["target"])[:200],
                  tier=t1.tier if t1 is not None else "skipped_tier2",
                  decision=behavior or "pass",
                  reason=t1.reason if t1 is not None else "tier-2 not evaluated on PermissionRequest",
                  category=None, confidence=None, latency_ms=None,
                  fail_mode=settings.fail_mode)

        return format_permission_request_output(behavior, t1.reason if t1 is not None else "")
    except Exception as exc:
        _audit_crash("PermissionRequest", payload, exc)
        return {}  # crash fallback: no decision, host prompt proceeds


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def main() -> int:
    event = "PreToolUse"
    if "--event" in sys.argv:
        idx = sys.argv.index("--event")
        if idx + 1 < len(sys.argv):
            event = sys.argv[idx + 1]

    raw = read_stdin_payload()
    if raw is None:
        # A PermissionRequest hook that emits nothing falls through to the
        # host prompt; only PreToolUse has an ask-shaped fail-closed output.
        _emit({} if event == "PermissionRequest"
               else format_zcode_output("ask", format_fallback_reason("payload read timeout / empty input")))
        return 0

    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        _emit(format_zcode_output("ask", format_fallback_reason(f"malformed hook payload: {exc}")))
        return 0

    if "hook_event_name" in payload:
        event = payload["hook_event_name"]
    elif "hookEventName" in payload:
        event = payload["hookEventName"]

    if event == "PermissionRequest":
        _emit(handle_permission_request(payload))
        return 0

    if event != "PreToolUse":
        _emit({})
        return 0

    try:
        tool_name, tool_input, cwd, session_id = extract_hook_context(payload)

        ws_root = find_workspace_root(cwd)
        norm = normalize_zcode_tool_call(tool_name, tool_input, cwd)

        settings = load_settings(host="zcode", workspace_dir=ws_root)
        try:
            logger = build_audit_logger(settings.log_file)
        except Exception:
            logger = None

        extra_roots = [str(DEFAULT_MEMORIES_ROOT)]

        t1 = evaluate_tool_call(norm["tool_name"], norm["command"], norm["cwd"],
                                norm["target"], [ws_root], settings.allow_network_commands,
                                extra_write_roots=extra_roots,
                                path_policy=settings.path_policy)
        if t1 is not None:
            decision = Decision(t1.decision, t1.reason, t1.tier)
        elif norm["tool_name"] == "run_command":
            verdict, cause = evaluate_command(norm["command"], norm["cwd"], [ws_root], settings)
            decision = finalize_tier2(settings, verdict, cause)
        else:
            decision = Decision("ask", f"unhandled tool {tool_name!r}", "fallback")

        if logger is not None:
            audit(logger, event=event, conversationId=session_id, tool=tool_name,
                  input=(norm["command"] or norm["target"])[:200], tier=decision.tier,
                  decision=decision.decision, reason=decision.reason,
                  category=decision.category, confidence=decision.confidence,
                  latency_ms=decision.latency_ms, fail_mode=settings.fail_mode)
        _emit(format_zcode_output(decision.decision, decision.reason))
    except Exception as exc:
        _audit_crash(event, payload, exc)
        _emit(format_zcode_output("ask", format_fallback_reason(f"evaluator crash: {exc}")))

    return 0


if __name__ == "__main__":
    _code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
