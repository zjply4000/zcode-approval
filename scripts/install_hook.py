#!/usr/bin/env python3
"""ZCode PreToolUse hook installer: safely merges hook configuration into config.json."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = Path.home() / ".zcode" / "cli" / "config.json"
DEFAULT_VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
DEFAULT_SCRIPT = ROOT / "scripts" / "zcode_evaluator.py"
MANAGED_EVENTS = ("PreToolUse", "PermissionRequest")
EVALUATOR_MATCHER = "Bash|Write|Edit|ApplyPatch"


def install(
    config_path: Path | None = None,
    venv_py: Path | None = None,
    script_path: Path | None = None,
) -> Path:
    """Safely and non-destructively merge the ZCode hook configuration into config.json.

    Registers one evaluator rule per managed event (PreToolUse, PermissionRequest).
    Creates an original backup `config.json.orig.bak` (if not already present)
    and a timestamped backup `config.json.<YYYYMMDD_HHMMSS>.bak` before writing.
    Preserves all third-party hooks and settings.
    """
    config_path = Path(config_path) if config_path is not None else DEFAULT_CONFIG
    venv_py = Path(venv_py) if venv_py is not None else DEFAULT_VENV_PY
    script_path = Path(script_path) if script_path is not None else DEFAULT_SCRIPT

    config_path.parent.mkdir(parents=True, exist_ok=True)

    if config_path.exists():
        # Permanent original backup created only if not already present
        orig_bak = config_path.with_name(f"{config_path.name}.orig.bak")
        if not orig_bak.exists():
            shutil.copy2(config_path, orig_bak)

        # Timestamped backup created on each run
        now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_bak = config_path.with_name(f"{config_path.name}.{now_str}.bak")
        shutil.copy2(config_path, ts_bak)

        try:
            raw = config_path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
        except Exception:
            data = {}
    else:
        data = {}

    if not isinstance(data, dict):
        data = {}

    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks

    hooks["enabled"] = True
    hooks.setdefault("timeoutMs", 60000)
    hooks.setdefault("maxOutputBytes", 32768)

    events = hooks.setdefault("events", {})
    if not isinstance(events, dict):
        events = {}
        hooks["events"] = events

    for event in MANAGED_EVENTS:
        upsert_evaluator_rule(
            events, event,
            {
                "type": "process",
                "command": venv_py.as_posix(),
                "args": [script_path.as_posix(), "--event", event],
                "enabled": True,
                "timeoutMs": 10000,
            },
        )

    tmp_cfg = config_path.with_suffix(".tmp")
    tmp_cfg.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp_cfg, config_path)
    return config_path


def upsert_evaluator_rule(events: dict, event: str, target_hook: dict) -> None:
    """Add or refresh this evaluator's rule under one hook event.

    An existing rule is matched by the evaluator script name in any hook
    command or arg, then updated in place so third-party rules keep order.
    """
    rules = events.setdefault(event, [])
    if not isinstance(rules, list):
        events[event] = rules = []

    evaluator_name = Path(target_hook["args"][0]).name
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_hooks = rule.get("hooks", [])
        if not isinstance(rule_hooks, list):
            continue
        for hook in rule_hooks:
            if not isinstance(hook, dict):
                continue
            cmd = str(hook.get("command", ""))
            args = [str(a) for a in hook.get("args", [])]
            if evaluator_name in cmd or any(evaluator_name in a for a in args):
                rule["matcher"] = EVALUATOR_MATCHER
                hook.clear()
                hook.update(target_hook)
                return

    rules.append({
        "matcher": EVALUATOR_MATCHER,
        "hooks": [dict(target_hook)],
    })


def main(
    config_path: Path | None = None,
    venv_py: Path | None = None,
    script_path: Path | None = None,
) -> int:
    """Entry point for the ZCode hook installer (PreToolUse + PermissionRequest)."""
    config_path = Path(config_path) if config_path is not None else DEFAULT_CONFIG
    venv_py = Path(venv_py) if venv_py is not None else DEFAULT_VENV_PY
    script_path = Path(script_path) if script_path is not None else DEFAULT_SCRIPT

    if not venv_py.exists():
        print(f"Error: Python venv interpreter not found at {venv_py}", file=sys.stderr)
        return 1

    proc = subprocess.run([str(venv_py), "-c", "import jev_eval"], capture_output=True, text=True)
    if proc.returncode != 0:
        print(
            f"Error: {venv_py} cannot import jev_eval: {proc.stderr.strip()}",
            file=sys.stderr,
        )
        return 1

    installed_path = install(config_path=config_path, venv_py=venv_py, script_path=script_path)
    print(f"Successfully installed ZCode PreToolUse hook into {installed_path}")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Install ZCode PreToolUse hook.")
    parser.add_argument("--config", type=Path, default=None, help="Path to config.json")
    parser.add_argument("--venv", type=Path, default=None, help="Path to venv python executable")
    parser.add_argument("--script", type=Path, default=None, help="Path to zcode_evaluator.py")
    parsed = parser.parse_args()
    sys.exit(main(config_path=parsed.config, venv_py=parsed.venv, script_path=parsed.script))
