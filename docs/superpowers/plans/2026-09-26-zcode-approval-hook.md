# ZCode Approval Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a robust, fail-closed `PreToolUse` permission evaluation hook for ZCode located in `D:\Projects\Jev\zcode-approval`, reusing the `jev_eval` core engine from `antigravity-approval`, implementing Strategy C security-ordered path protection, and providing an installer for `~/.zcode/cli/config.json`.

**Architecture:** Under Scheme 2 (Shared Core Package), `antigravity-approval/src/jev_eval` serves as the single source of truth for deterministic rules, stdin pump, and Jev System One evaluation. `zcode-approval` links to `jev_eval` via editable package installation, hosting `scripts/zcode_evaluator.py` (which normalizes ZCode tools, discovers project roots with home boundary protection, maps `force_ask` $\to$ `ask`, and flushes buffers before `os._exit(0)`) and `scripts/install_hook.py` (which safely merges into `~/.zcode/cli/config.json`).

**Tech Stack:** Python 3.10+, `typesafe-sdk`, `pytest`, standard library (`shlex`, `threading`, `json`, `pathlib`, `os`).

## Global Constraints

- **Strict Non-Regression**: All 81 existing tests in `antigravity-approval` must continue to pass 100% without modification.
- **Security Check Order**: System directories (`C:\Windows`, `Program Files`, `/etc`, etc.) and credentials (`~/.ssh`, `~/.gnupg`) must be evaluated *before* workspace boundaries in path checks, guaranteeing hard `deny`.
- **ZCode Schema Conformity**: Output `permissionDecision` must strictly be `"allow" | "ask" | "deny"`. `force_ask` must always map to `ask`.
- **Matcher Alignment**: Matcher must be `"Bash|Write|Edit|ApplyPatch"`.
- **Zero Automatic Git Commits**: In compliance with user rule `不要自动提交修改。`, do not execute `git commit`.

---

### Task 1: Shared Core Extraction — Stdin Reader & Multi-Host Config

**Files:**
- Create: `D:\Projects\Jev\antigravity-approval\src\jev_eval\reader.py`
- Modify: `D:\Projects\Jev\antigravity-approval\scripts\jev_evaluator.py:57-113`
- Modify: `D:\Projects\Jev\antigravity-approval\src\jev_eval\config.py:20-79`
- Modify: `D:\Projects\Jev\antigravity-approval\src\jev_eval\logging_setup.py:10-30`
- Create: `D:\Projects\Jev\antigravity-approval\tests\test_reader.py`
- Create: `D:\Projects\Jev\antigravity-approval\tests\test_config_multihost.py`

**Interfaces:**
- Produces: `read_stdin_payload(deadline_s: float | None = None, stream=None) -> str | None` in `jev_eval.reader` (supports `JEV_STDIN_TIMEOUT_MS` and immediate EOF short-circuit).
- Produces: `load_settings(host: str = "antigravity", ...)` in `jev_eval.config` (isolates `.agents` vs `.zcode` env files, falls back to `~/.gemini/config/jev.env` for API key).

- [ ] **Step 1: Write unit tests for `reader.py` and multi-host `config.py`**

Create `D:\Projects\Jev\antigravity-approval\tests\test_reader.py`:
```python
import io
import json
import pytest
from jev_eval.reader import read_stdin_payload

def test_reader_parses_valid_json_on_eof():
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
    stream = io.BytesIO((json.dumps(payload) + "\n").encode("utf-8"))
    res = read_stdin_payload(deadline_s=0.5, stream=stream)
    assert res is not None
    assert json.loads(res) == payload

def test_reader_empty_input_returns_none():
    stream = io.BytesIO(b"")
    res = read_stdin_payload(deadline_s=0.1, stream=stream)
    assert res is None
```

Create `D:\Projects\Jev\antigravity-approval\tests\test_config_multihost.py`:
```python
from pathlib import Path
from jev_eval.config import load_settings

def test_antigravity_host_ignores_zcode_env(tmp_path):
    zcode_env = tmp_path / ".zcode" / "jev.env"
    zcode_env.parent.mkdir(parents=True)
    zcode_env.write_text("ALLOW_NETWORK_COMMANDS=true\n", encoding="utf-8")
    
    settings = load_settings(host="antigravity", workspace_dir=tmp_path)
    assert settings.allow_network_commands is False

def test_zcode_host_reads_zcode_env(tmp_path):
    zcode_env = tmp_path / ".zcode" / "jev.env"
    zcode_env.parent.mkdir(parents=True)
    zcode_env.write_text("ALLOW_NETWORK_COMMANDS=true\n", encoding="utf-8")
    
    settings = load_settings(host="zcode", workspace_dir=tmp_path)
    assert settings.allow_network_commands is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```powershell
& "D:\Projects\Jev\antigravity-approval\.venv\Scripts\pytest.exe" tests/test_reader.py tests/test_config_multihost.py -v
```
Expected: FAIL (ModuleNotFoundError: no module named `jev_eval.reader`).

- [ ] **Step 3: Implement `reader.py` with EOF short-circuit**

Create `D:\Projects\Jev\antigravity-approval\src\jev_eval\reader.py`:
```python
# src/jev_eval/reader.py
"""Shared non-blocking stdin reader with deadline pump and EOF short-circuit."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import BinaryIO

def read_stdin_payload(deadline_s: float | None = None,
                       stream: BinaryIO | None = None) -> str | None:
    if deadline_s is None:
        try:
            deadline_s = int(os.environ.get("JEV_STDIN_TIMEOUT_MS", "1000")) / 1000.0
        except ValueError:
            deadline_s = 1.0

    in_stream = stream if stream is not None else sys.stdin.buffer
    buffer = bytearray()
    lock = threading.Lock()
    data_event = threading.Event()
    state = {"eof": False}

    def _pump() -> None:
        try:
            while True:
                # read1() if available, else read() for custom stream
                reader = getattr(in_stream, "read1", in_stream.read)
                chunk = reader(65536)
                if not chunk:
                    break
                with lock:
                    buffer.extend(chunk)
                data_event.set()
        except Exception:
            pass
        finally:
            with lock:
                state["eof"] = True
            data_event.set()

    threading.Thread(target=_pump, daemon=True).start()
    deadline = time.monotonic() + deadline_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        data_event.wait(remaining)
        data_event.clear()
        with lock:
            snapshot = bytes(buffer)
            eof = state["eof"]
        if snapshot:
            try:
                json.loads(snapshot.decode("utf-8"))
                return snapshot.decode("utf-8")
            except ValueError:
                pass
        if eof:
            # EOF reached: return parsed or decoded
            return snapshot.decode("utf-8", errors="replace") if snapshot else None
```

- [ ] **Step 4: Update `jev_evaluator.py`, `config.py`, and `logging_setup.py`**

In `antigravity-approval\scripts\jev_evaluator.py`:
Replace inline `_read_stdin_payload` with import:
```python
from jev_eval.reader import read_stdin_payload
```
Call `read_stdin_payload()` directly in `main()`.

In `antigravity-approval\src\jev_eval\config.py`:
Update `load_settings` signature and file resolution:
```python
def load_settings(env: Mapping[str, str] | None = None,
                  workspace_dir: Path | str | None = None,
                  user_file: Path | None = None,
                  host: str = "antigravity") -> Settings:
    env = dict(os.environ if env is None else env)
    merged = dict(_DEFAULTS)
    
    ws_path = Path(workspace_dir) if workspace_dir is not None else None
    
    if host == "zcode":
        # ZCode isolated search
        z_user = user_file or (Path.home() / ".zcode" / "jev.env")
        merged.update(_parse_env_file(z_user))
        if ws_path:
            merged.update(_parse_env_file(ws_path / ".zcode" / "jev.env"))
        # Fallback for TYPESAFE_API_KEY only
        if not merged.get("TYPESAFE_API_KEY"):
            gemini_user = _parse_env_file(Path.home() / ".gemini" / "config" / "jev.env")
            if gemini_user.get("TYPESAFE_API_KEY"):
                merged["TYPESAFE_API_KEY"] = gemini_user["TYPESAFE_API_KEY"]
        if "JEV_LOG_FILE" not in env and "JEV_LOG_FILE" not in merged:
            merged["JEV_LOG_FILE"] = str(Path.home() / ".zcode" / "cli" / "log" / "jev_evaluator.log")
    else:
        # Antigravity isolated search (100% strict)
        merged.update(_parse_env_file(user_file or Path.home() / ".gemini" / "config" / "jev.env"))
        if ws_path:
            merged.update(_parse_env_file(ws_path / ".agents" / "jev.env"))

    for key in merged:
        if env.get(key):
            merged[key] = env[key]
            
    try:
        threshold = float(merged["CONFIDENCE_THRESHOLD"])
    except ValueError:
        threshold = 0.96
    if not 0.0 <= threshold <= 1.0:
        threshold = 0.96
    try:
        timeout_ms = max(100, int(merged["EVAL_TIMEOUT_MS"]))
    except ValueError:
        timeout_ms = 1500
    fail_mode = merged["JEV_FAIL_MODE"].strip().lower()
    if fail_mode not in ("closed", "open"):
        fail_mode = "closed"
    api_key = env.get("TYPESAFE_API_KEY") or merged.get("TYPESAFE_API_KEY") or None
    return Settings(
        api_key=api_key,
        base_url=merged["TYPESAFE_BASE_URL"],
        confidence_threshold=threshold,
        eval_timeout_ms=timeout_ms,
        allow_network_commands=merged["ALLOW_NETWORK_COMMANDS"].strip().lower() in _TRUE,
        fail_mode=fail_mode,
        log_file=Path(merged["JEV_LOG_FILE"]).expanduser(),
    )
```

In `antigravity-approval\src\jev_eval\logging_setup.py`:
In `build_audit_logger(log_file: Path)`:
```python
def build_audit_logger(log_file: Path) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    ...
```

- [ ] **Step 5: Run tests to verify they pass**

Run:
```powershell
& "D:\Projects\Jev\antigravity-approval\.venv\Scripts\pytest.exe" -v
```
Expected: PASS (All 81 original tests + 2 new test modules pass).

---

### Task 2: Shared Core Enhancement — Strategy C Parameterized Path Guard & Arg Fallbacks

**Files:**
- Modify: `D:\Projects\Jev\antigravity-approval\src\jev_eval\deterministic.py:180-295`
- Modify: `D:\Projects\Jev\antigravity-approval\src\jev_eval\decide.py:20-76`
- Create: `D:\Projects\Jev\antigravity-approval\tests\test_strategy_c.py`

**Interfaces:**
- Produces: `check_file_target(target, cwd, workspace_paths, extra_roots=None, path_policy="strict_deny") -> tuple[str, str] | None`
- Produces: `evaluate_tool_call(..., path_policy="strict_deny") -> Tier1Outcome | None`
- Produces: `extract_args(tool_name, args)` recognizing `"path"` and `"target"` as file target candidates.

- [ ] **Step 1: Write unit tests for Strategy C and arg fallbacks**

Create `D:\Projects\Jev\antigravity-approval\tests\test_strategy_c.py`:
```python
import os
import sys
from pathlib import Path
from jev_eval.deterministic import evaluate_tool_call
from jev_eval.decide import extract_args

def test_strategy_c_hard_denies_system_dirs_even_outside_workspace(tmp_path):
    ws = str(tmp_path)
    system_target = "C:/Windows/System32/drivers/etc/hosts" if sys.platform == "win32" else "/etc/hosts"
    out = evaluate_tool_call("write_to_file", "", ws, system_target, [ws],
                             allow_network=False, path_policy="strategy_c")
    assert out is not None
    assert out.decision == "deny"
    assert "system directory or sensitive credential" in out.reason

def test_strategy_c_asks_on_regular_outside_workspace(tmp_path):
    ws = str(tmp_path / "ws")
    outside = str(tmp_path / "desktop" / "file.txt")
    out = evaluate_tool_call("write_to_file", "", ws, outside, [ws],
                             allow_network=False, path_policy="strategy_c")
    assert out is not None
    assert out.decision == "ask"
    assert "outside workspace" in out.reason

def test_strict_deny_remains_default(tmp_path):
    ws = str(tmp_path / "ws")
    outside = str(tmp_path / "desktop" / "file.txt")
    out = evaluate_tool_call("write_to_file", "", ws, outside, [ws],
                             allow_network=False)
    assert out is not None
    assert out.decision == "deny"

def test_extract_args_supports_path_and_target_fallbacks():
    ex = extract_args("write_to_file", {"path": "src/patch.py"})
    assert ex["target"] == "src/patch.py"
    ex2 = extract_args("write_to_file", {"target": "src/main.py"})
    assert ex2["target"] == "src/main.py"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```powershell
& "D:\Projects\Jev\antigravity-approval\.venv\Scripts\pytest.exe" tests/test_strategy_c.py -v
```
Expected: FAIL.

- [ ] **Step 3: Implement Security-Ordered Strategy C in `deterministic.py` and `decide.py`**

In `antigravity-approval\src\jev_eval\deterministic.py`:
Add credential directory resolver:
```python
def _credential_dirs() -> list[str]:
    dirs = [os.path.expanduser("~/.ssh"), os.path.expanduser("~/.gnupg")]
    return [_norm(d) for d in dirs]
```

Refactor `check_file_target`:
```python
def check_file_target(target: str, cwd: str, workspace_paths: list[str],
                      extra_roots: list[str] | None = None,
                      path_policy: str = "strict_deny") -> tuple[str, str] | None:
    """Evaluate target path against system dirs and workspace boundaries.
    Returns (decision, reason) on boundary restriction, or None if target is inside workspace.
    """
    if not target:
        return ("deny", "file tool missing target path")
    p = _expand_target(target, cwd)
    lex = _norm(p)
    real = _norm(os.path.realpath(p))

    # STEP 1: Always check system & credential directories FIRST -> hard DENY
    for d in _system_dirs() + _credential_dirs():
        if _inside(lex, [d]) or _inside(real, [d]):
            return ("deny", "target path in system directory or sensitive credential")

    # STEP 2: Workspace containment check
    roots = [_norm(w) for w in (workspace_paths or [])]
    roots += [_norm(r) for r in (extra_roots or []) if r]
    lex_in, real_in = _inside(lex, roots), _inside(real, roots)

    if not (lex_in and real_in):
        if lex_in != real_in:
            reason = f"junction/symlink target outside workspace (lex inside={lex_in}, realpath inside={real_in})"
        else:
            reason = "target path outside workspace"
        
        if path_policy == "strategy_c":
            return ("ask", reason)
        return ("deny", reason)

    return None
```

Update `evaluate_tool_call` to accept `path_policy: str = "strict_deny"`:
```python
def evaluate_tool_call(tool_name: str, command: str, cwd: str, target: str,
                       workspace_paths: list[str], allow_network: bool,
                       extra_write_roots: list[str] | None = None,
                       path_policy: str = "strict_deny") -> Tier1Outcome | None:
    if tool_name in _FILE_TOOLS:
        hit = check_file_target(target, cwd, workspace_paths, extra_roots=extra_write_roots,
                                path_policy=path_policy)
        if hit is not None:
            dec, reason = hit
            return Tier1Outcome(dec, reason, "path_guard")
        if _is_sanctioned_artifact(target, cwd, extra_write_roots):
            return Tier1Outcome("allow", "artifact: host-sanctioned conversation artifact", "artifact")
        return Tier1Outcome("ask", "file mutations are not auto-approved in v1", "write_policy")
    ...
```

In `antigravity-approval\src\jev_eval\decide.py`:
Update `extract_args`:
```python
    if tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        return {"command": "", "cwd": pick("Cwd", "cwd"),
                "target": pick("TargetFile", "AbsolutePath", "target_file", "file_path", "filePath", "path", "target")}
```
And propagate `path_policy` in `decide(...)`.

- [ ] **Step 4: Run tests to verify all tests pass**

Run:
```powershell
& "D:\Projects\Jev\antigravity-approval\.venv\Scripts\pytest.exe" -v
```
Expected: PASS (All original 81 tests + multi-host + Strategy C tests pass).

---

### Task 3: ZCode Project Scaffolding & Virtual Environment Setup

**Files:**
- Create: `D:\Projects\Jev\zcode-approval\pyproject.toml`
- Create: `D:\Projects\Jev\zcode-approval\.gitignore`
- Create: `D:\Projects\Jev\zcode-approval\tests\conftest.py`

- [ ] **Step 1: Create `pyproject.toml` and `.gitignore`**

Create `D:\Projects\Jev\zcode-approval\pyproject.toml`:
```toml
[project]
name = "zcode-approval"
version = "0.1.0"
description = "ZCode PreToolUse hook: deterministic & Jev-based automated approval"
requires-python = ">=3.10"
dependencies = [
    "jev-evaluator",
]

[project.optional-dependencies]
dev = ["pytest>=8"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.pytest.ini_options]
testpaths = ["tests"]
```

Create `D:\Projects\Jev\zcode-approval\.gitignore`:
```gitignore
.venv/
__pycache__/
*.pyc
.pytest_cache/
*.bak
*.log
```

- [ ] **Step 2: Create virtual environment and install editable dependencies**

Run:
```powershell
python -m venv D:\Projects\Jev\zcode-approval\.venv
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\python.exe" -m pip install -e "D:\Projects\Jev\antigravity-approval"
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\python.exe" -m pip install pytest
```

- [ ] **Step 3: Create `tests/conftest.py` and verify import**

Create `D:\Projects\Jev\zcode-approval\tests\conftest.py`:
```python
import sys
from pathlib import Path

# Ensure scripts directory is importable in tests
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
```

Verify in PowerShell:
```powershell
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\python.exe" -c "import jev_eval; print('jev_eval imported successfully')"
```
Expected: `jev_eval imported successfully`.

---

### Task 4: ZCode Adapter Implementation (`scripts/zcode_evaluator.py`)

**Files:**
- Create: `D:\Projects\Jev\zcode-approval\scripts\zcode_evaluator.py`
- Create: `D:\Projects\Jev\zcode-approval\tests\test_zcode_adapter.py`
- Create: `D:\Projects\Jev\zcode-approval\tests\test_workspace_root.py`

**Interfaces:**
- Produces: `find_workspace_root(cwd: str) -> str`
- Produces: `normalize_zcode_tool_call(tool_name: str, tool_input: dict | None, cwd: str) -> dict`
- Produces: `main() -> int` (CLI executable for ZCode PreToolUse hook)

- [ ] **Step 1: Write unit tests for ZCode adapter and workspace root discovery**

Create `D:\Projects\Jev\zcode-approval\tests\test_workspace_root.py`:
```python
from pathlib import Path
from zcode_evaluator import find_workspace_root

def test_find_workspace_root_finds_git(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    (ws / ".git").mkdir()
    sub = ws / "sub" / "dir"
    sub.mkdir(parents=True)
    assert find_workspace_root(str(sub)) == str(ws)

def test_find_workspace_root_stops_at_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".git").mkdir()  # dotfiles repo at ~
    proj = home / "work" / "proj"
    proj.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    
    # Should NOT swallow home
    assert find_workspace_root(str(proj)) == str(proj)
```

Create `D:\Projects\Jev\zcode-approval\tests\test_zcode_adapter.py`:
```python
from pathlib import Path
from zcode_evaluator import normalize_zcode_tool_call, format_zcode_output

def test_normalize_bash():
    norm = normalize_zcode_tool_call("Bash", {"command": "git status"}, "C:/demo")
    assert norm["tool_name"] == "run_command"
    assert norm["command"] == "git status"
    assert norm["target"] == ""

def test_normalize_write_resolves_relative_path():
    norm = normalize_zcode_tool_call("Write", {"file_path": "src/a.ts"}, "C:/demo")
    assert norm["tool_name"] == "write_to_file"
    assert norm["command"] == ""
    assert Path(norm["target"]).is_absolute()
    assert norm["target"] == str((Path("C:/demo") / "src/a.ts").resolve())

def test_normalize_apply_patch():
    norm = normalize_zcode_tool_call("ApplyPatch", {"path": "src/patch.diff"}, "C:/demo")
    assert norm["tool_name"] == "replace_file_content"
    assert norm["target"] == str((Path("C:/demo") / "src/patch.diff").resolve())

def test_normalize_unmapped_tool_safe():
    norm = normalize_zcode_tool_call("UnknownTool", {}, "C:/demo")
    assert norm["tool_name"] == "UnknownTool"
    assert norm["command"] == ""
    assert norm["target"] == ""

def test_format_zcode_output_maps_force_ask_to_ask():
    out = format_zcode_output("force_ask", "network disallowed")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "network disallowed"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```powershell
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\pytest.exe" tests/test_workspace_root.py tests/test_zcode_adapter.py -v
```
Expected: FAIL (ModuleNotFoundError: no module named `zcode_evaluator`).

- [ ] **Step 3: Implement `scripts/zcode_evaluator.py`**

Create `D:\Projects\Jev\zcode-approval\scripts\zcode_evaluator.py`:
```python
#!/usr/bin/env python3
"""ZCode PreToolUse hook evaluator: prints exactly one strict JSON decision on stdout."""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from jev_eval.config import load_settings
from jev_eval.decide import Decision, finalize_tier2
from jev_eval.deterministic import evaluate_tool_call
from jev_eval.jev_client import evaluate_command
from jev_eval.logging_setup import audit, build_audit_logger
from jev_eval.reader import read_stdin_payload

_TOOL_MAP = {
    "Bash": "run_command",
    "Write": "write_to_file",
    "Edit": "replace_file_content",
    "ApplyPatch": "replace_file_content",
}

def find_workspace_root(cwd: str) -> str:
    cur = Path(cwd).resolve() if cwd else Path.cwd()
    home = Path.home().resolve()
    for parent in [cur, *cur.parents]:
        if parent == home and cur != home:
            break
        if (parent / ".git").exists() or (parent / ".zcode").exists():
            return str(parent)
    return str(cur)

def normalize_zcode_tool_call(tool_name: str, tool_input: dict | None, cwd: str) -> dict:
    canonical = _TOOL_MAP.get(tool_name, tool_name)
    tool_input = tool_input or {}
    command = ""
    target = ""
    if canonical == "run_command":
        command = tool_input.get("command", "")
    elif canonical in ("write_to_file", "replace_file_content"):
        target = tool_input.get("file_path") or tool_input.get("path") or ""
        if target and not Path(target).is_absolute():
            target = str((Path(cwd) / target).resolve())
    return {"tool_name": canonical, "command": command, "cwd": cwd, "target": target}

def format_zcode_output(decision: str, reason: str) -> dict:
    zcode_decision = "ask" if decision in ("ask", "force_ask") else decision
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": zcode_decision,
            "permissionDecisionReason": reason or "evaluated by jev",
        }
    }

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
        _emit(format_zcode_output("ask", "payload read timeout / empty input"))
        return 0

    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        _emit(format_zcode_output("ask", f"malformed hook payload: {exc}"))
        return 0

    if event != "PreToolUse":
        _emit({})
        return 0

    try:
        tool_name = payload.get("tool_name") or ""
        tool_input = payload.get("tool_input") or {}
        cwd = payload.get("cwd") or os.getcwd()
        session_id = payload.get("session_id") or ""

        ws_root = find_workspace_root(cwd)
        norm = normalize_zcode_tool_call(tool_name, tool_input, cwd)

        settings = load_settings(host="zcode", workspace_dir=ws_root)
        logger = build_audit_logger(settings.log_file)

        t1 = evaluate_tool_call(norm["tool_name"], norm["command"], norm["cwd"],
                                norm["target"], [ws_root], settings.allow_network_commands,
                                path_policy="strategy_c")
        if t1 is not None:
            decision = Decision(t1.decision, t1.reason, t1.tier)
        elif norm["tool_name"] == "run_command":
            verdict, cause = evaluate_command(norm["command"], norm["cwd"], [ws_root], settings)
            decision = finalize_tier2(settings, verdict, cause)
        else:
            decision = Decision("ask", f"unhandled tool {tool_name!r}", "fallback")

        audit(logger, conversationId=session_id, tool=tool_name,
              input=(norm["command"] or norm["target"])[:200], tier=decision.tier,
              decision=decision.decision, reason=decision.reason,
              category=decision.category, confidence=decision.confidence,
              latency_ms=decision.latency_ms, fail_mode=settings.fail_mode)

        _emit(format_zcode_output(decision.decision, decision.reason))
    except Exception as exc:
        _emit(format_zcode_output("ask", f"evaluator crash: {exc}"))

    return 0

if __name__ == "__main__":
    _code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```powershell
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\pytest.exe" tests/test_workspace_root.py tests/test_zcode_adapter.py -v
```
Expected: PASS.

---

### Task 5: Hook Installer Implementation (`scripts/install_hook.py`)

**Files:**
- Create: `D:\Projects\Jev\zcode-approval\scripts\install_hook.py`
- Create: `D:\Projects\Jev\zcode-approval\tests\test_install_hook.py`

**Interfaces:**
- Produces: `install(config_path: Path | None = None, venv_py: Path | None = None, script_path: Path | None = None) -> Path`
- Produces: `main() -> int` (CLI installer script)

- [ ] **Step 1: Write unit tests for hermetic config installation**

Create `D:\Projects\Jev\zcode-approval\tests\test_install_hook.py`:
```python
import json
from pathlib import Path
from install_hook import install

def test_install_fresh_config(tmp_path):
    target = tmp_path / "config.json"
    venv_py = tmp_path / "python.exe"
    script = tmp_path / "zcode_evaluator.py"
    
    install(config_path=target, venv_py=venv_py, script_path=script)
    assert target.exists()
    
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["hooks"]["enabled"] is True
    rules = data["hooks"]["events"]["PreToolUse"]
    assert len(rules) == 1
    assert rules[0]["matcher"] == "Bash|Write|Edit|ApplyPatch"
    assert rules[0]["hooks"][0]["type"] == "process"

def test_install_preserves_third_party_hooks_and_backs_up(tmp_path):
    target = tmp_path / "config.json"
    initial_data = {
        "hooks": {
          "enabled": True,
          "events": {
            "PreToolUse": [
              {"matcher": "CustomTool", "hooks": [{"command": "linter.exe"}]}
            ]
          }
        }
    }
    target.write_text(json.dumps(initial_data), encoding="utf-8")
    venv_py = tmp_path / "python.exe"
    script = tmp_path / "zcode_evaluator.py"
    
    install(config_path=target, venv_py=venv_py, script_path=script)
    
    # Verify backup exists
    assert (tmp_path / "config.json.orig.bak").exists()
    
    # Verify both hooks present
    data = json.loads(target.read_text(encoding="utf-8"))
    rules = data["hooks"]["events"]["PreToolUse"]
    assert len(rules) == 2
    assert any(r.get("matcher") == "CustomTool" for r in rules)
    assert any(r.get("matcher") == "Bash|Write|Edit|ApplyPatch" for r in rules)
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```powershell
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\pytest.exe" tests/test_install_hook.py -v
```
Expected: FAIL (ModuleNotFoundError: no module named `install_hook`).

- [ ] **Step 3: Implement `scripts/install_hook.py`**

Create `D:\Projects\Jev\zcode-approval\scripts\install_hook.py`:
```python
# scripts/install_hook.py
"""Safely merge ZCode PreToolUse hook into ~/.zcode/cli/config.json with backups."""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def get_default_config_path() -> Path:
    return Path.home() / ".zcode" / "cli" / "config.json"

def get_default_venv_py() -> Path:
    return ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

def install(config_path: Path | None = None,
            venv_py: Path | None = None,
            script_path: Path | None = None) -> Path:
    cfg = config_path or get_default_config_path()
    py = (venv_py or get_default_venv_py()).resolve()
    script = (script_path or (ROOT / "scripts" / "zcode_evaluator.py")).resolve()

    cfg.parent.mkdir(parents=True, exist_ok=True)

    if cfg.exists():
        # 1. Permanent original backup if missing
        orig_bak = cfg.with_suffix(".json.orig.bak")
        if not orig_bak.exists():
            shutil.copy2(cfg, orig_bak)
        # 2. Timestamped backup
        ts = time.strftime("%Y%m%d_%H%M%S")
        ts_bak = cfg.with_suffix(f".json.{ts}.bak")
        shutil.copy2(cfg, ts_bak)

        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    else:
        data = {}

    hooks_obj = data.setdefault("hooks", {})
    hooks_obj["enabled"] = True
    hooks_obj.setdefault("timeoutMs", 60000)
    hooks_obj.setdefault("maxOutputBytes", 32768)

    events_obj = hooks_obj.setdefault("events", {})
    pre_tool = events_obj.setdefault("PreToolUse", [])

    our_hook_entry = {
        "type": "process",
        "command": py.as_posix(),
        "args": [script.as_posix(), "--event", "PreToolUse"],
        "enabled": True,
        "timeoutMs": 10000,
    }

    # Inspect existing rules
    found = False
    for rule in pre_tool:
        hook_list = rule.get("hooks", [])
        for h in hook_list:
            cmd = h.get("command", "")
            args = " ".join(h.get("args", []))
            if "zcode_evaluator.py" in cmd or "zcode_evaluator.py" in args:
                # Update in-place
                rule["matcher"] = "Bash|Write|Edit|ApplyPatch"
                h.clear()
                h.update(our_hook_entry)
                found = True
                break
        if found:
            break

    if not found:
        pre_tool.append({
            "matcher": "Bash|Write|Edit|ApplyPatch",
            "hooks": [our_hook_entry]
        })

    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    cfg.write_text(rendered, encoding="utf-8")
    return cfg

def main() -> int:
    py = get_default_venv_py()
    if not py.exists():
        print(f"ERROR: venv interpreter missing at {py}", file=sys.stderr)
        return 1

    cfg = install()
    print(f"Successfully installed ZCode hook to: {cfg}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```powershell
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\pytest.exe" tests/test_install_hook.py -v
```
Expected: PASS.

---

### Task 6: End-to-End Testing & Cross-Host Verification

**Files:**
- Create: `D:\Projects\Jev\zcode-approval\tests\test_e2e.py`

**Interfaces:**
- Validates the complete pipeline running `zcode_evaluator.py` in a separate subprocess with real JSON payloads piped through stdin.

- [ ] **Step 1: Write End-to-End integration tests**

Create `D:\Projects\Jev\zcode-approval\tests\test_e2e.py`:
```python
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
EVALUATOR = str(SCRIPTS / "zcode_evaluator.py")
PYTHON = sys.executable

def run_evaluator(payload: dict) -> tuple[int, dict]:
    proc = subprocess.run(
        [PYTHON, EVALUATOR, "--event", "PreToolUse"],
        input=(json.dumps(payload) + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
    )
    data = json.loads(proc.stdout.decode("utf-8"))
    return proc.returncode, data

def test_e2e_whitelisted_command():
    code, res = run_evaluator({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": "D:/Projects/Jev/zcode-approval",
        "session_id": "test-session"
    })
    assert code == 0
    assert res["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "whitelist" in res["hookSpecificOutput"]["permissionDecisionReason"]

def test_e2e_dangerous_blocklist_command():
    code, res = run_evaluator({
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": "D:/Projects/Jev/zcode-approval",
        "session_id": "test-session"
    })
    assert code == 0
    assert res["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "blocklist" in res["hookSpecificOutput"]["permissionDecisionReason"]

def test_e2e_system_path_write_denied():
    system_target = "C:/Windows/System32/evil.dll" if sys.platform == "win32" else "/etc/evil.conf"
    code, res = run_evaluator({
        "tool_name": "Write",
        "tool_input": {"file_path": system_target, "content": "bad"},
        "cwd": "D:/Projects/Jev/zcode-approval",
        "session_id": "test-session"
    })
    assert code == 0
    assert res["hookSpecificOutput"]["permissionDecision"] == "deny"

def test_e2e_outside_workspace_write_asks():
    outside_target = "C:/Users/test/Desktop/out.txt" if sys.platform == "win32" else "/tmp/out.txt"
    code, res = run_evaluator({
        "tool_name": "Write",
        "tool_input": {"file_path": outside_target, "content": "hello"},
        "cwd": "D:/Projects/Jev/zcode-approval",
        "session_id": "test-session"
    })
    assert code == 0
    assert res["hookSpecificOutput"]["permissionDecision"] == "ask"
```

- [ ] **Step 2: Run all tests in `zcode-approval`**

Run:
```powershell
& "D:\Projects\Jev\zcode-approval\.venv\Scripts\pytest.exe" -v
```
Expected: PASS.

- [ ] **Step 3: Run regression verification on `antigravity-approval`**

Run:
```powershell
& "D:\Projects\Jev\antigravity-approval\.venv\Scripts\pytest.exe" -v
```
Expected: PASS (All original 81 tests + new multi-host/Strategy C tests pass, 100% clean).
