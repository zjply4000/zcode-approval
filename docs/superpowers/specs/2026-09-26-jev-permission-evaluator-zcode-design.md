# Jev Permission Evaluator for ZCode — Design Spec (v1)

- **Date:** 2026-09-26
- **Status:** Approved design, revised with production durability & runtime patches · **Rev 4 (2026-09-26)**
- **Scope:** v1 = ZCode `PreToolUse` hook evaluator using shared `jev_eval` core engine, security-ordered Strategy C path guard, boundary-protected workspace discovery, host-isolated config loading, shared stdin pump with env timeout, and user-scope configuration in `~/.zcode/cli/config.json`.

---

## 1. Problem & Goals

ZCode prompts the user interactively for tool executions (`Bash`, `Write`, `Edit`, `ApplyPatch`). Following the proven architecture of `antigravity-approval`, this project brings the same tiered permission evaluation model (deterministic Tier 1 + TypeSafe Jev System One Tier 2) to ZCode:

- Whitelisted safe read-only commands auto-approve instantly with 0ms network latency.
- Ambiguous commands are classified by TypeSafe Jev; standard development commands with high confidence ($\ge 0.96$) auto-approve.
- Dangerous commands (blocklist) and sensitive system/credential directories are hard-denied (`deny`).
- Out-of-workspace writes and unverified/risky commands escalate to the user confirmation modal (`ask`).
- **Fail-Closed Robustness**: any error, timeout, or malformed input safely degrades to `ask`, never producing an unsound `allow` nor causing an accidental `deny`.
- **Zero-Regression Guarantee**: the shared core engine maintains full backward compatibility for Antigravity's existing 81 passing unit and integration tests.
- Every evaluation emits a structured JSONL audit record.

---

## 2. Verified External Contracts

### 2.1 ZCode Hooks Specification

Verified from official ZCode documentation (`https://zcode.z.ai/cn/docs/hooks`) and client diagnostics:

1. **Configuration Scopes**:
   - Project-level hooks (`<workspace>/.zcode/config.json`) are currently **ignored** by ZCode for security policies (`config_project_hooks_ignored`).
   - Hooks must be installed in **User Scope** (`~/.zcode/cli/config.json`) or distributed as a local/marketplace plugin.
   - User configuration hooks require `"hooks": { "enabled": true }` to run.
2. **Event & Matcher**:
   - Target event: `PreToolUse`.
   - Tool names: `Bash` (terminal execution), `Write` (file creation/overwrite), `Edit` (file patch/edit), `ApplyPatch` (patch alias).
   - Matcher: `"Bash|Write|Edit|ApplyPatch"`.
3. **Execution Type**:
   - `type: "process"`: directly executes executable + `args[]` vector without shell invocation. Most reliable and portable on Windows (avoids `cmd.exe` quote escaping issues).
   - `timeoutMs`: 10000 ms.
4. **Concrete User Configuration Schema (`~/.zcode/cli/config.json`)**:
   ```json
   {
     "hooks": {
       "enabled": true,
       "timeoutMs": 60000,
       "maxOutputBytes": 32768,
       "events": {
         "PreToolUse": [
           {
             "matcher": "Bash|Write|Edit|ApplyPatch",
             "hooks": [
               {
                 "type": "process",
                 "command": "D:/Projects/Jev/zcode-approval/.venv/Scripts/python.exe",
                 "args": [
                   "D:/Projects/Jev/zcode-approval/scripts/zcode_evaluator.py",
                   "--event",
                   "PreToolUse"
                 ],
                 "enabled": true,
                 "timeoutMs": 10000
               }
             ]
           }
         ]
       }
     }
   }
   ```
5. **Input Contract (stdin)**:
   - One line of JSON containing:
     ```json
     {
       "session_id": "session-xxx",
       "transcript_path": "...",
       "cwd": "D:\\Projects\\...",
       "permission_mode": "default",
       "hook_event_name": "PreToolUse",
       "tool_name": "Bash",
       "tool_input": {
         "command": "git status"
       },
       "tool_use_id": "tool-xxx"
     }
     ```
     For `Write`/`Edit`/`ApplyPatch`, `tool_input` contains `file_path` (or `path`) and `content`.
6. **Output Contract (stdout)**:
   - Valid JSON adhering strictly to ZCode's schema (any extra/unknown top-level fields cause validation errors).
   - **Allowed Decision Values**: strictly `"allow" | "ask" | "deny"`. ZCode **does not support** `force_ask`! Any internal `force_ask` must be normalized to `ask`.
     ```json
     {
       "hookSpecificOutput": {
         "hookEventName": "PreToolUse",
         "permissionDecision": "allow",
         "permissionDecisionReason": "whitelist: read-only command"
       }
     }
     ```
   - Exit code: `0` indicating success with stdout decision.

---

## 3. Architecture & Codebase Relationship

This project follows **Scheme 2 (Shared Core Package)**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   共享核心引擎 (jev-evaluator @ antigravity-approval)   │
│  src/jev_eval/                                                         │
│  ├── reader.py          (抽取共享: non-blocking stdin pump, 支持 env)   │
│  ├── deterministic.py   (Tier 1: 确定性黑白名单 + 严格安全排序策略 C)   │
│  ├── jev_client.py      (Tier 2: TypeSafe Jev SDK 智能分类与置信度)     │
│  ├── decide.py          (决策矩阵与统一决策结果封装)                   │
│  ├── config.py          (严格隔离的多宿主配置与日志: ZCode & Antigravity)│
│  └── logging_setup.py   (JSONL 结构化审计日志, 自动递归建目录)          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ editable 引用 (pip install -e)
        ┌──────────────────────────┴──────────────────────────┐
        ▼                                                     ▼
┌───────────────────────────────────┐ ┌───────────────────────────────────┐
│     Antigravity 适配端            │ │          ZCode 适配端             │
│ (d:\Projects\Jev\antigravity-...) │ │ (d:\Projects\Jev\zcode-approval)  │
│                                   │ │                                   │
│ • scripts/jev_evaluator.py        │ │ • scripts/zcode_evaluator.py      │
│   (host="antigravity",            │ │   (host="zcode",                  │
│    path_policy="strict_deny")     │ │    path_policy="strategy_c")     │
│ • scripts/install_hook.py         │ │ • scripts/install_hook.py         │
│   (写入 .agents/hooks.json)       │ │   (写入 ~/.zcode/cli/config.json) │
│ • tests/ (81 passing, 零破坏回归) │ │ • tests/ (ZCode 协议适配测套件)   │
└───────────────────────────────────┘ └───────────────────────────────────┘
```

- `D:\Projects\Jev\antigravity-approval\src\jev_eval`: holds the single source of truth for deterministic rules, stdin pump, and Jev API logic.
- `D:\Projects\Jev\zcode-approval`:
  - Contains `.venv` configured with `pip install -e ../antigravity-approval`.
  - Implements `scripts/zcode_evaluator.py` (CLI adapter for ZCode protocol).
  - Implements `scripts/install_hook.py` (installer for `~/.zcode/cli/config.json`).
  - Contains dedicated test suite `tests/` validating ZCode payloads and integration.

---

## 4. Decision Matrix & Parameterized Path Guard

### 4.1 Security-Ordered Strategy C Path Guard

In Strategy C, checking workspace containment first would classify a write to `C:\Windows` as "outside workspace" $\rightarrow$ `ask`, unsafely bypassing the hard `deny`!

Therefore, the evaluation order in `check_file_target()` is strictly ordered:

```
目标文件 Target
       │
       ▼
【第 1 步：优先检查高危敏感目录】 (无论在不在工作区，一律硬阻断)
  • 系统目录: C:\Windows, System32, Program Files, /etc, /usr, /bin
  • 用户凭据: ~/.ssh, ~/.gnupg
       ├─ 是 ──► 返回 ("deny", "path_guard: target path in system directory or sensitive credential")
       │
       └─ 否
           │
           ▼
【第 2 步：检查工作区边界与策略】
  • 是否位于工作区/合法产物根目录内？
       ├─ 是 ──► 返回 ("ask", "file mutations are not auto-approved in v1") (若为 artifact 则 allow)
       │
       └─ 否 ──► 检查 path_policy:
                  • path_policy == "strategy_c"  ──► 返回 ("ask", "path_guard: target path outside workspace")
                  • path_policy == "strict_deny" ──► 返回 ("deny", "path_guard: target path outside workspace")
```

1. **`path_policy="strict_deny"` (Default, used by Antigravity)**:
   - System directory hit $\rightarrow$ `deny`.
   - Outside workspace hit $\rightarrow$ `deny`.
   - Preserves 100% backward compatibility for all 81 existing Antigravity tests.
2. **`path_policy="strategy_c"` (Used by ZCode)**:
   - System directory / credential hit $\rightarrow$ **`deny`** (Checked FIRST; malicious OS overwrites can never degrade to `ask`).
   - Ordinary outside workspace $\rightarrow$ **`ask`** (Non-sensitive external paths like Desktop, user home, or sibling projects trigger interactive user prompt).
   - Inside workspace $\rightarrow$ **`ask`** (or `allow` for host artifacts).

### 4.2 Command Execution Matrix (for `Bash` / `run_command`)

| Matcher / Scenario | Pipeline Tier | Decision (Internal) | Decision (ZCode Output) | Reason / Trigger |
| :--- | :--- | :--- | :--- | :--- |
| **High-Risk Blocklist** | Tier 1 (Deterministic) | **`deny`** | **`deny`** | `rm -rf /`, `mkfs`, format, diskpart, `dd`, fork bomb, drop database |
| **Read-Only Whitelist** | Tier 1 (Deterministic) | **`allow`** | **`allow`** | `git status`, `git diff`, `git log`, `ls`, `dir`, `echo`, `cat` (no write redirect `>`) |
| **Network / Package Install** | Tier 1 (Deterministic) | **`force_ask`** | **`ask`** (mapped) | `npm install`, `pip install`, `curl`, `wget`, unless network commands explicitly enabled |
| **Safe Dev Command** | Tier 2 (Jev System One) | **`allow`** | **`allow`** | Jev category $\in$ `{"read_only", "standard_dev"}` and confidence $\ge 0.96$ |
| **Destructive / Low Confidence** | Tier 2 (Jev System One) | **`ask`** | **`ask`** | Jev category `"destructive"` or confidence $< 0.96$ |
| **Error / Timeout / Fallback** | Fallback Handler | **`ask`** | **`ask`** | Malformed JSON, deadline timeout, network failure, unhandled tool |

---

## 5. Component Specifications & Adapter Details

### 5.1 Shared Stdin Deadline Pump (`src/jev_eval/reader.py`)

Extract the incremental reader daemon from `antigravity-approval/scripts/jev_evaluator.py` into `src/jev_eval/reader.py`:
- `read_stdin_payload(deadline_s: float | None = None) -> dict | None`:
  - If `deadline_s` is omitted, reads `int(os.environ.get("JEV_STDIN_TIMEOUT_MS", "1000")) / 1000.0` (default 1.0s, configurable via environment).
  - Reads incrementally via daemon thread `read1()`, parsing top-level JSON without waiting for EOF (protecting against open-ended Windows host pipes).
- Used by both `scripts/jev_evaluator.py` and `scripts/zcode_evaluator.py` without code duplication.

### 5.2 Tool Name, Argument & Relative Path Normalization in `zcode_evaluator.py`

ZCode input must be explicitly mapped to standard `jev_eval` primitives before calling `evaluate_tool_call`. Relative paths must be resolved against payload `cwd` rather than process working directory:

```python
_TOOL_MAP = {
    "Bash": "run_command",
    "Write": "write_to_file",
    "Edit": "replace_file_content",
    "ApplyPatch": "replace_file_content",
}

def normalize_zcode_tool_call(tool_name: str, tool_input: dict | None, cwd: str) -> dict:
    canonical = _TOOL_MAP.get(tool_name, tool_name)
    tool_input = tool_input or {}
    target = ""
    command = ""

    if canonical == "run_command":
        command = tool_input.get("command", "")
    elif canonical in ("write_to_file", "replace_file_content"):
        target = tool_input.get("file_path") or tool_input.get("path") or ""
        if target and not Path(target).is_absolute():
            # Resolve relative target against payload cwd, not process working directory
            target = str((Path(cwd) / target).resolve())

    return {"tool_name": canonical, "command": command, "cwd": cwd, "target": target}
```

### 5.3 Boundary-Protected Workspace Root Discovery

Prevent root traversal from crossing `Path.home()` (protecting developers whose home directory contains a dotfiles git repository `~/.git`). Robust against Git worktrees and submodules (`.exists()` check) and defensive against empty `cwd`:

```python
def find_workspace_root(cwd: str) -> str:
    cur = Path(cwd).resolve() if cwd else Path.cwd()
    home = Path.home().resolve()
    for parent in [cur, *cur.parents]:
        if parent == home and cur != home:
            break  # Do not swallow user home as workspace root
        if (parent / ".git").exists() or (parent / ".zcode").exists():
            return str(parent)
    return str(cur)
```

### 5.4 Host-Isolated Configuration & Directory Creation in `src/jev_eval/`

Prevent cross-host setting contamination between Antigravity and ZCode, and ensure log directories exist:

- **When `host == "antigravity"`**:
  - User: `~/.gemini/config/jev.env`
  - Workspace: `<workspace>/.agents/jev.env`
  - Default Log: `~/.gemini/logs/jev_evaluator.log`
  - Completely isolated from any `.zcode` configuration.
- **When `host == "zcode"`**:
  - User: `~/.zcode/jev.env` (with fallback to `~/.gemini/config/jev.env` **only** for `TYPESAFE_API_KEY` convenience if `TYPESAFE_API_KEY` is not defined in `~/.zcode/jev.env`).
  - Workspace: `<workspace>/.zcode/jev.env`
  - Default Log: `~/.zcode/cli/log/jev_evaluator.log`
- **Log Setup (`logging_setup.py`)**:
  - Calls `log_path.parent.mkdir(parents=True, exist_ok=True)` before attaching `FileHandler` / `WatchedFileHandler`.

### 5.5 ZCode Decision Serialization & Fail-Closed Guarantee

In `zcode_evaluator.py`:
- Map `force_ask` $\rightarrow$ `ask`.
- Guarantee strictly formatted output:
  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "allow",
      "permissionDecisionReason": "whitelist: read-only command"
    }
  }
  ```
- Any unhandled exception or stdin timeout emits:
  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "ask",
      "permissionDecisionReason": "evaluator fallback: <error>"
    }
  }
  ```
- **Explicit I/O Flush**: Always call `sys.stdout.flush()` and `sys.stderr.flush()` before `os._exit(0)` to ensure stdout buffers reach ZCode over pipe.

### 5.6 Hook Installer with Safe Merge (`scripts/install_hook.py`)

- **Safe Backup**:
  - Creates `~/.zcode/cli/config.json.orig.bak` on initial run if not already present.
  - Creates timestamped backup `~/.zcode/cli/config.json.<timestamp>.bak` on every run.
- **Nested In-Place Merge**:
  - Uses `config.setdefault("hooks", {}).setdefault("events", {}).setdefault("PreToolUse", [])`.
  - Ensures `hooks.enabled = true`.
  - In `hooks.events.PreToolUse`, inspects matcher rule objects and their `rule.get("hooks", [])`:
    - Checks if any hook in `rule["hooks"]` references `zcode_evaluator.py` in its `command` or `args`.
    - If found: updates the entry in-place and sets `matcher = "Bash|Write|Edit|ApplyPatch"`.
    - If not found: appends a new rule with `matcher = "Bash|Write|Edit|ApplyPatch"`.
    - Preserves all other third-party hooks and events completely intact.

---

## 6. Testing & Quality Assurance Plan

1. **`test_zcode_adapter.py`**:
   - Verify argument extraction for `Bash` (`command`), `Write`/`Edit`/`ApplyPatch` (`file_path` and `path`).
   - Verify relative path target resolution against `cwd`.
   - Verify unmapped/unknown tools do not raise `UnboundLocalError` and fallback gracefully.
   - Verify `force_ask` maps to `ask`.
   - Verify JSON output adheres to exact `hookSpecificOutput` schema.
2. **`test_path_guard.py`**:
   - Verify security check order: `C:\Windows\...` returns `deny` even when outside workspace under `strategy_c`.
   - Verify `path_policy="strict_deny"` maintains existing strict behavior for Antigravity.
   - Verify `path_policy="strategy_c"`: normal outside-workspace paths return `ask`, workspace paths return `ask`.
3. **`test_workspace_root.py`**:
   - Verify upward directory traversal finding `.git` (directories, worktrees, submodules) / `.zcode`.
   - Verify empty `cwd` fallback to `Path.cwd()`.
   - Verify home directory boundary protection (does not ascend into `~/.git`).
4. **`test_config_isolation.py`**:
   - Verify `host="antigravity"` ignores `.zcode/jev.env`.
   - Verify `host="zcode"` reads `.zcode/jev.env` and falls back for API key only.
   - Verify log parent directory auto-creation.
5. **`test_reader.py`**:
   - Test shared `read_stdin_payload` with valid JSON, EOF, timeout, and `JEV_STDIN_TIMEOUT_MS`.
6. **`test_install_hook.py`**:
   - Test config reading, nested merging with existing third-party hooks, matcher `"Bash|Write|Edit|ApplyPatch"`, backup creation, and idempotence.
7. **`test_e2e.py`**:
   - Subprocess end-to-end tests piping JSON payloads through `zcode_evaluator.py` and asserting flushed stdout JSON and exit code `0`.
8. **Antigravity Regression Suite**:
   - Run `pytest` in `antigravity-approval` to guarantee all 81 existing tests pass 100% without modification or breakage.
