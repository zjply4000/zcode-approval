# zcode-approval

A `PreToolUse` permission guardrail for [ZCode](https://zcode.z.ai/) that adapts the shared **`jev-evaluator`** policy core to ZCode's hook protocol and security model.

It combines a deterministic fast path for clear `allow`/`deny` decisions with TypeSafe Jev classification for ambiguous tool calls. Uncertain or policy-sensitive actions fall back to manual approval (`ask`).

The shared policy core is maintained in [antigravity-approval](https://github.com/zjply4000/antigravity-approval); this repository depends on it directly (as a local editable install) rather than reimplementing it.

---

## Key Features

1. **Deterministic Fast Path (Tier 1)**:
   - **Safe Whitelist**: Benign read-only commands (`git status`, `ls`, `grep`, `pwd`, `npm list`, etc.) are auto-approved (`allow`) with no network traffic.
   - **Dangerous Blocklist**: High-risk destructive commands (`rm -rf /`, `mkfs`, `dd`, `chmod -R 777 /`, fork bombs) are hard-denied (`deny`). The blocklist is defense-in-depth, not a security boundary.
   - **Strategy C Path Guard**:
     - **Security-First Ordering**: High-risk system directories (`C:\Windows`, `/etc`, `/usr`, `/bin`) and sensitive user credentials (`~/.ssh`, `~/.gnupg`) are strictly evaluated **first** → hard `deny`.
     - **Safe Boundary Escalation**: Benign writes outside the active workspace are escalated to `ask` (prompting the user), rather than failing closed with `deny`.
     - **Workspace Scoping**: Workspace root is automatically detected via `.git` or `.zcode` markers, with safety bounds protecting developer home directories (`~/.git` boundary protection).

2. **Semantic Evaluation (Tier 2)**:
   - Ambiguous or compound commands undergo safety classification via TypeSafe Jev (`TYPESAFE_API_KEY`).
   - Safe development tasks auto-approve; network/package installation commands safely escalate to `ask` (ZCode protocol normalization: `force_ask` → `ask`).

3. **ZCode Protocol & Schema Compliance**:
   - Matches tools: `Bash`, `Write`, `Edit`, `ApplyPatch` via `"Bash|Write|Edit|ApplyPatch"` matcher.
   - Strictly conforms to ZCode `hookSpecificOutput` schema:
     ```json
     {
       "hookSpecificOutput": {
         "hookEventName": "PreToolUse",
         "permissionDecision": "allow" | "ask" | "deny",
         "permissionDecisionReason": "..."
       }
     }
     ```
   - Process safety on Windows: flushes buffers cleanly before terminating.

4. **Hermetic Non-Destructive Installer**:
   - `scripts/install_hook.py` updates user-scope configuration at `~/.zcode/cli/config.json`.
   - Creates dual backups (`config.json.orig.bak` preserved permanently, plus timestamped backups).
   - Preserves all existing settings and third-party hooks.

---

## Directory Structure

```text
zcode-approval\
├── pyproject.toml              # Project metadata; declares the jev-evaluator core dependency
├── scripts\
│   ├── zcode_evaluator.py      # Hook evaluator adapter (CLI entrypoint)
│   └── install_hook.py         # Hook installer & config.json merger
├── tests\
│   ├── conftest.py             # Test fixtures & path configuration
│   ├── test_workspace_root.py  # Tests for workspace root resolution & home boundary
│   ├── test_zcode_adapter.py   # Tests for tool normalization, output formatting & exit hygiene
│   ├── test_install_hook.py    # Hermetic tests for config merging & backup creation
│   └── test_e2e.py             # Full subprocess end-to-end integration tests
└── docs\
    └── superpowers\
        ├── specs\2026-09-26-jev-permission-evaluator-zcode-design.md
        └── plans\2026-09-26-zcode-approval-hook.md
```

---

## Quick Start

### 0. Prerequisites: clone both repositories

`zcode-approval` depends on the shared `jev-evaluator` package, which is **not published on PyPI**. It lives in the sibling repository `antigravity-approval` and is installed locally in editable mode, so the two repositories must sit side by side in the same parent directory:

```text
workspace/
├── antigravity-approval/   # shared jev-evaluator policy core
└── zcode-approval/         # ZCode integration (this repository)
```

```powershell
git clone https://github.com/zjply4000/antigravity-approval.git
git clone https://github.com/zjply4000/zcode-approval.git
cd zcode-approval
```

### 1. Setup Virtual Environment
The virtual environment links to the shared `jev_eval` core package in `antigravity-approval`:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ..\antigravity-approval
.venv\Scripts\python -m pip install -e ".[dev]"
```

The `jev-evaluator` entry in this repository's `pyproject.toml` dependencies is satisfied by that local editable install — pip does not fetch it from PyPI.

### 2. Run Tests
Verify both test suites:

```powershell
# ZCode adapter test suite (from zcode-approval)
.venv\Scripts\pytest -v

# Shared-core regression suite (from antigravity-approval; needs its own venv, see that repository's README)
..\antigravity-approval\.venv\Scripts\pytest -v
```

### 3. Install the Hook in ZCode
To register the hook into your ZCode CLI configuration (`~/.zcode/cli/config.json`):

```powershell
.venv\Scripts\python scripts\install_hook.py
```

### 4. Configuration & Logging
- **Configuration File**: `~/.zcode/jev_approval/config.json` (or workspace-local `.zcode/jev_approval/config.json`)
  ```json
  {
    "typesafe_api_key": "ts_...",
    "allow_network_commands": false,
    "log_file": "~/.zcode/jev_approval/audit.log"
  }
  ```
- **Audit Log**: Every evaluation is logged as a single-line JSON record in `~/.zcode/jev_approval/audit.log`.

---

## Testing

Two suites cover the system; both should pass before publishing changes:

| Suite | Location | Covers |
| :--- | :--- | :--- |
| **ZCode adapter suite** | `zcode-approval/tests` | Tool normalization, hook output formatting, workspace-root resolution, installer config merging, and end-to-end subprocess runs |
| **Shared-core regression suite** | `antigravity-approval/tests` | The deterministic rules, Jev client, and decision logic shared by both host integrations |
