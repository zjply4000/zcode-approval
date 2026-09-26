# ZCode Jev Permission Evaluator Hook

`zcode-approval` provides an autonomous, intelligent pre-tool execution evaluator hook for [ZCode](https://zcode.z.ai/), powered by the TypeSafe Jev System One engine. It emulates and shares the core policy evaluation engine from `antigravity-approval` while adapting to ZCode's hook protocol and security model.

---

## Key Features

1. **Deterministic Fast Path (Tier 1)**:
   - **Safe Whitelist**: Benign read-only commands (`git status`, `ls`, `grep`, `pwd`, `npm list`, etc.) are auto-approved (`allow`) with sub-millisecond latency.
   - **Dangerous Blocklist**: High-risk destructive commands (`rm -rf /`, `mkfs`, `dd`, `chmod -R 777 /`, fork bombs) are hard-denied (`deny`).
   - **Strategy C Path Guard**:
     - **Security-First Ordering**: High-risk system directories (`C:\Windows`, `/etc`, `/usr`, `/bin`) and sensitive user credentials (`~/.ssh`, `~/.gnupg`) are strictly evaluated **first** $\to$ hard `deny`.
     - **Safe Boundary Escalation**: Benign writes outside the active workspace are escalated to `ask` (prompting the user), rather than failing closed with `deny`.
     - **Workspace Scoping**: Workspace root is automatically detected via `.git` or `.zcode` markers, with safety bounds protecting developer home directories (`~/.git` boundary protection).

2. **Semantic Evaluation (Tier 2)**:
   - Ambiguous or compound commands undergo AI-assisted safety analysis via TypeSafe Jev System One (`TYPESAFE_API_KEY`).
   - Safe development tasks auto-approve; network/package installation commands safely escalate to `ask` (ZCode protocol normalization: `force_ask` $\to$ `ask`).

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
D:\Projects\Jev\zcode-approval\
├── pyproject.toml              # Project metadata & editable dependency on ../antigravity-approval
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

### 1. Setup Virtual Environment
The virtual environment links to the shared `jev_eval` core package in `antigravity-approval`:

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ..\antigravity-approval
.venv\Scripts\pip install pytest
```

### 2. Run Tests
Verify both test suites:

```powershell
# Run ZCode approval tests (45 tests)
.venv\Scripts\pytest -v

# Run Antigravity approval regression tests (102 tests)
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

## Testing & Verification Summary

| Test Suite | Location | Tests Passed | Status |
| :--- | :--- | :---: | :---: |
| **ZCode Hook & Adapter** | `zcode-approval/tests` | **45 / 45** | 100% Passing |
| **Shared Core & Antigravity** | `antigravity-approval/tests` | **102 / 102** | 100% Passing (0 Regressions) |
| **Total Cross-Host** | Cross-Project | **147 / 147** | Clean Pass |
