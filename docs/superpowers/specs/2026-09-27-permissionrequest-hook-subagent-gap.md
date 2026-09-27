# PermissionRequest Hook & the Subagent Hook Gap — Findings and Measures

- **Date:** 2026-09-27
- **Status:** Implemented and live-verified (v1–v4 experiments + fault-injection test suite) · uncommitted
- **Scope:** Investigation of why jev auto-approval did not apply to subagent tool calls; dual-event hook registration (`PreToolUse` + `PermissionRequest`); fault-path audit coverage; the verified limits of hook-based coverage on current ZCode.

---

## 1. Background

During a subagent-driven workflow in a separate session, an edit by a `general-purpose` subagent to a workspace source file (`src/core/utils/dates.ts`, a Tier-1 `safe_source` target) raised the manual confirmation dialog instead of being auto-approved. The evaluator itself was healthy: feeding the exact payload to `zcode_evaluator.py` returned `allow` instantly and wrote an audit line. The question was why the hook never ran.

## 2. Findings

All findings are evidence-based (jev audit log `~/.zcode/cli/log/jev_evaluator.log`, ZCode session log, and the client bundle).

**F1 — `PreToolUse` never fires for subagent tool calls.**
Across an entire day, every main-session `Bash`/`Write`/`Edit` produced a jev audit entry; none of the subagents' `Edit`/`Write`/`Bash` calls did. ZCode's log showed 25+ `tool.permission.resolved` records with `reason: "Approved once"` for those same subagent calls — they go straight to the host permission system.

**F2 — `PermissionRequest` event contract** (official docs cross-checked against the client bundle):
- Fires only when a permission outcome would prompt the user; matcher matches the tool name.
- stdin carries `tool_name`, `tool_input`, `cwd`, `permission_mode`, `session_id`, `permission_suggestions`.
- Output envelope: `{"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow" | "deny", "message"?}}}`. The allow branch carries no message; empty output (`{}`) means "no decision" and the prompt proceeds.

**F3 — Hook configuration is not hot-reloaded.** The hook runner is constructed once per session from `config.hooks` (client bundle: `S2o`/`uCa`). Config edits require a new session; the running session keeps its startup snapshot.

**F4 — Live experiments (v1–v4), same-window controlled:**

| Round | Design | Result |
|---|---|---|
| v1 | Benign subagent ops (workspace `Write`, `git status`) | Inconclusive for PermissionRequest: such ops never consult the permission system, so the event has no occasion to fire. Main-session control `Write` confirmed PreToolUse auto-allow works. |
| v2 | Subagent runs blocklist `rm -rf`; main-session out-of-workspace `Write` control | Superseded by v3 (control-group anomaly not reproducible; likely a mis-click). |
| v3 (decisive) | Strict 4-step protocol, same time window | Control: PreToolUse `path_guard/ask` → PermissionRequest `pass` → dialog → user reject → call rejected (full enforcement). Experiment: subagent `rm -rf` produced **zero jev entries** while ZCode logged `permission.resolved: "Approved once"` — the native dialog appeared and the user's manual approval let it run. |
| v4 | Main-session four-path health check | `safe_source/allow` (silent), `whitelist/allow` (silent), `blocklist/deny` (silent interception, never reaches a dialog), `path_guard/ask` → PermissionRequest `pass` → dialog → rejection enforced. Both rules present and enabled. |

**F5 — Both hook events are bypassed for subagent tool calls.** The native "需要权限[子智能体]" dialog (build mode) is the only gate on that path; it is fully disconnected from the hook system. In less restrictive modes (edit/yolo) dangerous subagent commands would run with no hook enforcement at all. The events' allow/deny decisions cannot reach subagent calls on current ZCode.

**F6 — Audit contract details.** The PermissionRequest audit line records up to `pass` (handoff to the UI); the user's final approve/reject outcome is not written back (no matching hook event; a rejected call produces no `PostToolUse`). Result-level auditing is only available from ZCode's own `tool.permission.resolved` records.

**F7 — Evaluator crashes originally left no audit trace** (audit was written only on the success path). Fixed — see M3.

## 3. Measures implemented

**M1 — Dual-event registration** (`scripts/install_hook.py`): idempotent upsert of one evaluator rule per managed event (`PreToolUse`, `PermissionRequest`), matcher `Bash|Write|Edit|ApplyPatch`, `timeoutMs` 10000, user scope `~/.zcode/cli/config.json`. Third-party rules are preserved.

**M2 — PermissionRequest handler** (`scripts/zcode_evaluator.py: handle_permission_request`): deterministic Tier-1 only.
- Tier-1 `allow` → `decision.behavior: "allow"` (dialog skipped);
- Tier-1 `deny` → `behavior: "deny"` with the formatted reason as `message`;
- everything else → `{}` (no decision, prompt proceeds).
- Tier-2 (LLM) evaluation is deliberately skipped: PreToolUse and PermissionRequest run the same deterministic function on the same input, so a second LLM pass could flip a PreToolUse `ask` into an `allow` on a differently-scored verdict. Consequence: non-whitelisted Bash still prompts on this path.

**M3 — Crash-path audit** (`_audit_crash`, `tier=crash_fallback`): both exception paths (PreToolUse and PermissionRequest) now emit a best-effort audit line so fault moments are visible; logging failures are swallowed.

**M4 — Core fix** (`antigravity-approval/src/jev_eval/logging_setup.py`): `build_audit_logger` previously short-circuited whenever the module-level logger had *any* handler, so foreign handlers (e.g. pytest capture handlers) permanently prevented binding the requested `JEV_LOG_FILE`. It now rebinds: stale own `RotatingFileHandler`s are removed and closed, foreign handlers are left untouched, and a handler for the requested file is guaranteed.

**M5 — Tests.** New suites: `tests/test_permission_request.py` (event dispatch, verdict mapping, audit event field), `tests/test_crash_fallback.py` (fault injection: PreToolUse crash → fail-closed `ask` + crash audit; PermissionRequest rescue of a workspace source edit to `allow`; blocklist `deny`; structural guard that Tier-2 never runs on the PermissionRequest path; fresh-process semantics via real subprocess), plus installer dual-event tests. A conftest fixture isolates `JEV_LOG_FILE` per test. Suite totals: zcode-approval 69, shared core 147 — all green.

## 4. Behavior envelope (honest limits)

- **Main-session happy path:** the PermissionRequest handler deterministically passes — PreToolUse and PermissionRequest evaluate the identical input with the identical deterministic function, so its decision-changing branches are unreachable there (7/7 live observations were `pass`). Cost: one short-lived interpreter per prompt (~100–200 ms) plus one audit line.
- **Fault-moment fallback (the reachable allow/deny branches):** if PreToolUse crashes or is killed by the host timeout, the call degrades to a prompt and PermissionRequest re-runs Tier-1 in a fresh process — rescuing workspace source edits to silent `allow` and blocking blocklist commands with `deny`. Note: a host-timeout kill leaves no `crash_fallback` audit line (the process cannot write); the PermissionRequest line is the visible trace.
- **Subagents:** no hook coverage on current ZCode. The native dialog is the sole gate in build mode.

## 5. Why the hook is kept despite the near-no-op happy path

1. It is the working fallback exactly when PreToolUse fails — the moments that matter most.
2. Every prompt event leaves an audit trace (this visibility carried the entire investigation).
3. It is a ready-made enforcement point should upstream ever route subagent escalations through hooks; re-running the v3 probe (subagent `rm -rf`) and seeing a `PermissionRequest/blocklist/deny` audit line would confirm wiring with zero code changes on our side.

## 6. Operational notes

- Hook configuration requires a **new session** to take effect (no hot reload).
- Verification signals: jev audit lines with `event: PermissionRequest`; absence of `"Approved once"` for subagent calls would indicate hook coverage (not achievable today).
- Test artifacts were removed; no residue in the workspace.

## 7. Follow-up options (not implemented)

- Switch the session permission mode to `edit` to stop subagent edit prompts (main-session jev PreToolUse still gates; whether subagent edits follow the mode needs a quick confirmation).
- Narrow project allow rules (e.g. `Edit` under `src/**`) — rule-vs-hook-ask precedence must be verified first so main-session sensitive-file prompts are not weakened.
- Upstream report: subagent permission escalations invoke neither `PreToolUse` nor `PermissionRequest` hooks, so policy engines are blind to subagents; in low-restriction modes dangerous subagent commands have no hook enforcement.
