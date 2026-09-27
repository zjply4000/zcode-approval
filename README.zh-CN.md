[English](README.md) | [简体中文](README.zh-CN.md)

> 本文档是 [English README](README.md) 的简体中文版本。项目行为、配置项和安全边界以代码及最新英文文档为准。

# zcode-approval

一个基于 hook 的权限防护栏（guardrail），面向 [ZCode](https://zcode.z.ai/)（`PreToolUse` + `PermissionRequest`）：它把共享的 **`jev-evaluator`** policy core 适配到 ZCode 的 hook 协议与安全模型上。

它把两条路径结合起来：明确的 `allow`/`deny` 判定走确定性快速通道，含糊的工具调用交给 TypeSafe Jev 分类。无法确定或涉及策略敏感的操作一律回退为人工审批（`ask`）。

共享 policy core 维护于 [antigravity-approval](https://github.com/zjply4000/antigravity-approval)；本仓库以本地 editable install 的方式直接依赖它，而不是对它做模拟或重新实现（emulation / reimplementation）。

---

## 核心特性

1. **确定性快速通道（Tier 1）**：
   - **安全白名单**：无害的只读命令（`git status`、`ls`、`grep`、`pwd`、`npm list` 等）被自动放行（`allow`），不产生任何网络流量。
   - **危险 blocklist**：高风险破坏性命令（`rm -rf /`、`mkfs`、`dd`、`chmod -R 777 /`、fork 炸弹）被硬拒绝（`deny`）。blocklist 只是纵深防御（defense-in-depth），不是安全边界（security boundary）。
   - **Strategy C 路径守卫**：
     - **安全优先排序**：高风险系统目录（`C:\Windows`、`/etc`、`/usr`、`/bin`）与敏感用户凭据（`~/.ssh`、`~/.gnupg`）会被**最先**严格评估 → 一律硬 `deny`。
     - **安全边界升级**：当前工作区之外的无害写入会升级为 `ask`（弹出提示请用户确认），而不是 fail closed 直接 `deny`。
     - **工作区范围界定**：通过 `.git` 或 `.zcode` 标记自动探测工作区根目录，并以安全边界保护开发者主目录（`~/.git` 边界保护）。

2. **语义评估（Tier 2）**：
   - 含糊或复合命令经由 TypeSafe Jev（`TYPESAFE_API_KEY`）做安全性分类。
   - 安全的开发任务自动放行；网络/包安装类命令安全地升级为 `ask`（ZCode 协议归一化：`force_ask` → `ask`）。

3. **ZCode 协议与 schema 合规**：
   - 通过 `"Bash|Write|Edit|ApplyPatch"` matcher 匹配以下工具：`Bash`、`Write`、`Edit`、`ApplyPatch`。
   - 严格遵守 ZCode 的 `hookSpecificOutput` schema：
     ```json
     {
       "hookSpecificOutput": {
         "hookEventName": "PreToolUse",
         "permissionDecision": "allow" | "ask" | "deny",
         "permissionDecisionReason": "..."
       }
     }
     ```
   - Windows 下的进程安全：终止前干净地刷新（flush）缓冲区。

4. **隔离式无损安装器**：
   - `scripts/install_hook.py` 更新用户级配置 `~/.zcode/cli/config.json`。
   - 创建双重备份（`config.json.orig.bak` 永久保留，另加带时间戳的备份）。
   - 保留全部既有设置与第三方 hook。

5. **PermissionRequest 回退路径**：
   - 与 `PreToolUse` 一同注册；每当宿主即将渲染确认弹窗时都会征询它。
   - 只重跑确定性的 Tier 1（不含 Tier 2）：在 PreToolUse 评估不可用（崩溃 / 宿主超时）时，把工作区内的源码编辑救回为静默 `allow`，并用 `deny` 拦下 blocklist 命令；其余一切照旧交给原生弹窗。
   - 崩溃路径会写出一条 `crash_fallback` 审计记录，让故障时刻可见。
   - 已知平台限制：对于子智能体（subagent）的工具调用，ZCode 不会触发这两个 hook 事件中的任何一个——参见 [docs/superpowers/specs/2026-09-27-permissionrequest-hook-subagent-gap.md](docs/superpowers/specs/2026-09-27-permissionrequest-hook-subagent-gap.md)。

---

## 目录结构

```text
zcode-approval\
├── pyproject.toml              # 项目元数据；声明对 jev-evaluator core 的依赖
├── scripts\
│   ├── zcode_evaluator.py      # Hook 评估适配器（CLI 入口）
│   └── install_hook.py         # Hook 安装器与 config.json 合并器
├── tests\
│   ├── conftest.py             # 测试 fixtures 与路径配置
│   ├── test_workspace_root.py  # 工作区根目录解析与主目录边界的测试
│   ├── test_zcode_adapter.py   # 工具归一化、输出格式化与退出清理（exit hygiene）的测试
│   ├── test_install_hook.py    # 配置合并与备份创建的隔离（hermetic）测试
│   ├── test_permission_request.py  # PermissionRequest 事件：分发、判定映射、审计
│   ├── test_crash_fallback.py  # 回退路径的故障注入测试
│   └── test_e2e.py             # 完整的子进程端到端集成测试
└── docs\
    └── superpowers\
        ├── specs\2026-09-26-jev-permission-evaluator-zcode-design.md
        ├── specs\2026-09-27-permissionrequest-hook-subagent-gap.md
        └── plans\2026-09-26-zcode-approval-hook.md
```

---

## 快速开始

### 0. 前置条件：克隆两个仓库

`zcode-approval` 依赖共享的 `jev-evaluator` 包，而该包**未发布到 PyPI**。它位于同级仓库 `antigravity-approval` 中，以本地 editable 模式安装，因此两个仓库必须并排放在同一个父目录下：

```text
workspace/
├── antigravity-approval/   # 共享的 jev-evaluator policy core
└── zcode-approval/         # ZCode 集成（本仓库）
```

```powershell
git clone https://github.com/zjply4000/antigravity-approval.git
git clone https://github.com/zjply4000/zcode-approval.git
cd zcode-approval
```

### 1. 创建虚拟环境
虚拟环境会链接到 `antigravity-approval` 中的共享 `jev_eval` core 包：

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ..\antigravity-approval
.venv\Scripts\python -m pip install -e ".[dev]"
```

本仓库 `pyproject.toml` 依赖中的 `jev-evaluator` 条目由上述本地 editable install 满足——pip 不会从 PyPI 拉取它。

### 2. 运行测试
验证两套测试：

```powershell
# ZCode 适配器测试套件（在 zcode-approval 下执行）
.venv\Scripts\pytest -v

# 共享 core 回归套件（在 antigravity-approval 下执行；需要它自己的 venv，见该仓库的 README）
..\antigravity-approval\.venv\Scripts\pytest -v
```

### 3. 在 ZCode 中安装 Hook
把 hook 注册进 ZCode CLI 配置（`~/.zcode/cli/config.json`）：

```powershell
.venv\Scripts\python scripts\install_hook.py
```

### 4. 配置与日志
- **配置文件**：`~/.zcode/jev_approval/config.json`（或工作区本地的 `.zcode/jev_approval/config.json`）
  ```json
  {
    "typesafe_api_key": "ts_...",
    "allow_network_commands": false,
    "log_file": "~/.zcode/jev_approval/audit.log"
  }
  ```
- **审计日志**：每次评估都会以单行 JSON 记录写入 `~/.zcode/jev_approval/audit.log`。

---

## 测试

两套测试覆盖整个系统；发布改动之前，两套都应当通过：

| 测试套件 | 位置 | 覆盖范围 |
| :--- | :--- | :--- |
| **ZCode 适配器套件** | `zcode-approval/tests` | 工具归一化、hook 输出格式化、工作区根目录解析、安装器配置合并，以及端到端子进程运行 |
| **共享 core 回归套件** | `antigravity-approval/tests` | 两套宿主集成共享的确定性规则、Jev 客户端与判定逻辑 |
