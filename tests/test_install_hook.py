# tests/test_install_hook.py
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from install_hook import install, main


def test_fresh_install_creates_config_and_structure(tmp_path: Path):
    config_path = tmp_path / ".zcode" / "cli" / "config.json"
    venv_py = tmp_path / "venv" / "Scripts" / "python.exe"
    script_path = tmp_path / "scripts" / "zcode_evaluator.py"

    res = install(config_path=config_path, venv_py=venv_py, script_path=script_path)
    assert res == config_path
    assert config_path.exists()

    data = json.loads(config_path.read_text(encoding="utf-8"))
    assert data["hooks"]["enabled"] is True
    assert data["hooks"]["timeoutMs"] == 60000
    assert data["hooks"]["maxOutputBytes"] == 32768

    events = data["hooks"]["events"]
    assert "PreToolUse" in events
    pre_tool = events["PreToolUse"]
    assert len(pre_tool) == 1

    rule = pre_tool[0]
    assert rule["matcher"] == "Bash|Write|Edit|ApplyPatch"
    assert len(rule["hooks"]) == 1

    hook = rule["hooks"][0]
    assert hook["type"] == "process"
    assert hook["command"] == venv_py.as_posix()
    assert hook["args"] == [script_path.as_posix(), "--event", "PreToolUse"]
    assert hook["enabled"] is True
    assert hook["timeoutMs"] == 10000

    # No backups should be created when config did not exist beforehand
    baks = list(tmp_path.glob("**/*.bak"))
    assert len(baks) == 0


def test_install_preserves_third_party_hooks_and_other_events(tmp_path: Path):
    config_path = tmp_path / "config.json"
    venv_py = tmp_path / "venv" / "bin" / "python"
    script_path = tmp_path / "scripts" / "zcode_evaluator.py"

    initial_config = {
        "custom_global_setting": 42,
        "hooks": {
            "enabled": False,
            "timeoutMs": 45000,
            "events": {
                "PostToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "process", "command": "/usr/bin/audit_logger"}],
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": "LinterTool",
                        "hooks": [
                            {
                                "type": "process",
                                "command": "/usr/bin/linter",
                                "args": ["--strict"],
                                "enabled": True,
                            }
                        ],
                    }
                ],
            },
        },
    }
    config_path.write_text(json.dumps(initial_config, indent=2), encoding="utf-8")

    install(config_path=config_path, venv_py=venv_py, script_path=script_path)

    data = json.loads(config_path.read_text(encoding="utf-8"))
    assert data["custom_global_setting"] == 42
    assert data["hooks"]["enabled"] is True
    assert data["hooks"]["timeoutMs"] == 45000
    assert data["hooks"]["maxOutputBytes"] == 32768

    events = data["hooks"]["events"]
    assert "PostToolUse" in events
    assert events["PostToolUse"][0]["hooks"][0]["command"] == "/usr/bin/audit_logger"

    pre_tool = events["PreToolUse"]
    assert len(pre_tool) == 2

    # Retains 3rd-party hook untouched
    assert pre_tool[0]["matcher"] == "LinterTool"
    assert pre_tool[0]["hooks"][0]["command"] == "/usr/bin/linter"

    # Appends ZCode evaluator rule
    assert pre_tool[1]["matcher"] == "Bash|Write|Edit|ApplyPatch"
    assert pre_tool[1]["hooks"][0]["command"] == venv_py.as_posix()
    assert pre_tool[1]["hooks"][0]["args"] == [script_path.as_posix(), "--event", "PreToolUse"]


def test_idempotent_in_place_update(tmp_path: Path):
    config_path = tmp_path / "config.json"
    venv_py1 = tmp_path / "venv1" / "python.exe"
    venv_py2 = tmp_path / "venv2" / "python.exe"
    script_path = tmp_path / "scripts" / "zcode_evaluator.py"

    # Run 1
    install(config_path=config_path, venv_py=venv_py1, script_path=script_path)
    data1 = json.loads(config_path.read_text(encoding="utf-8"))
    assert len(data1["hooks"]["events"]["PreToolUse"]) == 1
    assert data1["hooks"]["events"]["PreToolUse"][0]["hooks"][0]["command"] == venv_py1.as_posix()

    # Run 2 with updated venv
    install(config_path=config_path, venv_py=venv_py2, script_path=script_path)
    data2 = json.loads(config_path.read_text(encoding="utf-8"))
    assert len(data2["hooks"]["events"]["PreToolUse"]) == 1
    assert data2["hooks"]["events"]["PreToolUse"][0]["matcher"] == "Bash|Write|Edit|ApplyPatch"
    assert data2["hooks"]["events"]["PreToolUse"][0]["hooks"][0]["command"] == venv_py2.as_posix()
    assert data2["hooks"]["events"]["PreToolUse"][0]["hooks"][0]["args"] == [
        script_path.as_posix(),
        "--event",
        "PreToolUse",
    ]


def test_detects_evaluator_in_command_or_args(tmp_path: Path):
    config_path = tmp_path / "config.json"
    venv_py = tmp_path / "venv" / "python.exe"
    script_path = tmp_path / "scripts" / "zcode_evaluator.py"

    initial_config = {
        "hooks": {
            "events": {
                "PreToolUse": [
                    {
                        "matcher": "OldMatcher",
                        "hooks": [
                            {
                                "type": "process",
                                "command": "D:/some/path/zcode_evaluator.py",
                                "args": [],
                            }
                        ],
                    }
                ]
            }
        }
    }
    config_path.write_text(json.dumps(initial_config), encoding="utf-8")

    install(config_path=config_path, venv_py=venv_py, script_path=script_path)

    data = json.loads(config_path.read_text(encoding="utf-8"))
    pre_tool = data["hooks"]["events"]["PreToolUse"]
    assert len(pre_tool) == 1
    assert pre_tool[0]["matcher"] == "Bash|Write|Edit|ApplyPatch"
    assert pre_tool[0]["hooks"][0]["command"] == venv_py.as_posix()
    assert pre_tool[0]["hooks"][0]["args"] == [script_path.as_posix(), "--event", "PreToolUse"]


def test_backup_file_creation_and_preservation(tmp_path: Path):
    config_path = tmp_path / "config.json"
    venv_py = tmp_path / "venv" / "python.exe"
    script_path = tmp_path / "scripts" / "zcode_evaluator.py"

    initial_content = '{\n  "version": 1,\n  "original": true\n}\n'
    config_path.write_text(initial_content, encoding="utf-8")

    # First install
    install(config_path=config_path, venv_py=venv_py, script_path=script_path)

    orig_bak = config_path.with_name("config.json.orig.bak")
    assert orig_bak.exists()
    assert orig_bak.read_text(encoding="utf-8") == initial_content

    ts_pattern = re.compile(r"^config\.json\.\d{8}_\d{6}\.bak$")
    ts_baks = [p for p in tmp_path.iterdir() if ts_pattern.match(p.name)]
    assert len(ts_baks) == 1
    assert ts_baks[0].read_text(encoding="utf-8") == initial_content

    # Second install with modified content in config
    current_content = config_path.read_text(encoding="utf-8")
    install(config_path=config_path, venv_py=venv_py, script_path=script_path)

    # orig.bak must NOT be overwritten!
    assert orig_bak.read_text(encoding="utf-8") == initial_content

    # A timestamped backup was created reflecting state prior to run 2
    ts_baks_after = [p for p in tmp_path.iterdir() if ts_pattern.match(p.name)]
    assert len(ts_baks_after) >= 1
    # Check that at least one backup matches the state prior to run 2
    bak_contents = [b.read_text(encoding="utf-8") for b in ts_baks_after]
    assert current_content in bak_contents or initial_content in bak_contents


def test_main_venv_py_missing(tmp_path: Path, capsys: pytest.CaptureFixture):
    nonexistent_py = tmp_path / "missing" / "python.exe"
    ret = main(
        config_path=tmp_path / "config.json",
        venv_py=nonexistent_py,
        script_path=tmp_path / "zcode_evaluator.py",
    )
    assert ret == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_main_import_jev_eval_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_py = tmp_path / "python.exe"
    fake_py.write_text("", encoding="utf-8")

    mock_run = MagicMock(return_value=subprocess.CompletedProcess(
        args=[str(fake_py), "-c", "import jev_eval"],
        returncode=1,
        stdout="",
        stderr="ModuleNotFoundError: No module named 'jev_eval'",
    ))
    monkeypatch.setattr(subprocess, "run", mock_run)

    ret = main(
        config_path=tmp_path / "config.json",
        venv_py=fake_py,
        script_path=tmp_path / "zcode_evaluator.py",
    )
    assert ret == 1
    captured = capsys.readouterr()
    assert "cannot import jev_eval" in captured.err


def test_main_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_py = tmp_path / "python.exe"
    fake_py.write_text("", encoding="utf-8")

    mock_run = MagicMock(return_value=subprocess.CompletedProcess(
        args=[str(fake_py), "-c", "import jev_eval"],
        returncode=0,
        stdout="",
        stderr="",
    ))
    monkeypatch.setattr(subprocess, "run", mock_run)

    config_path = tmp_path / "config.json"
    ret = main(
        config_path=config_path,
        venv_py=fake_py,
        script_path=tmp_path / "zcode_evaluator.py",
    )
    assert ret == 0
    assert config_path.exists()
    captured = capsys.readouterr()
    assert "Successfully installed" in captured.out
