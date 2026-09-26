import os
from pathlib import Path
import pytest

from zcode_evaluator import find_workspace_root


def test_find_workspace_root_finds_git(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    (ws / ".git").mkdir()
    sub = ws / "sub" / "dir"
    sub.mkdir(parents=True)
    assert find_workspace_root(str(sub)) == str(ws)


def test_find_workspace_root_finds_git_file_worktree(tmp_path):
    ws = tmp_path / "worktree_repo"
    ws.mkdir()
    (ws / ".git").write_text("gitdir: /path/to/main/.git/worktrees/branch", encoding="utf-8")
    sub = ws / "deep" / "nested"
    sub.mkdir(parents=True)
    assert find_workspace_root(str(sub)) == str(ws)


def test_find_workspace_root_finds_zcode_dir(tmp_path):
    ws = tmp_path / "zcode_project"
    ws.mkdir()
    (ws / ".zcode").mkdir()
    sub = ws / "pkg" / "src"
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


def test_find_workspace_root_when_cwd_is_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".git").mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)

    # When cwd IS home directly, it can resolve to home
    assert find_workspace_root(str(home)) == str(home)


def test_find_workspace_root_empty_or_none_cwd():
    res_empty = find_workspace_root("")
    res_none = find_workspace_root(None)
    assert Path(res_empty).is_absolute()
    assert Path(res_none).is_absolute()
    # Should fall back to resolved current working directory
    assert res_empty == str(Path.cwd().resolve())
    assert res_none == str(Path.cwd().resolve())


def test_find_workspace_root_no_marker(tmp_path):
    standalone = tmp_path / "standalone"
    standalone.mkdir()
    # Real home boundary stops traversal before inspecting ~
    assert find_workspace_root(str(standalone)) == str(standalone)


def test_find_workspace_root_no_marker_under_fake_home(monkeypatch, tmp_path):
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    standalone = fake_home / "projects" / "standalone"
    standalone.mkdir(parents=True)
    assert find_workspace_root(str(standalone)) == str(standalone)
