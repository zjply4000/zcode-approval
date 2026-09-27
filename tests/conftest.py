import os
import pathlib
import sys
from pathlib import Path

import pytest

if hasattr(pathlib, "_NormalAccessor") and hasattr(pathlib._NormalAccessor, "mkdir"):
    pathlib._NormalAccessor.mkdir = staticmethod(pathlib._NormalAccessor.mkdir)

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    """pytest attaches capture handlers to the module-level audit logger, and
    build_audit_logger used to short-circuit on any non-empty handler list, so
    JEV_LOG_FILE never took effect in tests (and the real user log got
    written). The core now rebinds to the requested path; the per-test env
    keeps evaluations out of the real ~/.zcode log."""
    monkeypatch.setenv("JEV_LOG_FILE", str(tmp_path / "audit.log"))
    import logging

    logging.getLogger("jev_eval.audit").handlers.clear()
    yield
    logging.getLogger("jev_eval.audit").handlers.clear()
