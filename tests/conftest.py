import os
import pathlib
import sys
from pathlib import Path

if hasattr(pathlib, "_NormalAccessor") and hasattr(pathlib._NormalAccessor, "mkdir"):
    pathlib._NormalAccessor.mkdir = staticmethod(pathlib._NormalAccessor.mkdir)

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
