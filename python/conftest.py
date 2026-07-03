"""Pytest bootstrap for local-package resolution.

Ensures tests import the in-repo SDK and examples code instead of any
installed package versions in the active virtualenv.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
EXAMPLES = ROOT / "examples"

for path in (SRC, EXAMPLES):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
