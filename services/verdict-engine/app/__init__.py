"""Veris verdict engine.

Makes the monorepo's shared schema importable as `verdict` without an install
step, so a teammate can clone and run with nothing but `pip install -r`.
"""

import sys
from pathlib import Path

# ponytail: one path insert beats packaging packages/shared as a pip project.
# Swap for `pip install -e packages/shared` if the service ever ships alone.
_SHARED = Path(__file__).resolve().parents[3] / "packages" / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

ENGINE_VERSION = "0.1.0"
