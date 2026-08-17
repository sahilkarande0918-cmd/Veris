"""Veris verdict engine.

Makes the monorepo's shared schema importable as `verdict` without an install
step, so a teammate can clone and run with nothing but `pip install -r`.
"""

import sys
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parents[3]

# ponytail: one path insert beats packaging packages/shared as a pip project.
# Swap for `pip install -e packages/shared` if the service ever ships alone.
_SHARED = _ROOT / "packages" / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

# Real environment variables win over the file, so CI and `VERIS_OFFLINE=1 uvicorn …`
# still override it.
load_dotenv(_ROOT / ".env", override=False)

ENGINE_VERSION = "0.1.0"
