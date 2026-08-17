"""Presence of this file puts the service root on sys.path, so `import app`
works when pytest is run from anywhere.

Importing `app` here also wires `packages/shared` onto sys.path (see
app/__init__.py), so a test module can `from verdict import ...` regardless of
which test file pytest happens to collect first.
"""

import app  # noqa: F401
