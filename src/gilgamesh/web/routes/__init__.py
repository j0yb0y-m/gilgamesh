"""Page routers, one module per area of the UI.

Each module defines a module-level ``router`` that :func:`gilgamesh.web.app.create_app`
includes. Splitting them keeps every module small and gives each page area one obvious
home; the shared dependencies they import live in :mod:`gilgamesh.web.deps`.
"""

from __future__ import annotations
