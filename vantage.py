#!/usr/bin/env python3
"""Launcher: run Vantage straight from the checkout, no install required."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHONPATH", str(ROOT))

from vantage.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
