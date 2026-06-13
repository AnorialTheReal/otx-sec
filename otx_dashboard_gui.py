#!/usr/bin/env python3

"""
Legacy compatibility launcher.

The old standalone dashboard used hardcoded /opt, /var and sudo paths.
For safety and portability, use app/frontend.py instead.
"""

import os
import sys
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
APP_DIR = BASE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

import frontend  # noqa: F401
