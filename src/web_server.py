#!/usr/bin/env python3
"""
src/web_server.py
=================
Wrapper and launcher for the unified Border Surveillance Command Center backend.
"""

import os
import sys
import uvicorn

# Ensure root directory is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.dashboard_api import app, run_server, engine

if __name__ == "__main__":
    run_server(host="0.0.0.0", port=8000)
