# Copyright 2026 4Chains Inc. All rights reserved.
"""``python packaging/closed/build_wheel.py --out dist``: see closed_backend.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from closed_backend import main

main()
