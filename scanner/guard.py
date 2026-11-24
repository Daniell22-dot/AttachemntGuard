#!/usr/bin/env python3
import sys
from pathlib import Path

BOOTSTRAP_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
if str(BOOTSTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(BOOTSTRAP_ROOT))

from cli import main

if __name__ == "__main__":
    raise SystemExit(main())
