"""密评工具箱启动入口：python run.py [--page <页面id>]"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptotoolbox.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
