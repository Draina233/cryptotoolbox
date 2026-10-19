"""应用图标资源路径。"""
from pathlib import Path

ASSET_DIR = Path(__file__).resolve().parents[1] / "assets"


def app_icon_path(name: str = "app_icon.ico") -> str:
    return str(ASSET_DIR / name)
