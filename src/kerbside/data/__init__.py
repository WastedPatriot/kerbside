"""Bundled sample collections. Fictional. Offline. On purpose."""

from __future__ import annotations

from pathlib import Path


def fixtures_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"


def northsea_dir() -> Path:
    return fixtures_dir() / "northsea"
