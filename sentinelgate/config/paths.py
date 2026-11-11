"""Runtime path resolution for both source and compiled (Nuitka/PyInstaller) builds."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_compiled_binary() -> bool:
    """Return True when executing from a compiled/frozen desktop build."""
    return bool(
        getattr(sys, "frozen", False)
        or hasattr(sys, "_MEIPASS")
        or "__compiled__" in globals()
    )


def get_bundle_root() -> Path:
    """Return root directory containing bundled package resources (ui, validator)."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / "sentinelgate"
        if candidate.exists():
            return candidate
        return Path(meipass)
    return Path(__file__).resolve().parent.parent


def get_project_root() -> Path:
    """Return repository root when running from source, or executable directory when compiled."""
    if is_compiled_binary():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def get_app_data_dir() -> Path:
    """Return persistent per-user tamper-resistant AppData directory."""
    local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    app_dir = Path(local_app_data) / "SentinelGateAI"
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def get_validator_bin_path() -> Path:
    """Locate bundled Rust cf_validator.exe executable."""
    bundle_bin = get_bundle_root() / "validator" / "bin" / "cf_validator.exe"
    if bundle_bin.exists():
        return bundle_bin
    # Fallback for source tree layout
    legacy_bin = get_project_root() / "cf_validator" / "target" / "release" / "cf_validator.exe"
    return legacy_bin


def get_ui_dir() -> Path:
    """Locate bundled frontend UI directory."""
    return get_bundle_root() / "ui"


def get_workspace_data_dir() -> Path:
    """Locate consolidated workspace data directory in development mode."""
    return get_project_root() / "data"
