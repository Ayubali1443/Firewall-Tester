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


def _query_process_dir_win32(pid: int) -> Path | None:
    """Resolve executable parent directory of a Windows PID without admin privileges."""
    if pid <= 0 or os.name != "nt":
        return None
    try:
        import ctypes

        process_query_limited = 0x1000
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        handle = kernel32.OpenProcess(process_query_limited, 0, pid)
        if not handle:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_uint32(len(buf))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                exe_path = Path(buf.value).resolve()
                if exe_path.exists():
                    return exe_path.parent
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None
    return None


def get_project_root() -> Path:
    """Return repository root when running from source, or persistent install dir when compiled."""
    if is_compiled_binary():
        # In Nuitka --onefile, the first module consumes NUITKA_ONEFILE_DIRECTORY and unsets it,
        # so subsequent submodules would otherwise see the unpacked temp dir. Query the live
        # onefile parent EXE PID first, then __main__.__compiled__, before local fallbacks.
        ppid_raw = os.environ.get("NUITKA_ONEFILE_PARENT", "").strip()
        if ppid_raw.isdigit():
            parent_dir = _query_process_dir_win32(int(ppid_raw))
            if parent_dir is not None:
                return parent_dir

        main_mod = sys.modules.get("__main__")
        main_comp = getattr(main_mod, "__compiled__", None) if main_mod is not None else None
        main_dir = getattr(main_comp, "containing_dir", None) if main_comp is not None else None
        if main_dir:
            return Path(str(main_dir)).resolve()

        comp = globals().get("__compiled__")
        containing_dir = getattr(comp, "containing_dir", None) if comp is not None else None
        if containing_dir:
            return Path(str(containing_dir)).resolve()
        orig_argv0 = getattr(comp, "original_argv0", None) if comp is not None else None
        if orig_argv0:
            return Path(str(orig_argv0)).resolve().parent
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
