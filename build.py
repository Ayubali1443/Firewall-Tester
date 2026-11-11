"""Build script for compiling SentinelGate AI into a tamper-proof standalone Windows executable."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

from sentinelgate.config.cf_secrets import build_native_seal_rust_source
from sentinelgate.config.vault import extract_legacy_cf_from_vault


ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
VALIDATOR_SRC = ROOT / "sentinelgate" / "validator"
VALIDATOR_BIN = VALIDATOR_SRC / "bin" / "cf_validator.exe"
HASH_FILE = ROOT / "sentinelgate" / "core" / "_validator_hash.py"
SEAL_BUILD_DIR = ROOT / "sentinelgate" / "config" / "_seal_build"
SEAL_DLL_PATH = ROOT / "sentinelgate" / "config" / "sg_seal.dll"
SEAL_HASH_FILE = ROOT / "sentinelgate" / "config" / "_seal_hash.py"


def build_rust_validator() -> None:
    print("[1/4] Compiling Rust cf_validator.exe in release mode...")
    subprocess.run(["cargo", "build", "--release"], cwd=str(VALIDATOR_SRC), check=True)
    built_exe = VALIDATOR_SRC / "target" / "release" / "cf_validator.exe"
    if not built_exe.exists():
        raise FileNotFoundError(f"Expected compiled Rust binary at {built_exe}")
    VALIDATOR_BIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built_exe, VALIDATOR_BIN)
    digest = hashlib.sha256(VALIDATOR_BIN.read_bytes()).hexdigest().upper()
    HASH_FILE.write_text(
        f'"""Auto-maintained SHA-256 digest of the bundled Rust cf_validator.exe binary."""\n\n'
        f'EXPECTED_VALIDATOR_SHA256 = "{digest}"\n',
        encoding="utf-8",
    )
    print(f"  [OK] Validator ready at {VALIDATOR_BIN} (SHA-256: {digest[:16]}...)")


def compile_native_seal_dll(
    account_id: str = "",
    api_token: str = "",
    worker_url: str = "",
    worker_token: str = "",
    out_dll: Path | None = None,
    write_hash_module: bool = True,
) -> str:
    """Compile stripped native Rust sg_seal.dll with anti-debug & memory wiping."""
    SEAL_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    rs_file = SEAL_BUILD_DIR / "sg_seal.rs"
    target_dll = out_dll or SEAL_DLL_PATH
    rs_source = build_native_seal_rust_source(
        account_id=account_id,
        api_token=api_token,
        worker_url=worker_url,
        worker_token=worker_token,
    )
    rs_file.write_text(rs_source, encoding="utf-8")

    cmd = [
        "rustc",
        "--edition",
        "2021",
        "--crate-type",
        "cdylib",
        "-C",
        "opt-level=3",
        "-C",
        "lto=fat",
        "-C",
        "strip=symbols",
        "-C",
        "panic=abort",
        "-o",
        str(target_dll),
        str(rs_file),
    ]
    subprocess.run(cmd, cwd=str(SEAL_BUILD_DIR), check=True)
    digest = hashlib.sha256(target_dll.read_bytes()).hexdigest().upper()

    # Remove compiler sidecar artifacts (.lib, .exp, .pdb) and transient .rs immediately
    for leftover in SEAL_BUILD_DIR.iterdir():
        leftover.unlink(missing_ok=True)
    SEAL_BUILD_DIR.rmdir()
    for sidecar_ext in (".dll.lib", ".dll.exp", ".pdb", ".lib", ".exp"):
        sc = target_dll.with_suffix(sidecar_ext)
        if sc.exists():
            sc.unlink()

    if write_hash_module:
        SEAL_HASH_FILE.write_text(
            f'"""Auto-maintained SHA-256 digest of compiled native sg_seal.dll (empty in unbuilt source)."""\n\n'
            f'EXPECTED_SEAL_DLL_SHA256 = "{digest}"\n',
            encoding="utf-8",
        )
    return digest


def prepare_native_seal() -> None:
    """Seal Worker or Direct Cloudflare credentials into stripped native sg_seal.dll."""
    print("[2/4] Sealing Cloudflare transport into stripped native Rust DLL (anti-debug + volatile wipe)...")
    worker_url = (os.environ.get("SG_WORKER_URL") or "").strip().rstrip("/")
    worker_token = (os.environ.get("SG_WORKER_TOKEN") or "").strip()
    acct_id = (os.environ.get("CF_ACCOUNT_ID") or "").strip()
    api_token = (os.environ.get("CF_API_TOKEN") or "").strip()

    # Purge any legacy CF_* from DPAPI vault if still present
    v_acct, v_tok = extract_legacy_cf_from_vault(purge=True)
    if not acct_id:
        acct_id = v_acct
    if not api_token:
        api_token = v_tok

    if not (worker_url and worker_token) and not (acct_id and api_token):
        mode = input("Select sealing mode - [1] Zero-Token Worker Relay (Recommended) or [2] Direct Cloudflare API: ").strip()
        if mode == "1":
            worker_url = input("Enter Cloudflare Worker Relay URL (e.g. https://sentinelgate-relay.<sub>.workers.dev): ").strip().rstrip("/")
            worker_token = getpass.getpass("Enter RELAY_CLIENT_SECRET (hidden): ").strip()
        else:
            acct_id = input("Enter Cloudflare Account ID (will be sealed into native DLL): ").strip()
            api_token = getpass.getpass("Enter Cloudflare API Token (hidden, sealed into native DLL): ").strip()

    digest = compile_native_seal_dll(
        account_id=acct_id,
        api_token=api_token,
        worker_url=worker_url,
        worker_token=worker_token,
    )
    mode_desc = "Zero-Token Worker Relay" if (worker_url and worker_token) else "Direct Native Sealed"
    print(f"  [OK] {mode_desc} sg_seal.dll compiled & stripped (SHA-256: {digest[:16]}...)")


def cleanup_build_artifacts() -> None:
    """Remove transient sealed DLL, hash, Rust source, and intermediate C build files from disk."""
    for fpath in (SEAL_DLL_PATH, ROOT / "sentinelgate" / "config" / "_sealed_cf.py"):
        if fpath.exists():
            fpath.unlink()
    for sc in (ROOT / "sentinelgate" / "config").glob("sg_seal.*"):
        sc.unlink(missing_ok=True)
    if SEAL_BUILD_DIR.exists():
        shutil.rmtree(SEAL_BUILD_DIR, ignore_errors=True)
    SEAL_HASH_FILE.write_text(
        '"""Auto-maintained SHA-256 digest of compiled native sg_seal.dll (empty in unbuilt source)."""\n\n'
        'EXPECTED_SEAL_DLL_SHA256 = ""\n',
        encoding="utf-8",
    )
    for temp_dir in ("main.build", "main.dist", "main.onefile-build", "build"):
        p = DIST_DIR / temp_dir
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
        p_root = ROOT / temp_dir
        if p_root.exists():
            shutil.rmtree(p_root, ignore_errors=True)


def build_nuitka(onefile: bool = True) -> None:
    print("[3/4] Compiling SentinelGate AI natively with Nuitka (C machine code, no .py sources)...")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        *(["--onefile"] if onefile else []),
        "--windows-console-mode=disable",
        "--assume-yes-for-downloads",
        "--msvc=latest",
        "--include-package=sentinelgate",
        "--include-package=flask",
        "--include-package=werkzeug",
        "--include-package-data=pythonnet",
        "--include-package-data=clr_loader",
        "--nofollow-import-to=numpy,scipy,matplotlib,pandas,PIL,pytest,unittest,IPython,tkinter,google.genai",
        f"--include-data-dir={ROOT / 'sentinelgate' / 'ui'}=sentinelgate/ui",
        f"--include-data-files={VALIDATOR_BIN}=sentinelgate/validator/bin/cf_validator.exe",
        f"--include-data-files={SEAL_DLL_PATH}=sentinelgate/config/sg_seal.dll",
        "--output-filename=SentinelGateAI.exe",
        f"--output-dir={DIST_DIR}",
        str(ROOT / "sentinelgate" / "main.py"),
    ]
    subprocess.run(cmd, cwd=str(ROOT), check=True)
    print("[4/4] Native Nuitka build finished successfully.")


def build_pyinstaller() -> None:
    print("[3/4] Compiling SentinelGate AI via PyInstaller --onefile (fallback)...")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name",
        "SentinelGateAI",
        "--distpath",
        str(DIST_DIR),
        "--add-data",
        f"{ROOT / 'sentinelgate' / 'ui'};sentinelgate/ui",
        "--add-data",
        f"{VALIDATOR_BIN};sentinelgate/validator/bin",
        "--add-data",
        f"{SEAL_DLL_PATH};sentinelgate/config",
        "--hidden-import",
        "webview",
        str(ROOT / "sentinelgate" / "main.py"),
    ]
    subprocess.run(cmd, cwd=str(ROOT), check=True)
    print("[4/4] PyInstaller build finished successfully.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build tamper-proof SentinelGateAI.exe")
    parser.add_argument("--backend", choices=["nuitka", "pyinstaller"], default="nuitka")
    parser.add_argument("--standalone-dir", action="store_true", help="Build Nuitka folder instead of onefile exe")
    args = parser.parse_args()

    try:
        build_rust_validator()
        prepare_native_seal()
        if args.backend == "nuitka":
            build_nuitka(onefile=not args.standalone_dir)
        else:
            build_pyinstaller()
    finally:
        cleanup_build_artifacts()

    exe_path = DIST_DIR / "SentinelGateAI.exe"
    print(f"\n[DONE] Output executable: {exe_path} (exists={exe_path.exists()})")


if __name__ == "__main__":
    main()
