"""Build script for compiling SentinelGate AI into a tamper-proof standalone Windows executable."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

from sentinelgate.config.cf_secrets import (
    CloudflareTransportConfig,
    build_native_seal_rust_source,
    derive_build_handshake_parts,
    read_cf_from_env_or_dotenv,
    read_worker_from_env_or_dotenv,
)
from sentinelgate.config.vault import extract_legacy_cf_from_vault
from sentinelgate.core.cloudflare import CloudflareReadOnlyClient


ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
VALIDATOR_SRC = ROOT / "sentinelgate" / "validator"
VALIDATOR_BIN = VALIDATOR_SRC / "bin" / "cf_validator.exe"
HASH_FILE = ROOT / "sentinelgate" / "core" / "_validator_hash.py"
SEAL_BUILD_DIR = ROOT / "sentinelgate" / "config" / "_seal_build"
SEAL_DLL_PATH = ROOT / "sentinelgate" / "config" / "sg_seal.dll"
SEAL_HASH_FILE = ROOT / "sentinelgate" / "config" / "_seal_hash.py"
INSTALLER_SRC = ROOT / "sentinelgate" / "installer" / "src" / "main.rs"


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
    handshake_key: bytes | None = None,
    out_dll: Path | None = None,
    write_hash_module: bool = True,
    worker_url: str = "",
    relay_secret: str = "",
) -> str:
    """Compile stripped native Rust WinHTTP sg_seal.dll sealing Worker Relay (preferred) or Direct CF."""
    SEAL_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    rs_file = SEAL_BUILD_DIR / "sg_seal.rs"
    target_dll = out_dll or SEAL_DLL_PATH
    hs_key = handshake_key if handshake_key and len(handshake_key) == 32 else os.urandom(32)
    rs_source = build_native_seal_rust_source(
        account_id=account_id,
        api_token=api_token,
        handshake_key=hs_key,
        worker_url=worker_url,
        relay_secret=relay_secret,
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
        part_a, part_b = derive_build_handshake_parts(hs_key)
        SEAL_HASH_FILE.write_text(
            f'"""Auto-maintained integrity digest and obfuscated build handshake parts (empty in unbuilt source)."""\n\n'
            f'EXPECTED_SEAL_DLL_SHA256 = "{digest}"\n'
            f"SEAL_PART_A = {part_a!r}\n"
            f"SEAL_PART_B = {part_b!r}\n",
            encoding="utf-8",
        )
    return digest


def verify_credentials_before_build(
    account_id: str = "",
    api_token: str = "",
    worker_url: str = "",
    relay_secret: str = "",
) -> dict[str, object]:
    """Live-test Zero-Token Worker Relay (or direct CF credentials) BEFORE compiling native machine code."""
    w_url = (worker_url or "").strip().rstrip("/")
    r_sec = (relay_secret or "").strip()
    if w_url and r_sec:
        if not w_url.lower().startswith("https://"):
            return {"ok": False, "cf_ok": False, "mode": "worker", "error": "WORKER_URL must start with https://"}
        ro = CloudflareReadOnlyClient(
            CloudflareTransportConfig(mode="worker", worker_url=w_url, worker_token=r_sec)
        )
        cf_res = ro.verify_connection()
        if not cf_res.get("ok"):
            return {
                "ok": False,
                "cf_ok": False,
                "mode": "worker",
                "error": f"Worker relay verification failed: {cf_res.get('error', 'unknown error')}",
            }
        # Confirm unauthenticated callers are rejected (401)
        try:
            unauth_res = CloudflareReadOnlyClient(
                CloudflareTransportConfig(mode="worker", worker_url=w_url, worker_token="__invalid__")
            )._session.get(f"{w_url}/v1/health", timeout=8)
            if unauth_res.status_code != 401:
                return {
                    "ok": False,
                    "cf_ok": False,
                    "mode": "worker",
                    "error": f"Worker relay must reject unauthorized calls with 401 (got HTTP {unauth_res.status_code}).",
                }
        except Exception as exc:
            return {"ok": False, "cf_ok": False, "mode": "worker", "error": f"Worker auth probe failed: {exc}"}

        lists_map = ro.get_lists()
        return {
            "ok": True,
            "cf_ok": True,
            "mode": "worker",
            "rule_count": cf_res.get("rule_count", 0),
            "list_count": len(lists_map),
        }

    acct = (account_id or "").strip()
    tok = (api_token or "").strip()
    if not acct or not tok:
        return {
            "ok": False,
            "cf_ok": False,
            "error": "Missing WORKER_URL / RELAY_CLIENT_SECRET in .env (see worker/README.md).",
        }

    ro = CloudflareReadOnlyClient(CloudflareTransportConfig(mode="direct", account_id=acct, api_token=tok))
    cf_res = ro.verify_connection()
    if not cf_res.get("ok"):
        return {
            "ok": False,
            "cf_ok": False,
            "error": f"Cloudflare verification failed: {cf_res.get('error', 'unknown error')}",
        }

    lists_map = ro.get_lists()
    return {
        "ok": True,
        "cf_ok": True,
        "mode": "direct",
        "rule_count": cf_res.get("rule_count", 0),
        "list_count": len(lists_map),
    }


def prepare_native_seal(
    skip_live_check: bool = False,
    allow_unsafe_direct: bool = False,
) -> None:
    """Load Zero-Token Worker Relay config from `.env`, live-test it, and seal into native DLL.

    CF_ACCOUNT_ID and CF_API_TOKEN are NEVER embedded when using Worker Relay mode.
    """
    print("[2/4] Reading Worker Relay config from .env/environment & running pre-build API check...")
    extract_legacy_cf_from_vault(purge=True)

    worker_url, relay_secret = read_worker_from_env_or_dotenv(ROOT)
    if worker_url and relay_secret:
        if skip_live_check:
            print("  [!] Skipping live Worker Relay API test (--skip-live-check set).")
        else:
            print("  [*] Testing Zero-Token Worker Relay live (auth + upstream Gateway)...")
            check = verify_credentials_before_build(worker_url=worker_url, relay_secret=relay_secret)
            if not check.get("ok"):
                raise RuntimeError(str(check.get("error") or "Worker Relay verification failed."))
            print(
                f"  [OK] Pre-build Worker Relay check passed "
                f"({check.get('rule_count', 0)} rules, {check.get('list_count', 0)} lists; CF keys kept off client)."
            )
        digest = compile_native_seal_dll(worker_url=worker_url, relay_secret=relay_secret)
        print(f"  [OK] Zero-Token Worker Relay sg_seal.dll compiled & stripped (SHA-256: {digest[:16]}...)")
        return

    if not allow_unsafe_direct:
        raise RuntimeError(
            "Worker Relay credentials (WORKER_URL & RELAY_CLIENT_SECRET) are missing in .env!\n"
            "  To prevent Cloudflare API keys from ever touching client machines:\n"
            "    1. Follow worker/README.md (run: npx wrangler login ; .\\worker\\setup-worker.ps1)\n"
            "    2. Ensure WORKER_URL and RELAY_CLIENT_SECRET are set in .env\n"
            "    3. Re-run: .\\.venv\\Scripts\\python.exe build.py\n"
            "  (Only pass --allow-unsafe-direct-cf if explicitly building an offline single-PC test binary.)"
        )

    acct_id, api_token = read_cf_from_env_or_dotenv(ROOT)
    if not acct_id or not api_token:
        raise RuntimeError(
            "Direct CF credentials not found. Ensure ACCOUNT_ID and API_TOKEN are set in .env."
        )
    print("  [!] WARNING: --allow-unsafe-direct-cf active (sealing direct Cloudflare keys into native DLL).")
    if not skip_live_check:
        check = verify_credentials_before_build(account_id=acct_id, api_token=api_token)
        if not check.get("ok"):
            raise RuntimeError(str(check.get("error") or "Cloudflare credential verification failed."))
        print(
            f"  [OK] Pre-build Cloudflare API check passed "
            f"({check.get('rule_count', 0)} rules, {check.get('list_count', 0)} lists)."
        )
    digest = compile_native_seal_dll(account_id=acct_id, api_token=api_token)
    print(f"  [OK] Direct Native WinHTTP sg_seal.dll compiled & stripped (SHA-256: {digest[:16]}...)")


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
        '"""Auto-maintained integrity digest and obfuscated build handshake parts (empty in unbuilt source)."""\n\n'
        'EXPECTED_SEAL_DLL_SHA256 = ""\n'
        'SEAL_PART_A = b""\n'
        'SEAL_PART_B = b""\n',
        encoding="utf-8",
    )
    for temp_dir in ("main.build", "main.dist", "main.onefile-build", "build"):
        p = DIST_DIR / temp_dir
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
        p_root = ROOT / temp_dir
        if p_root.exists():
            shutil.rmtree(p_root, ignore_errors=True)


def build_nuitka() -> None:
    print("[3/4] Compiling SentinelGate AI natively with Nuitka (C machine code, no .py sources)...")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--onefile",
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


def build_single_setup_installer(payload_exe: Path, out_setup: Path | None = None) -> Path:
    """Compile single self-contained SentinelGateAI-Setup.exe via Rust embedding payload_exe."""
    if not payload_exe.exists():
        raise FileNotFoundError(f"Payload executable missing at {payload_exe}")
    target_setup = out_setup or (DIST_DIR / "SentinelGateAI-Setup.exe")
    target_setup.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SG_PAYLOAD_EXE"] = str(payload_exe.resolve())
    cmd = [
        "rustc",
        "--edition",
        "2021",
        "-C",
        "opt-level=3",
        "-C",
        "lto=fat",
        "-C",
        "strip=symbols",
        "-C",
        "link-arg=/MANIFEST:EMBED",
        "-C",
        "link-arg=/MANIFESTUAC:level='asInvoker'",
        "-o",
        str(target_setup),
        str(INSTALLER_SRC),
    ]
    subprocess.run(cmd, env=env, cwd=str(ROOT), check=True)
    for sidecar_ext in (".pdb", ".exp", ".lib"):
        sc = target_setup.with_suffix(sidecar_ext)
        if sc.exists():
            sc.unlink()
    return target_setup


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build tamper-proof SentinelGateAI-Setup.exe (Zero-Token Worker Relay + Nuitka + Rust seal)"
    )
    parser.add_argument("--skip-live-check", action="store_true", help="Skip pre-build live API test (offline build only)")
    parser.add_argument(
        "--allow-unsafe-direct-cf",
        action="store_true",
        help="Unsafe fallback: embed direct CF credentials locally if WORKER_URL is not configured",
    )
    args = parser.parse_args()

    try:
        build_rust_validator()
        prepare_native_seal(
            skip_live_check=args.skip_live_check,
            allow_unsafe_direct=args.allow_unsafe_direct_cf,
        )
        build_nuitka()
    finally:
        cleanup_build_artifacts()

    exe_path = DIST_DIR / "SentinelGateAI.exe"
    if not exe_path.exists():
        raise FileNotFoundError(f"Expected compiled binary at {exe_path}")

    print("[5/5] Packaging single self-contained SentinelGateAI-Setup.exe (with uninstaller)...")
    setup_path = build_single_setup_installer(exe_path)
    exe_path.unlink(missing_ok=True)

    # Verify zero plaintext secrets leaked into packaged installer
    blob = setup_path.read_bytes()
    acct_id, api_token = read_cf_from_env_or_dotenv(ROOT)
    worker_url, relay_secret = read_worker_from_env_or_dotenv(ROOT)
    for label, sec in (
        ("ACCOUNT_ID", acct_id),
        ("API_TOKEN", api_token),
        ("WORKER_URL", worker_url),
        ("RELAY_CLIENT_SECRET", relay_secret),
    ):
        if sec and sec.encode("utf-8") in blob:
            setup_path.unlink(missing_ok=True)
            raise RuntimeError(f"SECURITY ABORT: {label} appeared in plaintext inside output binary!")

    print(f"\n[DONE] Single Setup Installer: {setup_path} ({setup_path.stat().st_size / (1024*1024):.2f} MB)")


if __name__ == "__main__":
    main()
