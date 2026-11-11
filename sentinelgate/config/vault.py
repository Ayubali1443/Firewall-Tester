"""Windows DPAPI-encrypted vault for Gemini keys and Worker relay settings.

The Cloudflare API token remains exclusively in Cloudflare Worker Secrets. The
relay client key stored here is only the app-to-Worker shared key.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from sentinelgate.config.paths import get_app_data_dir, get_project_root, is_compiled_binary


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_CRYPTPROTECT_LOCAL_MACHINE = 0x04


def dpapi_protect(
    raw_bytes: bytes,
    entropy: bytes = b"SentinelGateAI::DPAPI::v2",
    local_machine: bool = False,
) -> bytes:
    """Encrypt arbitrary bytes with Windows DPAPI (user-bound by default, or machine-bound)."""
    if os.name != "nt":
        return base64.b64encode(raw_bytes)

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_buf = ctypes.create_string_buffer(raw_bytes, len(raw_bytes))
    in_blob = _DATA_BLOB(len(raw_bytes), in_buf)

    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
    ent_blob = _DATA_BLOB(len(entropy), ent_buf)

    out_blob = _DATA_BLOB()
    flags = _CRYPTPROTECT_UI_FORBIDDEN | (_CRYPTPROTECT_LOCAL_MACHINE if local_machine else 0)
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "SentinelGateAI",
        ctypes.byref(ent_blob),
        None,
        None,
        flags,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(f"CryptProtectData failed with error code {ctypes.GetLastError()}")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect(
    cipher_bytes: bytes,
    entropy: bytes = b"SentinelGateAI::DPAPI::v2",
    local_machine: bool = False,
) -> bytes:
    """Decrypt bytes previously protected by Windows DPAPI."""
    if os.name != "nt":
        return base64.b64decode(cipher_bytes)

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_buf = ctypes.create_string_buffer(cipher_bytes, len(cipher_bytes))
    in_blob = _DATA_BLOB(len(cipher_bytes), in_buf)

    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
    ent_blob = _DATA_BLOB(len(entropy), ent_buf)

    out_blob = _DATA_BLOB()
    flags = _CRYPTPROTECT_UI_FORBIDDEN
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob),
        None,
        None,
        flags,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed with error code {ctypes.GetLastError()}")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def mask_secret(value: str | None) -> str:
    """Return a safe masked representation of an AI API key for UI display."""
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 8:
        return "•" * len(v)
    return f"{v[:4]}{'•' * min(12, len(v) - 8)}{v[-4:]}"


def extract_legacy_cf_from_vault(vault_path: Path | None = None, purge: bool = False) -> tuple[str, str]:
    """Build-time migration helper to extract legacy CF_* from DPAPI vault and optionally purge them."""
    vp = vault_path or (get_app_data_dir() / "vault.dpapi")
    if not vp.exists():
        return "", ""
    try:
        payload = json.loads(dpapi_unprotect(vp.read_bytes()).decode("utf-8"))
        if not isinstance(payload, dict):
            return "", ""
        acct = str(payload.get("CF_ACCOUNT_ID") or "").strip()
        tok = str(payload.get("CF_API_TOKEN") or "").strip()
        if purge and ("CF_ACCOUNT_ID" in payload or "CF_API_TOKEN" in payload):
            cleaned = {
                "GEMINI_API_KEY": str(payload.get("GEMINI_API_KEY") or "").strip(),
                "GEMINI_API_KEY_BACKUP": str(payload.get("GEMINI_API_KEY_BACKUP") or "").strip(),
            }
            vp.write_bytes(dpapi_protect(json.dumps(cleaned, separators=(",", ":")).encode("utf-8")))
        return acct, tok
    except Exception:
        return "", ""


class ApiKeyVault:
    """Manages DPAPI-encrypted user-editable app and relay credentials."""

    FIELDS = (
        "GEMINI_API_KEY",
        "GEMINI_API_KEY_BACKUP",
        "WORKER_URL",
        "RELAY_CLIENT_SECRET",
    )

    FORBIDDEN_FIELDS = ("CF_ACCOUNT_ID", "ACCOUNT_ID", "CF_API_TOKEN", "API_TOKEN", "CF_API_KEY")

    def __init__(self, vault_path: Path | None = None) -> None:
        self.vault_path = vault_path or (get_app_data_dir() / "vault.dpapi")
        self._ensure_migrated()

    def _read_raw_all(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        try:
            encrypted = self.vault_path.read_bytes()
            decrypted = dpapi_unprotect(encrypted)
            payload = json.loads(decrypted.decode("utf-8"))
            if isinstance(payload, dict):
                return {str(k): str(v or "").strip() for k, v in payload.items()}
        except Exception:
            return {}
        return {}

    def _read_raw_vault(self) -> dict[str, str]:
        payload = self._read_raw_all()
        # In compiled builds, scrub any leftover legacy CF keys from disk automatically
        if is_compiled_binary() and any(f in payload for f in self.FORBIDDEN_FIELDS):
            clean = {k: payload.get(k, "") for k in self.FIELDS}
            self._write_raw_vault(clean)
            return clean
        return {k: payload.get(k, "") for k in self.FIELDS}

    def _write_raw_vault(self, data: dict[str, str]) -> None:
        clean = {k: str(data.get(k, "") or "").strip() for k in self.FIELDS}
        encoded = json.dumps(clean, separators=(",", ":")).encode("utf-8")
        encrypted = dpapi_protect(encoded)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_bytes(encrypted)

    def _discover_legacy_gemini_keys(self) -> dict[str, str]:
        """Never auto-import Gemini keys in compiled installs (prompt only when app opens)."""
        if is_compiled_binary():
            return {}
        root = get_project_root()
        candidates = [
            root / ".env",
            root / "Dns_Pentester" / ".env",
            root / "Search_Pentester" / ".env",
            root / "Dns_Uptester" / ".env",
            root / "Search_Uptester" / ".env",
        ]
        gemini_keys: list[str] = []
        for env_path in candidates:
            if not env_path.exists():
                continue
            vals = dotenv_values(env_path)
            gem = (vals.get("GEMINI_API_KEY") or "").strip()
            if gem and gem != "YOUR_GEMINI_API_KEY" and gem not in gemini_keys:
                gemini_keys.append(gem)

        merged: dict[str, str] = {}
        if gemini_keys:
            merged["GEMINI_API_KEY"] = gemini_keys[0]
        if len(gemini_keys) > 1:
            merged["GEMINI_API_KEY_BACKUP"] = gemini_keys[1]
        return merged

    def _ensure_migrated(self) -> None:
        current = self._read_raw_vault()
        if current.get("GEMINI_API_KEY"):
            return

        discovered = self._discover_legacy_gemini_keys()
        for k in self.FIELDS:
            if not current.get(k):
                env_val = (os.environ.get(k) or "").strip()
                current[k] = env_val or discovered.get(k, "")

        if any(current.values()):
            self._write_raw_vault(current)

    def get_credentials(self) -> dict[str, str]:
        """Return decrypted Gemini AI credentials dictionary."""
        creds = self._read_raw_vault()
        for k in self.FIELDS:
            if not creds.get(k):
                creds[k] = (os.environ.get(k) or "").strip()
        return creds

    def get_masked_status(self) -> dict[str, Any]:
        """Return masked secret status; the Worker URL is safe to display in the local UI."""
        creds = self.get_credentials()
        keys = {
            field: {
                "configured": bool(creds.get(field)),
                "masked": creds.get(field, "") if field == "WORKER_URL" else mask_secret(creds.get(field)),
            }
            for field in self.FIELDS
        }
        return {
            "vault_encrypted": self.vault_path.exists(),
            "keys": keys,
        }

    def update_credentials(self, updates: dict[str, str]) -> dict[str, Any]:
        """Securely update AI and Worker relay settings; never accepts Cloudflare API credentials."""
        for forbidden in self.FORBIDDEN_FIELDS:
            if forbidden in updates:
                raise PermissionError("Cloudflare API credentials are managed as Worker Secrets in Cloudflare.")

        if "WORKER_URL" in updates:
            worker_url = str(updates["WORKER_URL"] or "").strip().rstrip("/")
            if worker_url:
                from urllib.parse import urlparse

                parsed = urlparse(worker_url)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise ValueError("Worker URL must be a valid https:// URL without credentials, query, or fragment.")

        current = self.get_credentials()
        for field in self.FIELDS:
            if field in updates:
                new_val = str(updates[field] or "").strip()
                if new_val and "•" not in new_val:
                    current[field] = new_val
        self._write_raw_vault(current)
        return self.get_masked_status()

    def clear_backup_key(self) -> dict[str, Any]:
        """Allow clearing optional secondary Gemini fallback key only."""
        current = self.get_credentials()
        current["GEMINI_API_KEY_BACKUP"] = ""
        self._write_raw_vault(current)
        return self.get_masked_status()
