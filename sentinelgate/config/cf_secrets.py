"""Native Rust/C binary secret sealing & zero-token Worker transport resolver.

Security Architecture:
- Supports two production sealing modes inside stripped native machine code (`sg_seal.dll`):
  1. Zero-Token Cloudflare Worker Mode (`mode = 2`):
     Only the Worker relay URL + block-only relay secret live in native code.
     CF_ACCOUNT_ID and CF_API_TOKEN NEVER exist on the user's PC at all.
  2. Direct Native Sealed Mode (`mode = 1`):
     Cloudflare credentials are split across shuffled, keystream-encrypted byte tables
     inside stripped native Rust machine code with anti-debugger detection and
     volatile memory zeroing (`write_volatile`).
- In compiled builds, disk vaults and environment variables are strictly ignored.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any

from sentinelgate.config._seal_hash import EXPECTED_SEAL_DLL_SHA256
from sentinelgate.config.paths import get_bundle_root, is_compiled_binary
from sentinelgate.config.vault import (
    ApiKeyVault,
    dpapi_protect,
    dpapi_unprotect,
    save_gemini_install_seed,
)

_FIXED_SLOT_LEN = 256
_CF_ADMIN_HKLM_SUBKEY = r"SOFTWARE\SentinelGateAI"
_CF_ADMIN_ENTROPY_PREFIX = b"SentinelGateAI::CF_ADMIN::v1"
_CF_ADMIN_DIR_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
_CF_ADMIN_FILE_SDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
_CF_ADMIN_REG_SDDL = "D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)"
_SE_FILE_OBJECT = 1
_SE_REGISTRY_KEY = 4
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000


@dataclass(frozen=True)
class CloudflareTransportConfig:
    mode: str  # "worker", "direct", "admin_locked", or "none"
    account_id: str = ""
    api_token: str = ""
    worker_url: str = ""
    worker_token: str = ""

    def is_ready(self) -> bool:
        if self.mode == "worker":
            return bool(self.worker_url and self.worker_token)
        if self.mode == "direct":
            return bool(self.account_id and self.api_token)
        return False

    def is_admin_locked(self) -> bool:
        return self.mode == "admin_locked"


def is_admin_process() -> bool:
    """Return True when the current process holds Windows Administrator privileges."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def get_admin_cf_dir() -> Path:
    """Return shared Admin-locked ProgramData directory for Cloudflare credentials."""
    prog_data = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(prog_data) / "SentinelGateAI" / "AdminLock"


def get_admin_cf_vault_path() -> Path:
    """Return path to the Admin-ACL-protected Machine DPAPI Cloudflare credential blob."""
    return get_admin_cf_dir() / "cf_admin.dpapi"


def _apply_sddl_dacl(target: str | int, obj_type: int, sddl: str, by_handle: bool = False) -> None:
    """Apply a protected Windows SDDL DACL (and BUILTIN\\Administrators owner when OS-elevated)."""
    if os.name != "nt":
        return

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    real_admin = False
    try:
        real_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        real_admin = False

    full_sddl = f"O:BA{sddl}" if real_admin else sddl
    p_sd = wintypes.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(full_sddl, 1, ctypes.byref(p_sd), None):
        raise OSError(f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {ctypes.GetLastError()}")

    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        p_dacl = wintypes.LPVOID()
        if not advapi32.GetSecurityDescriptorDacl(p_sd, ctypes.byref(present), ctypes.byref(p_dacl), ctypes.byref(defaulted)):
            raise OSError(f"GetSecurityDescriptorDacl failed: {ctypes.GetLastError()}")

        p_owner = wintypes.LPVOID()
        sec_info = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
        if real_admin and advapi32.GetSecurityDescriptorOwner(p_sd, ctypes.byref(p_owner), ctypes.byref(defaulted)) and p_owner.value:
            sec_info |= _OWNER_SECURITY_INFORMATION
        else:
            p_owner = None

        rc = (
            advapi32.SetSecurityInfo(wintypes.HANDLE(target), obj_type, sec_info, p_owner, None, p_dacl, None)
            if by_handle
            else advapi32.SetNamedSecurityInfoW(str(target), obj_type, sec_info, p_owner, None, p_dacl, None)
        )
        if rc != 0:
            raise PermissionError(f"Failed setting Windows Admin-only ACL (Win32 code {rc}).")
    finally:
        kernel32.LocalFree(p_sd)


def lock_path_admin_only(path: Path, is_dir: bool = False) -> None:
    """Restrict filesystem object permissions exclusively to NT AUTHORITY\\SYSTEM and BUILTIN\\Administrators."""
    _apply_sddl_dacl(
        str(path),
        _SE_FILE_OBJECT,
        _CF_ADMIN_DIR_SDDL if is_dir else _CF_ADMIN_FILE_SDDL,
        by_handle=False,
    )


def save_admin_cf_credentials(
    account_id: str = "",
    api_token: str = "",
    worker_url: str = "",
    worker_token: str = "",
    vault_path: Path | None = None,
    entropy_bytes: bytes | None = None,
) -> None:
    """Encrypt and store Cloudflare credentials in a strict Windows Administrator/SYSTEM-only vault."""
    if os.name == "nt" and not is_admin_process():
        raise PermissionError("Administrator access on this desktop is required to configure Cloudflare credentials.")

    w_url = (worker_url or "").strip().rstrip("/")
    w_tok = (worker_token or "").strip()
    acct = (account_id or "").strip()
    tok = (api_token or "").strip()
    if w_url and w_tok:
        mode = "worker"
    elif acct and tok:
        mode = "direct"
    else:
        raise ValueError("Provide either Cloudflare Account ID + API Token or Worker URL + Relay Secret.")

    reg_entropy = entropy_bytes
    if reg_entropy is None:
        reg_entropy = os.urandom(32)
        if os.name == "nt":
            import winreg

            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, _CF_ADMIN_HKLM_SUBKEY, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "SealEntropy", 0, winreg.REG_BINARY, reg_entropy)
                winreg.SetValueEx(key, "Mode", 0, winreg.REG_SZ, mode)
                _apply_sddl_dacl(int(key.handle), _SE_REGISTRY_KEY, _CF_ADMIN_REG_SDDL, by_handle=True)

    payload = json.dumps(
        {
            "mode": mode,
            "account_id": acct if mode == "direct" else "",
            "api_token": tok if mode == "direct" else "",
            "worker_url": w_url if mode == "worker" else "",
            "worker_token": w_tok if mode == "worker" else "",
        },
        separators=(",", ":"),
    ).encode("utf-8")

    dpapi_entropy = _CF_ADMIN_ENTROPY_PREFIX + (reg_entropy or b"")
    cipher = dpapi_protect(payload, entropy=dpapi_entropy, local_machine=True)

    target = vault_path or get_admin_cf_vault_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path_admin_only(target.parent, is_dir=True)
    target.write_bytes(cipher)
    lock_path_admin_only(target, is_dir=False)


def _read_hklm_entropy() -> bytes:
    if os.name != "nt":
        return b""
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CF_ADMIN_HKLM_SUBKEY, 0, winreg.KEY_READ) as key:
        val, _ = winreg.QueryValueEx(key, "SealEntropy")
        return bytes(val) if val else b""


def is_admin_cf_store_present(vault_path: Path | None = None) -> bool:
    """Detect whether an Admin-locked Cloudflare credential store exists (even if read is denied)."""
    if os.name == "nt":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CF_ADMIN_HKLM_SUBKEY, 0, winreg.KEY_READ):
                return True
        except PermissionError:
            return True
        except FileNotFoundError:
            pass

    target = vault_path or get_admin_cf_vault_path()
    for p in (target.parent, target):
        try:
            os.stat(p)
            return True
        except PermissionError:
            return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def load_admin_cf_credentials(
    vault_path: Path | None = None,
    entropy_bytes: bytes | None = None,
) -> CloudflareTransportConfig:
    """Load Cloudflare transport config ONLY if Administrator privileges succeed against ACL & DPAPI."""
    if os.name == "nt" and not is_admin_process():
        if is_admin_cf_store_present(vault_path):
            return CloudflareTransportConfig(mode="admin_locked")
        return CloudflareTransportConfig(mode="none")

    target = vault_path or get_admin_cf_vault_path()
    try:
        reg_entropy = entropy_bytes if entropy_bytes is not None else _read_hklm_entropy()
        cipher = target.read_bytes()
        dpapi_entropy = _CF_ADMIN_ENTROPY_PREFIX + (reg_entropy or b"")
        plain = dpapi_unprotect(cipher, entropy=dpapi_entropy, local_machine=True)
        data = json.loads(plain.decode("utf-8"))
        if not isinstance(data, dict):
            return CloudflareTransportConfig(mode="none")
        mode = str(data.get("mode") or "")
        if mode == "worker":
            w_url = str(data.get("worker_url") or "").strip().rstrip("/")
            w_tok = str(data.get("worker_token") or "").strip()
            if w_url and w_tok:
                return CloudflareTransportConfig(mode="worker", worker_url=w_url, worker_token=w_tok)
        elif mode == "direct":
            acct = str(data.get("account_id") or "").strip()
            tok = str(data.get("api_token") or "").strip()
            if acct and tok:
                return CloudflareTransportConfig(mode="direct", account_id=acct, api_token=tok)
    except PermissionError:
        return CloudflareTransportConfig(mode="admin_locked")
    except FileNotFoundError:
        return CloudflareTransportConfig(mode="none")
    except Exception:
        return CloudflareTransportConfig(mode="none")
    return CloudflareTransportConfig(mode="none")


def _derive_stream(key: bytes, salt: bytes, slot_id: int, length: int) -> bytes:
    """Deterministic multi-block SHA-256 keystream used at build time and mirrored in Rust."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(
            key + salt + slot_id.to_bytes(1, "big") + counter.to_bytes(4, "big") + b"SG::NATIVE::SEAL"
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _encode_slot_bytes(raw_str: str, slot_id: int) -> dict[str, list[int]]:
    raw_b = (raw_str or "").strip().encode("utf-8")
    if len(raw_b) + 2 > _FIXED_SLOT_LEN:
        raise ValueError(f"Secret slot {slot_id} exceeds {_FIXED_SLOT_LEN} bytes.")

    pad_len = _FIXED_SLOT_LEN - (2 + len(raw_b))
    len_hi = (len(raw_b) >> 8) & 0xFF
    len_lo = len(raw_b) & 0xFF
    plain = bytes([len_hi, len_lo]) + raw_b + os.urandom(pad_len)

    key = os.urandom(32)
    salt = os.urandom(32)
    stream = _derive_stream(key, salt, slot_id, _FIXED_SLOT_LEN)
    masked = [
        (plain[i] ^ stream[i] ^ ((i * 97 + slot_id * 17 + 31) & 0xFF))
        for i in range(_FIXED_SLOT_LEN)
    ]

    perm = list(range(_FIXED_SLOT_LEN))
    secrets.SystemRandom().shuffle(perm)
    shuffled = [0] * _FIXED_SLOT_LEN
    for orig_idx, pos in enumerate(perm):
        shuffled[pos] = masked[orig_idx]

    k_enc = [key[i] ^ ((i * 53 + slot_id * 11 + 19) & 0xFF) for i in range(32)]
    s_enc = [salt[i] ^ ((i * 71 + slot_id * 7 + 11) & 0xFF) for i in range(32)]
    return {"k": k_enc, "s": s_enc, "p": perm, "c": shuffled}


def build_native_seal_rust_source(
    account_id: str = "",
    api_token: str = "",
    worker_url: str = "",
    worker_token: str = "",
    admin_vault: bool = False,
) -> str:
    """Generate stripped native Rust cdylib source encoding sealed transport credentials.

    Includes Windows anti-debugger detection and volatile memory wiping.
    Supports:
    - mode 1: Direct sealed Cloudflare credentials
    - mode 2: Zero-Token Worker Relay
    - mode 3: Windows Admin-Locked Vault (credentials prompted during desktop Setup)
    """
    use_worker = bool(worker_url.strip() and worker_token.strip())
    use_direct = bool(account_id.strip() and api_token.strip())
    if not use_worker and not use_direct and not admin_vault:
        raise ValueError("Provide Worker credentials, Direct Cloudflare credentials, or admin_vault=True.")

    mode_num = 2 if use_worker else (1 if use_direct else 3)
    slots = [
        _encode_slot_bytes(account_id if mode_num == 1 else "", 0),
        _encode_slot_bytes(api_token if mode_num == 1 else "", 1),
        _encode_slot_bytes(worker_url.rstrip("/") if mode_num == 2 else "", 2),
        _encode_slot_bytes(worker_token if mode_num == 2 else "", 3),
    ]

    def fmt_u8(arr: list[int]) -> str:
        return "[" + ", ".join(str(x) for x in arr) + "]"

    def fmt_usize(arr: list[int]) -> str:
        return "[" + ", ".join(str(x) for x in arr) + "]"

    return f'''#![allow(non_snake_case)]
use std::ptr;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {{
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(hProcess: isize, pbDebuggerPresent: *mut i32) -> i32;
    fn GetCurrentProcess() -> isize;
}}

#[inline(always)]
fn debugger_detected() -> bool {{
    #[cfg(windows)]
    unsafe {{
        if IsDebuggerPresent() != 0 {{
            return true;
        }}
        let mut remote: i32 = 0;
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote as *mut i32) != 0 && remote != 0 {{
            return true;
        }}
    }}
    false
}}

// Compact SHA-256 implementation (no external crates required)
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_bytes(msg: &[u8]) -> [u8; 32] {{
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (msg.len() as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {{
        padded.push(0);
    }}
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {{
        let mut w = [0u32; 64];
        for i in 0..16 {{
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }}
        for i in 16..64 {{
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }}
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {{
            let S1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(S1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let S0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = S0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }}
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }}
    let mut out = [0u8; 32];
    for i in 0..8 {{
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }}
    out
}}

struct SlotData {{
    k: [u8; 32],
    s: [u8; 32],
    p: [usize; 256],
    c: [u8; 256],
}}

static SLOTS: [SlotData; 4] = [
    SlotData {{ k: {fmt_u8(slots[0]["k"])}, s: {fmt_u8(slots[0]["s"])}, p: {fmt_usize(slots[0]["p"])}, c: {fmt_u8(slots[0]["c"])} }},
    SlotData {{ k: {fmt_u8(slots[1]["k"])}, s: {fmt_u8(slots[1]["s"])}, p: {fmt_usize(slots[1]["p"])}, c: {fmt_u8(slots[1]["c"])} }},
    SlotData {{ k: {fmt_u8(slots[2]["k"])}, s: {fmt_u8(slots[2]["s"])}, p: {fmt_usize(slots[2]["p"])}, c: {fmt_u8(slots[2]["c"])} }},
    SlotData {{ k: {fmt_u8(slots[3]["k"])}, s: {fmt_u8(slots[3]["s"])}, p: {fmt_usize(slots[3]["p"])}, c: {fmt_u8(slots[3]["c"])} }},
];

#[inline(never)]
fn volatile_zero(buf: &mut [u8]) {{
    for b in buf.iter_mut() {{
        unsafe {{ ptr::write_volatile(b as *mut u8, 0); }}
    }}
}}

#[no_mangle]
pub extern "C" fn sg_seal_mode() -> i32 {{
    if debugger_detected() {{
        return 0;
    }}
    {mode_num}
}}

#[no_mangle]
pub extern "C" fn sg_wipe_buffer(buf: *mut u8, len: usize) {{
    if buf.is_null() || len == 0 {{
        return;
    }}
    unsafe {{
        for i in 0..len {{
            ptr::write_volatile(buf.add(i), 0);
        }}
    }}
}}

#[no_mangle]
pub extern "C" fn sg_unseal_slot(slot_id: i32, out_buf: *mut u8, max_len: usize) -> i32 {{
    if debugger_detected() || out_buf.is_null() || slot_id < 0 || slot_id > 3 {{
        return -1;
    }}
    let sid = slot_id as usize;
    let slot = &SLOTS[sid];

    let mut key = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {{
        key[i] = slot.k[i] ^ (((i * 53 + sid * 11 + 19) & 0xFF) as u8);
        salt[i] = slot.s[i] ^ (((i * 71 + sid * 7 + 11) & 0xFF) as u8);
    }}

    let mut stream = [0u8; 256];
    for ctr in 0u32..8u32 {{
        let mut msg = Vec::with_capacity(85);
        msg.extend_from_slice(&key);
        msg.extend_from_slice(&salt);
        msg.push(sid as u8);
        msg.extend_from_slice(&ctr.to_be_bytes());
        msg.extend_from_slice(b"SG::NATIVE::SEAL");
        let digest = sha256_bytes(&msg);
        stream[(ctr as usize) * 32..(ctr as usize + 1) * 32].copy_from_slice(&digest);
        volatile_zero(&mut msg);
    }}

    let mut plain = [0u8; 256];
    for i in 0..256 {{
        let masked = slot.c[slot.p[i]];
        plain[i] = masked ^ stream[i] ^ (((i * 97 + sid * 17 + 31) & 0xFF) as u8);
    }}

    let len = ((plain[0] as usize) << 8) | (plain[1] as usize);
    let rc = if len + 2 > 256 || len > max_len {{
        -2
    }} else {{
        unsafe {{
            ptr::copy_nonoverlapping(plain.as_ptr().add(2), out_buf, len);
        }}
        len as i32
    }};

    volatile_zero(&mut key);
    volatile_zero(&mut salt);
    volatile_zero(&mut stream);
    volatile_zero(&mut plain);
    rc
}}
'''


def _get_seal_dll_path() -> Path:
    return get_bundle_root() / "config" / "sg_seal.dll"


def _load_native_seal_dll() -> ctypes.CDLL | None:
    dll_path = _get_seal_dll_path()
    if not dll_path.exists() or not EXPECTED_SEAL_DLL_SHA256:
        return None
    actual = hashlib.sha256(dll_path.read_bytes()).hexdigest().upper()
    if actual != EXPECTED_SEAL_DLL_SHA256.upper():
        return None
    lib = ctypes.CDLL(str(dll_path))
    lib.sg_seal_mode.restype = ctypes.c_int
    lib.sg_unseal_slot.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
    lib.sg_unseal_slot.restype = ctypes.c_int
    lib.sg_wipe_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.sg_wipe_buffer.restype = None
    return lib


def _read_native_slot(lib: ctypes.CDLL, slot_id: int) -> str:
    buf = ctypes.create_string_buffer(_FIXED_SLOT_LEN)
    try:
        n = lib.sg_unseal_slot(slot_id, buf, _FIXED_SLOT_LEN)
        if n <= 0:
            return ""
        return bytes(buf.raw[:n]).decode("utf-8")
    finally:
        lib.sg_wipe_buffer(buf, _FIXED_SLOT_LEN)


def get_cloudflare_transport_config() -> CloudflareTransportConfig:
    """Resolve Cloudflare transport enforcing desktop Administrator privilege boundaries.

    On Windows:
    - Any unelevated / standard-user process receives `mode='admin_locked'` whenever
      the Admin-only Cloudflare vault exists or when running as a compiled desktop build.
    - Only Windows Administrator processes can unseal `%ProgramData%\\SentinelGateAI\\AdminLock`
      + `HKLM\\SOFTWARE\\SentinelGateAI`.
    """
    lib = _load_native_seal_dll()

    if os.name == "nt" and not is_admin_process():
        if is_admin_cf_store_present() or is_compiled_binary() or lib is not None:
            return CloudflareTransportConfig(mode="admin_locked")
    else:
        admin_cfg = load_admin_cf_credentials()
        if admin_cfg.is_ready():
            return admin_cfg

        if lib is not None:
            mode_num = lib.sg_seal_mode()
            if mode_num == 2:
                w_url = _read_native_slot(lib, 2)
                w_tok = _read_native_slot(lib, 3)
                if w_url and w_tok:
                    return CloudflareTransportConfig(mode="worker", worker_url=w_url, worker_token=w_tok)
            elif mode_num == 1:
                acct = _read_native_slot(lib, 0)
                tok = _read_native_slot(lib, 1)
                if acct and tok:
                    return CloudflareTransportConfig(mode="direct", account_id=acct, api_token=tok)
            elif mode_num == 3:
                return CloudflareTransportConfig(mode="none")
            return CloudflareTransportConfig(mode="none")

    # Never read env vars when running from a compiled desktop executable
    if is_compiled_binary():
        return CloudflareTransportConfig(mode="none")

    w_url = (os.environ.get("SG_WORKER_URL") or "").strip().rstrip("/")
    w_tok = (os.environ.get("SG_WORKER_TOKEN") or "").strip()
    if w_url and w_tok:
        return CloudflareTransportConfig(mode="worker", worker_url=w_url, worker_token=w_tok)

    acct = (os.environ.get("CF_ACCOUNT_ID") or "").strip()
    tok = (os.environ.get("CF_API_TOKEN") or "").strip()
    if acct and tok:
        return CloudflareTransportConfig(mode="direct", account_id=acct, api_token=tok)

    return CloudflareTransportConfig(mode="none")


def get_cloudflare_credentials() -> tuple[str, str]:
    """Legacy tuple helper returning (account_id, api_token) when in direct mode."""
    cfg = get_cloudflare_transport_config()
    return cfg.account_id, cfg.api_token


def interactive_admin_setup() -> int:
    """Elevated Administrator setup prompt for Cloudflare API & Gemini API credentials."""
    print("=== SentinelGate AI - Administrator Credential Setup ===")
    if os.name == "nt" and not is_admin_process():
        print("[ERROR] Windows Administrator privileges are required to lock Cloudflare credentials.")
        return 5

    already_locked = is_admin_cf_store_present()
    if already_locked:
        print("An Admin-locked Cloudflare store already exists on this PC (leave blank to keep).")

    acct_id = input("Enter Cloudflare Account ID (or leave blank to keep/skip): ").strip()
    cf_token = getpass.getpass("Enter Cloudflare API Token (hidden, leave blank to keep/skip): ").strip()
    if acct_id and cf_token:
        save_admin_cf_credentials(account_id=acct_id, api_token=cf_token)
        print("[OK] Cloudflare credentials sealed in Admin/SYSTEM-only store (Machine DPAPI + HKLM + NTFS ACL).")
    elif not already_locked:
        print("[!] Cloudflare credentials skipped — re-run elevated setup anytime to configure.")

    vault = ApiKeyVault()
    has_gem = vault.get_masked_status()["keys"]["GEMINI_API_KEY"]["configured"]
    prompt_suffix = " (leave blank to keep existing)" if has_gem else ""
    gem_key = getpass.getpass(f"Enter Gemini AI API Key (hidden){prompt_suffix}: ").strip()
    gem_backup = getpass.getpass("Enter optional Backup Gemini AI API Key (hidden, Enter to skip): ").strip()
    if gem_key or gem_backup:
        updates: dict[str, str] = {}
        if gem_key:
            updates["GEMINI_API_KEY"] = gem_key
        if gem_backup:
            updates["GEMINI_API_KEY_BACKUP"] = gem_backup
        vault.update_credentials(updates)
        if gem_key:
            save_gemini_install_seed(gem_key, gem_backup)
        print("[OK] Gemini AI API key encrypted in Windows DPAPI Vault.")
    else:
        print("[OK] Gemini AI API key configuration unchanged.")

    return 0


if __name__ == "__main__":
    if "--interactive-setup" in sys.argv[1:]:
        raise SystemExit(interactive_admin_setup())
