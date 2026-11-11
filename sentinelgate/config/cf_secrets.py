"""Hardened Native Rust Machine-Code Secret Sealing & WinHTTP Transport Engine.

Security Architecture:
- Direct Native Sealed Mode (`sg_seal.dll`):
  Cloudflare credentials are split across per-byte randomized non-linear byte tables
  with SHA-256 keystreams inside stripped native Rust machine code.
  All HTTPS requests to `api.cloudflare.com` run directly from native Rust via
  `winhttp.dll` (`WINHTTP_ACCESS_TYPE_NO_PROXY`).
  `ACCOUNT_ID` and `API_TOKEN` NEVER enter Python memory or Python objects in compiled builds.
- Protections against technical extraction & reverse engineering:
  - Zero credential-getter exports on `sg_seal.dll` (`sg_unseal_slot` absent).
  - Per-build PID-bound HMAC-SHA256 caller handshake compiled into Nuitka C extension
    (`_seal_hash.py`) prevents external callers from using a copied `sg_seal.dll`.
  - Native anti-debugger detection (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
    x64 hardware debug registers `Dr0..Dr3`) wipes stack secrets immediately.
  - Native WinHTTP bypasses user/system proxies and verifies server cert Issuer/Subject
    before sending any secret headers (blocks local Fiddler/mitmproxy/Burp MITM).
  - Native block-only JSON/path policy guard rejects allow-listing, disables, list
    removals, or policy/list/item deletions directly inside Rust machine code.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import urlparse

from dotenv import dotenv_values

from sentinelgate.config._seal_hash import (
    EXPECTED_SEAL_DLL_SHA256,
    SEAL_PART_A,
    SEAL_PART_B,
)
from sentinelgate.config.paths import get_bundle_root, get_project_root, is_compiled_binary

_FIXED_SLOT_LEN = 256


@dataclass(frozen=True)
class CloudflareTransportConfig:
    mode: str  # "native_worker", "native_sealed", "worker", "direct", or "none"
    account_id: str = ""
    api_token: str = ""
    worker_url: str = ""
    worker_token: str = ""

    def is_ready(self) -> bool:
        if self.mode in ("native_worker", "native_sealed"):
            return True
        if self.mode == "worker":
            return bool(self.worker_url and self.worker_token)
        if self.mode == "direct":
            return bool(self.account_id and self.api_token)
        return False


def read_cf_from_env_or_dotenv(root_dir: Path | None = None) -> tuple[str, str]:
    """Read Cloudflare ACCOUNT_ID & API_TOKEN from process env or `.env` (Worker Secrets setup only)."""
    acct = (os.environ.get("CF_ACCOUNT_ID") or os.environ.get("ACCOUNT_ID") or "").strip()
    tok = (os.environ.get("CF_API_TOKEN") or os.environ.get("API_TOKEN") or "").strip()
    if acct and tok:
        return acct, tok

    env_path = (root_dir or get_project_root()) / ".env"
    if env_path.exists():
        vals = dotenv_values(env_path)
        if not acct:
            acct = str(vals.get("CF_ACCOUNT_ID") or vals.get("ACCOUNT_ID") or "").strip()
        if not tok:
            tok = str(vals.get("CF_API_TOKEN") or vals.get("API_TOKEN") or "").strip()
    return acct, tok


def read_worker_from_env_or_dotenv(root_dir: Path | None = None) -> tuple[str, str]:
    """Read WORKER_URL & RELAY_CLIENT_SECRET from process env or `.env`."""
    wurl = (
        os.environ.get("WORKER_URL")
        or os.environ.get("SG_WORKER_URL")
        or os.environ.get("RELAY_URL")
        or ""
    ).strip()
    wsec = (
        os.environ.get("RELAY_CLIENT_SECRET")
        or os.environ.get("SG_WORKER_TOKEN")
        or os.environ.get("WORKER_TOKEN")
        or ""
    ).strip()
    if not (wurl and wsec):
        env_path = (root_dir or get_project_root()) / ".env"
        if env_path.exists():
            vals = dotenv_values(env_path)
            if not wurl:
                wurl = str(
                    vals.get("WORKER_URL")
                    or vals.get("SG_WORKER_URL")
                    or vals.get("RELAY_URL")
                    or ""
                ).strip()
            if not wsec:
                wsec = str(
                    vals.get("RELAY_CLIENT_SECRET")
                    or vals.get("SG_WORKER_TOKEN")
                    or vals.get("WORKER_TOKEN")
                    or ""
                ).strip()
    return wurl.rstrip("/"), wsec


def derive_build_handshake_parts(handshake_key: bytes) -> tuple[bytes, bytes]:
    """Split a 32-byte per-build handshake secret into XOR-obfuscated Nuitka-compiled C shares."""
    if len(handshake_key) != 32:
        raise ValueError("Handshake secret must be 32 bytes.")
    mask_a = os.urandom(32)
    mask_b = bytes(handshake_key[i] ^ mask_a[i] ^ ((i * 131 + 47) & 0xFF) for i in range(32))
    return mask_a, mask_b


def reconstruct_handshake_key(part_a: bytes = SEAL_PART_A, part_b: bytes = SEAL_PART_B) -> bytes:
    """Reconstruct the per-build handshake secret in memory from compiled C shares."""
    if not part_a or not part_b or len(part_a) != 32 or len(part_b) != 32:
        return b""
    return bytes(part_a[i] ^ part_b[i] ^ ((i * 131 + 47) & 0xFF) for i in range(32))


def _encode_slot_bytes(raw_str: str, slot_id: int) -> dict[str, Any]:
    raw_b = (raw_str or "").strip().encode("utf-8")
    if len(raw_b) + 2 > _FIXED_SLOT_LEN:
        raise ValueError(f"Secret slot {slot_id} exceeds {_FIXED_SLOT_LEN} bytes.")

    pad_len = _FIXED_SLOT_LEN - (2 + len(raw_b))
    len_hi = (len(raw_b) >> 8) & 0xFF
    len_lo = len(raw_b) & 0xFF
    plain = bytes([len_hi, len_lo]) + raw_b + os.urandom(pad_len)

    key = os.urandom(32)
    salt = os.urandom(32)
    mul_c = (secrets.randbelow(120) * 2 + 1) & 0xFF
    add_c = (secrets.randbelow(250) + 1) & 0xFF

    out = bytearray()
    counter = 0
    while len(out) < _FIXED_SLOT_LEN:
        block = hashlib.sha256(
            key + salt + slot_id.to_bytes(1, "big") + counter.to_bytes(4, "big") + b"SG::WINHTTP::SEAL"
        ).digest()
        out.extend(block)
        counter += 1
    stream = bytes(out[:_FIXED_SLOT_LEN])

    masked = [
        (plain[i] ^ stream[i] ^ ((i * mul_c + slot_id * 29 + add_c) & 0xFF))
        for i in range(_FIXED_SLOT_LEN)
    ]

    perm = list(range(_FIXED_SLOT_LEN))
    secrets.SystemRandom().shuffle(perm)
    shuffled = [0] * _FIXED_SLOT_LEN
    for orig_idx, pos in enumerate(perm):
        shuffled[pos] = masked[orig_idx]

    # Split cipher halves so raw memory scans find neither table alone
    split_mask = [secrets.randbelow(256) for _ in range(_FIXED_SLOT_LEN)]
    c_hi = [shuffled[i] ^ split_mask[i] for i in range(_FIXED_SLOT_LEN)]
    k_enc = [key[i] ^ ((i * 59 + slot_id * 13 + 23) & 0xFF) for i in range(32)]
    s_enc = [salt[i] ^ ((i * 73 + slot_id * 11 + 17) & 0xFF) for i in range(32)]

    return {
        "k": k_enc,
        "s": s_enc,
        "p": perm,
        "c1": c_hi,
        "c2": split_mask,
        "mul": mul_c,
        "add": add_c,
    }


def build_native_seal_rust_source(
    account_id: str = "",
    api_token: str = "",
    handshake_key: bytes | None = None,
    worker_url: str = "",
    relay_secret: str = "",
) -> str:
    """Generate stripped native Rust WinHTTP cdylib sealing either Worker Relay (mode 2) or Direct CF (mode 1).

    In Worker Relay mode (recommended), CF_ACCOUNT_ID and CF_API_TOKEN are NEVER present in the
    generated Rust code, compiled DLL, or desktop binary. All TLS calls run through WinHTTP with
    HCCE_LOCAL_MACHINE chain validation (rejects CurrentUser\\Root MITM CAs), anti-debug checks,
    caller PID-bound HMAC authentication, block-only guards, and volatile heap zeroing.
    """
    w_url = (worker_url or "").strip().rstrip("/")
    r_sec = (relay_secret or "").strip()
    if w_url and r_sec:
        parsed = urlparse(w_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("WORKER_URL must be a valid https:// URL.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("WORKER_URL must not include credentials, query strings, or fragments.")
        port = parsed.port or 443
        prefix = parsed.path.rstrip("/")
        slot0_val = f"{parsed.hostname}:{port}{prefix}"
        slot1_val = r_sec
        seal_mode = 2
    else:
        acct = (account_id or "").strip()
        tok = (api_token or "").strip()
        if not acct or not tok:
            raise ValueError("Provide WORKER_URL + RELAY_CLIENT_SECRET (or Cloudflare Account ID + API Token).")
        slot0_val = acct
        slot1_val = tok
        seal_mode = 1

    hs_key = handshake_key if handshake_key and len(handshake_key) == 32 else os.urandom(32)
    hs_mul = (secrets.randbelow(120) * 2 + 1) & 0xFF
    hs_add = (secrets.randbelow(250) + 1) & 0xFF
    hs_a = [secrets.randbelow(256) for _ in range(32)]
    hs_b = [hs_key[i] ^ hs_a[i] ^ ((i * hs_mul + hs_add) & 0xFF) for i in range(32)]

    slots = [
        _encode_slot_bytes(slot0_val, 0),
        _encode_slot_bytes(slot1_val, 1),
    ]

    def fmt_arr(arr: list[int]) -> str:
        return "[" + ", ".join(str(x) for x in arr) + "]"

    return f'''#![allow(non_snake_case)]
#![allow(clippy::needless_range_loop)]

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{{AtomicBool, Ordering}};

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {{
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(hProcess: isize, pbDebuggerPresent: *mut i32) -> i32;
    fn GetCurrentProcess() -> isize;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> isize;
    fn GetThreadContext(hThread: isize, lpContext: *mut c_void) -> i32;
}}

#[cfg(windows)]
#[link(name = "winhttp")]
extern "system" {{
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> *mut c_void;
    fn WinHttpSetTimeouts(internet: *mut c_void, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
    fn WinHttpConnect(session: *mut c_void, server: *const u16, port: u16, reserved: u32) -> *mut c_void;
    fn WinHttpOpenRequest(
        connect: *mut c_void,
        verb: *const u16,
        obj_name: *const u16,
        version: *const u16,
        referrer: *const u16,
        accept_types: *const *const u16,
        flags: u32,
    ) -> *mut c_void;
    fn WinHttpAddRequestHeaders(request: *mut c_void, headers: *const u16, len: u32, modifiers: u32) -> i32;
    fn WinHttpSendRequest(
        request: *mut c_void,
        headers: *const u16,
        headers_len: u32,
        optional: *const u8,
        optional_len: u32,
        total_len: u32,
        context: usize,
    ) -> i32;
    fn WinHttpReceiveResponse(request: *mut c_void, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(
        request: *mut c_void,
        info_level: u32,
        name: *const u16,
        buffer: *mut c_void,
        buffer_len: *mut u32,
        index: *mut u32,
    ) -> i32;
    fn WinHttpQueryOption(
        internet: *mut c_void,
        option: u32,
        buffer: *mut c_void,
        buffer_len: *mut u32,
    ) -> i32;
    fn WinHttpQueryDataAvailable(request: *mut c_void, available: *mut u32) -> i32;
    fn WinHttpReadData(request: *mut c_void, buffer: *mut u8, to_read: u32, read: *mut u32) -> i32;
    fn WinHttpCloseHandle(internet: *mut c_void) -> i32;
}}

#[cfg(windows)]
#[link(name = "crypt32")]
extern "system" {{
    fn CertGetNameStringW(
        cert_context: *const c_void,
        dw_type: u32,
        dw_flags: u32,
        type_para: *const c_void,
        name_string: *mut u16,
        cch_name_string: u32,
    ) -> u32;
    fn CertFreeCertificateContext(cert_context: *const c_void) -> i32;
    fn CertGetCertificateChain(
        h_chain_engine: *mut c_void,
        p_cert_context: *const c_void,
        p_time: *const c_void,
        h_additional_store: *mut c_void,
        p_chain_para: *const CertChainPara,
        dw_flags: u32,
        pv_reserved: *mut c_void,
        pp_chain_context: *mut *const CertChainContextHead,
    ) -> i32;
    fn CertFreeCertificateChain(p_chain_context: *const CertChainContextHead);
}}

#[repr(C)]
struct CtlUsage {{
    c_usage_identifier: u32,
    rgpsz_usage_identifier: *const *const u8,
}}

#[repr(C)]
struct CertUsageMatch {{
    dw_type: u32,
    usage: CtlUsage,
}}

#[repr(C)]
struct CertChainPara {{
    cb_size: u32,
    requested_usage: CertUsageMatch,
}}

#[repr(C)]
struct CertTrustStatus {{
    dw_error_status: u32,
    dw_info_status: u32,
}}

#[repr(C)]
struct CertChainContextHead {{
    cb_size: u32,
    trust_status: CertTrustStatus,
}}

const HCCE_LOCAL_MACHINE: usize = 1;
const SEAL_MODE: i32 = {seal_mode};
const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x2000_0000;
const WINHTTP_ADDREQ_FLAG_REPLACE: u32 = 0x8000_0000;
const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
const WINHTTP_OPTION_SERVER_CERT_CONTEXT: u32 = 78;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_NAME_ISSUER_FLAG: u32 = 1;

static TLS_TRUST_OK: AtomicBool = AtomicBool::new(false);

fn volatile_zero(buf: &mut [u8]) {{
    for b in buf.iter_mut() {{
        unsafe {{ ptr::write_volatile(b, 0) }};
    }}
}}

fn volatile_zero_u16(buf: &mut [u16]) {{
    for w in buf.iter_mut() {{
        unsafe {{ ptr::write_volatile(w, 0) }};
    }}
}}

#[repr(C, align(16))]
struct AlignedCtx([u8; 1232]);

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
        #[cfg(target_arch = "x86_64")]
        {{
            let mut ctx = AlignedCtx([0u8; 1232]);
            // ContextFlags at offset 0x30 (48) = CONTEXT_AMD64 (0x100000) | CONTEXT_DEBUG_REGISTERS (0x10)
            let flags: u32 = 0x0010_0010;
            ptr::copy_nonoverlapping(&flags as *const u32 as *const u8, ctx.0.as_mut_ptr().add(48), 4);
            if GetThreadContext(GetCurrentThread(), ctx.0.as_mut_ptr() as *mut c_void) != 0 {{
                for off in [72usize, 80usize, 88usize, 96usize] {{
                    let mut dr = 0u64;
                    ptr::copy_nonoverlapping(ctx.0.as_ptr().add(off), &mut dr as *mut u64 as *mut u8, 8);
                    if dr != 0 {{
                        return true;
                    }}
                }}
            }}
        }}
    }}
    false
}}

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

fn sha256_bytes(input: &[u8]) -> [u8; 32] {{
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {{
        padded.push(0);
    }}
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in padded.chunks_exact(64) {{
        for i in 0..16 {{
            w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
        }}
        for i in 16..64 {{
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }}
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {{
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(temp1);
            d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }}
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }}
    volatile_zero(&mut padded);
    let mut out = [0u8; 32];
    for i in 0..8 {{
        out[4*i..4*i+4].copy_from_slice(&h[i].to_be_bytes());
    }}
    out
}}

fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {{
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {{
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }}
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256_bytes(&inner);
    volatile_zero(&mut inner);

    let mut outer = [0u8; 96];
    outer[..64].copy_from_slice(&opad);
    outer[64..].copy_from_slice(&inner_hash);
    let res = sha256_bytes(&outer);
    volatile_zero(&mut ipad);
    volatile_zero(&mut opad);
    volatile_zero(&mut outer);
    res
}}

struct SealedSlot {{
    k: [u8; 32],
    s: [u8; 32],
    p: [usize; 256],
    c1: [u8; 256],
    c2: [u8; 256],
    mul: u8,
    add: u8,
}}

const HS_MUL: u8 = {hs_mul};
const HS_ADD: u8 = {hs_add};
const HS_A: [u8; 32] = {fmt_arr(hs_a)};
const HS_B: [u8; 32] = {fmt_arr(hs_b)};

#[used]
static DECOY_TABLE: [u8; 64] = {fmt_arr([secrets.randbelow(256) for _ in range(64)])};

static SLOTS: [SealedSlot; 2] = [
    SealedSlot {{
        k: {fmt_arr(slots[0]["k"])}, s: {fmt_arr(slots[0]["s"])}, p: {fmt_arr(slots[0]["p"])},
        c1: {fmt_arr(slots[0]["c1"])}, c2: {fmt_arr(slots[0]["c2"])}, mul: {slots[0]["mul"]}, add: {slots[0]["add"]},
    }},
    SealedSlot {{
        k: {fmt_arr(slots[1]["k"])}, s: {fmt_arr(slots[1]["s"])}, p: {fmt_arr(slots[1]["p"])},
        c1: {fmt_arr(slots[1]["c1"])}, c2: {fmt_arr(slots[1]["c2"])}, mul: {slots[1]["mul"]}, add: {slots[1]["add"]},
    }},
];

fn unseal_vec(sid: usize) -> Option<Vec<u8>> {{
    let slot = &SLOTS[sid];
    let mut key = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {{
        key[i] = slot.k[i] ^ (((i * 59 + sid * 13 + 23) & 0xFF) as u8);
        salt[i] = slot.s[i] ^ (((i * 73 + sid * 11 + 17) & 0xFF) as u8);
    }}
    let mut stream = [0u8; 256];
    for ctr in 0u32..8u32 {{
        let mut msg = Vec::with_capacity(86);
        msg.extend_from_slice(&key);
        msg.extend_from_slice(&salt);
        msg.push(sid as u8);
        msg.extend_from_slice(&ctr.to_be_bytes());
        msg.extend_from_slice(b"SG::WINHTTP::SEAL");
        let digest = sha256_bytes(&msg);
        stream[(ctr as usize)*32..(ctr as usize + 1)*32].copy_from_slice(&digest);
        volatile_zero(&mut msg);
    }}
    let mut plain = [0u8; 256];
    for i in 0..256 {{
        let pos = slot.p[i];
        let sh = slot.c1[pos] ^ slot.c2[pos];
        plain[i] = sh ^ stream[i] ^ (((i * (slot.mul as usize) + sid * 29 + (slot.add as usize)) & 0xFF) as u8);
    }}
    let len = ((plain[0] as usize) << 8) | (plain[1] as usize);
    let out = if len + 2 <= 256 {{
        Some(plain[2..2+len].to_vec())
    }} else {{
        None
    }};
    volatile_zero(&mut key);
    volatile_zero(&mut salt);
    volatile_zero(&mut stream);
    volatile_zero(&mut plain);
    out
}}

fn verify_caller_hmac(msg: &[u8], sig_hex: &[u8]) -> bool {{
    if sig_hex.len() != 64 {{
        return false;
    }}
    let mut hs_key = [0u8; 32];
    for i in 0..32 {{
        hs_key[i] = HS_A[i] ^ HS_B[i] ^ (((i * (HS_MUL as usize) + (HS_ADD as usize)) & 0xFF) as u8);
    }}
    let mac = hmac_sha256(&hs_key, msg);
    volatile_zero(&mut hs_key);
    let hex_chars = b"0123456789abcdef";
    let mut diff = 0u8;
    for i in 0..32 {{
        let hi = hex_chars[(mac[i] >> 4) as usize];
        let lo = hex_chars[(mac[i] & 0x0f) as usize];
        diff |= hi ^ sig_hex[2 * i].to_ascii_lowercase();
        diff |= lo ^ sig_hex[2 * i + 1].to_ascii_lowercase();
    }}
    diff == 0
}}

fn to_wide_vec(s: &str) -> Vec<u16> {{
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}}

// Extract top-level / simple JSON key values cleanly without matching text inside unrelated string values
fn json_extract_kv_tokens(json: &str) -> Vec<(String, String)> {{
    let mut pairs = Vec::new();
    let bytes = json.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    let read_str = |idx: &mut usize| -> Option<String> {{
        if *idx >= n || bytes[*idx] != b'"' {{ return None; }}
        *idx += 1;
        let mut s = String::new();
        while *idx < n {{
            let ch = bytes[*idx];
            if ch == b'\\\\' && *idx + 1 < n {{
                s.push(bytes[*idx + 1] as char);
                *idx += 2;
                continue;
            }}
            if ch == b'"' {{
                *idx += 1;
                return Some(s);
            }}
            s.push(ch as char);
            *idx += 1;
        }}
        None
    }};
    while i < n {{
        if bytes[i] == b'"' {{
            if let Some(key) = read_str(&mut i) {{
                while i < n && bytes[i].is_ascii_whitespace() {{ i += 1; }}
                if i < n && bytes[i] == b':' {{
                    i += 1;
                    while i < n && bytes[i].is_ascii_whitespace() {{ i += 1; }}
                    if i < n && bytes[i] == b'"' {{
                        if let Some(val) = read_str(&mut i) {{
                            pairs.push((key, val));
                            continue;
                        }}
                    }} else if i < n && (bytes[i] == b'[' || bytes[i] == b'{{') {{
                        pairs.push((key, String::from(bytes[i] as char)));
                        i += 1;
                        continue;
                    }} else if i < n {{
                        let start = i;
                        while i < n && !matches!(bytes[i], b',' | b'}}' | b']') && !bytes[i].is_ascii_whitespace() {{
                            i += 1;
                        }}
                        pairs.push((key, String::from_utf8_lossy(&bytes[start..i]).to_string()));
                        continue;
                    }}
                }}
            }}
        }}
        i += 1;
    }}
    pairs
}}

fn validate_path(path: &str) -> bool {{
    if path.is_empty() || path.len() > 512 || path.contains("..") || path.contains('@') || path.contains('#') {{
        return false;
    }}
    if path.bytes().any(|b| b <= 0x20) {{
        return false;
    }}
    let base_ok = (SEAL_MODE == 2 && (path == "/health" || path == "/v1/health"))
        || path == "/lists"
        || path.starts_with("/lists?")
        || path.starts_with("/lists/")
        || path == "/rules"
        || path.starts_with("/rules?")
        || path.starts_with("/rules/");
    base_ok
}}

fn validate_body_policy(method: &str, path: &str, body: &str) -> bool {{
    let path_base = path.split('?').next().unwrap_or("");
    let kvs = json_extract_kv_tokens(body);
    if (method == "POST" || method == "PUT") && (path_base == "/rules" || path_base.starts_with("/rules/")) {{
        let has_block = kvs.iter().any(|(k, v)| k == "action" && v.eq_ignore_ascii_case("block"));
        let has_bad_action = kvs.iter().any(|(k, v)| k == "action" && !v.eq_ignore_ascii_case("block"));
        let has_disabled = kvs.iter().any(|(k, v)| k == "enabled" && !v.eq_ignore_ascii_case("true"));
        let has_enabled = kvs.iter().any(|(k, v)| k == "enabled" && v.eq_ignore_ascii_case("true"));
        return has_block && !has_bad_action && has_enabled && !has_disabled;
    }}
    if method == "POST" && path_base == "/lists" {{
        return kvs.iter().any(|(k, v)| k == "type" && v.eq_ignore_ascii_case("DOMAIN"));
    }}
    if method == "PATCH" && path_base.starts_with("/lists/") {{
        let has_append = kvs.iter().any(|(k, _)| k == "append");
        let has_forbidden = kvs.iter().any(|(k, _)| k == "remove" || k == "items");
        return has_append && !has_forbidden;
    }}
    method == "GET"
}}

#[cfg(windows)]
fn verify_no_mitm_cert(h_conn: *mut c_void) -> bool {{
    if TLS_TRUST_OK.load(Ordering::Acquire) {{
        return true;
    }}
    unsafe {{
        let m_head = to_wide_vec("HEAD");
        let p_root = to_wide_vec("/");
        let h_req = WinHttpOpenRequest(h_conn, m_head.as_ptr(), p_root.as_ptr(), ptr::null(), ptr::null(), ptr::null(), WINHTTP_FLAG_SECURE);
        if h_req.is_null() {{
            return false;
        }}
        let ok_send = WinHttpSendRequest(h_req, ptr::null(), 0, ptr::null(), 0, 0, 0);
        let mut trusted = false;
        if ok_send != 0 && WinHttpReceiveResponse(h_req, ptr::null_mut()) != 0 {{
            let mut cert_ctx: *const c_void = ptr::null();
            let mut sz = std::mem::size_of::<*const c_void>() as u32;
            if WinHttpQueryOption(h_req, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &mut cert_ctx as *mut *const c_void as *mut c_void, &mut sz) != 0 && !cert_ctx.is_null() {{
                let mut issuer_buf = [0u16; 256];
                let mut subj_buf = [0u16; 256];
                let n1 = CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, ptr::null(), issuer_buf.as_mut_ptr(), 256);
                let n2 = CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, ptr::null(), subj_buf.as_mut_ptr(), 256);
                let issuer = if n1 > 1 {{ String::from_utf16_lossy(&issuer_buf[..(n1 as usize - 1)]).to_lowercase() }} else {{ String::new() }};
                let subj = if n2 > 1 {{ String::from_utf16_lossy(&subj_buf[..(n2 as usize - 1)]).to_lowercase() }} else {{ String::new() }};
                let combined = format!("{{}}|{{}}", issuer, subj);
                let bad = ["fiddler", "do_not_trust", "mitmproxy", "portswigger", "burp", "charles", "proxyman", "httptoolkit"];
                let not_blacklisted = !bad.iter().any(|k| combined.contains(k));

                // Validate certificate chain using HCCE_LOCAL_MACHINE (ignores user-added CurrentUser\\Root CAs)
                let para = CertChainPara {{
                    cb_size: std::mem::size_of::<CertChainPara>() as u32,
                    requested_usage: CertUsageMatch {{
                        dw_type: 0,
                        usage: CtlUsage {{
                            c_usage_identifier: 0,
                            rgpsz_usage_identifier: ptr::null(),
                        }},
                    }},
                }};
                let mut chain_ctx: *const CertChainContextHead = ptr::null();
                let mut lm_chain_ok = false;
                if CertGetCertificateChain(
                    HCCE_LOCAL_MACHINE as *mut c_void,
                    cert_ctx,
                    ptr::null(),
                    ptr::null_mut(),
                    &para,
                    0,
                    ptr::null_mut(),
                    &mut chain_ctx,
                ) != 0 && !chain_ctx.is_null() {{
                    lm_chain_ok = (*chain_ctx).trust_status.dw_error_status == 0;
                    CertFreeCertificateChain(chain_ctx);
                }}

                CertFreeCertificateContext(cert_ctx);
                trusted = not_blacklisted && lm_chain_ok;
            }}
        }}
        WinHttpCloseHandle(h_req);
        if trusted {{
            TLS_TRUST_OK.store(true, Ordering::Release);
        }}
        trusted
    }}
}}

#[cfg(windows)]
fn exec_http_raw(method: &str, rel_path: &str, body_bytes: &[u8]) -> Result<(i32, Vec<u8>), i32> {{
    let mut s0 = unseal_vec(0).ok_or(-5)?;
    let mut s1 = unseal_vec(1).ok_or(-5)?;

    let (host_owned, port, full_path, auth_hdr) = if SEAL_MODE == 2 {{
        let endpoint = String::from_utf8_lossy(&s0).into_owned();
        let secret = String::from_utf8_lossy(&s1).into_owned();
        let (h_owned, p_num, prefix_owned) = {{
            let (host_port, base_prefix) = match endpoint.find('/') {{
                Some(idx) => (&endpoint[..idx], endpoint[idx..].trim_end_matches('/')),
                None => (endpoint.as_str(), ""),
            }};
            let (h_str, p_u16) = if let Some((h, p_str)) = host_port.rsplit_once(':') {{
                (h.to_string(), p_str.parse::<u16>().unwrap_or(443))
            }} else {{
                (host_port.to_string(), 443u16)
            }};
            (h_str, p_u16, base_prefix.to_string())
        }};
        let v1_rel = if rel_path.starts_with("/v1/") || rel_path == "/v1" {{
            rel_path.to_string()
        }} else {{
            format!("/v1{{}}", rel_path)
        }};
        let fpath = format!("{{}}{{}}", prefix_owned, v1_rel);
        let ahdr = format!("X-SG-Relay-Key: {{}}\\r\\nContent-Type: application/json\\r\\nConnection: close\\r\\n", secret);
        volatile_zero(&mut endpoint.into_bytes());
        volatile_zero(&mut secret.into_bytes());
        volatile_zero(&mut prefix_owned.into_bytes());
        (h_owned, p_num, fpath, ahdr)
    }} else {{
        let acct = String::from_utf8_lossy(&s0).into_owned();
        let tok = String::from_utf8_lossy(&s1).into_owned();
        let fpath = format!("/client/v4/accounts/{{}}/gateway{{}}", acct, rel_path);
        let ahdr = format!("Authorization: Bearer {{}}\\r\\nContent-Type: application/json\\r\\nConnection: close\\r\\n", tok);
        volatile_zero(&mut acct.into_bytes());
        volatile_zero(&mut tok.into_bytes());
        ("api.cloudflare.com".to_string(), 443u16, fpath, ahdr)
    }};

    volatile_zero(&mut s0);
    volatile_zero(&mut s1);

    unsafe {{
        let agent_w = to_wide_vec("SentinelGateAI/2.0");
        let h_sess = WinHttpOpen(agent_w.as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY, ptr::null(), ptr::null(), 0);
        if h_sess.is_null() {{
            volatile_zero(&mut host_owned.into_bytes());
            volatile_zero(&mut full_path.into_bytes());
            volatile_zero(&mut auth_hdr.into_bytes());
            return Err(-5);
        }}
        WinHttpSetTimeouts(h_sess, 10000, 10000, 15000, 25000);
        let mut host_w = to_wide_vec(&host_owned);
        volatile_zero(&mut host_owned.into_bytes());
        let h_conn = WinHttpConnect(h_sess, host_w.as_ptr(), port, 0);
        volatile_zero_u16(&mut host_w);
        if h_conn.is_null() {{
            WinHttpCloseHandle(h_sess);
            volatile_zero(&mut full_path.into_bytes());
            volatile_zero(&mut auth_hdr.into_bytes());
            return Err(-5);
        }}

        if !verify_no_mitm_cert(h_conn) {{
            WinHttpCloseHandle(h_conn);
            WinHttpCloseHandle(h_sess);
            volatile_zero(&mut full_path.into_bytes());
            volatile_zero(&mut auth_hdr.into_bytes());
            return Err(-5);
        }}

        let m_w = to_wide_vec(method);
        let mut p_w = to_wide_vec(&full_path);
        volatile_zero(&mut full_path.into_bytes());
        let h_req = WinHttpOpenRequest(h_conn, m_w.as_ptr(), p_w.as_ptr(), ptr::null(), ptr::null(), ptr::null(), WINHTTP_FLAG_SECURE);
        volatile_zero_u16(&mut p_w);
        if h_req.is_null() {{
            WinHttpCloseHandle(h_conn);
            WinHttpCloseHandle(h_sess);
            volatile_zero(&mut auth_hdr.into_bytes());
            return Err(-5);
        }}

        let mut hdr_w = to_wide_vec(&auth_hdr);
        volatile_zero(&mut auth_hdr.into_bytes());
        WinHttpAddRequestHeaders(h_req, hdr_w.as_ptr(), (hdr_w.len() - 1) as u32, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        volatile_zero_u16(&mut hdr_w);

        let opt_ptr = if body_bytes.is_empty() {{ ptr::null() }} else {{ body_bytes.as_ptr() }};
        let opt_len = body_bytes.len() as u32;
        let sent = WinHttpSendRequest(h_req, ptr::null(), 0, opt_ptr, opt_len, opt_len, 0);
        let ok_recv = if sent != 0 {{ WinHttpReceiveResponse(h_req, ptr::null_mut()) }} else {{ 0 }};
        if ok_recv == 0 {{
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_conn);
            WinHttpCloseHandle(h_sess);
            return Err(-5);
        }}

        let mut status_code: u32 = 0;
        let mut status_len: u32 = 4;
        WinHttpQueryHeaders(
            h_req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            &mut status_code as *mut u32 as *mut c_void,
            &mut status_len,
            ptr::null_mut(),
        );

        let mut resp = Vec::new();
        loop {{
            let mut avail: u32 = 0;
            if WinHttpQueryDataAvailable(h_req, &mut avail) == 0 || avail == 0 {{
                break;
            }}
            let mut tmp = vec![0u8; avail as usize];
            let mut read_cnt: u32 = 0;
            if WinHttpReadData(h_req, tmp.as_mut_ptr(), avail, &mut read_cnt) == 0 || read_cnt == 0 {{
                break;
            }}
            resp.extend_from_slice(&tmp[..read_cnt as usize]);
        }}

        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_conn);
        WinHttpCloseHandle(h_sess);
        Ok((status_code as i32, resp))
    }}
}}

#[no_mangle]
pub extern "C" fn sg_cf_mode(
    nonce_ptr: *const u8,
    nonce_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {{
    if debugger_detected() {{
        return -1;
    }}
    if nonce_ptr.is_null() || sig_ptr.is_null() || nonce_len == 0 || nonce_len > 128 {{
        return -2;
    }}
    let (nonce, sig) = unsafe {{
        (
            std::slice::from_raw_parts(nonce_ptr, nonce_len),
            std::slice::from_raw_parts(sig_ptr, sig_len),
        )
    }};
    #[cfg(windows)]
    let pid = unsafe {{ GetCurrentProcessId() }};
    #[cfg(not(windows))]
    let pid = 0u32;

    let mut msg = Vec::with_capacity(32 + nonce.len());
    msg.extend_from_slice(b"SG::MODE::");
    msg.extend_from_slice(pid.to_string().as_bytes());
    msg.extend_from_slice(b"::");
    msg.extend_from_slice(nonce);
    let ok = verify_caller_hmac(&msg, sig);
    volatile_zero(&mut msg);
    if !ok {{
        return -4;
    }}
    SEAL_MODE
}}

#[no_mangle]
pub extern "C" fn sg_cf_request(
    nonce_ptr: *const u8,
    nonce_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    method_ptr: *const u8,
    method_len: usize,
    path_ptr: *const u8,
    path_len: usize,
    body_ptr: *const u8,
    body_len: usize,
    out_status: *mut i32,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {{
    if debugger_detected() {{
        return -1;
    }}
    if nonce_ptr.is_null() || sig_ptr.is_null() || method_ptr.is_null() || path_ptr.is_null() || out_status.is_null() || out_len.is_null() {{
        return -2;
    }}
    if nonce_len == 0 || nonce_len > 128 || method_len == 0 || method_len > 16 || path_len == 0 || path_len > 512 {{
        return -2;
    }}
    let (nonce, sig, method_b, path_b) = unsafe {{
        (
            std::slice::from_raw_parts(nonce_ptr, nonce_len),
            std::slice::from_raw_parts(sig_ptr, sig_len),
            std::slice::from_raw_parts(method_ptr, method_len),
            std::slice::from_raw_parts(path_ptr, path_len),
        )
    }};
    let body_b = if body_ptr.is_null() || body_len == 0 {{
        &[][..]
    }} else {{
        unsafe {{ std::slice::from_raw_parts(body_ptr, body_len) }}
    }};

    #[cfg(windows)]
    let pid = unsafe {{ GetCurrentProcessId() }};
    #[cfg(not(windows))]
    let pid = 0u32;

    let mut msg = Vec::with_capacity(40 + nonce.len() + method_b.len() + path_b.len());
    msg.extend_from_slice(b"SG::REQ::");
    msg.extend_from_slice(pid.to_string().as_bytes());
    msg.extend_from_slice(b"::");
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(b"::");
    msg.extend_from_slice(method_b);
    msg.extend_from_slice(b"::");
    msg.extend_from_slice(path_b);
    let auth_ok = verify_caller_hmac(&msg, sig);
    volatile_zero(&mut msg);
    if !auth_ok {{
        return -4;
    }}

    let method = match std::str::from_utf8(method_b) {{
        Ok(m) if matches!(m, "GET" | "POST" | "PUT" | "PATCH") => m,
        _ => return -3,
    }};
    let rel_path = match std::str::from_utf8(path_b) {{
        Ok(p) if validate_path(p) => p,
        _ => return -3,
    }};
    let body_str = match std::str::from_utf8(body_b) {{
        Ok(s) => s,
        Err(_) => return -3,
    }};
    if !validate_body_policy(method, rel_path, body_str) {{
        return -3;
    }}
    #[cfg(windows)]
    {{
        match exec_http_raw(method, rel_path, body_b) {{
            Ok((st, resp)) => unsafe {{
                *out_status = st;
                *out_len = resp.len();
                if resp.len() > out_buf_cap {{
                    return -6;
                }}
                if !out_buf.is_null() && !resp.is_empty() {{
                    ptr::copy_nonoverlapping(resp.as_ptr(), out_buf, resp.len());
                }}
                0
            }},
            Err(rc) => rc,
        }}
    }}
    #[cfg(not(windows))]
    -5
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
    lib.sg_cf_mode.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    lib.sg_cf_mode.restype = ctypes.c_int
    lib.sg_cf_request.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.sg_cf_request.restype = ctypes.c_int
    return lib


def _sign_caller_message(msg: bytes, handshake_key: bytes | None = None) -> bytes:
    hs_key = handshake_key if handshake_key is not None else reconstruct_handshake_key()
    if len(hs_key) != 32:
        raise PermissionError("Sealed engine caller handshake secret unavailable.")
    return hmac.new(hs_key, msg, hashlib.sha256).hexdigest().encode("ascii")


def query_sealed_mode(lib: ctypes.CDLL, handshake_key: bytes | None = None) -> int:
    """Authenticate current process against stripped sg_seal.dll and return mode (1 or 2)."""
    nonce = secrets.token_hex(16).encode("ascii")
    msg = b"SG::MODE::" + str(os.getpid()).encode("ascii") + b"::" + nonce
    sig = _sign_caller_message(msg, handshake_key=handshake_key)
    return int(lib.sg_cf_mode(nonce, len(nonce), sig, len(sig)))


def execute_sealed_request(
    method: str,
    rel_path: str,
    json_body: dict[str, Any] | None = None,
    lib: ctypes.CDLL | None = None,
    handshake_key: bytes | None = None,
) -> tuple[int, str]:
    """Execute Cloudflare API request inside stripped native Rust WinHTTP with zero Python secret exposure."""
    dll = lib or _load_native_seal_dll()
    if dll is None:
        raise RuntimeError("Sealed Cloudflare native library is unavailable or failed integrity verification.")

    method_b = method.upper().encode("ascii")
    path_b = rel_path.encode("utf-8")
    body_b = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else b""

    buf_cap = 524288  # 512 KB initial buffer; expands automatically if large JSON list returned
    while buf_cap <= 8 * 1024 * 1024:
        nonce = secrets.token_hex(16).encode("ascii")
        msg = b"SG::REQ::" + str(os.getpid()).encode("ascii") + b"::" + nonce + b"::" + method_b + b"::" + path_b
        sig = _sign_caller_message(msg, handshake_key=handshake_key)

        out_status = ctypes.c_int(0)
        out_len = ctypes.c_size_t(0)
        out_buf = ctypes.create_string_buffer(buf_cap)
        rc = int(
            dll.sg_cf_request(
                nonce, len(nonce),
                sig, len(sig),
                method_b, len(method_b),
                path_b, len(path_b),
                body_b if body_b else None, len(body_b),
                ctypes.byref(out_status),
                out_buf, buf_cap,
                ctypes.byref(out_len),
            )
        )
        if rc == -6:
            buf_cap = max(buf_cap * 2, int(out_len.value) + 4096)
            continue
        if rc == 0:
            raw = bytes(out_buf.raw[: int(out_len.value)])
            return int(out_status.value), raw.decode("utf-8", errors="replace")
        if rc == -1:
            raise PermissionError("Native engine halted: debugger or hardware breakpoint detected.")
        if rc == -3:
            raise PermissionError("Native block-only policy guard rejected disallowed API operation.")
        if rc == -4:
            raise PermissionError("Native engine rejected unauthorized caller signature.")
        raise ConnectionError(f"Sealed WinHTTP transport error (code {rc}).")

    raise BufferError("Cloudflare response exceeded maximum native transport buffer.")


def get_cloudflare_transport_config() -> CloudflareTransportConfig:
    """Resolve the user-configured Worker relay before any legacy sealed transport."""
    # Worker endpoint and app-to-Worker key can be changed in the app without
    # rebuilding the native library. The Cloudflare API token never enters this
    # process; it stays in the Worker's Cloudflare dashboard secrets.
    try:
        from sentinelgate.config.vault import ApiKeyVault

        relay_settings = ApiKeyVault().get_credentials()
        worker_url = (relay_settings.get("WORKER_URL") or "").strip().rstrip("/")
        relay_secret = (relay_settings.get("RELAY_CLIENT_SECRET") or "").strip()
        if worker_url and relay_secret:
            parsed = urlparse(worker_url)
            if parsed.scheme.lower() == "https" and parsed.hostname and not (parsed.username or parsed.password or parsed.query or parsed.fragment):
                return CloudflareTransportConfig(mode="worker", worker_url=worker_url, worker_token=relay_secret)
    except Exception:
        # Keep startup resilient if a vault cannot be read; normal fallback
        # transport resolution below will report the engine as unavailable.
        pass

    lib = _load_native_seal_dll()
    if lib is not None:
        try:
            mode_code = query_sealed_mode(lib)
            if mode_code == 2:
                return CloudflareTransportConfig(mode="native_worker")
            if mode_code == 1:
                return CloudflareTransportConfig(mode="native_sealed")
        except Exception:
            return CloudflareTransportConfig(mode="none")
        return CloudflareTransportConfig(mode="none")

    # Never read .env or env vars when running from a compiled desktop executable
    if is_compiled_binary():
        return CloudflareTransportConfig(mode="none")

    w_url, w_sec = read_worker_from_env_or_dotenv()
    if w_url and w_sec:
        return CloudflareTransportConfig(mode="worker", worker_url=w_url, worker_token=w_sec)

    acct, tok = read_cf_from_env_or_dotenv()
    if acct and tok:
        return CloudflareTransportConfig(mode="direct", account_id=acct, api_token=tok)

    return CloudflareTransportConfig(mode="none")


def get_cloudflare_credentials() -> tuple[str, str]:
    """Legacy helper returning empty strings when sealed natively (credentials never leave native code)."""
    cfg = get_cloudflare_transport_config()
    return cfg.account_id, cfg.api_token
