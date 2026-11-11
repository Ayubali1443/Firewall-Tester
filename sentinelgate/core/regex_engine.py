"""Retained Core Regex Obfuscation & Dynamic Chunking Engine + Rust DFA Pre-flight."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from typing import Callable

from sentinelgate.config.paths import get_validator_bin_path
from sentinelgate.core._validator_hash import EXPECTED_VALIDATOR_SHA256

# --- Advanced Regex Obfuscation Engine (Exact Retained Mapping) ---
# Maps every character to its absolute widest leetspeak and slang variant natively in RE2.
CHAR_MAP = {
    "a": r"[a@4\^]*",     # Vowels are optional (*) to catch dropped letters like "prn"
    "b": r"[bv8]+",       # Consonants are required (+)
    "c": r"[ckq]+",
    "d": r"[d]+",
    "e": r"[e3i1!y]*",    # E, I, and Y are highly interchangeable in slang
    "f": r"[fp]+",
    "g": r"[g96]+",
    "h": r"[h]*",         # H is often dropped (e.g., bhabhi vs babi)
    "i": r"[i1!l|y]*",
    "j": r"[jz]+",
    "k": r"[kcq]+",
    "l": r"[l1|i]+",
    "m": r"[m]+",
    "n": r"[n]+",
    "o": r"[o0u]*",
    "p": r"[p]+",
    "q": r"[qkw]+",
    "r": r"[r]+",
    "s": r"[s5$zc]+",
    "t": r"[t7+]+",
    "u": r"[uvwo0]*",
    "v": r"[vub]+",
    "w": r"[wv]+",
    "x": r"[x]+",
    "y": r"[yi1!]*",
    "z": r"[zs5$]+",
}

_SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def verify_validator_integrity() -> tuple[bool, str]:
    """Verify cf_validator.exe exists and matches its compiled SHA-256 digest."""
    bin_path = get_validator_bin_path()
    if not bin_path.exists():
        return False, f"Validator binary not found at {bin_path}"
    digest = hashlib.sha256(bin_path.read_bytes()).hexdigest().upper()
    if digest != EXPECTED_VALIDATOR_SHA256:
        return False, f"Validator SHA-256 mismatch (got {digest[:12]}...)"
    return True, str(bin_path)


def obfuscate_term(term: str) -> str:
    """Transform a clean base word into a heavy regex pattern covering spaces, typos, and leetspeak."""
    term = term.strip().lower()
    if not term:
        return ""

    words = term.split()
    obfuscated_words = []

    for w in words:
        w_parts = []
        has_required = False

        for char in w:
            if char in CHAR_MAP:
                pattern = CHAR_MAP[char]
                w_parts.append(pattern)
                # Check if this character map forces at least one character match
                if "+" in pattern:
                    has_required = True
            elif char.isalnum():
                w_parts.append(f"{re.escape(char)}+")
                has_required = True

        # CRITICAL FIX: If the word is made entirely of optional characters (e.g., 'yaoi'),
        # force the quantifiers to be required (+) to prevent matching an empty string.
        if not has_required:
            w_parts = [p.replace("*", "+") for p in w_parts]

        # Intercept spaces, dots, dashes, underscores, and URL encodings BETWEEN every single letter.
        w_regex = r"(?:%20|[^a-zA-Z0-9])*".join(w_parts)
        obfuscated_words.append(w_regex)

    # Require at least one separator between distinct words in a phrase
    return r"(?:%20|[^a-zA-Z0-9])+".join(obfuscated_words)


def build_flat_regex(terms: list[str]) -> str:
    """Build exact RE2-compatible case-insensitive boundary-wrapped flat regex."""
    patterns = []
    for term in terms:
        obf_pattern = obfuscate_term(term)
        if obf_pattern:
            patterns.append(obf_pattern)

    if not patterns:
        return ""
    # (?i) enforces global case-insensitivity.
    # Bounded by strict non-alphanumeric boundaries to prevent accidental partial substring blocks.
    return r"(?i)(?:^|[^a-zA-Z0-9])(?:%s)(?:[^a-zA-Z0-9]|$)" % "|".join(patterns)


def format_traffic_condition(raw_regex: str) -> str:
    """Format Cloudflare Gateway HTTP traffic condition for Google Search URI matching."""
    safe_regex = raw_regex.replace("\\", "\\\\").replace('"', '\\"')
    return f'http.request.host in {{"google.com" "www.google.com"}} and http.request.uri matches "{safe_regex}"'


def local_rust_preflight_silent(raw_regex: str) -> bool | None:
    """Validate regex against Cloudflare's exact 512KB RE2 DFA memory limit via Rust cf_validator."""
    ok, info = verify_validator_integrity()
    if not ok:
        bin_path = get_validator_bin_path()
        if not bin_path.exists():
            return None
        # Refuse tampered binary if integrity fails
        return False

    try:
        result = subprocess.run(
            [info, raw_regex],
            capture_output=True,
            text=True,
            creationflags=_SUBPROCESS_FLAGS,
        )
        return result.returncode == 0
    except Exception:
        return False


def validate_regex_detailed(raw_regex: str) -> dict:
    """Return full diagnostic status (char length, DFA validation, Python compile check)."""
    traffic = format_traffic_condition(raw_regex) if raw_regex else ""
    bin_ok, bin_info = verify_validator_integrity()
    dfa_ok = local_rust_preflight_silent(raw_regex) if (raw_regex and bin_ok) else None

    py_ok = False
    py_err = ""
    if raw_regex:
        try:
            re.compile(raw_regex)
            py_ok = True
        except re.error as exc:
            py_err = str(exc)

    return {
        "raw_regex": raw_regex,
        "traffic_condition": traffic,
        "traffic_length": len(traffic),
        "max_traffic_length": 4090,
        "within_char_limit": len(traffic) <= 4090,
        "validator_integrity_ok": bin_ok,
        "validator_info": bin_info,
        "rust_dfa_ok": dfa_ok,
        "python_re_ok": py_ok,
        "python_re_error": py_err,
    }


def calculate_dynamic_chunks(
    terms: list[str],
    log_cb: Callable[[str], None] | None = None,
) -> list[list[str]]:
    """Condense base terms into optimal chunks obeying 4090-char and 512KB Rust DFA limits."""
    if log_cb:
        log_cb("Calculating optimal dynamic chunks (maxing out Cloudflare 4090-char & 512KB DFA limits)...")

    chunks: list[list[str]] = []
    current_chunk: list[str] = []

    has_rust, rust_msg = verify_validator_integrity()
    if not has_rust and log_cb:
        log_cb(f"[!] Rust validator issue ({rust_msg}). Falling back to string length limits.")

    batch_proc: subprocess.Popen[str] | None = None
    if has_rust:
        try:
            batch_proc = subprocess.Popen(
                [rust_msg, "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=_SUBPROCESS_FLAGS,
            )
        except Exception:
            batch_proc = None

    def _check_dfa(pattern: str) -> bool:
        if not has_rust:
            return True
        if batch_proc and batch_proc.stdin and batch_proc.stdout and batch_proc.poll() is None:
            try:
                clean_pat = pattern.replace("\r", "").replace("\n", "")
                batch_proc.stdin.write(clean_pat + "\n")
                batch_proc.stdin.flush()
                reply = batch_proc.stdout.readline().strip()
                return reply == "OK"
            except Exception:
                pass
        return bool(local_rust_preflight_silent(pattern))

    try:
        for term in terms:
            current_chunk.append(term)
            test_regex = build_flat_regex(current_chunk)
            test_traffic = format_traffic_condition(test_regex)

            # 1. Cloudflare has a hard 4096 character limit for the traffic expression string
            is_valid_len = len(test_traffic) <= 4090

            # 2. Rust DFA memory limits (512KB computational limit check)
            is_valid_dfa = _check_dfa(test_regex) if is_valid_len else False

            # If either limit is breached, revert the last addition and finalize the chunk
            if not is_valid_len or (has_rust and not is_valid_dfa):
                current_chunk.pop()
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = [term]

        if current_chunk:
            chunks.append(current_chunk)
    finally:
        if batch_proc:
            try:
                if batch_proc.stdin and not batch_proc.stdin.closed:
                    batch_proc.stdin.close()
            except Exception:
                pass
            try:
                batch_proc.wait(timeout=2)
            except Exception:
                batch_proc.kill()
            for pipe in (batch_proc.stdout, batch_proc.stderr):
                try:
                    if pipe and not pipe.closed:
                        pipe.close()
                except Exception:
                    pass

    return chunks
