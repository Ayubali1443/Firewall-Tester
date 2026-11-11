"""Gemini Threat Intelligence Agent focused strictly on DNS/SafeSearch Slip-Throughs.

Uses the official Gemini Generative Language REST API directly over HTTPS so the
compiled desktop executable stays lean, fast, and free of bloated third-party SDK schemas.
"""

from __future__ import annotations

import concurrent.futures
import json
import random
import re
import threading
import time
from typing import Any, Callable

import requests

from sentinelgate.core.quality_gate import (
    filter_useful_dns_candidates,
    filter_useful_search_candidates,
    parse_ai_exhausted_signal,
)


GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiRestClient:
    """Lightweight, thread-safe client for Google Gemini v1beta REST endpoints."""

    def __init__(self, api_key: str) -> None:
        self.api_key = (api_key or "").strip()
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is empty.")

    def list_models(self, timeout: float = 10.0) -> list[dict[str, Any]]:
        url = f"{GEMINI_API_BASE}/models"
        res = requests.get(url, params={"key": self.api_key, "pageSize": 100}, timeout=timeout)
        if res.status_code != 200:
            raise RuntimeError(f"Gemini models.list HTTP {res.status_code}: {res.text[:220]}")
        return res.json().get("models", [])

    def generate_content(
        self,
        model_name: str,
        contents: str | list[dict[str, Any]],
        timeout: float = 30.0,
    ) -> str:
        model_path = model_name if model_name.startswith("models/") else f"models/{model_name}"
        url = f"{GEMINI_API_BASE}/{model_path}:generateContent"
        if isinstance(contents, str):
            payload_contents = [{"role": "user", "parts": [{"text": contents}]}]
        else:
            payload_contents = contents

        res = requests.post(
            url,
            params={"key": self.api_key},
            json={"contents": payload_contents},
            timeout=timeout,
        )
        if res.status_code != 200:
            raise RuntimeError(f"Gemini generateContent HTTP {res.status_code}: {res.text[:220]}")

        body = res.json()
        candidates = body.get("candidates") or []
        if not candidates:
            raise RuntimeError("Gemini returned no candidates.")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(str(p.get("text", "")) for p in parts).strip()
        if not text:
            raise RuntimeError("Gemini returned empty text.")
        return text


class GeminiChatSession:
    """Stateless-HTTP multi-turn conversation wrapper preserving turn history."""

    def __init__(self, client: GeminiRestClient, model_name: str) -> None:
        self.client = client
        self.model_name = model_name
        self.history: list[dict[str, Any]] = []

    def send_message(self, prompt: str, timeout: float = 35.0) -> str:
        self.history.append({"role": "user", "parts": [{"text": prompt}]})
        try:
            # Cap history window to last 12 turns to keep payload bounded
            recent_window = self.history[-12:]
            reply = self.client.generate_content(self.model_name, recent_window, timeout=timeout)
            self.history.append({"role": "model", "parts": [{"text": reply}]})
            return reply
        except Exception:
            self.history.pop()
            raise


def get_model_score(model_name: str) -> float:
    """Score models so Pro > Flash > Lite, and newer versions outrank older ones."""
    score = 0.0
    name_lower = model_name.lower()

    if "pro" in name_lower:
        score += 1000
    elif "flash" in name_lower and "lite" not in name_lower:
        score += 500
    elif "lite" in name_lower:
        score += 100

    match = re.search(r"(\d+\.\d+|\d+)", name_lower)
    if match:
        score += float(match.group(1)) * 10
    return score


def ping_model_fast(client: GeminiRestClient, model_name: str, timeout: float = 4.0) -> bool:
    """Execute a ping test with a strict hard timeout."""
    try:
        reply = client.generate_content(model_name, "Reply OK", timeout=timeout)
        return bool(reply)
    except Exception:
        return False


def discover_and_test_models(
    api_key: str,
    max_working: int = 6,
    log_cb: Callable[[str], None] | None = None,
) -> list[str]:
    """Fetch, rank, and pre-flight ping available Gemini text models."""
    if not api_key or api_key == "YOUR_GEMINI_API_KEY":
        raise ValueError("GEMINI_API_KEY is not configured in the API Vault.")

    client = GeminiRestClient(api_key=api_key)
    if log_cb:
        log_cb("Fetching and ranking available Gemini models...")

    available_models: list[str] = []
    excluded_keywords = ["embed", "image", "vision", "audio", "argon", "nano", "aqa", "omni", "learn"]

    try:
        for m in client.list_models():
            name = m.get("name", "")
            name_lower = name.lower()
            methods = [meth.lower() for meth in m.get("supportedGenerationMethods", [])]
            if methods and "generatecontent" not in methods:
                continue
            if "gemini" in name_lower and not any(kw in name_lower for kw in excluded_keywords):
                available_models.append(name)
    except Exception as exc:
        if log_cb:
            log_cb(f"[!] Model list query failed ({exc}), using fallback candidate queue.")
        available_models = [
            "models/gemini-2.5-flash",
            "models/gemini-2.5-pro",
            "models/gemini-2.0-flash",
        ]

    if not available_models:
        available_models = ["models/gemini-2.5-flash", "models/gemini-2.5-pro"]

    available_models = list(dict.fromkeys(available_models))
    available_models.sort(key=get_model_score, reverse=True)
    candidates = available_models[:10]

    if log_cb:
        log_cb(f"Pre-flight pinging top {len(candidates)} ranked models (4s timeout)...")

    working: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(candidates), 6)) as executor:
        future_map = {executor.submit(ping_model_fast, client, m, 4.0): m for m in candidates}
        done, _ = concurrent.futures.wait(future_map.keys(), timeout=6.0)
        for m in candidates:
            matching_future = next((f for f, name in future_map.items() if name == m), None)
            if matching_future in done:
                try:
                    if matching_future.result():
                        working.append(m)
                        if log_cb:
                            log_cb(f"  [OK] {m.replace('models/', '')} is ONLINE.")
                        if len(working) >= max_working:
                            break
                        continue
                except Exception:
                    pass
            if log_cb:
                log_cb(f"  [--] {m.replace('models/', '')} unavailable or timed out.")

    return working


def build_dns_slipthrough_prompt(category: str, description: str, existing_domains: list[str]) -> str:
    sample = random.sample(existing_domains, min(len(existing_domains), 60)) if existing_domains else []
    return f"""You are an expert threat-intelligence agent assisting a strict secondary desktop web filter.

CONTEXT & TARGETING CONSTRAINTS (CRITICAL):
- Google SafeSearch and Cloudflare Zero Trust network filters are ALREADY active and block mainstream pornography, encrypted DNS (DoH/DoT), and standard Security categories.
- Desktop VPN client installations and local software installs are ALREADY blocked at the OS Standard User policy level.
- DO NOT waste suggestions on famous mainstream adult sites (e.g., pornhub, xvideos), desktop VPN software vendors (e.g., nordvpn, wireguard), or encrypted DNS servers.
- YOUR STRICT FOCUS IS SLIP-THROUGHS:
  1. Web-based proxies, CGI proxies (Glype, PHProxy, MiniProxy, Rammerhead, Ultraviolet), serverless `.workers.dev`/`.vercel.app` proxy portals, and HTML/browser-in-browser unblockers.
  2. Obscure or newly rotated adult domains, niche leak hubs, and dedicated SOLE-PORN / nude / topless image-hosting websites that evade standard Cloudflare DNS categorization.
  3. Web-based media rippers, stream converters, and APK/software download portals.
- CRITICAL IMAGE-HOST RULE: NEVER suggest multipurpose CDNs or general cloud/asset hosts (e.g., cloudfront.net, s3.amazonaws.com, imagedelivery.net, googleusercontent.com, azureedge.net, fastly.net, akamaized.net, cloudinary.com, imgix.net, b-cdn.net, imgur.com, postimg.cc, imgbb, githubusercontent.com). ONLY target dedicated porn/nude/topless image-hosting sites.

TARGET CATEGORY: '{category}'
CATEGORY FOCUS: {description or 'Web slip-through domains for this category.'}
CURRENTLY BLOCKED SAMPLE (DO NOT REPEAT): {sample}

TASK: Identify up to 10 genuinely active, real-world slip-through domains (hostnames only, e.g., "example.net") matching '{category}' that are NOT in the list above and have not been suggested earlier.
STRICT QUALITY RULE: Quality matters far more than quantity. NEVER invent hypothetical/fake domains, random character strings, or subdomains of already-blocked sites just to fill a quota. If you cannot think of genuinely real, active slip-through domains missing from the list, return ONLY [].
OUTPUT FORMAT: Return ONLY a valid JSON array of domain strings (e.g. ["site1.com", "proxy2.net"]) or []. No markdown fences, no commentary."""


def build_search_slipthrough_prompt(
    category: str,
    description: str,
    existing_terms: list[str],
    history_terms: list[str],
) -> str:
    sample_active = random.sample(existing_terms, min(len(existing_terms), 45)) if existing_terms else []
    history_context = ""
    if history_terms:
        sample_hist = random.sample(history_terms, min(len(history_terms), 250))
        history_context = f"\nPREVIOUSLY TESTED (DO NOT REPEAT THESE):\n{', '.join(sample_hist)}\n"

    return (
        "You are an expert Red Team penetration tester assisting a strict secondary Google Search regex filter.\n\n"
        "FIREWALL CAPABILITIES:\n"
        "The target firewall automatically generates all programmatic tweaks for existing blocklist words natively via a heavy RE2 regex engine. "
        "It already PERFECTLY intercepts all leetspeak (e.g., e->3, a->@), dropped vowels, repeated consonants, interspersed spaces, dashes, dots, and URL encodings natively.\n\n"
        "ENVIRONMENT CONSTRAINTS (AVOID REDUNDANCY):\n"
        "- Google SafeSearch + Cloudflare Zero Trust DNS already filter standard mainstream pornography and Encrypted DNS.\n"
        "- OS Standard User policies already block local VPN & software installations.\n"
        "- DO NOT output desktop VPN client brand names or mainstream broad adult words.\n"
        "- DO NOT return typos, misspellings, leetspeak, space-variations, or phonetic variations of ANY words in the active blocklist or history.\n"
        "- NEVER suggest multipurpose CDNs or general cloud/image hosts (cloudfront, cloudinary, imgix, fastly, akamai, aws, googleusercontent, imgur, imgbb, postimg). ONLY target dedicated sole-porn/nude image hosts.\n"
        "- FOCUS STRICTLY ON SLIP-THROUGHS: obscure regional/niche adult slang, dedicated nude/porn image hosting brands, CGI proxy scripts (Glype/PHProxy/MiniProxy/Ultraviolet/Rammerhead), web-based proxy portals, stealth search mirrors, and software/media downloader portals.\n\n"
        f"TARGET CATEGORY: '{category}'\n"
        f"CATEGORY FOCUS: {description or 'Slip-through base search terms.'}\n"
        f"CURRENT ACTIVE BLOCKLIST SAMPLE:\n{', '.join(sample_active)}\n"
        f"{history_context}\n"
        "TASK: Suggest up to 20 concise, high-signal base search keywords/phrases (1 to 3 words each, clean lowercase canonical forms that real users actually search).\n"
        "STRICT QUALITY RULE: Quality matters far more than quantity. NEVER pad with contrived 5+ word sentences, generic single words ('free', 'online', 'fast', 'unblock'), or minor variants just to add items. "
        "If no genuinely useful, non-redundant keywords remain for this category, return ONLY the exact word NONE.\n"
        "CRITICAL: Return ONLY a comma-separated list of concise terms, OR NONE. No markdown, no numbers, no explanations.\n"
    )


def run_slipthrough_hunt_loop(
    mode: str,
    api_key: str,
    backup_api_key: str,
    model_queue: list[str],
    category_key: str,
    get_category_snapshot: Callable[[], dict[str, Any]],
    on_discovered: Callable[[str, list[str]], dict[str, Any]],
    duration_minutes: float,
    max_iterations: int,
    stop_event: threading.Event,
    log_cb: Callable[[str], None],
    progress_cb: Callable[[dict[str, Any]], None] | None = None,
    get_all_search_terms: Callable[[], list[str]] | None = None,
    max_dry_cycles: int = 2,
) -> dict[str, Any]:
    """Run an on-demand bounded Gemini slip-through hunting loop with quality gate & saturation stop."""
    active_keys = [k for k in [api_key, backup_api_key] if k and k != "YOUR_GEMINI_API_KEY"]
    if not active_keys:
        raise ValueError("No valid Gemini API key configured.")

    key_idx = 0
    client = GeminiRestClient(api_key=active_keys[key_idx])
    if not model_queue:
        model_queue = ["models/gemini-2.5-flash", "models/gemini-2.5-pro"]

    model_idx = 0
    current_model = model_queue[model_idx]
    chat = GeminiChatSession(client, current_model) if mode == "dns" else None

    end_time = time.time() + max(0.2, duration_minutes) * 60.0
    iteration = 1
    total_added = 0
    total_rejected = 0
    dry_cycles = 0
    stop_reason = "completed"
    discovered_all: list[str] = []

    log_cb(
        f"[*] Starting {mode.upper()} Slip-Through Hunter on '{category_key}' "
        f"using {current_model.replace('models/', '')} (duration: {duration_minutes}m, max iterations: {max_iterations})."
    )

    while not stop_event.is_set() and time.time() < end_time and iteration <= max_iterations:
        snap = get_category_snapshot()
        cat_name = snap.get("category", category_key.replace("+block", ""))
        description = snap.get("description", "")

        log_cb(f"\n[Iteration {iteration}/{max_iterations}] Hunting slip-through vectors with {current_model.replace('models/', '')}...")

        try:
            if mode == "dns":
                existing = snap.get("domains", [])
                prompt = build_dns_slipthrough_prompt(cat_name, description, existing)
                if chat is None:
                    chat = GeminiChatSession(client, current_model)
                res_text = chat.send_message(prompt)
                if parse_ai_exhausted_signal(res_text):
                    log_cb("  [*] AI indicated no further genuine domains remain for this category.")
                    stop_reason = "saturated"
                    break
                raw_text = res_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                parsed = json.loads(raw_text)
                if not isinstance(parsed, list):
                    raise ValueError("Expected JSON array of domains.")
                if not parsed:
                    log_cb("  [*] AI returned empty list — category saturated.")
                    stop_reason = "saturated"
                    break
                gated = filter_useful_dns_candidates(parsed, existing, verify_live=True)
            else:
                existing = snap.get("terms", [])
                history = snap.get("history", [])
                prompt = build_search_slipthrough_prompt(cat_name, description, existing, history)
                raw_text = client.generate_content(current_model, prompt)
                if parse_ai_exhausted_signal(raw_text):
                    log_cb("  [*] AI indicated no further useful search terms remain for this category.")
                    stop_reason = "saturated"
                    break
                raw_candidates = [t.strip() for t in re.split(r"[,\n]", raw_text) if t.strip()]
                all_active = get_all_search_terms() if get_all_search_terms else existing
                gated = filter_useful_search_candidates(
                    raw_candidates,
                    existing,
                    history,
                    all_blocklist_terms=all_active,
                )

            candidates = gated["accepted"]
            rejected = gated["rejected"]
            total_rejected += len(rejected)
            if rejected:
                log_cb(f"  [~] Quality gate filtered out {len(rejected)} redundant/dead/low-value item(s).")

            if candidates:
                dry_cycles = 0
                deploy_res = on_discovered(category_key, candidates)
                added = deploy_res.get("added", [])
                total_added += len(added)
                discovered_all.extend(added)
                log_cb(f"  [+] Added {len(added)} verified slip-through entries (Sync status: {deploy_res.get('sync_status', 'queued')}).")
                for item in added[:8]:
                    log_cb(f"      - {item}")
                if len(added) > 8:
                    log_cb(f"      ... +{len(added) - 8} more")
            else:
                dry_cycles += 1
                log_cb(f"  [-] 0 useful novel items passed quality gate ({dry_cycles}/{max_dry_cycles} dry cycles).")
                if dry_cycles >= max_dry_cycles:
                    stop_reason = "saturated"
                    log_cb("  [SATURATION STOP] Diminishing returns reached — stopping hunt early to prevent list bloat.")
                    break

            if progress_cb:
                progress_cb(
                    {
                        "iteration": iteration,
                        "max_iterations": max_iterations,
                        "total_added": total_added,
                        "total_rejected": total_rejected,
                        "current_model": current_model,
                        "seconds_remaining": max(0, int(end_time - time.time())),
                    }
                )

        except json.JSONDecodeError:
            log_cb("  [!] Model returned malformed JSON; retrying next cycle.")
        except Exception as exc:
            log_cb(f"  [!] Gemini error ({current_model.replace('models/', '')}): {exc}")
            if len(model_queue) > 1 and (model_idx + 1) < len(model_queue):
                model_idx += 1
                current_model = model_queue[model_idx]
                chat = GeminiChatSession(client, current_model) if mode == "dns" else None
                log_cb(f"  [->] Auto-failover to model: {current_model.replace('models/', '')}")
            elif (key_idx + 1) < len(active_keys):
                key_idx += 1
                model_idx = 0
                current_model = model_queue[0]
                client = GeminiRestClient(api_key=active_keys[key_idx])
                chat = GeminiChatSession(client, current_model) if mode == "dns" else None
                log_cb("  [->] Switching to Backup Gemini API Key from Vault.")
            else:
                log_cb("  [!] Cooldown 15s before retry...")
                for _ in range(15):
                    if stop_event.is_set():
                        break
                    time.sleep(1)

        iteration += 1
        remaining = end_time - time.time()
        if remaining > 0 and iteration <= max_iterations and not stop_event.is_set():
            cooldown = min(15 if mode == "dns" else 20, remaining)
            log_cb(f"  [*] Cooling down {int(cooldown)}s ({int(remaining)}s left)...")
            end_sleep = time.time() + cooldown
            while time.time() < end_sleep and not stop_event.is_set():
                time.sleep(0.5)

    if stop_event.is_set():
        stop_reason = "stopped_by_user"
    log_cb(
        f"\n[{stop_reason.upper()}] AI Slip-Through Hunt finished. "
        f"Added: {total_added} | Filtered redundant/low-value: {total_rejected}."
    )
    return {
        "ok": True,
        "stopped_early": stop_event.is_set(),
        "stop_reason": stop_reason,
        "iterations_completed": iteration - 1,
        "total_added": total_added,
        "total_rejected": total_rejected,
        "discovered": discovered_all,
    }
