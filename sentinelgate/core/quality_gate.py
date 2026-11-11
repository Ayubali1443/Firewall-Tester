"""Quality, utility, and redundancy gate for AI-discovered DNS domains and search terms.

Prevents the AI agent from bloating blocklists with:
1. Hallucinated / dead / non-existent domains.
2. Domains or search terms ALREADY blocked by Cloudflare Zero Trust or existing RE2 regexes.
3. Contrived long-tail filler phrases, single generic English words, or skeleton duplicates.
"""

from __future__ import annotations

import re
import socket
from typing import Any

import requests

from sentinelgate.core.cleaner import get_skeleton
from sentinelgate.core.regex_engine import build_flat_regex

# Single generic English words that cause noisy over-blocking or provide zero unique evasion signal
GENERIC_SINGLE_STOPWORDS = frozenset(
    {
        "app",
        "apps",
        "best",
        "browser",
        "chat",
        "clean",
        "click",
        "cool",
        "direct",
        "download",
        "downloads",
        "easy",
        "fast",
        "file",
        "files",
        "free",
        "full",
        "game",
        "games",
        "get",
        "good",
        "guide",
        "help",
        "home",
        "hub",
        "info",
        "internet",
        "link",
        "links",
        "live",
        "login",
        "media",
        "mirror",
        "mirrors",
        "mobile",
        "movie",
        "movies",
        "music",
        "new",
        "none",
        "online",
        "open",
        "page",
        "portal",
        "private",
        "quick",
        "safe",
        "search",
        "secret",
        "server",
        "site",
        "sites",
        "song",
        "songs",
        "speed",
        "stealth",
        "stream",
        "streaming",
        "tool",
        "tools",
        "top",
        "tube",
        "unblock",
        "unblocked",
        "url",
        "video",
        "videos",
        "watch",
        "web",
        "website",
        "websites",
        "work",
    }
)

_DOMAIN_LABEL_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")

# Multipurpose CDNs, cloud object stores, and general-purpose image/asset hosts
# that MUST NEVER be blocked by the sole-porn image-host filter.
MULTIPURPOSE_CDN_DOMAINS = frozenset(
    {
        "cloudflare.com",
        "imagedelivery.net",
        "r2.dev",
        "pages.dev",
        "amazonaws.com",
        "cloudfront.net",
        "googleusercontent.com",
        "ggpht.com",
        "gstatic.com",
        "googleapis.com",
        "azureedge.net",
        "windows.net",
        "fastly.net",
        "akamaized.net",
        "akamaihd.net",
        "akamai.net",
        "jsdelivr.net",
        "unpkg.com",
        "cloudinary.com",
        "imgix.net",
        "imagekit.io",
        "b-cdn.net",
        "bunny.net",
        "digitaloceanspaces.com",
        "githubusercontent.com",
        "github.com",
        "imgur.com",
        "redd.it",
        "redditmedia.com",
        "postimg.cc",
        "ibb.co",
        "imgbb.com",
        "giphy.com",
        "tenor.com",
        "gravatar.com",
        "wp.com",
        "twimg.com",
        "fbcdn.net",
        "cdninstagram.com",
        "ytimg.com",
        "licdn.com",
        "wikimedia.org",
    }
)

MULTIPURPOSE_CDN_KEYWORDS = frozenset(
    {
        "cloudflare",
        "imagedelivery",
        "amazonaws",
        "cloudfront",
        "googleusercontent",
        "azureedge",
        "fastly",
        "akamaized",
        "akamaihd",
        "jsdelivr",
        "unpkg",
        "cloudinary",
        "imgix",
        "imagekit",
        "bunnycdn",
        "b-cdn",
        "githubusercontent",
        "imgur",
        "imgbb",
        "postimg",
        "gravatar",
    }
)


def is_multipurpose_cdn_domain(domain: str) -> bool:
    """Return True if domain or any parent suffix is a protected multipurpose CDN/cloud host."""
    d = (domain or "").strip().lower()
    if d in MULTIPURPOSE_CDN_DOMAINS:
        return True
    parts = d.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in MULTIPURPOSE_CDN_DOMAINS:
            return True
    return False


def parse_ai_exhausted_signal(raw_text: str) -> bool:
    """Return True when the AI explicitly indicates no meaningful new targets remain."""
    cleaned = (raw_text or "").strip().strip("`").strip().lower()
    return cleaned in ("", "none", "null", "[]", "done", "n/a", "no new terms", "no new domains")


def is_domain_syntactically_valid(domain: str, existing_domains: set[str]) -> tuple[bool, str]:
    """Validate hostname structure and ensure it is not a subdomain of an already-blocked root."""
    d = (domain or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    if not d or len(d) > 65:
        return False, "invalid_length"
    if not _DOMAIN_LABEL_RE.match(d):
        return False, "invalid_hostname"
    if d.count("-") >= 4:
        return False, "suspicious_hyphens"
    if is_multipurpose_cdn_domain(d):
        return False, "multipurpose_cdn_protected"
    if d in existing_domains:
        return False, "duplicate"

    # Reject subdomains when parent domain is already blocked (e.g., sub.croxyproxy.com)
    parts = d.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in existing_domains:
            return False, "covered_by_parent"

    return True, "ok"


def check_live_domain_slipthrough(domain: str) -> tuple[bool, str]:
    """Confirm a candidate domain actually resolves and is NOT already blocked by Cloudflare.

    Returns (True, "live_slipthrough") only for real, reachable unblocked domains.
    Rejects NXDOMAIN/dead domains (hallucinations) and domains already sinkholed by Cloudflare.
    """
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return False, "unresolvable_or_nxdomain"

    if ip == "0.0.0.0" or ip.startswith("162.159."):
        return False, "already_blocked_dns"

    try:
        res = requests.get(
            f"https://{domain}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=4,
            allow_redirects=True,
        )
        if "web-access-notice.ubaidpateladmin.workers.dev" in (res.url or ""):
            return False, "already_blocked_http"
    except requests.exceptions.RequestException:
        # Real DNS resolved to non-sinkhole IP; server may block automated HEAD/GET bots,
        # so treat as potentially reachable unless DNS itself sinkholed it.
        pass

    return True, "live_slipthrough"


def filter_useful_dns_candidates(
    candidates: list[str],
    existing_domains: list[str],
    verify_live: bool = True,
) -> dict[str, Any]:
    """Filter AI-proposed domains down to genuine, live, non-redundant slip-throughs."""
    existing_set = set(d.strip().lower() for d in existing_domains if d)
    accepted: list[str] = []
    rejected: list[dict[str, str]] = []
    seen_batch: set[str] = set()

    for raw in candidates:
        d = str(raw or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
        if d in seen_batch:
            continue
        seen_batch.add(d)

        ok_syntax, reason = is_domain_syntactically_valid(d, existing_set)
        if not ok_syntax:
            rejected.append({"item": d, "reason": reason})
            continue

        if verify_live:
            ok_live, live_reason = check_live_domain_slipthrough(d)
            if not ok_live:
                rejected.append({"item": d, "reason": live_reason})
                continue

        accepted.append(d)
        existing_set.add(d)

    return {"accepted": accepted, "rejected": rejected}


def filter_useful_search_candidates(
    candidates: list[str],
    existing_terms: list[str],
    history_terms: list[str],
    all_blocklist_terms: list[str] | None = None,
) -> dict[str, Any]:
    """Filter AI-proposed search keywords against length, filler, skeleton, and active regex rules."""
    known_pool = set(t.strip().lower() for t in (existing_terms + history_terms) if t and t.strip())
    all_active = all_blocklist_terms if all_blocklist_terms is not None else existing_terms

    # Pre-build skeletons and compiled RE2-compatible checks over active terms
    existing_skeletons = {get_skeleton(t) for t in all_active if t and len(get_skeleton(t)) >= 3}

    # Build chunked compiled regexes (avoid giant single-compile overhead) to verify if existing rules already catch candidate
    compiled_patterns: list[re.Pattern[str]] = []
    batch: list[str] = []
    for t in all_active:
        batch.append(t)
        if len(batch) >= 35:
            rx = build_flat_regex(batch)
            if rx:
                try:
                    compiled_patterns.append(re.compile(rx))
                except re.error:
                    pass
            batch = []
    if batch:
        rx = build_flat_regex(batch)
        if rx:
            try:
                compiled_patterns.append(re.compile(rx))
            except re.error:
                pass

    accepted: list[str] = []
    rejected: list[dict[str, str]] = []
    seen_batch: set[str] = set()

    for raw in candidates:
        term = re.sub(r"^[\-\*\d\.\)\s\"']+|[\"\'\.\s]+$", "", str(raw or "").strip().lower())
        term = re.sub(r"\s+", " ", term).strip()
        if not term or term in seen_batch:
            continue
        seen_batch.add(term)

        if term in ("none", "null", "n/a", "done", "[]"):
            continue
        if len(term) < 3 or len(term) > 36:
            rejected.append({"item": term, "reason": "length_out_of_bounds"})
            continue
        words = term.split()
        if len(words) > 4:
            rejected.append({"item": term, "reason": "contrived_long_phrase"})
            continue
        if len(words) == 1 and words[0] in GENERIC_SINGLE_STOPWORDS:
            rejected.append({"item": term, "reason": "generic_stopword"})
            continue
        if any(bad in term for bad in ("http:", "https:", "/", "\\", "{", "}", "`", "\n")):
            rejected.append({"item": term, "reason": "invalid_chars"})
            continue
        if term.isdigit():
            rejected.append({"item": term, "reason": "digits_only"})
            continue
        if any(cdn in term for cdn in MULTIPURPOSE_CDN_KEYWORDS):
            rejected.append({"item": term, "reason": "multipurpose_cdn_protected"})
            continue
        if term in known_pool:
            rejected.append({"item": term, "reason": "duplicate"})
            continue

        # Check if skeleton matches an existing base word
        skel = get_skeleton(term)
        if skel and len(skel) >= 3 and skel in existing_skeletons:
            rejected.append({"item": term, "reason": "skeleton_duplicate"})
            continue

        # Check if existing regex engine ALREADY intercepts this candidate
        if any(pat.search(term) for pat in compiled_patterns):
            rejected.append({"item": term, "reason": "already_matched_by_regex"})
            continue

        accepted.append(term)
        known_pool.add(term)
        if skel and len(skel) >= 3:
            existing_skeletons.add(skel)

    return {"accepted": accepted, "rejected": rejected}
