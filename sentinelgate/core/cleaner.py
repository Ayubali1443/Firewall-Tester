"""Retained Skeleton Cleaning, Human Variation Generator, and Virtual Brute-Force Pentester."""

from __future__ import annotations

import difflib
import itertools
import random
import re

from sentinelgate.core.regex_engine import build_flat_regex

COMMON_LEET = {
    "a": ["a", "@", "4"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
    "t": ["t", "7"],
    "b": ["b", "v"],
    "v": ["v", "b"],
    "c": ["c", "k"],
    "k": ["k", "c"],
}


# ==========================================
# 1. JSON CLEANING LOGIC (Skeleton Clusters)
# ==========================================
def get_skeleton(text: str) -> str:
    """Compute phonetic/consonant skeleton used to cluster obfuscated variations."""
    text = text.lower()
    leet = {
        "0": "o",
        "1": "i",
        "2": "z",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "!": "i",
        "$": "s",
    }
    for k, v in leet.items():
        text = text.replace(k, v)
    text = re.sub(r"[^a-z]", "", text)

    text = (
        text.replace("ph", "f")
        .replace("sh", "s")
        .replace("kh", "k")
        .replace("gh", "g")
        .replace("ch", "c")
    )
    text = (
        text.replace("z", "s")
        .replace("v", "b")
        .replace("w", "b")
        .replace("k", "c")
        .replace("q", "c")
        .replace("x", "ks")
        .replace("j", "z")
        .replace("y", "i")
    )
    text = re.sub(r"[aeiouh]", "", text)
    text = re.sub(r"(.)\1+", r"\1", text)
    return text


def clean_category(config: dict) -> list[tuple[str, str]]:
    """Cluster and merge obfuscated variations into clean canonical base terms."""
    all_words = list(set(config.get("terms", []) + config.get("history", [])))
    all_words.sort(key=lambda w: (bool(re.search(r"[^a-zA-Z\s]", w)), -len(w)))

    groups: list[list[str]] = []
    for w in all_words:
        skel = get_skeleton(w)
        best_match_idx = -1
        best_ratio = 0.80
        for i, group in enumerate(groups):
            center_skel = get_skeleton(group[0])
            if skel == center_skel:
                best_match_idx = i
                break
            elif difflib.SequenceMatcher(None, skel, center_skel).ratio() > best_ratio:
                best_match_idx = i

        if best_match_idx != -1:
            groups[best_match_idx].append(w)
        else:
            groups.append([w])

    clean_terms = set()
    removed: list[tuple[str, str]] = []
    for group in groups:
        best_base = group[0]
        clean_terms.add(best_base)
        for tweaked in group[1:]:
            removed.append((tweaked, best_base))

    new_terms = [w for w in config.get("terms", []) if w in clean_terms]
    new_history = [w for w in config.get("history", []) if w in clean_terms]
    config["terms"] = list(dict.fromkeys(new_terms))
    config["history"] = list(dict.fromkeys(new_history))

    return removed


# ==========================================
# 2. REALISTIC OBFUSCATION GENERATOR
# ==========================================
def generate_human_variations(keyword: str, max_results: int = 5000) -> list[str]:
    """Generate realistic human leetspeak, split, vowel-drop, and stretch variations."""
    keyword = keyword.lower().strip()
    if not keyword:
        return []
    results = set([keyword])
    no_space_keyword = keyword.replace(" ", "")

    # Strategy 0: Complete space removal
    results.add(no_space_keyword)

    # Strategy 1: Targeted Leetspeak & Phonetic Swaps (bounded for long phrases in UI)
    pools = [COMMON_LEET.get(char, [char]) for char in keyword]
    for idx, combo in enumerate(itertools.product(*pools)):
        results.add("".join(combo))
        if idx >= max_results:
            break

    # Strategy 2: Vowel Dropping
    no_vowels = re.sub(r"[aeiou]", "", keyword)
    results.add(no_vowels)

    if " " in keyword:
        words = keyword.split()
        results.add(re.sub(r"[aeiou]", "", words[0]) + " " + " ".join(words[1:]))
        results.add(words[0] + " " + re.sub(r"[aeiou]", "", " ".join(words[1:])))

    # Strategy 3: Interspersed Separators
    separators = [".", "_", "-", " "]
    for sep in separators:
        results.add(sep.join(no_space_keyword))
        if " " in keyword:
            results.add(keyword.replace(" ", sep))

    # Strategy 4: Arbitrary Word Splitting
    for i in range(1, len(no_space_keyword)):
        results.add(no_space_keyword[:i] + " " + no_space_keyword[i:])

    if len(no_space_keyword) > 4:
        for i in range(1, len(no_space_keyword) - 1):
            for j in range(i + 1, len(no_space_keyword)):
                results.add(
                    no_space_keyword[:i] + " " + no_space_keyword[i:j] + " " + no_space_keyword[j:]
                )
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break

    # Strategy 5: Character Stretching / Extra Letters
    for i, char in enumerate(no_space_keyword):
        if char.isalpha():
            results.add(no_space_keyword[:i] + char * 2 + no_space_keyword[i + 1 :])
            results.add(no_space_keyword[:i] + char * 3 + no_space_keyword[i + 1 :])

    return sorted(list(results))


def generate_extreme_obfuscations(word: str, count: int = 500) -> list[str]:
    """Generate highly evasive permutations of a base word for offline pentesting."""
    variations = set()
    leet_map = {
        "a": ["a", "@", "4", "^", ""],
        "b": ["b", "v", "8", "bb"],
        "c": ["c", "k", "q"],
        "e": ["e", "3", "i", "1", "!", "y", ""],
        "g": ["g", "9", "6"],
        "i": ["i", "1", "!", "l", "y", ""],
        "o": ["o", "0", "u", ""],
        "s": ["s", "5", "$", "z", "c", "ss"],
        "t": ["t", "7", "+", "tt"],
    }
    separators = ["", " ", ".", "-", "_", "%20", "%2B", "%2D", "%2E", "+"]

    for _ in range(count):
        obf = ""
        for char in word:
            c = random.choice(leet_map.get(char, [char, char + char]))
            sep = random.choice(separators) if random.random() > 0.3 else ""
            obf += c + sep
        clean_obf = obf.strip(" .-_%+").strip()
        if clean_obf:
            variations.add(clean_obf)
    return list(variations)


def run_virtual_pentest_for_terms(terms: list[str], variants_per_term: int = 800) -> dict:
    """Offline brute-forcer. Test permutations against local Python RE2 simulator."""
    if not terms:
        return {"ok": False, "error": "No search terms provided."}

    raw_regex = build_flat_regex(terms)
    try:
        compiled_regex = re.compile(raw_regex)
    except re.error as exc:
        return {"ok": False, "error": f"Failed to compile local regex: {exc}"}

    total_tested = 0
    bypasses: list[dict[str, str]] = []

    for term in terms:
        variants = generate_extreme_obfuscations(term, count=variants_per_term)
        total_tested += len(variants)

        for variant in variants:
            if not compiled_regex.search(variant):
                bypasses.append({"base": term, "variant": variant})

    blocked_count = total_tested - len(bypasses)
    block_rate = round((blocked_count / total_tested) * 100, 2) if total_tested else 100.0
    return {
        "ok": True,
        "term_count": len(terms),
        "total_tested": total_tested,
        "blocked_count": blocked_count,
        "bypass_count": len(bypasses),
        "block_rate": block_rate,
        "bypasses": bypasses[:100],
    }


def deduplicate_terms_for_sync(terms: list[str]) -> tuple[list[str], int]:
    """Eliminate case/whitespace/skeleton duplicates before Cloudflare chunking.

    Prefers compact no-space canonical forms (e.g., 'croxyproxy' over 'croxy proxy')
    because obfuscate_term inserts optional separators between letters, covering both.
    """
    seen_lower: set[str] = set()
    unique_raw: list[str] = []
    for raw in terms:
        clean = re.sub(r"\s+", " ", str(raw or "").strip().lower())
        if clean and clean not in seen_lower:
            seen_lower.add(clean)
            unique_raw.append(clean)

    # Sort so clean pure-alphabetic compact forms win over digits/leetspeak/spaced duplicates
    ordered = sorted(
        unique_raw,
        key=lambda w: (bool(re.search(r"[^a-zA-Z\s]", w)), " " in w, len(w)),
    )

    by_skeleton: dict[str, str] = {}
    deduped: list[str] = []
    for w in ordered:
        skel = get_skeleton(w)
        if skel and len(skel) >= 3:
            if skel in by_skeleton:
                continue
            by_skeleton[skel] = w
        deduped.append(w)

    # Restore deterministic alphabetical ordering for stable chunk diffs
    deduped.sort()
    removed_count = len(terms) - len(deduped)
    return deduped, max(0, removed_count)
