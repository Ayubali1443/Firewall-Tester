"""Tamper-resistant append-only storage manager for blocklists, uptime baselines, and states."""

from __future__ import annotations

import copy
import json
import threading
from pathlib import Path
from typing import Any

from sentinelgate.config.paths import (
    get_app_data_dir,
    get_workspace_data_dir,
    is_compiled_binary,
)
from sentinelgate.config.vault import dpapi_protect, dpapi_unprotect
from sentinelgate.core.baseline_data import (
    BASELINE_DNS_BLOCKLIST,
    BASELINE_DNS_UPTIME,
    BASELINE_SEARCH_BLOCKLIST,
    BASELINE_SEARCH_UPTIME,
)
from sentinelgate.core.cleaner import clean_category
from sentinelgate.core.quality_gate import is_multipurpose_cdn_domain


class StorageManager:
    """Thread-safe tamper-resistant dataset manager.

    Invariants enforced regardless of dev or compiled execution:
    1. Immutable compiled-in baselines are ALWAYS merged into active blocklists.
    2. Only 'block' actions are accepted in Pentester datasets (no allow-listing).
    3. Deleting domains, search terms, or categories is strictly unsupported.
    4. In compiled builds, user/AI additions are sealed via Windows DPAPI on disk.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.compiled = is_compiled_binary()
        self.app_data_dir = get_app_data_dir()
        self.workspace_data_dir = get_workspace_data_dir()
        self.overlay_path = self.app_data_dir / "blocklist_overlay.dpapi"
        self.state_dpapi_path = self.app_data_dir / "runtime_state.dpapi"

    # --- Internal DPAPI & Dev-JSON Helpers ---
    def _read_dpapi_json(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            raw = dpapi_unprotect(path.read_bytes())
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _write_dpapi_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        path.write_bytes(dpapi_protect(encoded))

    def _read_dev_json(self, filename: str, fallback: dict[str, Any]) -> dict[str, Any]:
        if not self.compiled:
            dev_path = self.workspace_data_dir / filename
            if dev_path.exists():
                try:
                    data = json.loads(dev_path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        return data
                except Exception:
                    pass
        return copy.deepcopy(fallback)

    def _write_dev_json(self, filename: str, data: dict[str, Any]) -> None:
        if not self.compiled and self.workspace_data_dir.exists():
            dev_path = self.workspace_data_dir / filename
            dev_path.write_text(json.dumps(data, indent=4), encoding="utf-8")

    # --- Monotonic Baseline + Overlay Merging ---
    @staticmethod
    def _merge_dns_blocklists(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
        merged = copy.deepcopy(base)
        for list_id, cfg in overlay.items():
            if not isinstance(cfg, dict):
                continue
            # Strictly enforce block-only invariant
            if str(cfg.get("action", "block")).lower() != "block":
                continue
            cat = str(cfg.get("category") or list_id.split("+")[0]).strip()
            if not cat:
                continue
            canonical_id = f"{cat}+block"
            domains = [str(d).strip().lower() for d in cfg.get("domains", []) if str(d).strip()]
            if canonical_id not in merged:
                merged[canonical_id] = {
                    "category": cat,
                    "action": "block",
                    "ai_target": bool(cfg.get("ai_target", True)),
                    "scope": str(cfg.get("scope", "slip_through")),
                    "description": str(cfg.get("description", "")),
                    "domains": list(dict.fromkeys(domains)),
                }
            else:
                existing = set(merged[canonical_id].get("domains", []))
                for d in domains:
                    if d not in existing:
                        merged[canonical_id]["domains"].append(d)
                        existing.add(d)
        # Ensure every category strictly reports action == "block"
        for cfg in merged.values():
            cfg["action"] = "block"
        return merged

    @staticmethod
    def _merge_search_blocklists(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
        merged = copy.deepcopy(base)
        for list_id, cfg in overlay.items():
            if not isinstance(cfg, dict):
                continue
            if str(cfg.get("action", "block")).lower() != "block":
                continue
            cat = str(cfg.get("category") or list_id.split("+")[0]).strip()
            if not cat:
                continue
            canonical_id = list_id if list_id.endswith("+block") else f"{cat}+block"
            terms = [str(t).strip().lower() for t in cfg.get("terms", []) if str(t).strip()]
            history = [str(h).strip().lower() for h in cfg.get("history", []) if str(h).strip()]

            if canonical_id not in merged:
                merged[canonical_id] = {
                    "category": cat,
                    "action": "block",
                    "ai_target": bool(cfg.get("ai_target", True)),
                    "scope": str(cfg.get("scope", "slip_through")),
                    "description": str(cfg.get("description", "")),
                    "terms": list(dict.fromkeys(terms)),
                    "history": list(dict.fromkeys(history)),
                }
            else:
                existing_terms = set(merged[canonical_id].get("terms", []))
                for t in terms:
                    if t not in existing_terms:
                        merged[canonical_id]["terms"].append(t)
                        existing_terms.add(t)
                existing_hist = set(merged[canonical_id].get("history", []))
                for h in history:
                    if h not in existing_hist:
                        merged[canonical_id].setdefault("history", []).append(h)
                        existing_hist.add(h)
        for cfg in merged.values():
            cfg["action"] = "block"
            cfg.setdefault("history", [])
        return merged

    # --- Public Read APIs ---
    def load_dns_blocklist(self) -> dict[str, Any]:
        with self._lock:
            base = self._read_dev_json("dns_blocklist.json", BASELINE_DNS_BLOCKLIST)
            # Always guarantee compiled baseline is monotonically present
            base = self._merge_dns_blocklists(BASELINE_DNS_BLOCKLIST, base)
            overlay = self._read_dpapi_json(self.overlay_path).get("dns", {})
            return self._merge_dns_blocklists(base, overlay)

    def load_search_blocklist(self) -> dict[str, Any]:
        with self._lock:
            base = self._read_dev_json("search_blocklist.json", BASELINE_SEARCH_BLOCKLIST)
            base = self._merge_search_blocklists(BASELINE_SEARCH_BLOCKLIST, base)
            overlay = self._read_dpapi_json(self.overlay_path).get("search", {})
            return self._merge_search_blocklists(base, overlay)

    def load_dns_uptime_sites(self) -> dict[str, Any]:
        with self._lock:
            return self._read_dev_json("dns_uptime_sites.json", BASELINE_DNS_UPTIME)

    def load_search_uptime_terms(self) -> dict[str, Any]:
        with self._lock:
            return self._read_dev_json("search_uptime_terms.json", BASELINE_SEARCH_UPTIME)

    def load_state(self, kind: str) -> dict[str, str]:
        """Load test cache state ('dns_pentest' or 'dns_uptime')."""
        with self._lock:
            filename = "dns_pentest_state.json" if kind == "dns_pentest" else "dns_uptime_state.json"
            fallback: dict[str, str] = {}
            if not self.compiled:
                dev_path = self.workspace_data_dir / filename
                if dev_path.exists():
                    try:
                        fallback = json.loads(dev_path.read_text(encoding="utf-8"))
                    except Exception:
                        fallback = {}
            dpapi_state = self._read_dpapi_json(self.state_dpapi_path).get(kind, {})
            combined = dict(fallback)
            if isinstance(dpapi_state, dict):
                combined.update(dpapi_state)
            return combined

    def save_state(self, kind: str, state: dict[str, str]) -> None:
        with self._lock:
            all_states = self._read_dpapi_json(self.state_dpapi_path)
            all_states[kind] = state
            self._write_dpapi_json(self.state_dpapi_path, all_states)
            filename = "dns_pentest_state.json" if kind == "dns_pentest" else "dns_uptime_state.json"
            self._write_dev_json(filename, state)

    # --- Public Append-Only Write APIs (Pentester Only) ---
    @staticmethod
    def _validate_block_category_name(category: str) -> str:
        cat = category.strip()
        if not cat:
            raise ValueError("Category name cannot be empty.")
        if "+allow" in cat.lower() or cat.lower() == "allow":
            raise ValueError("Allow-listing is permanently disabled in SentinelGate AI.")
        if cat.endswith("+block"):
            cat = cat[:-6].strip()
        if not cat:
            raise ValueError("Invalid category name.")
        return cat

    def add_dns_domains(
        self,
        category_or_list_id: str,
        domains: list[str],
        description: str = "",
        action: str = "block",
    ) -> dict[str, Any]:
        if str(action).strip().lower() != "block":
            raise ValueError("Allow-listing is prohibited. Only 'block' rules are permitted.")

        cat = self._validate_block_category_name(category_or_list_id)
        list_id = f"{cat}+block"
        cleaned_domains = [
            d.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
            for d in domains
            if d and d.strip()
        ]
        cleaned_domains = [
            d
            for d in dict.fromkeys(cleaned_domains)
            if "." in d and not is_multipurpose_cdn_domain(d)
        ]
        if not cleaned_domains:
            return {"list_id": list_id, "added": [], "skipped": 0}

        with self._lock:
            current = self.load_dns_blocklist()
            existing_set = set(current.get(list_id, {}).get("domains", []))
            added = [d for d in cleaned_domains if d not in existing_set]

            if added:
                overlay_root = self._read_dpapi_json(self.overlay_path)
                dns_overlay = overlay_root.setdefault("dns", {})
                if list_id not in dns_overlay:
                    dns_overlay[list_id] = {
                        "category": cat,
                        "action": "block",
                        "ai_target": True,
                        "scope": "slip_through",
                        "description": description or current.get(list_id, {}).get("description", ""),
                        "domains": [],
                    }
                ov_set = set(dns_overlay[list_id]["domains"])
                for d in added:
                    if d not in ov_set:
                        dns_overlay[list_id]["domains"].append(d)
                        ov_set.add(d)
                self._write_dpapi_json(self.overlay_path, overlay_root)

                updated = self.load_dns_blocklist()
                self._write_dev_json("dns_blocklist.json", updated)

            return {
                "list_id": list_id,
                "added": added,
                "skipped": len(cleaned_domains) - len(added),
            }

    def add_search_terms(
        self,
        category_or_list_id: str,
        terms: list[str],
        history_terms: list[str] | None = None,
        description: str = "",
        action: str = "block",
    ) -> dict[str, Any]:
        if str(action).strip().lower() != "block":
            raise ValueError("Allow-listing is prohibited. Only 'block' keywords are permitted.")

        cat = self._validate_block_category_name(category_or_list_id)
        list_id = f"{cat}+block"
        # Preserve exact lookup if existing key uses spaces like "Web Proxies+block"
        current_all = self.load_search_blocklist()
        if category_or_list_id in current_all:
            list_id = category_or_list_id
            cat = current_all[list_id].get("category", cat)

        cleaned_terms = [t.strip().lower() for t in terms if t and t.strip()]
        cleaned_terms = list(dict.fromkeys(cleaned_terms))
        cleaned_hist = [h.strip().lower() for h in (history_terms or []) if h and h.strip()]

        with self._lock:
            current = self.load_search_blocklist()
            existing_set = set(t.lower() for t in current.get(list_id, {}).get("terms", []))
            added = [t for t in cleaned_terms if t not in existing_set]

            overlay_root = self._read_dpapi_json(self.overlay_path)
            search_overlay = overlay_root.setdefault("search", {})
            if list_id not in search_overlay:
                search_overlay[list_id] = {
                    "category": cat,
                    "action": "block",
                    "ai_target": True,
                    "scope": "slip_through",
                    "description": description or current.get(list_id, {}).get("description", ""),
                    "terms": [],
                    "history": [],
                }
            ov_terms = set(t.lower() for t in search_overlay[list_id]["terms"])
            for t in added:
                if t not in ov_terms:
                    search_overlay[list_id]["terms"].append(t)
                    ov_terms.add(t)

            ov_hist = set(h.lower() for h in search_overlay[list_id]["history"])
            for h in cleaned_hist + added:
                if h not in ov_hist:
                    search_overlay[list_id]["history"].append(h)
                    ov_hist.add(h)

            self._write_dpapi_json(self.overlay_path, overlay_root)
            updated = self.load_search_blocklist()
            self._write_dev_json("search_blocklist.json", updated)

            return {
                "list_id": list_id,
                "added": added,
                "skipped": len(cleaned_terms) - len(added),
            }

    def run_search_skeleton_cleanup(self) -> dict[str, Any]:
        """Deduplicate obfuscated additions via skeleton clustering without ever removing baseline bases."""
        with self._lock:
            overlay_root = self._read_dpapi_json(self.overlay_path)
            search_overlay = overlay_root.get("search", {})
            current_full = self.load_search_blocklist()

            merged_events: list[dict[str, str]] = []
            for list_id, ov_cfg in search_overlay.items():
                base_terms = set(
                    t.lower()
                    for t in BASELINE_SEARCH_BLOCKLIST.get(list_id, {}).get("terms", [])
                )
                combined_cfg = copy.deepcopy(current_full.get(list_id, ov_cfg))
                removed = clean_category(combined_cfg)
                surviving = set(t.lower() for t in combined_cfg.get("terms", []))

                # Only drop from overlay if the canonical base exists in surviving or baseline
                new_ov_terms = []
                for t in ov_cfg.get("terms", []):
                    tl = t.lower()
                    if tl in surviving or tl in base_terms:
                        new_ov_terms.append(t)
                    else:
                        merged_base = next((b for tw, b in removed if tw.lower() == tl), None)
                        if merged_base and (
                            merged_base.lower() in surviving or merged_base.lower() in base_terms
                        ):
                            merged_events.append(
                                {"list_id": list_id, "tweaked": t, "merged_into": merged_base}
                            )
                        else:
                            new_ov_terms.append(t)
                ov_cfg["terms"] = new_ov_terms

            self._write_dpapi_json(self.overlay_path, overlay_root)
            updated = self.load_search_blocklist()
            self._write_dev_json("search_blocklist.json", updated)
            return {
                "merged_count": len(merged_events),
                "events": merged_events[:100],
                "baseline_preserved": True,
            }

    def verify_integrity(self) -> dict[str, Any]:
        """Confirm baseline lists and overlay integrity have not been stripped."""
        dns = self.load_dns_blocklist()
        search = self.load_search_blocklist()

        dns_baseline_total = sum(len(v.get("domains", [])) for v in BASELINE_DNS_BLOCKLIST.values())
        dns_active_total = sum(len(v.get("domains", [])) for v in dns.values())

        search_baseline_total = sum(len(v.get("terms", [])) for v in BASELINE_SEARCH_BLOCKLIST.values())
        search_active_total = sum(len(v.get("terms", [])) for v in search.values())

        return {
            "compiled_binary": self.compiled,
            "dpapi_overlay_exists": self.overlay_path.exists(),
            "dns_baseline_count": dns_baseline_total,
            "dns_active_count": dns_active_total,
            "dns_intact": dns_active_total >= dns_baseline_total,
            "search_baseline_count": search_baseline_total,
            "search_active_count": search_active_total,
            "search_intact": search_active_total >= search_baseline_total,
            "block_only_enforced": all(
                v.get("action") == "block"
                for v in list(dns.values()) + list(search.values())
            ),
        }
