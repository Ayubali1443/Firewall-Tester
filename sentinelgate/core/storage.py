"""Tamper-resistant append-only storage manager for blocklists, uptime baselines, and states."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
    """Thread-safe dataset manager for JSON-driven local state and append-only remote state.

    Invariants enforced regardless of dev or compiled execution:
    1. Compiled-in baselines seed missing JSON files; existing JSON is authoritative.
    2. Only 'block' actions are accepted in Pentester datasets (no allow-listing).
    3. External JSON controls active local datasets, including removals of seeded defaults.
    4. Removing JSON entries never deletes already-created Cloudflare protections.
    5. In compiled builds, the legacy addition ledger and runtime state are sealed via Windows DPAPI.
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        app_data_dir: Path | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.compiled = is_compiled_binary()
        self.app_data_dir = app_data_dir or get_app_data_dir()
        self.overlay_path = self.app_data_dir / "blocklist_overlay.dpapi"
        self.state_dpapi_path = self.app_data_dir / "runtime_state.dpapi"
        self.workspace_data_dir = self._resolve_writable_data_dir(data_dir or get_workspace_data_dir())
        self._ensure_editable_json_files()

    def _resolve_writable_data_dir(self, preferred: Path) -> Path:
        """Prefer `<install_dir>/data` when writable so users can edit JSONs directly after install."""
        for candidate in (preferred, self.app_data_dir / "data"):
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                probe = candidate / ".sg_write_probe"
                probe.write_text("", encoding="utf-8")
                probe.unlink(missing_ok=True)
                return candidate
            except Exception:
                continue
        return preferred

    def _ensure_editable_json_files(self) -> None:
        """Create editable starter JSON files on disk if missing (never overwrites user edits)."""
        overlay = self._read_dpapi_json(self.overlay_path)
        starters: dict[str, dict[str, Any]] = {
            "dns_blocklist.json": self._merge_dns_blocklists(BASELINE_DNS_BLOCKLIST, overlay.get("dns", {})),
            "search_blocklist.json": self._merge_search_blocklists(BASELINE_SEARCH_BLOCKLIST, overlay.get("search", {})),
            "dns_uptime_sites.json": copy.deepcopy(BASELINE_DNS_UPTIME),
            "search_uptime_terms.json": copy.deepcopy(BASELINE_SEARCH_UPTIME),
        }
        for fname, default_data in starters.items():
            target = self.workspace_data_dir / fname
            if not target.exists():
                try:
                    target.write_text(json.dumps(default_data, indent=4), encoding="utf-8")
                except Exception:
                    pass

    # --- Internal DPAPI & Editable JSON Helpers ---
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
        """Read a dataset JSON file; malformed files are reported instead of hidden."""
        json_path = self.workspace_data_dir / filename
        if not json_path.exists():
            return copy.deepcopy(fallback)
        try:
            data = json.loads(json_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot load {json_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{json_path} must contain a JSON object keyed by category.")
        self._validate_dataset_json(filename, data, json_path)
        return data

    @staticmethod
    def _validate_dataset_json(filename: str, data: dict[str, Any], path: Path) -> None:
        if filename in ("dns_blocklist.json", "dns_uptime_sites.json"):
            item_key = "domains"
        else:
            item_key = "terms"
        is_blocklist = filename in ("dns_blocklist.json", "search_blocklist.json")
        for category, cfg in data.items():
            if not isinstance(cfg, dict):
                raise ValueError(f"{path}: category {category!r} must contain an object.")
            # Allow records remain ignored in blocklist files and are valid uptime data.
            if is_blocklist and (
                "+allow" in str(category).lower()
                or str(cfg.get("action", "block")).lower() != "block"
            ):
                continue
            items = cfg.get(item_key, [])
            if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
                raise ValueError(f"{path}: {category!r}.{item_key} must be an array of strings.")

    def _write_dev_json(self, filename: str, data: dict[str, Any]) -> None:
        """Atomically persist dataset or state JSON without leaving partial files."""
        self.workspace_data_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.workspace_data_dir / filename
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=self.workspace_data_dir,
                prefix=f".{filename}.", suffix=".tmp", delete=False,
            ) as stream:
                temp_path = Path(stream.name)
                stream.write(json.dumps(data, indent=4, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, json_path)
        except Exception:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _normalize_json_hostname(value: str) -> str:
        raw = value.strip().lower()
        if raw.startswith(("http://", "https://")):
            raw = urlsplit(raw).hostname or ""
        else:
            raw = raw.split("/", 1)[0].split(":", 1)[0]
        return raw.strip().strip(".")

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
            domains = [
                StorageManager._normalize_json_hostname(str(d))
                for d in cfg.get("domains", []) if str(d).strip()
            ]
            domains = [
                d for d in domains
                if "." in d and not any(ch.isspace() for ch in d) and not is_multipurpose_cdn_domain(d)
            ]
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

    def _latch_json_dns_additions(self, json_data: dict[str, Any], overlay_root: dict[str, Any]) -> bool:
        """Monotonically record any newly added JSON DNS block entries into DPAPI overlay (never removes)."""
        dns_overlay = overlay_root.setdefault("dns", {})
        changed = False
        for list_id, cfg in json_data.items():
            if not isinstance(cfg, dict) or str(cfg.get("action", "block")).lower() != "block":
                continue
            cat = str(cfg.get("category") or list_id.split("+")[0]).strip()
            if not cat or "+allow" in cat.lower() or cat.lower() == "allow":
                continue
            canonical_id = f"{cat}+block"
            raw_domains = [
                self._normalize_json_hostname(str(d)) for d in cfg.get("domains", []) if str(d).strip()
            ]
            valid_domains = [d for d in dict.fromkeys(raw_domains) if "." in d and not is_multipurpose_cdn_domain(d)]
            known = set(BASELINE_DNS_BLOCKLIST.get(canonical_id, {}).get("domains", [])) | set(
                dns_overlay.get(canonical_id, {}).get("domains", [])
            )
            new_items = [d for d in valid_domains if d not in known]
            if canonical_id not in BASELINE_DNS_BLOCKLIST and canonical_id not in dns_overlay:
                dns_overlay[canonical_id] = {
                    "category": cat,
                    "action": "block",
                    "ai_target": bool(cfg.get("ai_target", True)),
                    "scope": str(cfg.get("scope", "slip_through")),
                    "description": str(cfg.get("description", "")),
                    "domains": list(new_items),
                }
                changed = True
            elif new_items:
                entry = dns_overlay.setdefault(
                    canonical_id,
                    {
                        "category": cat,
                        "action": "block",
                        "ai_target": bool(cfg.get("ai_target", True)),
                        "scope": str(cfg.get("scope", "slip_through")),
                        "description": str(cfg.get("description", "")),
                        "domains": [],
                    },
                )
                entry["domains"].extend(new_items)
                changed = True
        return changed

    def _latch_json_search_additions(self, json_data: dict[str, Any], overlay_root: dict[str, Any]) -> bool:
        """Monotonically record any newly added JSON search block entries into DPAPI overlay (never removes)."""
        search_overlay = overlay_root.setdefault("search", {})
        changed = False
        for list_id, cfg in json_data.items():
            if not isinstance(cfg, dict) or str(cfg.get("action", "block")).lower() != "block":
                continue
            cat = str(cfg.get("category") or list_id.split("+")[0]).strip()
            if not cat or "+allow" in cat.lower() or cat.lower() == "allow":
                continue
            canonical_id = list_id if list_id.endswith("+block") else f"{cat}+block"
            raw_terms = list(dict.fromkeys(str(t).strip().lower() for t in cfg.get("terms", []) if str(t).strip()))
            known = set(
                t.lower() for t in BASELINE_SEARCH_BLOCKLIST.get(canonical_id, {}).get("terms", [])
            ) | set(t.lower() for t in search_overlay.get(canonical_id, {}).get("terms", []))
            new_terms = [t for t in raw_terms if t not in known]
            if canonical_id not in BASELINE_SEARCH_BLOCKLIST and canonical_id not in search_overlay:
                search_overlay[canonical_id] = {
                    "category": cat,
                    "action": "block",
                    "ai_target": bool(cfg.get("ai_target", True)),
                    "scope": str(cfg.get("scope", "slip_through")),
                    "description": str(cfg.get("description", "")),
                    "terms": list(new_terms),
                    "history": list(new_terms),
                }
                changed = True
            elif new_terms:
                entry = search_overlay.setdefault(
                    canonical_id,
                    {
                        "category": cat,
                        "action": "block",
                        "ai_target": bool(cfg.get("ai_target", True)),
                        "scope": str(cfg.get("scope", "slip_through")),
                        "description": str(cfg.get("description", "")),
                        "terms": [],
                        "history": [],
                    },
                )
                entry["terms"].extend(new_terms)
                hist_set = set(h.lower() for h in entry.setdefault("history", []))
                for t in new_terms:
                    if t not in hist_set:
                        entry["history"].append(t)
                        hist_set.add(t)
                changed = True
        return changed

    # --- Public Read APIs ---
    def load_dns_blocklist(self) -> dict[str, Any]:
        with self._lock:
            json_data = self._read_dev_json("dns_blocklist.json", BASELINE_DNS_BLOCKLIST)
            overlay_root = self._read_dpapi_json(self.overlay_path)
            if self._latch_json_dns_additions(json_data, overlay_root):
                self._write_dpapi_json(self.overlay_path, overlay_root)
            # The current disk file controls visible app data. The DPAPI overlay
            # records legacy additions but must not resurrect entries removed from JSON.
            # A present JSON file is the user's desired local state. Defaults are
            # copied into a new file once, but must not be re-merged on reload:
            # doing so resurrects entries the user intentionally removed.
            return self._merge_dns_blocklists({}, json_data)

    def load_search_blocklist(self) -> dict[str, Any]:
        with self._lock:
            json_data = self._read_dev_json("search_blocklist.json", BASELINE_SEARCH_BLOCKLIST)
            overlay_root = self._read_dpapi_json(self.overlay_path)
            if self._latch_json_search_additions(json_data, overlay_root):
                self._write_dpapi_json(self.overlay_path, overlay_root)
            return self._merge_search_blocklists({}, json_data)

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

    def reload_external_datasets(self) -> dict[str, Any]:
        """Validate the on-disk datasets and prune cached statuses for removed items."""
        with self._lock:
            dns = self.load_dns_blocklist()
            search = self.load_search_blocklist()
            dns_uptime = self.load_dns_uptime_sites()
            search_uptime = self.load_search_uptime_terms()

            current_items = {
                "dns_pentest": {item for cfg in dns.values() for item in cfg.get("domains", [])},
                "dns_uptime": {item for cfg in dns_uptime.values() for item in cfg.get("domains", [])},
            }
            for kind, valid_items in current_items.items():
                old_state = self.load_state(kind)
                new_state = {key: value for key, value in old_state.items() if key in valid_items}
                if new_state != old_state:
                    self.save_state(kind, new_state)

            return {
                "data_dir": str(self.workspace_data_dir),
                "dns_categories": len(dns),
                "dns_domains": sum(len(cfg.get("domains", [])) for cfg in dns.values()),
                "search_categories": len(search),
                "search_terms": sum(len(cfg.get("terms", [])) for cfg in search.values()),
                "dns_uptime_categories": len(dns_uptime),
                "search_uptime_categories": len(search_uptime),
            }

    def get_dataset_file_manifest(self) -> dict[str, Any]:
        """Return file locations and timestamps without exposing editable file contents."""
        files = []
        for filename in (
            "dns_blocklist.json",
            "search_blocklist.json",
            "dns_uptime_sites.json",
            "search_uptime_terms.json",
        ):
            path = self.workspace_data_dir / filename
            try:
                stat = path.stat()
                files.append({
                    "name": filename,
                    "path": str(path),
                    "modified_at": stat.st_mtime,
                    "size": stat.st_size,
                    "exists": True,
                })
            except OSError:
                files.append({"name": filename, "path": str(path), "exists": False})
        return {"data_dir": str(self.workspace_data_dir), "files": files}

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
            self._normalize_json_hostname(d)
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
                json_data = self._read_dev_json("dns_blocklist.json", BASELINE_DNS_BLOCKLIST)
                entry = json_data.setdefault(
                    list_id,
                    {
                        "category": cat,
                        "action": "block",
                        "ai_target": True,
                        "scope": "slip_through",
                        "description": description or current.get(list_id, {}).get("description", ""),
                        "domains": [],
                    },
                )
                entry.setdefault("domains", [])
                entry["domains"] = list(dict.fromkeys(entry["domains"] + added))
                self._write_dev_json("dns_blocklist.json", json_data)

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

            json_data = self._read_dev_json("search_blocklist.json", BASELINE_SEARCH_BLOCKLIST)
            entry = json_data.setdefault(
                list_id,
                {
                    "category": cat,
                    "action": "block",
                    "ai_target": True,
                    "scope": "slip_through",
                    "description": description or current.get(list_id, {}).get("description", ""),
                    "terms": [],
                    "history": [],
                },
            )
            entry.setdefault("terms", [])
            entry.setdefault("history", [])
            entry["terms"] = list(dict.fromkeys(entry["terms"] + added))
            for term in cleaned_hist + added:
                if term not in entry["history"]:
                    entry["history"].append(term)
            self._write_dev_json("search_blocklist.json", json_data)

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

            return {
                "list_id": list_id,
                "added": added,
                "skipped": len(cleaned_terms) - len(added),
            }

    def run_search_skeleton_cleanup(self) -> dict[str, Any]:
        """Deduplicate the current JSON search terms without restoring removed defaults."""
        with self._lock:
            json_data = self._read_dev_json("search_blocklist.json", BASELINE_SEARCH_BLOCKLIST)
            current_full = self.load_search_blocklist()
            merged_events: list[dict[str, str]] = []
            for list_id, cfg in json_data.items():
                if not isinstance(cfg, dict) or str(cfg.get("action", "block")).lower() != "block":
                    continue
                canonical_id = list_id if list_id.endswith("+block") else f"{cfg.get('category') or list_id}+block"
                base_terms = {
                    str(t).lower() for t in BASELINE_SEARCH_BLOCKLIST.get(canonical_id, {}).get("terms", [])
                }
                combined_cfg = copy.deepcopy(current_full.get(canonical_id, cfg))
                removed = clean_category(combined_cfg)
                surviving = {str(t).lower() for t in combined_cfg.get("terms", [])}
                kept_terms = []
                for term in cfg.get("terms", []):
                    normalized = str(term).strip().lower()
                    if normalized in surviving or normalized in base_terms:
                        kept_terms.append(term)
                        continue
                    merged_base = next((base for tweaked, base in removed if str(tweaked).lower() == normalized), None)
                    if merged_base and str(merged_base).lower() in (surviving | base_terms):
                        merged_events.append({"list_id": canonical_id, "tweaked": term, "merged_into": merged_base})
                    else:
                        kept_terms.append(term)
                cfg["terms"] = list(dict.fromkeys(kept_terms))

            self._write_dev_json("search_blocklist.json", json_data)
            return {
                "merged_count": len(merged_events),
                "events": merged_events[:100],
                "json_is_source_of_truth": True,
            }

    def verify_integrity(self) -> dict[str, Any]:
        """Report active local dataset validity and block-only enforcement."""
        dns = self.load_dns_blocklist()
        search = self.load_search_blocklist()

        dns_active_total = sum(len(v.get("domains", [])) for v in dns.values())
        search_active_total = sum(len(v.get("terms", [])) for v in search.values())
        dns_valid = all(v.get("action") == "block" for v in dns.values())
        search_valid = all(v.get("action") == "block" for v in search.values())

        return {
            "compiled_binary": self.compiled,
            "dpapi_overlay_exists": self.overlay_path.exists(),
            "dns_baseline_count": sum(len(v.get("domains", [])) for v in BASELINE_DNS_BLOCKLIST.values()),
            "dns_active_count": dns_active_total,
            "dns_intact": dns_valid,
            "search_baseline_count": sum(len(v.get("terms", [])) for v in BASELINE_SEARCH_BLOCKLIST.values()),
            "search_active_count": search_active_total,
            "search_intact": search_valid,
            "block_only_enforced": all(
                v.get("action") == "block"
                for v in list(dns.values()) + list(search.values())
            ),
        }
