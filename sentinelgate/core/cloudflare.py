"""Cloudflare Zero Trust Gateway API Clients with Adaptive Limit Enforcement & Worker Support."""

from __future__ import annotations

import re
import time
from typing import Any, Callable

import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sentinelgate.config.cf_secrets import CloudflareTransportConfig

# Documented Cloudflare Zero Trust Gateway Account Quotas & Limits
CF_MAX_LISTS_PER_ACCOUNT = 100
CF_MAX_LIST_ITEMS_STANDARD = 1000
CF_MAX_LIST_ITEMS_ENTERPRISE = 5000
CF_MAX_EXPRESSION_CHARS = 4090  # Safe ceiling under Cloudflare's 4096-byte wirefilter limit
CF_MAX_DNS_POLICIES = 500
CF_MAX_HTTP_POLICIES = 500
CF_LIST_APPEND_BATCH = 500


def _build_session(auth_headers: dict[str, str]) -> requests.Session:
    session = requests.Session()
    # Prevent HTTP_PROXY / HTTPS_PROXY / REQUESTS_CA_BUNDLE env-var MITM hijacking
    session.trust_env = False
    session.verify = certifi.where()
    session.headers.update(
        {
            **auth_headers,
            "Content-Type": "application/json",
            "Connection": "close",
        }
    )
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class CloudflareReadOnlyClient:
    """Strictly READ-ONLY Cloudflare Gateway client (used by Uptester and status dashboards).

    Supports paginated reads, quota telemetry, Zero-Token Worker Relay mode, and Direct Sealed mode.
    Exposes zero write, create, patch, put, or delete methods.
    """

    def __init__(
        self,
        account_id: str | CloudflareTransportConfig = "",
        api_token: str = "",
    ) -> None:
        if isinstance(account_id, CloudflareTransportConfig):
            cfg = account_id
        else:
            acct = (account_id or "").strip()
            tok = (api_token or "").strip()
            cfg = CloudflareTransportConfig(
                mode="direct" if (acct and tok) else "none",
                account_id=acct,
                api_token=tok,
            )

        self._cfg = cfg
        self.mode = cfg.mode
        self.account_id = cfg.account_id
        self.api_token = cfg.api_token
        self.worker_url = cfg.worker_url.rstrip("/")
        self.worker_token = cfg.worker_token

        if self.mode == "worker":
            self.lists_url = f"{self.worker_url}/v1/lists"
            self.rules_url = f"{self.worker_url}/v1/rules"
            self.health_url = f"{self.worker_url}/v1/health"
            self._session = _build_session({"X-SG-Relay-Key": self.worker_token})
        elif self.mode == "direct":
            self.lists_url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/gateway/lists"
            self.rules_url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/gateway/rules"
            self.health_url = self.rules_url
            self._session = _build_session({"Authorization": f"Bearer {self.api_token}"})
        else:
            self.lists_url = ""
            self.rules_url = ""
            self.health_url = ""
            self._session = _build_session({})

    def is_configured(self) -> bool:
        return self._cfg.is_ready()

    def is_admin_locked(self) -> bool:
        return self._cfg.is_admin_locked()

    def _redact(self, text: str) -> str:
        msg = str(text or "")
        for secret_val, replacement in (
            (self.api_token, "[SEALED]"),
            (self.account_id, "[SEALED]"),
            (self.worker_token, "[SEALED]"),
            (self.worker_url, "[SEALED-RELAY]"),
        ):
            if secret_val:
                msg = msg.replace(secret_val, replacement)
        return msg

    def _get_paginated(self, base_url: str, timeout: float = 15.0) -> list[dict[str, Any]]:
        """Fetch all pages of a Cloudflare Gateway collection safely (handles result_info pagination)."""
        if not self.is_configured():
            return []
        items: list[dict[str, Any]] = []
        page = 1
        while page <= 20:
            res = self._session.get(base_url, params={"page": page, "per_page": 100}, timeout=timeout)
            if res.status_code != 200:
                break
            body = res.json()
            chunk = body.get("result") or []
            if isinstance(chunk, list):
                items.extend(chunk)
            info = body.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages or not chunk:
                break
            page += 1
        return items

    def verify_connection(self) -> dict[str, Any]:
        if self.is_admin_locked():
            return {
                "ok": False,
                "admin_locked": True,
                "error": "Administrator access on this desktop is required to unlock Cloudflare API.",
            }
        if not self.is_configured():
            return {"ok": False, "admin_locked": False, "error": "Cloudflare engine is offline."}
        try:
            res = self._session.get(self.health_url, timeout=8)
            if self.mode == "worker":
                if res.status_code == 200 and res.json().get("ok"):
                    return {"ok": True, "rule_count": res.json().get("rule_count", 0)}
                return {"ok": False, "error": self._redact(f"HTTP {res.status_code}: {res.text[:220]}")}
            if res.status_code == 200 and res.json().get("success"):
                rules = self.get_rules()
                return {"ok": True, "rule_count": len(rules)}
            return {"ok": False, "error": self._redact(f"HTTP {res.status_code}: {res.text[:220]}")}
        except Exception as exc:
            return {"ok": False, "error": self._redact(str(exc))}

    def get_lists(self) -> dict[str, str]:
        lists = self._get_paginated(self.lists_url)
        return {lst["name"]: lst["id"] for lst in lists if "name" in lst and "id" in lst}

    def get_list_summaries(self) -> dict[str, dict[str, Any]]:
        """Return {list_name: {'id': uuid, 'count': item_count, 'type': type}}."""
        lists = self._get_paginated(self.lists_url)
        out: dict[str, dict[str, Any]] = {}
        for lst in lists:
            name = lst.get("name")
            lst_id = lst.get("id")
            if name and lst_id:
                out[name] = {
                    "id": lst_id,
                    "count": int(lst.get("count") or 0),
                    "type": lst.get("type", ""),
                }
        return out

    def get_rules(self) -> list[dict[str, Any]]:
        return self._get_paginated(self.rules_url)

    def get_existing_list_items(self, list_id: str) -> set[str]:
        if not self.is_configured():
            return set()
        res = self._session.get(f"{self.lists_url}/{list_id}", timeout=15)
        if res.status_code == 200:
            items = (res.json().get("result") or {}).get("items") or []
            return set(item["value"] for item in items if "value" in item)
        return set()

    def is_block_policy_active(self) -> bool:
        rules = self.get_rules()
        return any(
            (r.get("name") or "").startswith("automated_block") and r.get("enabled", False)
            for r in rules
        )

    def get_blocked_domains_from_rule(self) -> set[str]:
        """Fetch all automated_block* rules and extract domains linked across all their shards."""
        rules = self.get_rules()
        blocked_domains: set[str] = set()
        seen_list_ids: set[str] = set()
        for r in rules:
            if (r.get("name") or "").startswith("automated_block") and r.get("enabled", False):
                traffic = r.get("traffic", "")
                for lst_id in re.findall(r"\$([a-f0-9\-]{36})", traffic):
                    if lst_id not in seen_list_ids:
                        seen_list_ids.add(lst_id)
                        blocked_domains.update(self.get_existing_list_items(lst_id))
        return blocked_domains

    def get_quota_telemetry(
        self,
        rules: list[dict[str, Any]] | None = None,
        list_summaries: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Compute live Cloudflare Gateway quota usage and near-limit warnings."""
        if not self.is_configured():
            return {
                "ready": False,
                "lists_used": 0,
                "lists_limit": CF_MAX_LISTS_PER_ACCOUNT,
                "dns_policies_used": 0,
                "dns_policies_limit": CF_MAX_DNS_POLICIES,
                "http_policies_used": 0,
                "http_policies_limit": CF_MAX_HTTP_POLICIES,
                "per_list_item_limit": CF_MAX_LIST_ITEMS_STANDARD,
                "expression_char_limit": CF_MAX_EXPRESSION_CHARS,
                "warnings": [],
            }

        all_rules = rules if rules is not None else self.get_rules()
        all_lists = list_summaries if list_summaries is not None else self.get_list_summaries()

        dns_policies = [r for r in all_rules if "dns" in (r.get("filters") or ["dns"])]
        http_policies = [r for r in all_rules if "http" in (r.get("filters") or [])]

        # Infer Enterprise 5k tier automatically if any existing list already stores >1000 items
        max_existing_items = max((meta.get("count", 0) for meta in all_lists.values()), default=0)
        item_limit = CF_MAX_LIST_ITEMS_ENTERPRISE if max_existing_items > CF_MAX_LIST_ITEMS_STANDARD else CF_MAX_LIST_ITEMS_STANDARD

        warnings: list[str] = []
        if len(all_lists) >= int(CF_MAX_LISTS_PER_ACCOUNT * 0.85):
            warnings.append(f"Account Gateway lists at {len(all_lists)}/{CF_MAX_LISTS_PER_ACCOUNT} capacity.")
        if len(dns_policies) >= int(CF_MAX_DNS_POLICIES * 0.85):
            warnings.append(f"DNS policies at {len(dns_policies)}/{CF_MAX_DNS_POLICIES} capacity.")
        if len(http_policies) >= int(CF_MAX_HTTP_POLICIES * 0.85):
            warnings.append(f"HTTP policies at {len(http_policies)}/{CF_MAX_HTTP_POLICIES} capacity.")

        near_full_lists = [
            f"{name} ({meta.get('count', 0)}/{item_limit})"
            for name, meta in all_lists.items()
            if meta.get("count", 0) >= int(item_limit * 0.9)
        ]
        if near_full_lists:
            warnings.append(f"Auto-sharding lists near cap: {', '.join(near_full_lists[:4])}")

        return {
            "ready": True,
            "lists_used": len(all_lists),
            "lists_limit": CF_MAX_LISTS_PER_ACCOUNT,
            "dns_policies_used": len(dns_policies),
            "dns_policies_limit": CF_MAX_DNS_POLICIES,
            "http_policies_used": len(http_policies),
            "http_policies_limit": CF_MAX_HTTP_POLICIES,
            "per_list_item_limit": item_limit,
            "expression_char_limit": CF_MAX_EXPRESSION_CHARS,
            "warnings": warnings,
        }

    def get_policy_overview(self) -> dict[str, Any]:
        """Return live read-only status of managed block policies and quotas without exposing internals."""
        if not self.is_configured():
            return {
                "ready": False,
                "admin_locked": self.is_admin_locked(),
                "dns_rule_active": False,
                "dns_rules": [],
                "search_rules": [],
                "total_gateway_rules": 0,
                "quotas": self.get_quota_telemetry([], {}),
            }
        try:
            rules = self.get_rules()
            list_summaries = self.get_list_summaries()
            dns_rules = [
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "enabled": bool(r.get("enabled", False)),
                    "action": r.get("action"),
                    "traffic_length": len(r.get("traffic") or ""),
                }
                for r in rules
                if (r.get("name") or "").startswith("automated_block")
            ]
            search_rules = [
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "enabled": bool(r.get("enabled", False)),
                    "action": r.get("action"),
                    "traffic_length": len(r.get("traffic") or ""),
                }
                for r in rules
                if (r.get("name") or "").startswith("automated_http_search_block")
            ]
            return {
                "ready": True,
                "admin_locked": False,
                "dns_rule_active": any(r["enabled"] for r in dns_rules),
                "dns_rules": dns_rules,
                "search_rules": search_rules,
                "total_gateway_rules": len(rules),
                "quotas": self.get_quota_telemetry(rules, list_summaries),
            }
        except Exception as exc:
            return {
                "ready": False,
                "admin_locked": False,
                "error": self._redact(str(exc)),
                "dns_rule_active": False,
                "dns_rules": [],
                "search_rules": [],
                "total_gateway_rules": 0,
                "quotas": self.get_quota_telemetry([], {}),
            }


class CloudflarePolicyWriter(CloudflareReadOnlyClient):
    """Write-capable Cloudflare client restricted EXCLUSIVELY to the Pentester module.

    Security & Quota Invariants:
    - Only creates/syncs 'block' policies (never 'allow').
    - Automatically shards lists across _p2/_p3 when exceeding per-list limits (1000/5000).
    - Automatically splits DNS & Search rules across 4090-char policy boundaries atomically.
    """

    @staticmethod
    def _part_sort_key(name: str) -> tuple[int, str]:
        m = re.search(r"_p(\d+)$", name or "")
        return (int(m.group(1)) if m else 1 if "_p" not in (name or "") else 9999, name or "")

    @staticmethod
    def _rule_sort_key(rule: dict[str, Any]) -> tuple[int, str]:
        name = str(rule.get("name") or "")
        m = re.search(r"_p(\d+)$", name)
        return (int(m.group(1)) if m else 0, name)

    def create_block_list(self, name: str, current_list_count: int | None = None) -> str | None:
        if not self.is_configured():
            return None
        count_now = current_list_count if current_list_count is not None else len(self.get_lists())
        if count_now >= CF_MAX_LISTS_PER_ACCOUNT:
            return None
        payload = {
            "name": name,
            "type": "HOSTNAME",
            "description": "Auto-generated blocklist by SentinelGate AI Pentester",
        }
        res = self._session.post(self.lists_url, json=payload, timeout=15)
        if res.status_code == 200 and res.json().get("success"):
            return res.json()["result"]["id"]
        return None

    def append_domains_to_list(
        self,
        list_id: str,
        domains: list[str],
        log_cb: Callable[[str], None] | None = None,
    ) -> int:
        existing = self.get_existing_list_items(list_id)
        new_domains = [d for d in domains if d not in existing]
        if not new_domains:
            return 0

        pushed = 0
        for i in range(0, len(new_domains), CF_LIST_APPEND_BATCH):
            batch = new_domains[i : i + CF_LIST_APPEND_BATCH]
            payload = {"append": [{"value": d} for d in batch]}
            res = self._session.patch(f"{self.lists_url}/{list_id}", json=payload, timeout=20)
            if res.status_code == 200 and res.json().get("success"):
                pushed += len(batch)
                if log_cb:
                    log_cb(f"  -> Successfully pushed {len(batch)} domains to Cloudflare list.")
            else:
                if log_cb:
                    log_cb(self._redact(f"  [X] Failed pushing domains batch: HTTP {res.status_code} {res.text[:180]}"))
        return pushed

    def push_domains_adaptive(
        self,
        base_list_name: str,
        domains: list[str],
        list_summaries: dict[str, dict[str, Any]] | None = None,
        log_cb: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Push domains across sharded lists (base, base_p2, ...) respecting 1000/5000 item & 100-list caps."""
        if not self.is_configured():
            return {"pushed": 0, "lists_used": list_summaries or {}, "quota_hit": False}

        summaries = dict(list_summaries) if list_summaries is not None else self.get_list_summaries()
        shard_names = sorted(
            [n for n in summaries if n == base_list_name or n.startswith(f"{base_list_name}_p")],
            key=self._part_sort_key,
        )

        # Deduplicate against ALL existing shards in this category family
        existing_across_shards: set[str] = set()
        for s_name in shard_names:
            existing_across_shards.update(self.get_existing_list_items(summaries[s_name]["id"]))

        remaining = [d for d in dict.fromkeys(domains) if d not in existing_across_shards]
        if not remaining:
            return {"pushed": 0, "lists_used": summaries, "quota_hit": False}

        # Detect tier limit (5000 on Enterprise if any list exceeds 1000, else safe 1000)
        max_seen = max((m.get("count", 0) for m in summaries.values()), default=0)
        item_cap = CF_MAX_LIST_ITEMS_ENTERPRISE if max_seen > CF_MAX_LIST_ITEMS_STANDARD else CF_MAX_LIST_ITEMS_STANDARD

        pushed = 0
        quota_hit = False
        next_part_num = 1
        if shard_names:
            last_part = self._part_sort_key(shard_names[-1])[0]
            next_part_num = max(2, last_part + 1)

        # Fill existing under-capacity shards first
        for s_name in shard_names:
            if not remaining:
                break
            meta = summaries[s_name]
            current_cnt = meta.get("count", 0)
            space = max(0, item_cap - current_cnt)
            if space <= 0:
                continue

            to_push = remaining[:space]
            added_here, limit_err = self._patch_append_chunked(meta["id"], to_push, log_cb=log_cb)
            pushed += added_here
            meta["count"] = current_cnt + added_here
            remaining = remaining[added_here:]
            if limit_err:
                # Hit exact Cloudflare plan cap on this shard; stop filling it and spill to next shard
                meta["count"] = item_cap

        # Create new _p2/_p3 shards for any remaining domains
        while remaining:
            if len(summaries) >= CF_MAX_LISTS_PER_ACCOUNT:
                quota_hit = True
                if log_cb:
                    log_cb(f"  [!] Cloudflare account list limit ({CF_MAX_LISTS_PER_ACCOUNT}) reached; cannot create new shard for {len(remaining)} domain(s).")
                break

            new_name = base_list_name if not shard_names else f"{base_list_name}_p{next_part_num}"
            next_part_num += 1
            if log_cb:
                log_cb(f"  [+] Creating list shard '{new_name}' ({len(summaries) + 1}/{CF_MAX_LISTS_PER_ACCOUNT})...")
            new_id = self.create_block_list(new_name, current_list_count=len(summaries))
            if not new_id:
                quota_hit = True
                if log_cb:
                    log_cb(f"  [X] Unable to create list '{new_name}' (account list quota may be full).")
                break

            summaries[new_name] = {"id": new_id, "count": 0, "type": "HOSTNAME"}
            shard_names.append(new_name)

            to_push = remaining[:item_cap]
            added_here, limit_err = self._patch_append_chunked(new_id, to_push, log_cb=log_cb)
            pushed += added_here
            summaries[new_name]["count"] = added_here
            remaining = remaining[added_here:]
            if added_here == 0 and limit_err:
                break

        return {"pushed": pushed, "lists_used": summaries, "quota_hit": quota_hit}

    def _patch_append_chunked(
        self,
        list_id: str,
        domains: list[str],
        log_cb: Callable[[str], None] | None = None,
    ) -> tuple[int, bool]:
        """Append domains in <=500 item batches, detecting Cloudflare list-item limit errors cleanly."""
        pushed = 0
        for i in range(0, len(domains), CF_LIST_APPEND_BATCH):
            batch = domains[i : i + CF_LIST_APPEND_BATCH]
            payload = {"append": [{"value": d} for d in batch]}
            res = self._session.patch(f"{self.lists_url}/{list_id}", json=payload, timeout=20)
            if res.status_code == 200 and res.json().get("success"):
                pushed += len(batch)
                if log_cb:
                    log_cb(f"  -> Pushed {len(batch)} domain(s) to Cloudflare list.")
            else:
                txt = res.text.lower()
                is_limit = res.status_code in (400, 409, 422) and (
                    "limit" in txt or "maximum" in txt or "exceed" in txt or "items" in txt
                )
                if log_cb:
                    log_cb(self._redact(f"  [!] Batch stopped ({'list item cap reached' if is_limit else f'HTTP {res.status_code}'}): {res.text[:160]}"))
                return pushed, is_limit
        return pushed, False

    def sync_dns_block_policy(
        self,
        dns_data: dict[str, Any],
        cf_lists: dict[str, str],
        log_cb: Callable[[str], None] | None = None,
    ) -> bool:
        """Sync automated_block* DNS policies across sharded lists & 4090-char wirefilter limits atomically."""
        rules = self.get_rules()
        base_name = "automated_block"
        existing_dns_rules = sorted(
            [r for r in rules if (r.get("name") or "").startswith(base_name)],
            key=self._rule_sort_key,
        )

        # Collect ALL sharded lists belonging to active block categories (e.g., Proxies+block, Proxies+block_p2)
        active_bases = [name for name, cfg in dns_data.items() if cfg.get("action") == "block"]
        list_ids_for_block: list[str] = []
        seen_ids: set[str] = set()
        for cf_name in sorted(cf_lists.keys(), key=self._part_sort_key):
            if any(cf_name == b or cf_name.startswith(f"{b}_p") for b in active_bases):
                lid = cf_lists[cf_name]
                if lid not in seen_ids:
                    seen_ids.add(lid)
                    list_ids_for_block.append(lid)

        if not list_ids_for_block:
            if log_cb:
                log_cb("  [!] No Cloudflare block lists found to bind to automated_block.")
            return False

        # Pack `any(dns.domains[*] in $uuid)` expressions within 4090 chars per DNS policy
        policy_traffics: list[str] = []
        curr_parts: list[str] = []
        for cf_id in list_ids_for_block:
            cond = f"any(dns.domains[*] in ${cf_id})"
            candidate = " or ".join(curr_parts + [cond])
            if len(candidate) > CF_MAX_EXPRESSION_CHARS and curr_parts:
                policy_traffics.append(" or ".join(curr_parts))
                curr_parts = [cond]
            else:
                curr_parts.append(cond)
        if curr_parts:
            policy_traffics.append(" or ".join(curr_parts))

        # Check DNS policy quota (500 per account)
        non_managed_dns = len([
            r for r in rules
            if "dns" in (r.get("filters") or ["dns"]) and not (r.get("name") or "").startswith(base_name)
        ])
        if non_managed_dns + len(policy_traffics) > CF_MAX_DNS_POLICIES:
            if log_cb:
                log_cb(f"  [X] DNS policy limit ({CF_MAX_DNS_POLICIES}) exceeded.")
            return False

        total_parts = len(policy_traffics)
        active_ids: list[str] = []
        errors: list[str] = []

        for idx, desired_traffic in enumerate(policy_traffics, start=1):
            policy_name = f"{base_name}_p{idx}" if total_parts > 1 else base_name
            payload = {
                "name": policy_name,
                "description": f"Auto-managed block policy by SentinelGate AI (Part {idx})" if total_parts > 1 else "Auto-managed block policy by SentinelGate AI",
                "action": "block",
                "traffic": desired_traffic,
                "enabled": True,
                "rule_settings": {"block_page_enabled": True},
                "precedence": idx,
            }

            target_rule = existing_dns_rules.pop(0) if existing_dns_rules else None
            if (
                target_rule
                and target_rule.get("traffic") == desired_traffic
                and target_rule.get("name") == policy_name
                and target_rule.get("action") == "block"
                and target_rule.get("enabled") is True
            ):
                active_ids.append(target_rule["id"])
                continue

            try:
                if target_rule:
                    res = self._session.put(f"{self.rules_url}/{target_rule['id']}", json=payload, timeout=20)
                else:
                    res = self._session.post(self.rules_url, json=payload, timeout=20)
                if res.status_code == 200 and res.json().get("success") is True:
                    active_ids.append(res.json()["result"]["id"])
                else:
                    errors.append(self._redact(f"DNS {policy_name} HTTP {res.status_code}: {res.text[:160]}"))
            except Exception as exc:
                errors.append(self._redact(f"DNS {policy_name} error: {exc}"))

        # Trim superseded trailing DNS chunks ONLY if all new DNS chunks succeeded
        if not errors and len(active_ids) == total_parts and existing_dns_rules:
            for leftover in existing_dns_rules:
                if leftover.get("id") not in active_ids:
                    self._session.delete(f"{self.rules_url}/{leftover['id']}", timeout=15)

        ok = len(errors) == 0 and len(active_ids) == total_parts
        if log_cb:
            if ok:
                log_cb(f"  -> DNS 'automated_block' policy synced across {total_parts} rule(s) ({len(list_ids_for_block)} lists).")
            else:
                for err in errors:
                    log_cb(f"  [X] {err}")
        return ok

    def sync_search_block_rules(
        self,
        traffic_chunks: list[str],
        log_cb: Callable[[str], None] | None = None,
        phase_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Atomically update/push search block rules in-place BEFORE trimming trailing chunks.

        Anti-Exploit & Limit-Adaptive Design:
        - Checks Cloudflare's 500 HTTP policy account limit before pushing.
        - Never deletes existing rules before new rules are confirmed live (200 OK).
        - If ANY network/API error occurs, aborts trailing deletion fail-closed.
        """
        if not traffic_chunks:
            return {"ok": False, "error": "No regex chunks generated.", "sync_phase": "failed"}

        def emit_phase(phase: str, detail: str, **extra: Any) -> None:
            if phase_cb:
                phase_cb({"sync_phase": phase, "sync_detail": detail, **extra})

        emit_phase("fetching_rules", "Fetching active Cloudflare Gateway search policies...")
        if log_cb:
            log_cb("[SYNC PHASE 1/3] Fetching existing Cloudflare policies & checking account limits...")

        rules = self.get_rules()
        base_name = "automated_http_search_block"
        existing_action_rules = sorted(
            [r for r in rules if (r.get("name") or "").startswith(base_name)],
            key=self._rule_sort_key,
        )
        non_managed_http = len([
            r for r in rules
            if "http" in (r.get("filters") or []) and not (r.get("name") or "").startswith(base_name)
        ])
        available_http_slots = max(0, CF_MAX_HTTP_POLICIES - non_managed_http)
        if len(traffic_chunks) > available_http_slots:
            msg = f"Search chunks ({len(traffic_chunks)}) exceed available HTTP policy slots ({available_http_slots}/{CF_MAX_HTTP_POLICIES})."
            emit_phase("aborted_preserved", msg)
            if log_cb:
                log_cb(f"[X] {msg}")
            return {
                "ok": False,
                "error": msg,
                "sync_phase": "aborted_preserved",
                "aborted_delete_preserved_protection": True,
                "total_chunks": len(traffic_chunks),
                "updated": 0,
                "unchanged": 0,
                "consolidated_extra": 0,
                "errors": [msg],
            }

        active_rule_ids: list[str] = []
        updated_count = 0
        unchanged_count = 0
        errors: list[str] = []

        total_chunks = len(traffic_chunks)
        emit_phase(
            "pushing_in_place",
            f"Pushing {total_chunks} rule(s) in-place (0 deletions yet - fail-closed)...",
            pushed=0,
            total=total_chunks,
        )
        if log_cb:
            log_cb(f"[SYNC PHASE 2/3] Pushing {total_chunks} search block rule(s) in-place ({non_managed_http + total_chunks}/{CF_MAX_HTTP_POLICIES} HTTP policy cap)...")

        for part_index, traffic in enumerate(traffic_chunks, start=1):
            policy_name = f"{base_name}_p{part_index}" if total_chunks > 1 else base_name
            payload = {
                "name": policy_name,
                "description": f"Auto-managed Search Regex Block (Part {part_index})",
                "action": "block",
                "traffic": traffic,
                "enabled": True,
                "filters": ["http"],
            }

            target_rule = existing_action_rules.pop(0) if existing_action_rules else None

            if (
                target_rule
                and target_rule.get("traffic") == traffic
                and target_rule.get("name") == policy_name
                and target_rule.get("action") == "block"
                and target_rule.get("enabled") is True
            ):
                active_rule_ids.append(target_rule["id"])
                unchanged_count += 1
                emit_phase(
                    "pushing_in_place",
                    f"Verified chunk {part_index}/{total_chunks} already up-to-date",
                    pushed=part_index,
                    total=total_chunks,
                )
                continue

            action_word = "Updating in-place" if target_rule else "Creating new"
            emit_phase(
                "pushing_in_place",
                f"{action_word} rule {part_index}/{total_chunks} ({len(traffic)}/{CF_MAX_EXPRESSION_CHARS} chars)...",
                pushed=part_index - 1,
                total=total_chunks,
            )
            if log_cb:
                log_cb(f"  -> {action_word} {policy_name} ({part_index}/{total_chunks}, {len(traffic)}/{CF_MAX_EXPRESSION_CHARS} chars)...")

            try:
                if target_rule:
                    res = self._session.put(f"{self.rules_url}/{target_rule['id']}", json=payload, timeout=20)
                else:
                    res = self._session.post(self.rules_url, json=payload, timeout=20)

                if res.status_code != 200 or res.json().get("success") is not True:
                    msg = self._redact(f"Chunk {part_index} API Error: {res.text[:220]}")
                    errors.append(msg)
                    if log_cb:
                        log_cb(f"  [X] {msg}")
                    continue

                active_rule_ids.append(res.json()["result"]["id"])
                updated_count += 1
                emit_phase(
                    "pushing_in_place",
                    f"Confirmed live {part_index}/{total_chunks}",
                    pushed=part_index,
                    total=total_chunks,
                )
                time.sleep(0.8)
            except Exception as exc:
                msg = self._redact(f"Chunk {part_index} network error: {exc}")
                errors.append(msg)
                if log_cb:
                    log_cb(f"  [X] {msg}")

        cleaned_obsolete = 0
        aborted_delete = False
        if errors or len(active_rule_ids) != total_chunks:
            aborted_delete = True
            emit_phase(
                "aborted_preserved",
                "Push interrupted/failed - aborted deletion so existing blocks remain 100% active!",
                pushed=len(active_rule_ids),
                total=total_chunks,
            )
            if log_cb:
                log_cb("[FAIL-CLOSED] Push incomplete - 0 existing rules deleted; prior protections remain intact.")
        elif existing_action_rules:
            leftovers = [r for r in existing_action_rules if r.get("id") not in active_rule_ids]
            if leftovers:
                emit_phase(
                    "trimming_trailing",
                    f"All {total_chunks} new rules LIVE! Trimming {len(leftovers)} superseded trailing rule(s)...",
                    deleted=0,
                    delete_total=len(leftovers),
                )
                if log_cb:
                    log_cb(f"[SYNC PHASE 3/3] All {total_chunks} new rules confirmed LIVE. Trimming {len(leftovers)} obsolete trailing chunk(s)...")
                for idx_del, leftover_rule in enumerate(leftovers, start=1):
                    if log_cb:
                        log_cb(f"  [-] Deleting obsolete trailing rule {leftover_rule.get('name')} ({idx_del}/{len(leftovers)})...")
                    try:
                        del_res = self._session.delete(f"{self.rules_url}/{leftover_rule['id']}", timeout=15)
                        if del_res.status_code == 200:
                            cleaned_obsolete += 1
                        emit_phase(
                            "trimming_trailing",
                            f"Trimmed obsolete rule {idx_del}/{len(leftovers)}",
                            deleted=cleaned_obsolete,
                            delete_total=len(leftovers),
                        )
                    except Exception as exc:
                        if log_cb:
                            log_cb(self._redact(f"  [!] Failed trimming {leftover_rule.get('name')}: {exc}"))
        else:
            if log_cb:
                log_cb("[SYNC PHASE 3/3] All rule slots updated in-place - 0 policy deletions needed.")

        if not errors and len(active_rule_ids) == total_chunks:
            emit_phase(
                "completed",
                f"Sync complete: {total_chunks} live rule(s) enforced ({updated_count} updated, {unchanged_count} unchanged, {cleaned_obsolete} trimmed).",
                pushed=total_chunks,
                total=total_chunks,
                deleted=cleaned_obsolete,
            )

        return {
            "ok": len(errors) == 0 and len(active_rule_ids) == total_chunks,
            "sync_phase": "aborted_preserved" if aborted_delete else "completed",
            "aborted_delete_preserved_protection": aborted_delete,
            "total_chunks": total_chunks,
            "updated": updated_count,
            "unchanged": unchanged_count,
            "consolidated_extra": cleaned_obsolete,
            "errors": errors,
        }
