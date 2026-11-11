"""Cloudflare Zero Trust Gateway API Clients with Worker-Relay & Direct Sealed support."""

from __future__ import annotations

import re
import time
from typing import Any, Callable

import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sentinelgate.config.cf_secrets import CloudflareTransportConfig


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
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class CloudflareReadOnlyClient:
    """Strictly READ-ONLY Cloudflare Gateway client (used by Uptester and status dashboards).

    Supports both Zero-Token Worker Relay mode and Direct Sealed mode.
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

    def verify_connection(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "error": "Cloudflare engine is offline."}
        try:
            res = self._session.get(self.health_url, timeout=8)
            if self.mode == "worker":
                if res.status_code == 200 and res.json().get("ok"):
                    return {"ok": True, "rule_count": res.json().get("rule_count", 0)}
                return {"ok": False, "error": self._redact(f"HTTP {res.status_code}: {res.text[:220]}")}
            if res.status_code == 200 and res.json().get("success"):
                rules = res.json().get("result") or []
                return {"ok": True, "rule_count": len(rules)}
            return {"ok": False, "error": self._redact(f"HTTP {res.status_code}: {res.text[:220]}")}
        except Exception as exc:
            return {"ok": False, "error": self._redact(str(exc))}

    def get_lists(self) -> dict[str, str]:
        if not self.is_configured():
            return {}
        res = self._session.get(self.lists_url, timeout=15)
        if res.status_code != 200:
            return {}
        lists = res.json().get("result") or []
        return {lst["name"]: lst["id"] for lst in lists if "name" in lst and "id" in lst}

    def get_rules(self) -> list[dict[str, Any]]:
        if not self.is_configured():
            return []
        res = self._session.get(self.rules_url, timeout=15)
        if res.status_code == 200:
            return res.json().get("result") or []
        return []

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
        target_rule = next((r for r in rules if r.get("name") == "automated_block"), None)
        return bool(target_rule and target_rule.get("enabled", False))

    def get_blocked_domains_from_rule(self) -> set[str]:
        """Fetch automated_block rule and extract all domains linked to its Cloudflare lists."""
        rules = self.get_rules()
        target_rule = next((r for r in rules if r.get("name") == "automated_block"), None)
        blocked_domains: set[str] = set()
        if target_rule and target_rule.get("enabled", False):
            traffic = target_rule.get("traffic", "")
            list_ids = re.findall(r"\$([a-f0-9\-]{36})", traffic)
            for lst_id in list_ids:
                blocked_domains.update(self.get_existing_list_items(lst_id))
        return blocked_domains

    def get_policy_overview(self) -> dict[str, Any]:
        """Return live read-only status of managed block policies without exposing credential internals."""
        if not self.is_configured():
            return {"ready": False, "dns_rule_active": False, "search_rules": [], "total_gateway_rules": 0}
        try:
            res = self._session.get(self.rules_url, timeout=6)
            if res.status_code != 200:
                return {"ready": False, "dns_rule_active": False, "search_rules": [], "total_gateway_rules": 0}
            rules = res.json().get("result") or []
            dns_rule = next((r for r in rules if r.get("name") == "automated_block"), None)
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
                "dns_rule_active": bool(dns_rule and dns_rule.get("enabled", False)),
                "dns_rule_action": dns_rule.get("action") if dns_rule else None,
                "search_rules": search_rules,
                "total_gateway_rules": len(rules),
            }
        except Exception as exc:
            return {
                "ready": False,
                "error": self._redact(str(exc)),
                "dns_rule_active": False,
                "search_rules": [],
                "total_gateway_rules": 0,
            }


class CloudflarePolicyWriter(CloudflareReadOnlyClient):
    """Write-capable Cloudflare client restricted EXCLUSIVELY to the Pentester module.

    Security Invariants:
    - Only creates/syncs 'block' policies (never 'allow').
    - Never provides an external policy deletion capability.
    """

    def create_block_list(self, name: str) -> str | None:
        if not self.is_configured():
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
        for i in range(0, len(new_domains), 500):
            batch = new_domains[i : i + 500]
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

    def sync_dns_block_policy(
        self,
        dns_data: dict[str, Any],
        cf_lists: dict[str, str],
        log_cb: Callable[[str], None] | None = None,
    ) -> bool:
        """Sync ONLY the automated_block DNS policy (never creates automated_allow)."""
        rules = self.get_rules()
        policy_name = "automated_block"
        target_rule = next((r for r in rules if r.get("name") == policy_name), None)

        list_ids_for_block = [
            cf_lists[name]
            for name, config in dns_data.items()
            if config.get("action") == "block" and name in cf_lists
        ]
        if not list_ids_for_block:
            if log_cb:
                log_cb("  [!] No Cloudflare block lists found to bind to automated_block.")
            return False

        traffic_conditions = [f"any(dns.domains[*] in ${cf_id})" for cf_id in list_ids_for_block]
        desired_traffic = " or ".join(traffic_conditions)

        payload = {
            "name": policy_name,
            "description": "Auto-managed block policy by SentinelGate AI",
            "action": "block",
            "traffic": desired_traffic,
            "enabled": True,
            "rule_settings": {"block_page_enabled": True},
            "precedence": 1,
        }

        if target_rule:
            res = self._session.put(f"{self.rules_url}/{target_rule['id']}", json=payload, timeout=20)
        else:
            res = self._session.post(self.rules_url, json=payload, timeout=20)

        ok = res.status_code == 200 and res.json().get("success") is True
        if log_cb:
            if ok:
                log_cb("  -> DNS 'automated_block' policy synced with Cloudflare.")
            else:
                log_cb(self._redact(f"  [X] Policy sync error: {res.text[:200]}"))
        return ok

    def sync_search_block_rules(
        self,
        traffic_chunks: list[str],
        log_cb: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Push dynamic RE2 regex chunks to Cloudflare automated_http_search_block rules (block-only)."""
        if not traffic_chunks:
            return {"ok": False, "error": "No regex chunks generated."}

        rules = self.get_rules()
        base_name = "automated_http_search_block"
        existing_action_rules = [r for r in rules if (r.get("name") or "").startswith(base_name)]
        active_rule_ids: list[str] = []
        updated_count = 0
        unchanged_count = 0
        errors: list[str] = []

        total_chunks = len(traffic_chunks)
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
                continue

            if log_cb:
                log_cb(f"  -> Pushing regex chunk {part_index}/{total_chunks} ({len(traffic)} chars) to Cloudflare...")

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
            time.sleep(1.0)

        cleaned_obsolete = 0
        if not errors and active_rule_ids:
            for leftover_rule in existing_action_rules:
                if leftover_rule.get("id") not in active_rule_ids:
                    if log_cb:
                        log_cb(f"  [-] Removing superseded split chunk {leftover_rule.get('name')} (fully consolidated)...")
                    del_res = self._session.delete(f"{self.rules_url}/{leftover_rule['id']}", timeout=15)
                    if del_res.status_code == 200:
                        cleaned_obsolete += 1

        return {
            "ok": len(errors) == 0,
            "total_chunks": total_chunks,
            "updated": updated_count,
            "unchanged": unchanged_count,
            "consolidated_extra": cleaned_obsolete,
            "errors": errors,
        }
