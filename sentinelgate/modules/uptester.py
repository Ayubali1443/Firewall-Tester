"""Uptester Module — STRICTLY READ-ONLY Verification & Monitoring Engine.

SECURITY INVARIANT:
This module NEVER creates, modifies, patches, or deletes any Cloudflare Gateway lists,
Cloudflare Gateway rules, or local blocklist policies. It holds only a CloudflareReadOnlyClient.
Only PentesterService handles blocking/policy operations.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from sentinelgate.config.cf_secrets import get_cloudflare_transport_config
from sentinelgate.config.vault import ApiKeyVault
from sentinelgate.core.cloudflare import CloudflareReadOnlyClient
from sentinelgate.core.storage import StorageManager
from sentinelgate.modules.pentester import is_domain_blocked, is_search_term_blocked


class UptesterService:
    """Strictly read-only auditor for both essential uptime baselines and critical block enforcement."""

    def __init__(self, storage: StorageManager, vault: ApiKeyVault) -> None:
        self.storage = storage
        self.vault = vault

    def _get_readonly_client(self) -> CloudflareReadOnlyClient:
        return CloudflareReadOnlyClient(get_cloudflare_transport_config())

    def run_critical_block_audit(
        self,
        scope: str = "slip_throughs",
        stop_event: threading.Event | None = None,
        log_cb: Callable[[str], None] | None = None,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Verify necessary blocked items remain enforced without altering ANY policy.

        Any detected slip-throughs are reported for operator escalation to Pentester.
        """
        ro_client = self._get_readonly_client()
        dns_data = self.storage.load_dns_blocklist()
        search_data = self.storage.load_search_blocklist()

        cf_blocked_domains: set[str] = set()
        dns_rule_active = False
        if ro_client.is_configured():
            if log_cb:
                log_cb("[READ-ONLY] Inspecting live Cloudflare automated_block rule...")
            overview = ro_client.get_policy_overview()
            dns_rule_active = overview.get("dns_rule_active", False)
            cf_blocked_domains = ro_client.get_blocked_domains_from_rule()

        # Select target categories for critical block check
        target_dns_cats = (
            ["Proxies+block", "CGIProxies+block", "AdultImageHosts+block", "SoftwareMediaDownloaders+block", "ObscureAdult+block"]
            if scope == "slip_throughs"
            else list(dns_data.keys())
        )
        dns_items = [
            (cat, d)
            for cat in target_dns_cats
            for d in dns_data.get(cat, {}).get("domains", [])
        ]

        target_search_cats = (
            ["Web Proxies+block", "CGIProxies+block", "AdultImageHosts+block", "SoftwareDownloadSites+block", "ObscureAdult+block"]
            if scope == "slip_throughs"
            else list(search_data.keys())
        )
        search_items = [
            (cat, t)
            for cat in target_search_cats
            for t in search_data.get(cat, {}).get("terms", [])
        ][:40]  # Bounded live search probes so Google doesn't throttle

        total = len(dns_items) + len(search_items)
        checked = 0
        enforced = 0
        slip_throughs: list[dict[str, str]] = []
        indeterminate = 0

        if log_cb:
            log_cb(f"[READ-ONLY] Auditing {len(dns_items)} critical domains & {len(search_items)} search vectors...")

        for cat, domain in dns_items:
            if stop_event and stop_event.is_set():
                break
            checked += 1
            in_cf = domain in cf_blocked_domains and dns_rule_active
            blocked_live = is_domain_blocked(domain)
            if blocked_live and (not ro_client.is_configured() or in_cf):
                enforced += 1
                if log_cb:
                    log_cb(f"  [ENFORCED] DNS {domain}")
            elif blocked_live and not in_cf:
                # Blocked locally (e.g., upstream/Cloudflare category), note CF list status
                enforced += 1
                if log_cb:
                    log_cb(f"  [BLOCKED-UPSTREAM] DNS {domain} (not yet in automated_block list)")
            else:
                slip_throughs.append({"kind": "dns", "category": cat, "item": domain})
                if log_cb:
                    log_cb(f"  [SLIP-THROUGH] DNS {domain} is REACHABLE — escalate to Pentester!")
            if progress_cb:
                progress_cb({"current": checked, "total": total, "item": domain})

        for cat, term in search_items:
            if stop_event and stop_event.is_set():
                break
            checked += 1
            blocked, label = is_search_term_blocked(term)
            if blocked:
                enforced += 1
                if log_cb:
                    log_cb(f"  [ENFORCED] Search '{term}' ({label})")
            elif label == "BYPASSED":
                slip_throughs.append({"kind": "search", "category": cat, "item": term})
                if log_cb:
                    log_cb(f"  [SLIP-THROUGH] Search '{term}' BYPASSED — escalate to Pentester!")
            else:
                indeterminate += 1
                if log_cb:
                    log_cb(f"  [INDETERMINATE] Search '{term}' could not be classified; retry when connectivity is stable.")
            if progress_cb:
                progress_cb({"current": checked, "total": total, "item": term})
            time.sleep(0.8)

        if log_cb:
            log_cb("\n[READ-ONLY LOCK] Uptester finished. Zero Cloudflare policies were modified.")

        return {
            "ok": True,
            "read_only": True,
            "policy_modified": False,
            "checked": checked,
            "enforced": enforced,
            "indeterminate_count": indeterminate,
            "slip_through_count": len(slip_throughs),
            "slip_throughs": slip_throughs,
        }

    def run_dns_uptime_baseline(
        self,
        full_test: bool = False,
        category_filter: str | None = None,
        stop_event: threading.Event | None = None,
        log_cb: Callable[[str], None] | None = None,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Read-only check verifying essential productivity/tech/govt/finance sites remain reachable."""
        data = self.storage.load_dns_uptime_sites()
        state = self.storage.load_state("dns_uptime")
        ro_client = self._get_readonly_client()

        target_data = (
            {category_filter: data[category_filter]}
            if category_filter and category_filter in data
            else data
        )

        cf_blocked_domains: set[str] = set()
        if not full_test and ro_client.is_configured():
            if log_cb:
                log_cb("[READ-ONLY] Syncing blocked-rule snapshot from Cloudflare (GET only)...")
            cf_blocked_domains = ro_client.get_blocked_domains_from_rule()

        total = sum(len(cfg.get("domains", [])) for cfg in target_data.values())
        checked = 0
        healthy = 0
        skipped = 0
        overblocked: list[dict[str, str]] = []

        for list_id, cfg in target_data.items():
            domains = cfg.get("domains", [])
            if log_cb:
                log_cb(f"\n=== Uptime Baseline: {list_id} ({len(domains)} sites) ===")
            for domain in domains:
                if stop_event and stop_event.is_set():
                    break
                checked += 1
                if not full_test:
                    if domain in cf_blocked_domains:
                        overblocked.append({"category": list_id, "domain": domain, "reason": "Found in automated_block"})
                        state[domain] = "failed"
                        continue
                    if state.get(domain) == "allow":
                        skipped += 1
                        healthy += 1
                        continue

                blocked = is_domain_blocked(domain)
                if not blocked:
                    healthy += 1
                    state[domain] = "allow"
                    if log_cb:
                        log_cb(f"  [OK] {domain} reachable.")
                else:
                    overblocked.append({"category": list_id, "domain": domain, "reason": "Blocked or unreachable"})
                    state[domain] = "failed"
                    if log_cb:
                        log_cb(f"  [WARN] {domain} appears blocked/unreachable.")
                if progress_cb:
                    progress_cb({"current": checked, "total": total, "item": domain})

        self.storage.save_state("dns_uptime", state)
        if log_cb:
            log_cb("\n[READ-ONLY LOCK] Policy updates disabled in Uptester module.")

        return {
            "ok": True,
            "read_only": True,
            "policy_modified": False,
            "total": total,
            "healthy": healthy,
            "skipped": skipped,
            "overblocked_count": len(overblocked),
            "overblocked": overblocked,
        }

    def run_search_uptime_baseline(
        self,
        category_filter: str | None = None,
        sample_limit: int = 25,
        stop_event: threading.Event | None = None,
        log_cb: Callable[[str], None] | None = None,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Read-only check verifying essential day-to-day search queries remain accessible."""
        data = self.storage.load_search_uptime_terms()
        target_data = (
            {category_filter: data[category_filter]}
            if category_filter and category_filter in data
            else data
        )

        items = [
            (cat, term)
            for cat, cfg in target_data.items()
            for term in cfg.get("terms", [])
        ]
        if sample_limit > 0 and len(items) > sample_limit:
            items = items[:sample_limit]

        total = len(items)
        healthy = 0
        blocked_queries: list[dict[str, str]] = []
        indeterminate_queries: list[dict[str, str]] = []
        tested = 0

        for idx, (cat, term) in enumerate(items, start=1):
            if stop_event and stop_event.is_set():
                break
            tested += 1
            blocked, label = is_search_term_blocked(term)
            if label == "BYPASSED" and not blocked:
                healthy += 1
                if log_cb:
                    log_cb(f"  [OK] '{term}' allowed.")
            elif blocked:
                blocked_queries.append({"category": cat, "term": term, "status": label})
                if log_cb:
                    log_cb(f"  [WARN] '{term}' was {label}.")
            else:
                indeterminate_queries.append({"category": cat, "term": term, "status": label})
                if log_cb:
                    log_cb(f"  [INDETERMINATE] '{term}' probe did not confirm an allow or block result.")
            if progress_cb:
                progress_cb({"current": idx, "total": total, "item": term})
            if idx < total:
                time.sleep(1.0)

        return {
            "ok": True,
            "read_only": True,
            "policy_modified": False,
            "tested": tested,
            "healthy": healthy,
            "blocked_count": len(blocked_queries),
            "blocked_queries": blocked_queries,
            "indeterminate_count": len(indeterminate_queries),
            "indeterminate_queries": indeterminate_queries,
        }
