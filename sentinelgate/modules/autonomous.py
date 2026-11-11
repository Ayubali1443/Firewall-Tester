"""Autonomous Multi-Hour 3-Stage Protection, Testing, Audit & Final Reporting Pipeline."""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import re
import threading
import time
from typing import Any, Callable
import uuid

from sentinelgate.config.paths import get_app_data_dir
from sentinelgate.config.vault import ApiKeyVault
from sentinelgate.core.gemini_agent import (
    GeminiChatSession,
    GeminiRestClient,
    build_dns_slipthrough_prompt,
    build_search_slipthrough_prompt,
)
from sentinelgate.core.quality_gate import (
    filter_useful_dns_candidates,
    filter_useful_search_candidates,
    parse_ai_exhausted_signal,
)
from sentinelgate.core.storage import StorageManager
from sentinelgate.modules.pentester import PentesterService
from sentinelgate.modules.uptester import UptesterService


_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001


def _prevent_system_sleep(enable: bool) -> None:
    """Keep Windows awake during unattended multi-hour autonomous runs."""
    if os.name != "nt":
        return
    try:
        flags = (_ES_CONTINUOUS | _ES_SYSTEM_REQUIRED) if enable else _ES_CONTINUOUS
        ctypes.windll.kernel32.SetThreadExecutionState(flags)
    except Exception:
        pass


class ReportStore:
    """Persists and retrieves structured autonomous final audit reports."""

    def __init__(self, reports_dir: Path | None = None) -> None:
        self.reports_dir = reports_dir or (get_app_data_dir() / "reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def save_report(self, report: dict[str, Any]) -> str:
        report_id = report.get("report_id") or f"rep_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        report["report_id"] = report_id
        path = self.reports_dir / f"{report_id}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report_id

    def list_reports(self, limit: int = 25) -> list[dict[str, Any]]:
        files = sorted(self.reports_dir.glob("rep_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        summaries: list[dict[str, Any]] = []
        for f in files[:limit]:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                summaries.append(
                    {
                        "report_id": data.get("report_id", f.stem),
                        "created_at": data.get("finished_at") or data.get("started_at"),
                        "duration_seconds": data.get("duration_seconds", 0),
                        "stopped_early": bool(data.get("stopped_early", False)),
                        "new_sites_blocked": data.get("stage1_dns", {}).get("ai_new_domains_added", 0),
                        "new_terms_blocked": data.get("stage2_search", {}).get("ai_new_terms_added", 0),
                        "overblocked_dns": data.get("stage3_uptester", {}).get("dns_overblocked_count", 0),
                        "overblocked_search": data.get("stage3_uptester", {}).get("search_overblocked_count", 0),
                        "critical_slips": data.get("stage3_uptester", {}).get("critical_slip_through_count", 0),
                    }
                )
            except Exception:
                continue
        return summaries

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        safe_id = "".join(ch for ch in report_id if ch.isalnum() or ch in ("_", "-"))
        path = self.reports_dir / f"{safe_id}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None


class AutonomousRunner:
    """Orchestrates the 3-stage multi-hour Pentester + Read-Only Uptester + Reporting cycle."""

    def __init__(
        self,
        storage: StorageManager,
        vault: ApiKeyVault,
        pentester: PentesterService,
        uptester: UptesterService,
        reports: ReportStore | None = None,
    ) -> None:
        self.storage = storage
        self.vault = vault
        self.pentester = pentester
        self.uptester = uptester
        self.reports = reports or ReportStore()

    @staticmethod
    def _interruptible_sleep(seconds: float, stop_event: threading.Event) -> None:
        deadline = time.time() + max(0.0, seconds)
        while time.time() < deadline and not stop_event.is_set():
            time.sleep(min(0.5, max(0.0, deadline - time.time())))

    def _init_ai_clients(self, log_cb: Callable[[str], None]) -> tuple[list[str], list[str]]:
        creds = self.vault.get_credentials()
        keys = [
            k
            for k in (creds.get("GEMINI_API_KEY", ""), creds.get("GEMINI_API_KEY_BACKUP", ""))
            if k and k != "YOUR_GEMINI_API_KEY"
        ]
        if not keys:
            return [], []
        models = self.pentester.list_working_gemini_models(log_cb=log_cb)
        if not models:
            models = ["models/gemini-2.5-flash", "models/gemini-2.5-pro"]
        return keys, models

    def run_full_autonomous_pipeline(
        self,
        total_minutes: float = 120.0,
        enable_stage1_dns: bool = True,
        enable_stage2_search: bool = True,
        enable_stage3_uptester: bool = True,
        full_dns_baseline_reprobe: bool = False,
        stop_event: threading.Event | None = None,
        log_cb: Callable[[str], None] | None = None,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Run complete 3-stage autonomous protection & verification pipeline."""
        stop_ev = stop_event or threading.Event()
        log = log_cb or (lambda _msg: None)
        report_id = f"rep_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        started_ts = time.time()
        started_iso = datetime.now(timezone.utc).isoformat()

        total_seconds = max(60.0, float(total_minutes) * 60.0)
        # Allocate time across Stage 1 (40%), Stage 2 (45%), reserving 15% (capped 25m) for Stage 3 audit
        stage3_reserve = min(1500.0, max(45.0, total_seconds * 0.15)) if enable_stage3_uptester else 0.0
        hunt_budget = max(30.0, total_seconds - stage3_reserve)

        if enable_stage1_dns and enable_stage2_search:
            stage1_budget = hunt_budget * 0.45
            stage2_budget = hunt_budget * 0.55
        elif enable_stage1_dns:
            stage1_budget = hunt_budget
            stage2_budget = 0.0
        elif enable_stage2_search:
            stage1_budget = 0.0
            stage2_budget = hunt_budget
        else:
            stage1_budget = 0.0
            stage2_budget = 0.0

        def emit_progress(stage: int, label: str, extra: dict[str, Any] | None = None) -> None:
            if not progress_cb:
                return
            elapsed = time.time() - started_ts
            pct = min(99, int((elapsed / total_seconds) * 100))
            payload = {
                "stage": stage,
                "stage_label": label,
                "elapsed_seconds": int(elapsed),
                "total_seconds": int(total_seconds),
                "current": pct,
                "total": 100,
            }
            if extra:
                payload.update(extra)
            progress_cb(payload)

        log("================================================================")
        log(f" SENTINELGATE AI — AUTONOMOUS FULL PIPELINE ({total_minutes:.1f} min)")
        log(f" Report ID: {report_id}")
        log("================================================================")

        _prevent_system_sleep(True)
        stage1_summary: dict[str, Any] = {"executed": False}
        stage2_summary: dict[str, Any] = {"executed": False}
        stage3_summary: dict[str, Any] = {"executed": False}

        try:
            keys, models = self._init_ai_clients(log)
            if not keys:
                log("[!] No Gemini API key configured — AI discovery cycles will be skipped; local/Cloudflare testing will still run.")

            # =================================================================
            # STAGE 1: PENTESTER — TEST & BLOCK MORE SITES (DNS SHIELD)
            # =================================================================
            if enable_stage1_dns and not stop_ev.is_set():
                emit_progress(1, "Stage 1: DNS Penetration Test & AI Site Blocking")
                log("\n>>> STAGE 1/3: PENTESTER — TEST & BLOCK MORE SITES <<<")
                s1_deadline = time.time() + stage1_budget

                # 1A: Probe existing blocklist & remediate any failures
                log("[1A] Probing existing DNS blocklists and auto-remediating slip-throughs...")
                base_dns_res = self.pentester.run_dns_penetration_test(
                    full_test=full_dns_baseline_reprobe,
                    auto_remediate=True,
                    stop_event=stop_ev,
                    log_cb=log,
                )

                ai_dns_added = 0
                ai_dns_rejected = 0
                ai_dns_cycles = 0
                ai_dns_by_cat: dict[str, int] = {}
                ai_dns_remediated = 0
                dns_saturated = False

                if keys and not stop_ev.is_set() and time.time() < s1_deadline:
                    dns_data = self.storage.load_dns_blocklist()
                    target_cats = [
                        k for k, cfg in dns_data.items()
                        if cfg.get("ai_target") and cfg.get("scope") != "legacy_os_managed"
                    ]
                    priority = ["CGIProxies+block", "Proxies+block", "AdultImageHosts+block", "SoftwareMediaDownloaders+block", "ObscureAdult+block"]
                    target_cats.sort(key=lambda c: (0 if c in priority else 1, c))

                    key_idx = 0
                    model_idx = 0
                    client = GeminiRestClient(keys[key_idx])
                    chats: dict[str, GeminiChatSession] = {}
                    active_dns_cats = list(target_cats)
                    cat_dry_counts: dict[str, int] = {c: 0 for c in active_dns_cats}
                    cat_cursor = 0

                    log(f"[1B] Hunting live unblocked slip-through domains across {len(active_dns_cats)} categories (auto-stops on saturation)...")
                    while not stop_ev.is_set() and time.time() < s1_deadline and active_dns_cats:
                        cat_key = active_dns_cats[cat_cursor % len(active_dns_cats)]
                        cat_cursor += 1
                        snap = self.storage.load_dns_blocklist().get(cat_key, {})
                        cat_name = snap.get("category", cat_key.replace("+block", ""))
                        desc = snap.get("description", "")
                        existing_domains = snap.get("domains", [])
                        current_model = models[model_idx]

                        emit_progress(
                            1,
                            f"Stage 1: AI Hunting DNS ({cat_key})",
                            {"ai_sites_added": ai_dns_added, "cycle": ai_dns_cycles + 1},
                        )
                        log(f"\n[Stage 1 Cycle {ai_dns_cycles + 1}] Target: {cat_key} | Model: {current_model.replace('models/', '')}")

                        try:
                            chat = chats.get(cat_key)
                            if chat is None or chat.model_name != current_model:
                                chat = GeminiChatSession(client, current_model)
                                chats[cat_key] = chat

                            prompt = build_dns_slipthrough_prompt(cat_name, desc, existing_domains)
                            res_text = chat.send_message(prompt)
                            if parse_ai_exhausted_signal(res_text):
                                log(f"  [*] AI signaled '{cat_key}' is saturated; retiring category.")
                                active_dns_cats.remove(cat_key)
                                continue

                            raw_text = res_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                            parsed = json.loads(raw_text)
                            if not isinstance(parsed, list):
                                raise ValueError("AI output was not a JSON array.")
                            if not parsed:
                                log(f"  [*] Empty array for '{cat_key}'; retiring category.")
                                active_dns_cats.remove(cat_key)
                                continue

                            gated = filter_useful_dns_candidates(parsed, existing_domains, verify_live=True)
                            ai_dns_rejected += len(gated["rejected"])
                            if gated["rejected"]:
                                log(f"  [~] Filtered {len(gated['rejected'])} already-blocked/dead/redundant domains.")

                            if gated["accepted"]:
                                cat_dry_counts[cat_key] = 0
                                add_res = self.storage.add_dns_domains(cat_key, gated["accepted"], action="block")
                                newly_added = add_res["added"]
                                if newly_added:
                                    ai_dns_added += len(newly_added)
                                    ai_dns_by_cat[cat_key] = ai_dns_by_cat.get(cat_key, 0) + len(newly_added)
                                    for dom in newly_added:
                                        log(f"  [LIVE SLIP-THROUGH -> BLOCK] {dom}")
                                    rem = self.pentester.remediate_dns_domains({cat_key: newly_added}, log_cb=log)
                                    ai_dns_remediated += rem.get("pushed", 0)
                            else:
                                cat_dry_counts[cat_key] += 1
                                log(f"  [-] 0 live unblocked slip-throughs in '{cat_key}' ({cat_dry_counts[cat_key]}/2 dry).")
                                if cat_dry_counts[cat_key] >= 2:
                                    log(f"  [SATURATED] Retiring '{cat_key}' to prevent domain bloat.")
                                    active_dns_cats.remove(cat_key)

                        except json.JSONDecodeError:
                            log("  [!] Malformed JSON from Gemini; continuing to next cycle.")
                        except Exception as exc:
                            log(f"  [!] Gemini error in Stage 1: {exc}")
                            if (model_idx + 1) < len(models):
                                model_idx += 1
                                log(f"  [->] Failover model -> {models[model_idx].replace('models/', '')}")
                            elif (key_idx + 1) < len(keys):
                                key_idx += 1
                                model_idx = 0
                                client = GeminiRestClient(keys[key_idx])
                                chats.clear()
                                log("  [->] Failover to Backup Gemini API Key.")
                            else:
                                log("  [*] Cooling down 30s after all models/keys hit limits...")
                                self._interruptible_sleep(30, stop_ev)

                        ai_dns_cycles += 1
                        if not active_dns_cats:
                            dns_saturated = True
                            log("[STAGE 1 SATURATION STOP] All DNS slip-through categories saturated; moving to Stage 2.")
                            break
                        rem_s = s1_deadline - time.time()
                        if rem_s > 0 and not stop_ev.is_set():
                            self._interruptible_sleep(min(18.0, rem_s), stop_ev)

                stage1_summary = {
                    "executed": True,
                    "baseline_tested": base_dns_res.get("total_domains", 0),
                    "baseline_failed_remediated": base_dns_res.get("remediated_domains", 0),
                    "ai_cycles": ai_dns_cycles,
                    "ai_new_domains_added": ai_dns_added,
                    "ai_rejected_low_value": ai_dns_rejected,
                    "ai_domains_pushed_to_cf": ai_dns_remediated,
                    "stopped_on_saturation": dns_saturated,
                    "added_by_category": ai_dns_by_cat,
                }

            # =================================================================
            # STAGE 2: PENTESTER — TEST & BLOCK MORE SEARCH TERMS
            # =================================================================
            if enable_stage2_search and not stop_ev.is_set():
                emit_progress(2, "Stage 2: AI Search Term Hunting, Regex Sync & Testing")
                log("\n>>> STAGE 2/3: PENTESTER — TEST & BLOCK MORE SEARCH TERMS <<<")
                s2_deadline = time.time() + stage2_budget

                ai_terms_added = 0
                ai_terms_rejected = 0
                ai_search_cycles = 0
                ai_terms_by_cat: dict[str, int] = {}
                new_terms_pool: list[str] = []
                pending_sync_terms = 0
                sync_count = 0
                search_saturated = False

                if keys and time.time() < s2_deadline:
                    search_data = self.storage.load_search_blocklist()
                    target_cats = [
                        k for k, cfg in search_data.items()
                        if cfg.get("ai_target") and cfg.get("scope") != "legacy_os_managed"
                    ]
                    priority = ["CGIProxies+block", "Web Proxies+block", "AdultImageHosts+block", "SoftwareDownloadSites+block", "ObscureAdult+block", "Downloaders+block"]
                    target_cats.sort(key=lambda c: (0 if c in priority else 1, c))

                    key_idx = 0
                    model_idx = 0
                    client = GeminiRestClient(keys[key_idx])
                    active_search_cats = list(target_cats)
                    cat_dry_counts = {c: 0 for c in active_search_cats}
                    cat_cursor = 0

                    log(f"[2A] Hunting non-redundant search terms across {len(active_search_cats)} slip-through categories (auto-stops on saturation)...")
                    while not stop_ev.is_set() and time.time() < s2_deadline and active_search_cats:
                        cat_key = active_search_cats[cat_cursor % len(active_search_cats)]
                        cat_cursor += 1
                        full_ds = self.storage.load_search_blocklist()
                        snap = full_ds.get(cat_key, {})
                        all_active_terms = [t for cfg in full_ds.values() for t in cfg.get("terms", [])]
                        cat_name = snap.get("category", cat_key.replace("+block", ""))
                        desc = snap.get("description", "")
                        existing_terms = snap.get("terms", [])
                        history_terms = snap.get("history", [])
                        current_model = models[model_idx]

                        emit_progress(
                            2,
                            f"Stage 2: AI Hunting Search ({cat_key})",
                            {"ai_terms_added": ai_terms_added, "cycle": ai_search_cycles + 1},
                        )
                        log(f"\n[Stage 2 Cycle {ai_search_cycles + 1}] Target: {cat_key} | Model: {current_model.replace('models/', '')}")

                        try:
                            prompt = build_search_slipthrough_prompt(cat_name, desc, existing_terms, history_terms)
                            raw_text = client.generate_content(current_model, prompt)
                            if parse_ai_exhausted_signal(raw_text):
                                log(f"  [*] AI signaled '{cat_key}' is saturated; retiring category.")
                                active_search_cats.remove(cat_key)
                                continue

                            raw_candidates = [t.strip() for t in re.split(r"[,\n]", raw_text) if t.strip()]
                            gated = filter_useful_search_candidates(
                                raw_candidates,
                                existing_terms,
                                history_terms,
                                all_blocklist_terms=all_active_terms,
                            )
                            ai_terms_rejected += len(gated["rejected"])
                            if gated["rejected"]:
                                log(f"  [~] Quality gate rejected {len(gated['rejected'])} redundant/generic/filler terms.")

                            if gated["accepted"]:
                                cat_dry_counts[cat_key] = 0
                                add_res = self.storage.add_search_terms(
                                    cat_key,
                                    gated["accepted"],
                                    history_terms=gated["accepted"],
                                    action="block",
                                )
                                added = add_res["added"]
                                if added:
                                    ai_terms_added += len(added)
                                    pending_sync_terms += len(added)
                                    new_terms_pool.extend(added)
                                    ai_terms_by_cat[cat_key] = ai_terms_by_cat.get(cat_key, 0) + len(added)
                                    log(f"  [+] Added {len(added)} high-signal base terms: {', '.join(added[:8])}")
                            else:
                                cat_dry_counts[cat_key] += 1
                                log(f"  [-] 0 useful novel terms passed gate for '{cat_key}' ({cat_dry_counts[cat_key]}/2 dry).")
                                if cat_dry_counts[cat_key] >= 2:
                                    log(f"  [SATURATED] Retiring '{cat_key}' to prevent keyword bloat.")
                                    active_search_cats.remove(cat_key)

                            # Periodic batch sync to Cloudflare (every 3 cycles or >= 45 new terms)
                            if pending_sync_terms >= 45 or (pending_sync_terms > 0 and (ai_search_cycles + 1) % 3 == 0):
                                log("[2B] Running skeleton deduplication & batch Cloudflare regex sync...")
                                self.storage.run_search_skeleton_cleanup()
                                sres = self.pentester.sync_search_policies(log_cb=log)
                                if sres.get("ok"):
                                    pending_sync_terms = 0
                                    sync_count += 1

                        except Exception as exc:
                            log(f"  [!] Gemini error in Stage 2: {exc}")
                            if (model_idx + 1) < len(models):
                                model_idx += 1
                                log(f"  [->] Failover model -> {models[model_idx].replace('models/', '')}")
                            elif (key_idx + 1) < len(keys):
                                key_idx += 1
                                model_idx = 0
                                client = GeminiRestClient(keys[key_idx])
                                log("  [->] Failover to Backup Gemini API Key.")
                            else:
                                log("  [*] Cooling down 30s after all models/keys hit limits...")
                                self._interruptible_sleep(30, stop_ev)

                        ai_search_cycles += 1
                        if not active_search_cats:
                            search_saturated = True
                            log("[STAGE 2 SATURATION STOP] All search categories saturated; proceeding to final sync & verification.")
                            break
                        rem_s = s2_deadline - time.time()
                        if rem_s > 0 and not stop_ev.is_set():
                            self._interruptible_sleep(min(20.0, rem_s), stop_ev)

                # Mandatory final cleanup, regex sync, virtual pentest, and bounded live verification
                cleanup_res = {"merged_count": 0}
                sync_res: dict[str, Any] = {"ok": False}
                vp_res: dict[str, Any] = {"ok": False}
                real_res: dict[str, Any] = {"tested": 0, "blocked": 0, "bypassed": []}

                if not stop_ev.is_set():
                    log("\n[2C] Finalizing Skeleton Deduplication & Cloudflare Regex Sync...")
                    cleanup_res = self.storage.run_search_skeleton_cleanup()
                    sync_res = self.pentester.sync_search_policies(log_cb=log)
                    if sync_res.get("ok"):
                        sync_count += 1

                    log("[2D] Running Virtual RE2 Brute-Force Verification (200x/term across slip-throughs)...")
                    vp_res = self.pentester.run_virtual_pentest(list_id="CGIProxies+block", variants_per_term=200)

                    # Live probe up to 25 newly discovered + random slip-through terms
                    sample_live = list(dict.fromkeys(new_terms_pool))[:15]
                    if len(sample_live) < 20:
                        all_t = [
                            t
                            for k, cfg in self.storage.load_search_blocklist().items()
                            if cfg.get("ai_target")
                            for t in cfg.get("terms", [])
                        ]
                        if all_t:
                            sample_live.extend(random.sample(all_t, min(20 - len(sample_live), len(all_t))))
                    if sample_live:
                        log(f"[2E] Running Live Google Search Traffic Probe on {len(sample_live)} terms...")
                        real_res = self.pentester.run_search_real_traffic_test(
                            sample_live,
                            stop_event=stop_ev,
                            log_cb=log,
                        )

                stage2_summary = {
                    "executed": True,
                    "ai_cycles": ai_search_cycles,
                    "ai_new_terms_added": ai_terms_added,
                    "ai_rejected_low_value": ai_terms_rejected,
                    "stopped_on_saturation": search_saturated,
                    "added_by_category": ai_terms_by_cat,
                    "skeleton_merged": cleanup_res.get("merged_count", 0),
                    "cf_sync_count": sync_count,
                    "final_chunk_count": sync_res.get("total_chunks", 0),
                    "final_sync_ok": bool(sync_res.get("ok", False)),
                    "virtual_pentest_block_rate": vp_res.get("block_rate"),
                    "live_terms_tested": real_res.get("tested", 0),
                    "live_terms_blocked": real_res.get("blocked", 0),
                    "live_terms_bypassed": real_res.get("bypassed", []),
                }

            # =================================================================
            # STAGE 3: UPTESTER (READ-ONLY) — CHECK OVER-BLOCKING & BLOCK AUDIT
            # =================================================================
            if enable_stage3_uptester and not stop_ev.is_set():
                emit_progress(3, "Stage 3: Read-Only Uptester False-Positive & Block Audit")
                log("\n>>> STAGE 3/3: UPTESTER (READ-ONLY) — FALSE-POSITIVE & ENFORCEMENT AUDIT <<<")
                log("[READ-ONLY LOCK] Checking essential sites & search queries that should NOT be blocked...")

                dns_up_res = self.uptester.run_dns_uptime_baseline(
                    full_test=True,
                    stop_event=stop_ev,
                    log_cb=log,
                )
                search_up_res = self.uptester.run_search_uptime_baseline(
                    sample_limit=0,  # Test ALL essential baseline queries across all 15 categories
                    stop_event=stop_ev,
                    log_cb=log,
                )
                block_audit_res = self.uptester.run_critical_block_audit(
                    scope="slip_throughs",
                    stop_event=stop_ev,
                    log_cb=log,
                )

                stage3_summary = {
                    "executed": True,
                    "read_only": True,
                    "policy_modified": False,
                    "dns_total": dns_up_res.get("total", 0),
                    "dns_healthy": dns_up_res.get("healthy", 0),
                    "dns_overblocked_count": dns_up_res.get("overblocked_count", 0),
                    "dns_overblocked": dns_up_res.get("overblocked", []),
                    "search_tested": search_up_res.get("tested", 0),
                    "search_healthy": search_up_res.get("healthy", 0),
                    "search_overblocked_count": search_up_res.get("blocked_count", 0),
                    "search_overblocked": search_up_res.get("blocked_queries", []),
                    "critical_checked": block_audit_res.get("checked", 0),
                    "critical_enforced": block_audit_res.get("enforced", 0),
                    "critical_slip_through_count": block_audit_res.get("slip_through_count", 0),
                    "critical_slip_throughs": block_audit_res.get("slip_throughs", []),
                }

        finally:
            _prevent_system_sleep(False)

        finished_ts = time.time()
        final_report = {
            "report_id": report_id,
            "started_at": started_iso,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(finished_ts - started_ts, 2),
            "target_minutes": total_minutes,
            "stopped_early": stop_ev.is_set(),
            "stage1_dns": stage1_summary,
            "stage2_search": stage2_summary,
            "stage3_uptester": stage3_summary,
        }
        self.reports.save_report(final_report)

        log("\n================================================================")
        log(f" FINAL AUTONOMOUS REPORT SAVED: {report_id}")
        log(f"  - Stage 1 (Sites): +{stage1_summary.get('ai_new_domains_added', 0)} AI domains | {stage1_summary.get('baseline_failed_remediated', 0)} remediated")
        log(f"  - Stage 2 (Search): +{stage2_summary.get('ai_new_terms_added', 0)} AI terms | {stage2_summary.get('final_chunk_count', 0)} regex chunks synced")
        log(
            f"  - Stage 3 (Over-Block Check): DNS {stage3_summary.get('dns_healthy', 0)}/{stage3_summary.get('dns_total', 0)} healthy "
            f"({stage3_summary.get('dns_overblocked_count', 0)} over-blocked) | "
            f"Search {stage3_summary.get('search_healthy', 0)}/{stage3_summary.get('search_tested', 0)} healthy "
            f"({stage3_summary.get('search_overblocked_count', 0)} over-blocked)"
        )
        log("================================================================")

        return {"ok": True, "report": final_report}
