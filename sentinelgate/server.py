"""Local Authenticated HTTP/JSON Backend Server for the SentinelGate AI Desktop Shell."""

from __future__ import annotations

from dataclasses import dataclass, field
import random
import secrets
import threading
import time
import traceback
from typing import Any, Callable
import uuid

from flask import Flask, jsonify, request, send_from_directory

from sentinelgate import __app_name__, __version__
from sentinelgate.config.cf_secrets import get_cloudflare_transport_config
from sentinelgate.config.paths import get_ui_dir
from sentinelgate.config.vault import ApiKeyVault
from sentinelgate.core.cleaner import generate_human_variations
from sentinelgate.core.cloudflare import CloudflareReadOnlyClient
from sentinelgate.core.gemini_agent import GeminiRestClient
from sentinelgate.core.regex_engine import (
    build_flat_regex,
    obfuscate_term,
    validate_regex_detailed,
    verify_validator_integrity,
)
from sentinelgate.core.storage import StorageManager
from sentinelgate.modules.autonomous import AutonomousRunner, ReportStore
from sentinelgate.modules.pentester import PentesterService
from sentinelgate.modules.uptester import UptesterService


@dataclass
class BackgroundJob:
    job_id: str
    kind: str
    title: str
    status: str = "running"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)
    dropped_logs: int = 0
    progress: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def append_log(self, msg: str) -> None:
        with self.lock:
            for line in str(msg).splitlines():
                self.logs.append(line)
            if len(self.logs) > 2000:
                overflow = len(self.logs) - 2000
                self.dropped_logs += overflow
                self.logs = self.logs[-2000:]

    def set_progress(self, prog: dict[str, Any]) -> None:
        with self.lock:
            self.progress = prog

    def snapshot(self, since_idx: int = 0) -> dict[str, Any]:
        with self.lock:
            rel_idx = max(0, since_idx - self.dropped_logs)
            return {
                "job_id": self.job_id,
                "kind": self.kind,
                "title": self.title,
                "status": self.status,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "total_logs": self.dropped_logs + len(self.logs),
                "logs": self.logs[rel_idx:],
                "progress": self.progress,
                "result": self.result,
                "error": self.error,
            }


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, BackgroundJob] = {}
        self._lock = threading.Lock()

    def start_job(
        self,
        kind: str,
        title: str,
        worker: Callable[[BackgroundJob], dict[str, Any]],
    ) -> BackgroundJob:
        job_id = uuid.uuid4().hex[:12]
        job = BackgroundJob(job_id=job_id, kind=kind, title=title)
        with self._lock:
            self._jobs[job_id] = job

        def _runner() -> None:
            try:
                res = worker(job)
                with job.lock:
                    job.result = res
                    job.status = "stopped" if job.stop_event.is_set() else "completed"
                    job.finished_at = time.time()
            except Exception as exc:
                job.append_log(f"[ERROR] {exc}")
                job.append_log(traceback.format_exc())
                with job.lock:
                    job.error = str(exc)
                    job.status = "failed"
                    job.finished_at = time.time()

        t = threading.Thread(target=_runner, daemon=True, name=f"sg-job-{job_id}")
        t.start()
        return job

    def get(self, job_id: str) -> BackgroundJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_recent(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)[:15]
            return [
                {
                    "job_id": j.job_id,
                    "kind": j.kind,
                    "title": j.title,
                    "status": j.status,
                    "started_at": j.started_at,
                    "finished_at": j.finished_at,
                }
                for j in jobs
            ]


def create_app(session_token: str | None = None) -> tuple[Flask, str]:
    token = session_token or secrets.token_hex(24)
    ui_dir = get_ui_dir()

    app = Flask(__name__, static_folder=str(ui_dir), static_url_path="/static")
    vault = ApiKeyVault()
    storage = StorageManager()
    pentester = PentesterService(storage=storage, vault=vault)
    uptester = UptesterService(storage=storage, vault=vault)
    reports = ReportStore()
    autonomous = AutonomousRunner(
        storage=storage,
        vault=vault,
        pentester=pentester,
        uptester=uptester,
        reports=reports,
    )
    jobs = JobManager()

    # Enforce per-session token on all /api/ routes so arbitrary local apps cannot invoke actions
    @app.before_request
    def _enforce_api_auth() -> Any:
        if request.path.startswith("/api/"):
            supplied = request.headers.get("X-SG-Token", "")
            if not secrets.compare_digest(supplied, token):
                return jsonify({"ok": False, "error": "Unauthorized local API request."}), 401
        return None

    @app.after_request
    def _security_headers(resp: Any) -> Any:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    @app.route("/")
    def index() -> Any:
        html = (ui_dir / "index.html").read_text(encoding="utf-8")
        html = html.replace("__SG_SESSION_TOKEN__", token)
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.route("/assets/<path:filename>")
    def assets(filename: str) -> Any:
        return send_from_directory(str(ui_dir), filename)

    # --- Overview & Posture ---
    @app.get("/api/overview")
    def api_overview() -> Any:
        ro_cf = CloudflareReadOnlyClient(get_cloudflare_transport_config())
        cf_overview = ro_cf.get_policy_overview()
        integrity = storage.verify_integrity()
        val_ok, val_info = verify_validator_integrity()
        dns_data = storage.load_dns_blocklist()
        search_data = storage.load_search_blocklist()

        return jsonify(
            {
                "ok": True,
                "app_name": __app_name__,
                "version": __version__,
                "integrity": integrity,
                "validator": {"ok": val_ok, "detail": val_info},
                "cloudflare": cf_overview,
                "vault": vault.get_masked_status(),
                "stats": {
                    "dns_categories": len(dns_data),
                    "dns_domains": sum(len(v.get("domains", [])) for v in dns_data.values()),
                    "search_categories": len(search_data),
                    "search_terms": sum(len(v.get("terms", [])) for v in search_data.values()),
                },
                "recent_jobs": jobs.list_recent(),
            }
        )

    # --- Pentester: DNS Shield ---
    @app.get("/api/pentester/dns/datasets")
    def api_dns_datasets() -> Any:
        data = storage.load_dns_blocklist()
        state = storage.load_state("dns_pentest")
        categories = []
        for list_id, cfg in data.items():
            domains = cfg.get("domains", [])
            failed = [d for d in domains if state.get(d) == "failed"]
            blocked = [d for d in domains if state.get(d) == "block"]
            categories.append(
                {
                    "list_id": list_id,
                    "category": cfg.get("category"),
                    "action": "block",
                    "ai_target": bool(cfg.get("ai_target", True)),
                    "scope": cfg.get("scope", "slip_through"),
                    "description": cfg.get("description", ""),
                    "count": len(domains),
                    "blocked_cached": len(blocked),
                    "failed_cached": len(failed),
                    "domains": domains,
                }
            )
        return jsonify({"ok": True, "categories": categories})

    @app.post("/api/pentester/dns/add")
    def api_dns_add() -> Any:
        payload = request.get_json(force=True) or {}
        if str(payload.get("action", "block")).lower() != "block":
            return jsonify({"ok": False, "error": "Allow-listing is strictly prohibited."}), 403
        category = str(payload.get("category", "")).strip()
        raw_text = str(payload.get("domains_text", ""))
        items = [x.strip() for x in raw_text.replace("\n", ",").split(",") if x.strip()]
        try:
            res = pentester.add_dns_block_domains(category, items, description=str(payload.get("description", "")))
            return jsonify({"ok": True, **res})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/pentester/dns/test")
    def api_dns_test() -> Any:
        payload = request.get_json(force=True) or {}
        full_test = bool(payload.get("full_test", False))
        category = payload.get("category") or None
        auto_remediate = bool(payload.get("auto_remediate", False))
        title = f"DNS {'Complete' if full_test else 'Smart'} Penetration Test"
        job = jobs.start_job(
            "dns_pentest",
            title,
            lambda j: pentester.run_dns_penetration_test(
                full_test=full_test,
                category_filter=category,
                auto_remediate=auto_remediate,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.post("/api/pentester/dns/remediate")
    def api_dns_remediate() -> Any:
        payload = request.get_json(force=True) or {}
        remediation_map = payload.get("remediation_map") or {}
        if not isinstance(remediation_map, dict) or not remediation_map:
            return jsonify({"ok": False, "error": "No failed domains provided for remediation."}), 400
        job = jobs.start_job(
            "dns_remediate",
            "Push Failed Domains to Cloudflare automated_block",
            lambda j: pentester.remediate_dns_domains(remediation_map, log_cb=j.append_log),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    # --- Pentester: Search & Regex Engine ---
    @app.get("/api/pentester/search/datasets")
    def api_search_datasets() -> Any:
        data = storage.load_search_blocklist()
        categories = []
        for list_id, cfg in data.items():
            terms = cfg.get("terms", [])
            categories.append(
                {
                    "list_id": list_id,
                    "category": cfg.get("category"),
                    "action": "block",
                    "ai_target": bool(cfg.get("ai_target", True)),
                    "scope": cfg.get("scope", "slip_through"),
                    "description": cfg.get("description", ""),
                    "count": len(terms),
                    "history_count": len(cfg.get("history", [])),
                    "terms": terms,
                }
            )
        return jsonify({"ok": True, "categories": categories})

    @app.post("/api/pentester/search/add")
    def api_search_add() -> Any:
        payload = request.get_json(force=True) or {}
        if str(payload.get("action", "block")).lower() != "block":
            return jsonify({"ok": False, "error": "Allow-listing is strictly prohibited."}), 403
        category = str(payload.get("category", "")).strip()
        raw_text = str(payload.get("terms_text", ""))
        terms = [x.strip() for x in raw_text.replace("\n", ",").split(",") if x.strip()]
        try:
            res = pentester.add_search_block_terms(category, terms, description=str(payload.get("description", "")))
            return jsonify({"ok": True, **res})
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/pentester/search/preview-regex")
    def api_search_preview_regex() -> Any:
        payload = request.get_json(force=True) or {}
        raw_terms = [x.strip() for x in str(payload.get("terms_text", "")).replace("\n", ",").split(",") if x.strip()]
        sample_query = str(payload.get("sample_query", "")).strip()

        if not raw_terms:
            return jsonify({"ok": False, "error": "Enter at least one base term to inspect."}), 400

        single_obf = obfuscate_term(raw_terms[0])
        flat = build_flat_regex(raw_terms)
        details = validate_regex_detailed(flat)
        variations = generate_human_variations(raw_terms[0], max_results=200)[:30]

        match_result = None
        if sample_query and details["python_re_ok"]:
            import re as _re

            match_result = bool(_re.search(flat, sample_query))

        return jsonify(
            {
                "ok": True,
                "single_term_pattern": single_obf,
                "details": details,
                "variations_sample": variations,
                "sample_query": sample_query,
                "sample_matched": match_result,
            }
        )

    @app.get("/api/pentester/search/chunks")
    def api_search_chunks() -> Any:
        return jsonify({"ok": True, **pentester.preview_search_chunks()})

    @app.post("/api/pentester/search/sync")
    def api_search_sync() -> Any:
        job = jobs.start_job(
            "search_sync",
            "Compile Regex Chunks & Sync to Cloudflare HTTP Rules",
            lambda j: pentester.sync_search_policies(log_cb=j.append_log),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.post("/api/pentester/search/cleanup")
    def api_search_cleanup() -> Any:
        res = storage.run_search_skeleton_cleanup()
        return jsonify({"ok": True, **res})

    @app.post("/api/pentester/search/virtual-test")
    def api_search_virtual_test() -> Any:
        payload = request.get_json(force=True) or {}
        list_id = payload.get("list_id") or None
        variants_per_term = min(1500, max(100, int(payload.get("variants_per_term", 800))))
        job = jobs.start_job(
            "virtual_pentest",
            f"Virtual RE2 Brute-Force ({list_id or 'All Categories'})",
            lambda j: pentester.run_virtual_pentest(list_id=list_id, variants_per_term=variants_per_term),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.post("/api/pentester/search/real-test")
    def api_search_real_test() -> Any:
        payload = request.get_json(force=True) or {}
        mode = str(payload.get("mode", "random20"))
        data = storage.load_search_blocklist()
        terms: list[str] = []

        if mode == "custom":
            terms = [x.strip() for x in str(payload.get("terms_text", "")).replace("\n", ",").split(",") if x.strip()]
        elif mode == "category":
            cat = str(payload.get("category", ""))
            terms = data.get(cat, {}).get("terms", [])
        elif mode == "random20":
            all_t = [t for cfg in data.values() for t in cfg.get("terms", [])]
            terms = random.sample(all_t, min(20, len(all_t))) if all_t else []
        elif mode == "all":
            terms = [t for cfg in data.values() for t in cfg.get("terms", [])]

        if not terms:
            return jsonify({"ok": False, "error": "No terms selected for live traffic test."}), 400

        job = jobs.start_job(
            "search_real_test",
            f"Real Google Search Traffic Test ({len(terms)} terms)",
            lambda j: pentester.run_search_real_traffic_test(
                terms,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    # --- AI Slip-Through Hunter ---
    @app.post("/api/ai/models")
    def api_ai_models() -> Any:
        job = jobs.start_job(
            "ai_models",
            "Pre-flight Discover & Rank Working Gemini Models",
            lambda j: {"ok": True, "models": pentester.list_working_gemini_models(log_cb=j.append_log)},
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.post("/api/ai/hunt")
    def api_ai_hunt() -> Any:
        payload = request.get_json(force=True) or {}
        mode = str(payload.get("mode", "search")).lower()
        if mode not in ("dns", "search"):
            return jsonify({"ok": False, "error": "Mode must be 'dns' or 'search'."}), 400

        category_key = str(payload.get("category_key", "")).strip()
        if not category_key:
            return jsonify({"ok": False, "error": "Target category is required."}), 400

        # Block hunting on legacy OS-managed desktop VPN categories
        ds = storage.load_dns_blocklist() if mode == "dns" else storage.load_search_blocklist()
        if category_key not in ds:
            return jsonify({"ok": False, "error": f"Unknown category '{category_key}'."}), 404
        if ds[category_key].get("scope") == "legacy_os_managed":
            return jsonify(
                {
                    "ok": False,
                    "error": "Desktop VPN/software installs are already blocked at OS level. Choose a web slip-through category.",
                }
            ), 400

        models = payload.get("models") or []
        if isinstance(models, str):
            models = [models]
        duration_minutes = min(120.0, max(0.25, float(payload.get("duration_minutes", 3.0))))
        max_iterations = min(40, max(1, int(payload.get("max_iterations", 5))))
        auto_deploy = bool(payload.get("auto_deploy", True))

        job = jobs.start_job(
            "ai_hunt",
            f"AI Slip-Through Hunter ({mode.upper()}: {category_key})",
            lambda j: pentester.run_ai_slipthrough_hunt(
                mode=mode,
                category_key=category_key,
                model_queue=models,
                duration_minutes=duration_minutes,
                max_iterations=max_iterations,
                auto_deploy=auto_deploy,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    # --- Uptester (STRICTLY READ-ONLY) ---
    @app.get("/api/uptester/datasets")
    def api_uptester_datasets() -> Any:
        return jsonify(
            {
                "ok": True,
                "read_only": True,
                "dns_uptime": storage.load_dns_uptime_sites(),
                "search_uptime": storage.load_search_uptime_terms(),
                "dns_uptime_state": storage.load_state("dns_uptime"),
            }
        )

    @app.post("/api/uptester/audit-blocks")
    def api_uptester_audit_blocks() -> Any:
        payload = request.get_json(force=True) or {}
        scope = str(payload.get("scope", "slip_throughs"))
        job = jobs.start_job(
            "uptester_blocks",
            "Uptester: Critical Block Enforcement Audit (Read-Only)",
            lambda j: uptester.run_critical_block_audit(
                scope=scope,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.post("/api/uptester/dns-baseline")
    def api_uptester_dns_baseline() -> Any:
        payload = request.get_json(force=True) or {}
        full_test = bool(payload.get("full_test", False))
        category = payload.get("category") or None
        job = jobs.start_job(
            "uptester_dns",
            "Uptester: Essential DNS Baseline Check (Read-Only)",
            lambda j: uptester.run_dns_uptime_baseline(
                full_test=full_test,
                category_filter=category,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.post("/api/uptester/search-baseline")
    def api_uptester_search_baseline() -> Any:
        payload = request.get_json(force=True) or {}
        category = payload.get("category") or None
        sample_limit = min(150, max(5, int(payload.get("sample_limit", 25))))
        job = jobs.start_job(
            "uptester_search",
            "Uptester: Essential Search Baseline Check (Read-Only)",
            lambda j: uptester.run_search_uptime_baseline(
                category_filter=category,
                sample_limit=sample_limit,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    # --- Autonomous Multi-Hour Full Pipeline & Reports ---
    @app.post("/api/autonomous/start")
    def api_autonomous_start() -> Any:
        payload = request.get_json(force=True) or {}
        if "duration_hours" in payload and payload["duration_hours"] not in (None, ""):
            total_minutes = float(payload["duration_hours"]) * 60.0
        else:
            total_minutes = float(payload.get("duration_minutes", 120.0))
        total_minutes = min(1440.0, max(1.0, total_minutes))

        enable_s1 = bool(payload.get("enable_stage1_dns", True))
        enable_s2 = bool(payload.get("enable_stage2_search", True))
        enable_s3 = bool(payload.get("enable_stage3_uptester", True))
        full_dns = bool(payload.get("full_dns_baseline_reprobe", False))

        hours_lbl = f"{total_minutes / 60.0:.2f}h" if total_minutes >= 60 else f"{int(total_minutes)}m"
        job = jobs.start_job(
            "autonomous_pipeline",
            f"Autonomous Full Pipeline ({hours_lbl})",
            lambda j: autonomous.run_full_autonomous_pipeline(
                total_minutes=total_minutes,
                enable_stage1_dns=enable_s1,
                enable_stage2_search=enable_s2,
                enable_stage3_uptester=enable_s3,
                full_dns_baseline_reprobe=full_dns,
                stop_event=j.stop_event,
                log_cb=j.append_log,
                progress_cb=j.set_progress,
            ),
        )
        return jsonify({"ok": True, "job_id": job.job_id})

    @app.get("/api/reports")
    def api_reports_list() -> Any:
        return jsonify({"ok": True, "reports": reports.list_reports()})

    @app.get("/api/reports/<report_id>")
    def api_report_detail(report_id: str) -> Any:
        rep = reports.get_report(report_id)
        if not rep:
            return jsonify({"ok": False, "error": "Report not found."}), 404
        return jsonify({"ok": True, "report": rep})

    # --- Jobs ---
    @app.get("/api/jobs/<job_id>")
    def api_job_status(job_id: str) -> Any:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Job not found."}), 404
        since = int(request.args.get("since", 0))
        return jsonify({"ok": True, **job.snapshot(since_idx=since)})

    @app.post("/api/jobs/<job_id>/stop")
    def api_job_stop(job_id: str) -> Any:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Job not found."}), 404
        job.stop_event.set()
        return jsonify({"ok": True, "stopping": True})

    # --- API Key Vault (AI Keys Editable Only; Cloudflare Sealed) ---
    @app.get("/api/vault/status")
    def api_vault_status() -> Any:
        return jsonify({"ok": True, **vault.get_masked_status()})

    @app.post("/api/vault/update")
    def api_vault_update() -> Any:
        payload = request.get_json(force=True) or {}
        try:
            status = vault.update_credentials(payload)
            return jsonify({"ok": True, "status": status})
        except PermissionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 403

    @app.post("/api/vault/clear-backup")
    def api_vault_clear_backup() -> Any:
        status = vault.clear_backup_key()
        return jsonify({"ok": True, "status": status})

    @app.post("/api/vault/test")
    def api_vault_test() -> Any:
        cf_client = CloudflareReadOnlyClient(get_cloudflare_transport_config())
        cf_res = cf_client.verify_connection()

        creds = vault.get_credentials()
        gem_primary = creds.get("GEMINI_API_KEY", "")
        gem_res: dict[str, Any] = {"ok": False, "error": "Not configured"}
        if gem_primary:
            try:
                client = GeminiRestClient(api_key=gem_primary)
                models = [m.get("name") for m in client.list_models() if "gemini" in (m.get("name") or "").lower()]
                gem_res = {"ok": bool(models), "models_found": len(models)}
            except Exception as exc:
                gem_res = {"ok": False, "error": str(exc)}

        gem_backup = creds.get("GEMINI_API_KEY_BACKUP", "")
        backup_res: dict[str, Any] | None = None
        if gem_backup:
            try:
                bclient = GeminiRestClient(api_key=gem_backup)
                bmodels = [m.get("name") for m in bclient.list_models() if "gemini" in (m.get("name") or "").lower()]
                backup_res = {"ok": bool(bmodels), "models_found": len(bmodels)}
            except Exception as exc:
                backup_res = {"ok": False, "error": str(exc)}

        return jsonify(
            {
                "ok": True,
                "cloudflare": cf_res,
                "gemini_primary": gem_res,
                "gemini_backup": backup_res,
            }
        )

    return app, token
