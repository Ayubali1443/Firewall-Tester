"""Automated security, core regex logic, storage, vault, and API endpoint tests for SentinelGate AI."""

from __future__ import annotations

import ctypes
import re
import tempfile
import types
from pathlib import Path
import unittest

import build
from sentinelgate.config.cf_secrets import (
    CloudflareTransportConfig,
    _read_native_slot,
    get_cloudflare_transport_config,
    is_admin_cf_store_present,
    load_admin_cf_credentials,
    lock_path_admin_only,
    save_admin_cf_credentials,
)
from sentinelgate.config.vault import (
    ApiKeyVault,
    dpapi_protect,
    dpapi_unprotect,
    mask_secret,
    save_gemini_install_seed,
)
from sentinelgate.core.cleaner import (
    clean_category,
    deduplicate_terms_for_sync,
    get_skeleton,
    run_virtual_pentest_for_terms,
)
from sentinelgate.core.cloudflare import CloudflarePolicyWriter, CloudflareReadOnlyClient
from sentinelgate.core.gemini_agent import GeminiRestClient, run_slipthrough_hunt_loop
from sentinelgate.core.quality_gate import (
    filter_useful_dns_candidates,
    filter_useful_search_candidates,
    is_multipurpose_cdn_domain,
    parse_ai_exhausted_signal,
)
from sentinelgate.core.regex_engine import (
    build_flat_regex,
    calculate_dynamic_chunks,
    format_traffic_condition,
    local_rust_preflight_silent,
    obfuscate_term,
    verify_validator_integrity,
)
from sentinelgate.core.storage import StorageManager
from sentinelgate.modules.autonomous import AutonomousRunner, ReportStore
from sentinelgate.modules.pentester import PentesterService
from sentinelgate.modules.uptester import UptesterService
from sentinelgate.server import BackgroundJob, create_app


class SentinelGateCoreTests(unittest.TestCase):
    def test_exact_regex_obfuscation_and_empty_vowel_guard(self) -> None:
        # Vowel-only word 'yaoi' must not match empty string
        yaoi_rx = build_flat_regex(["yaoi"])
        compiled = re.compile(yaoi_rx)
        self.assertIsNone(compiled.search(""))
        self.assertIsNone(compiled.search("   "))
        self.assertIsNotNone(compiled.search("yaoi"))
        self.assertIsNotNone(compiled.search("y.a.0.1"))

        # Multi-word leetspeak + URL encoding check
        proxy_rx = build_flat_regex(["web proxy"])
        p_comp = re.compile(proxy_rx)
        self.assertIsNotNone(p_comp.search("web proxy"))
        self.assertIsNotNone(p_comp.search("w3b%20pr0xy"))
        self.assertIsNotNone(p_comp.search("wb-prxy"))
        # Strict boundary check
        self.assertIsNone(p_comp.search("mywebproxytool"))

    def test_rust_validator_integrity_and_preflight(self) -> None:
        ok, detail = verify_validator_integrity()
        self.assertTrue(ok, f"Rust validator check failed: {detail}")
        self.assertTrue(local_rust_preflight_silent(build_flat_regex(["web proxy", "glype"])))
        self.assertFalse(local_rust_preflight_silent(r"(?i)(unclosed"))

    def test_dynamic_chunking_limits(self) -> None:
        terms = ["web proxy", "glype", "phproxy", "miniproxy", "y2mate", "savefrom"]
        chunks = calculate_dynamic_chunks(terms)
        self.assertGreaterEqual(len(chunks), 1)
        for ch in chunks:
            traffic = format_traffic_condition(build_flat_regex(ch))
            self.assertLessEqual(len(traffic), 4090)

    def test_skeleton_cleaner_and_virtual_pentest(self) -> None:
        self.assertEqual(get_skeleton("p0rn"), get_skeleton("porn"))
        cfg = {"terms": ["proxy", "pr0xy", "glype"], "history": ["proxy", "pr0xy"]}
        removed = clean_category(cfg)
        self.assertGreaterEqual(len(removed), 1)
        self.assertIn("glype", cfg["terms"])

        vp = run_virtual_pentest_for_terms(["glype", "phproxy"], variants_per_term=200)
        self.assertTrue(vp["ok"])
        self.assertGreater(vp["total_tested"], 0)
        self.assertGreater(vp["blocked_count"], 0)
        self.assertGreaterEqual(vp["block_rate"], 0.0)
        self.assertLessEqual(vp["block_rate"], 100.0)

    def test_dpapi_vault_roundtrip_and_masking(self) -> None:
        secret = b"test-secret-credential-12345"
        cipher = dpapi_protect(secret)
        self.assertNotEqual(cipher, secret)
        self.assertEqual(dpapi_unprotect(cipher), secret)
        self.assertEqual(mask_secret("AIzaSyABCDEFGHIJKLMN1234"), "AIza••••••••••••1234")

        with tempfile.TemporaryDirectory() as td:
            vault = ApiKeyVault(vault_path=Path(td) / "vault.dpapi")
            vault.update_credentials({"GEMINI_API_KEY": "AIzaTestKey1234567890"})
            creds = vault.get_credentials()
            self.assertEqual(creds["GEMINI_API_KEY"], "AIzaTestKey1234567890")
            self.assertNotIn("CF_API_TOKEN", creds)
            self.assertNotIn("CF_ACCOUNT_ID", creds)
            with self.assertRaises(PermissionError):
                vault.update_credentials({"CF_API_TOKEN": "attempted-overwrite"})

    def test_sealed_cloudflare_native_dll_and_worker_redaction(self) -> None:
        fake_acct = "acct_9876543210fedcba9876543210fedcba"
        fake_tok = "cf_secret_token_ABC123XYZ789_very_sensitive"
        fake_worker_url = "https://sg-relay.example.workers.dev"
        fake_worker_tok = "relay_secret_XYZ_999888777"

        with tempfile.TemporaryDirectory() as td:
            # 1. Test Direct Native Stripped Rust DLL sealing
            dll_direct = Path(td) / "sg_seal_direct.dll"
            digest_d = build.compile_native_seal_dll(
                account_id=fake_acct,
                api_token=fake_tok,
                out_dll=dll_direct,
                write_hash_module=False,
            )
            self.assertEqual(len(digest_d), 64)
            dll_bytes = dll_direct.read_bytes()
            self.assertNotIn(fake_acct.encode("utf-8"), dll_bytes)
            self.assertNotIn(fake_tok.encode("utf-8"), dll_bytes)

            lib_d = ctypes.CDLL(str(dll_direct))
            lib_d.sg_seal_mode.restype = ctypes.c_int
            lib_d.sg_unseal_slot.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
            lib_d.sg_unseal_slot.restype = ctypes.c_int
            lib_d.sg_wipe_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            self.assertEqual(lib_d.sg_seal_mode(), 1)
            self.assertEqual(_read_native_slot(lib_d, 0), fake_acct)
            self.assertEqual(_read_native_slot(lib_d, 1), fake_tok)

            # 2. Test Zero-Token Worker Relay Native Stripped Rust DLL sealing
            dll_worker = Path(td) / "sg_seal_worker.dll"
            build.compile_native_seal_dll(
                worker_url=fake_worker_url,
                worker_token=fake_worker_tok,
                out_dll=dll_worker,
                write_hash_module=False,
            )
            w_bytes = dll_worker.read_bytes()
            self.assertNotIn(fake_worker_url.encode("utf-8"), w_bytes)
            self.assertNotIn(fake_worker_tok.encode("utf-8"), w_bytes)

            lib_w = ctypes.CDLL(str(dll_worker))
            lib_w.sg_seal_mode.restype = ctypes.c_int
            lib_w.sg_unseal_slot.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
            lib_w.sg_unseal_slot.restype = ctypes.c_int
            lib_w.sg_wipe_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            self.assertEqual(lib_w.sg_seal_mode(), 2)
            self.assertEqual(_read_native_slot(lib_w, 2), fake_worker_url)
            self.assertEqual(_read_native_slot(lib_w, 3), fake_worker_tok)
            self.assertEqual(_read_native_slot(lib_w, 0), "")
            self.assertEqual(_read_native_slot(lib_w, 1), "")

            # Explicitly unload DLLs on Windows before temp directory cleanup
            kernel32 = ctypes.windll.kernel32
            kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            kernel32.FreeLibrary(lib_d._handle)
            kernel32.FreeLibrary(lib_w._handle)

        # 3. Verify Worker-mode client endpoints, headers, trust_env=False, and redaction
        ro_worker = CloudflareReadOnlyClient(
            CloudflareTransportConfig(mode="worker", worker_url=fake_worker_url, worker_token=fake_worker_tok)
        )
        self.assertFalse(ro_worker._session.trust_env)
        self.assertEqual(ro_worker.rules_url, f"{fake_worker_url}/v1/rules")
        self.assertEqual(ro_worker._session.headers.get("X-SG-Relay-Key"), fake_worker_tok)
        redacted = ro_worker._redact(f"Error calling {fake_worker_url} with {fake_worker_tok}")
        self.assertNotIn(fake_worker_url, redacted)
        self.assertNotIn(fake_worker_tok, redacted)

    def test_single_file_rust_setup_installer_build_and_silent_extract(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            dummy_payload = td_path / "SentinelGateAI.exe"
            dummy_bytes = b"MZ_TEST_SENTINELGATE_PAYLOAD_BYTES_123456"
            dummy_payload.write_bytes(dummy_bytes)

            setup_exe = td_path / "SentinelGateAI-Setup.exe"
            out = build.build_single_setup_installer(dummy_payload, out_setup=setup_exe)
            self.assertTrue(out.exists())

            install_target = td_path / "installed_app"
            res = subprocess.run(
                [str(out), "--silent", "--no-shortcuts", "--install-dir", str(install_target)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(res.returncode, 0)
            installed_exe = install_target / "SentinelGateAI.exe"
            self.assertTrue(installed_exe.exists())
            self.assertEqual(installed_exe.read_bytes(), dummy_bytes)

            # Passing Cloudflare credentials in non-admin context must fail cleanly (exit 5)
            nonadmin_cf = subprocess.run(
                [
                    str(out),
                    "--silent",
                    "--no-shortcuts",
                    "--cf-account",
                    "acct_123",
                    "--cf-token",
                    "tok_123",
                    "--install-dir",
                    str(td_path / "inst_nonadmin"),
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(nonadmin_cf.returncode, 5)

    def test_security_invariants_no_allow_no_delete_uptester_readonly(self) -> None:
        storage = StorageManager()
        with self.assertRaises(ValueError):
            storage.add_dns_domains("TestCat", ["example.com"], action="allow")
        with self.assertRaises(ValueError):
            storage.add_search_terms("TestCat+allow", ["test query"], action="block")
        with self.assertRaises(ValueError):
            storage.add_search_terms("TestCat", ["test query"], action="allow")

        integ = storage.verify_integrity()
        self.assertTrue(integ["dns_intact"])
        self.assertTrue(integ["search_intact"])
        self.assertTrue(integ["block_only_enforced"])

        # Verify CloudflareReadOnlyClient has ZERO write methods
        for forbidden in ("post", "put", "patch", "delete", "create_block_list", "sync_dns_block_policy", "sync_search_block_rules"):
            self.assertFalse(hasattr(CloudflareReadOnlyClient, forbidden))
            self.assertFalse(hasattr(UptesterService, forbidden))

    def test_flask_api_auth_and_block_only_guards(self) -> None:
        app, token = create_app(session_token="unit-test-token-123")
        client = app.test_client()

        # Unauthenticated request rejected
        unauth = client.get("/api/overview")
        self.assertEqual(unauth.status_code, 401)

        # Authenticated overview returns ok without leaking seal internals
        ov = client.get("/api/overview", headers={"X-SG-Token": token})
        self.assertEqual(ov.status_code, 200)
        ov_json = ov.get_json()
        self.assertTrue(ov_json["ok"])
        self.assertTrue(ov_json["integrity"]["block_only_enforced"])
        self.assertNotIn("cloudflare_sealed", ov_json)
        self.assertNotIn("CF_API_TOKEN", str(ov_json))
        self.assertNotIn("CF_ACCOUNT_ID", str(ov_json))

        # Cloudflare credentials cannot be edited or viewed via Vault API
        cf_edit = client.post(
            "/api/vault/update",
            json={"CF_API_TOKEN": "hack", "CF_ACCOUNT_ID": "hack"},
            headers={"X-SG-Token": token},
        )
        self.assertEqual(cf_edit.status_code, 403)

        # AI key can be checked via vault status without leaking CF metadata or paths
        vs = client.get("/api/vault/status", headers={"X-SG-Token": token}).get_json()
        self.assertNotIn("cloudflare_sealed", vs)
        self.assertNotIn("vault_path", vs)
        self.assertNotIn("CF_API_TOKEN", vs.get("keys", {}))
        self.assertNotIn("CF_ACCOUNT_ID", vs.get("keys", {}))

        # UI HTML and JS never render 'NOT SEALED'
        with client.get("/") as r_html:
            ui_html = r_html.get_data(as_text=True)
        with client.get("/assets/app.js") as r_js:
            ui_js = r_js.get_data(as_text=True)
        self.assertIn("SEALED &amp; LOCKED", ui_html)
        self.assertNotIn("NOT SEALED", ui_html)
        self.assertNotIn("NOT SEALED", ui_js)

        # Allow-listing via API strictly rejected
        bad_dns = client.post(
            "/api/pentester/dns/add",
            json={"category": "BypassAttempt", "domains_text": "example.com", "action": "allow"},
            headers={"X-SG-Token": token},
        )
        self.assertEqual(bad_dns.status_code, 403)

        bad_search = client.post(
            "/api/pentester/search/add",
            json={"category": "BypassAttempt", "terms_text": "proxy", "action": "allow"},
            headers={"X-SG-Token": token},
        )
        self.assertEqual(bad_search.status_code, 403)

        # AI hunt on non-existent or legacy OS-managed desktop VPN category strictly blocked
        bad_ai = client.post(
            "/api/ai/hunt",
            json={"mode": "search", "category_key": "Browsers+block"},
            headers={"X-SG-Token": token},
        )
        self.assertIn(bad_ai.status_code, (400, 404))

        # Regex preview endpoint works end-to-end
        rx_res = client.post(
            "/api/pentester/search/preview-regex",
            json={"terms_text": "web proxy", "sample_query": "w3b%20pr0xy"},
            headers={"X-SG-Token": token},
        )
        self.assertEqual(rx_res.status_code, 200)
        rx_json = rx_res.get_json()
        self.assertTrue(rx_json["details"]["rust_dfa_ok"])
        self.assertTrue(rx_json["sample_matched"])

        # Reports endpoint returns valid list
        reps = client.get("/api/reports", headers={"X-SG-Token": token})
        self.assertEqual(reps.status_code, 200)
        self.assertTrue(reps.get_json()["ok"])

    def test_background_job_monotonic_log_offset_over_2000_lines(self) -> None:
        job = BackgroundJob(job_id="j1", kind="test", title="Long Job")
        for i in range(2505):
            job.append_log(f"line-{i}")
        snap1 = job.snapshot(since_idx=0)
        self.assertEqual(snap1["total_logs"], 2505)
        self.assertEqual(len(snap1["logs"]), 2000)
        self.assertEqual(snap1["logs"][0], "line-505")

        job.append_log("line-2505")
        snap2 = job.snapshot(since_idx=snap1["total_logs"])
        self.assertEqual(snap2["logs"], ["line-2505"])

    def test_autonomous_pipeline_report_generation_with_mocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            storage = StorageManager()
            vault = ApiKeyVault(vault_path=Path(td) / "vault.dpapi")
            pentester = PentesterService(storage, vault)
            uptester = UptesterService(storage, vault)
            reports = ReportStore(reports_dir=Path(td) / "reports")
            runner = AutonomousRunner(storage, vault, pentester, uptester, reports=reports)

            # Mock network-heavy methods so pipeline runs deterministically offline in <0.5s
            runner._init_ai_clients = lambda _log: ([], [])
            pentester.run_dns_penetration_test = lambda **_kw: {"total_domains": 10, "remediated_domains": 1}
            pentester.sync_search_policies = lambda **_kw: {"ok": True, "total_chunks": 33}
            pentester.run_virtual_pentest = lambda **_kw: {"ok": True, "block_rate": 99.5}
            pentester.run_search_real_traffic_test = lambda terms, **_kw: {"tested": len(terms), "blocked": len(terms), "bypassed": []}
            uptester.run_dns_uptime_baseline = lambda **_kw: {"total": 69, "healthy": 68, "overblocked_count": 1, "overblocked": [{"category": "Tech+allow", "domain": "example.dev", "reason": "Blocked"}]}
            uptester.run_search_uptime_baseline = lambda **_kw: {"tested": 111, "healthy": 111, "blocked_count": 0, "blocked_queries": []}
            uptester.run_critical_block_audit = lambda **_kw: {"checked": 20, "enforced": 20, "slip_through_count": 0, "slip_throughs": []}

            res = runner.run_full_autonomous_pipeline(total_minutes=1.0)
            self.assertTrue(res["ok"])
            rep = res["report"]
            self.assertTrue(rep["stage1_dns"]["executed"])
            self.assertTrue(rep["stage2_search"]["executed"])
            self.assertTrue(rep["stage3_uptester"]["executed"])
            self.assertTrue(rep["stage3_uptester"]["read_only"])
            self.assertFalse(rep["stage3_uptester"]["policy_modified"])
            self.assertEqual(rep["stage3_uptester"]["dns_overblocked_count"], 1)

            listed = reports.list_reports()
            self.assertEqual(len(listed), 1)
            loaded = reports.get_report(rep["report_id"])
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["report_id"], rep["report_id"])

    def test_ai_quality_gate_and_saturation_early_stop(self) -> None:
        self.assertTrue(parse_ai_exhausted_signal("NONE"))
        self.assertTrue(parse_ai_exhausted_signal("[]"))
        self.assertFalse(parse_ai_exhausted_signal("glype proxy"))

        # Search gate rejects long contrived phrases, single generic stopwords, leetspeak/regex-covered variants
        res = filter_useful_search_candidates(
            candidates=[
                "free",
                "open a blocked site now pls",
                "how to bypass school firewall with a super fast proxy",
                "gl1pe",
                "free w3b pr0xy tool",
                "ultraviolet proxy",
            ],
            existing_terms=["glype", "web proxy"],
            history_terms=[],
        )
        self.assertEqual(res["accepted"], ["ultraviolet proxy"])
        reasons = {r["item"]: r["reason"] for r in res["rejected"]}
        self.assertEqual(reasons["free"], "generic_stopword")
        self.assertEqual(reasons["open a blocked site now pls"], "contrived_long_phrase")
        self.assertEqual(reasons["how to bypass school firewall with a super fast proxy"], "length_out_of_bounds")
        self.assertEqual(reasons["gl1pe"], "skeleton_duplicate")
        self.assertEqual(reasons["free w3b pr0xy tool"], "already_matched_by_regex")

        # DNS gate rejects subdomains of already-blocked roots and non-live hallucinations
        import unittest.mock as mock
        import socket

        def fake_gethostbyname(host: str) -> str:
            if host == "deadhallucination999.xyz":
                raise socket.gaierror("NXDOMAIN")
            if host == "alreadyblocked.com":
                return "0.0.0.0"
            return "93.184.216.34"

        with mock.patch("sentinelgate.core.quality_gate.socket.gethostbyname", side_effect=fake_gethostbyname), \
             mock.patch("sentinelgate.core.quality_gate.requests.get") as mget:
            mget.return_value = mock.Mock(url="https://realslipthrough.net")
            dns_res = filter_useful_dns_candidates(
                ["sub.croxyproxy.com", "deadhallucination999.xyz", "alreadyblocked.com", "realslipthrough.net"],
                existing_domains=["croxyproxy.com"],
                verify_live=True,
            )
        self.assertEqual(dns_res["accepted"], ["realslipthrough.net"])

        # Hunt loop stops cleanly on NONE exhaustion signal
        import threading
        with mock.patch.object(GeminiRestClient, "generate_content", return_value="NONE"):
            hunt_res = run_slipthrough_hunt_loop(
                mode="search",
                api_key="dummy-key",
                backup_api_key="",
                model_queue=["models/gemini-2.5-flash"],
                category_key="CGIProxies+block",
                get_category_snapshot=lambda: {"category": "CGIProxies", "terms": ["glype"], "history": []},
                on_discovered=lambda _c, items: {"added": items, "sync_status": "ok"},
                duration_minutes=5.0,
                max_iterations=10,
                stop_event=threading.Event(),
                log_cb=lambda _m: None,
            )
        self.assertEqual(hunt_res["stop_reason"], "saturated")
        self.assertEqual(hunt_res["iterations_completed"], 0)
        self.assertEqual(hunt_res["total_added"], 0)

    def test_adult_image_hosts_blocks_sole_porn_but_protects_multipurpose_cdns(self) -> None:
        # Multipurpose CDNs & general cloud hosts must NEVER be accepted
        for protected in (
            "cloudfront.net",
            "d1234.cloudfront.net",
            "s3.amazonaws.com",
            "imagedelivery.net",
            "lh3.googleusercontent.com",
            "res.cloudinary.com",
            "cdn.jsdelivr.net",
            "i.imgur.com",
            "i.redd.it",
            "postimg.cc",
        ):
            self.assertTrue(is_multipurpose_cdn_domain(protected), f"Expected protected CDN: {protected}")

        # Dedicated sole-porn image hosts must NOT be flagged as protected multipurpose CDNs
        for porn_host in ("pixhost.to", "imagetwist.com", "imx.to", "imagevenue.com"):
            self.assertFalse(is_multipurpose_cdn_domain(porn_host))

        # Quality gate & storage refuse multipurpose CDNs while accepting sole-porn image hosts
        import unittest.mock as mock

        with mock.patch("sentinelgate.core.quality_gate.socket.gethostbyname", return_value="93.184.216.34"), \
             mock.patch("sentinelgate.core.quality_gate.requests.get", return_value=mock.Mock(url="https://newpornimg.to")):
            gated = filter_useful_dns_candidates(
                ["d999.cloudfront.net", "res.cloudinary.com", "i.imgur.com", "newpornimg.to"],
                existing_domains=["pixhost.to"],
                verify_live=True,
            )
        self.assertEqual(gated["accepted"], ["newpornimg.to"])
        reasons = {r["item"]: r["reason"] for r in gated["rejected"]}
        self.assertEqual(reasons["d999.cloudfront.net"], "multipurpose_cdn_protected")
        self.assertEqual(reasons["res.cloudinary.com"], "multipurpose_cdn_protected")
        self.assertEqual(reasons["i.imgur.com"], "multipurpose_cdn_protected")

        # Search gate rejects multipurpose CDN brand keywords
        s_gated = filter_useful_search_candidates(
            ["cloudinary", "cloudfront", "imgur", "newpornimg"],
            existing_terms=["pixhost"],
            history_terms=[],
        )
        self.assertEqual(s_gated["accepted"], ["newpornimg"])

        # StorageManager skips multipurpose CDNs even on direct add calls
        storage = StorageManager()
        add_res = storage.add_dns_domains("AdultImageHosts+block", ["d1.cloudfront.net", "s3.amazonaws.com"])
        self.assertEqual(add_res["added"], [])

    def test_atomic_search_sync_push_before_delete_and_fail_closed(self) -> None:
        # Cross-category deduplication prevents blocking the same keyword multiple times
        deduped, removed = deduplicate_terms_for_sync(
            ["CroxyProxy", "croxy proxy", "croxyproxy", "gl1pe", "glype", "glype"]
        )
        self.assertEqual(deduped, ["croxyproxy", "glype"])
        self.assertEqual(removed, 4)

        import unittest.mock as mock

        existing_rules = [
            {"id": "id-3", "name": "automated_http_search_block_p3", "traffic": "old3", "action": "block", "enabled": True},
            {"id": "id-1", "name": "automated_http_search_block_p1", "traffic": "old1", "action": "block", "enabled": True},
            {"id": "id-2", "name": "automated_http_search_block_p2", "traffic": "old2", "action": "block", "enabled": True},
        ]

        # Scenario 1: Shrinking 3 -> 2 rules updates p1 & p2 in-place FIRST, then trims p3
        ops: list[str] = []
        phases: list[str] = []
        writer = CloudflarePolicyWriter("acct_1", "tok_1")

        def ok_put(url: str, **_kw):
            ops.append(f"PUT:{url.rsplit('/', 1)[-1]}")
            return mock.Mock(status_code=200, json=lambda: {"success": True, "result": {"id": url.rsplit("/", 1)[-1]}})

        def ok_del(url: str, **_kw):
            ops.append(f"DELETE:{url.rsplit('/', 1)[-1]}")
            return mock.Mock(status_code=200, json=lambda: {"success": True})

        with mock.patch.object(writer, "get_rules", return_value=existing_rules), \
             mock.patch.object(writer._session, "put", side_effect=ok_put), \
             mock.patch.object(writer._session, "delete", side_effect=ok_del), \
             mock.patch("sentinelgate.core.cloudflare.time.sleep"):
            res1 = writer.sync_search_block_rules(
                ["new_traffic_1", "new_traffic_2"],
                phase_cb=lambda p: phases.append(p["sync_phase"]),
            )
        self.assertTrue(res1["ok"])
        self.assertEqual(ops, ["PUT:id-1", "PUT:id-2", "DELETE:id-3"])
        self.assertIn("pushing_in_place", phases)
        self.assertIn("trimming_trailing", phases)
        self.assertEqual(phases[-1], "completed")

        # Scenario 2: Mid-push network outage (user switches data off) must NEVER delete id-3!
        ops_fail: list[str] = []

        def flaky_put(url: str, **_kw):
            rid = url.rsplit("/", 1)[-1]
            ops_fail.append(f"PUT:{rid}")
            if rid == "id-2":
                raise ConnectionError("Network switched off mid-push")
            return mock.Mock(status_code=200, json=lambda: {"success": True, "result": {"id": rid}})

        with mock.patch.object(writer, "get_rules", return_value=existing_rules), \
             mock.patch.object(writer._session, "put", side_effect=flaky_put), \
             mock.patch.object(writer._session, "delete", side_effect=lambda u, **_k: ops_fail.append(f"DELETE:{u}")), \
             mock.patch("sentinelgate.core.cloudflare.time.sleep"):
            res2 = writer.sync_search_block_rules(["new_traffic_1", "new_traffic_2"])
        self.assertFalse(res2["ok"])
        self.assertTrue(res2["aborted_delete_preserved_protection"])
        self.assertEqual(res2["sync_phase"], "aborted_preserved")
        self.assertFalse(any(o.startswith("DELETE:") for o in ops_fail))

    def test_cloudflare_limits_pagination_sharding_and_policy_splitting(self) -> None:
        import unittest.mock as mock

        # 1. Single oversized term does not poison dynamic chunking
        huge_term = " ".join(["proxy"] * 120)
        chunks = calculate_dynamic_chunks([huge_term, "glype", "phproxy"])
        self.assertEqual(chunks, [["glype", "phproxy"]])

        writer = CloudflarePolicyWriter("acct_1", "tok_1")

        # 2. Pagination fetches page 1 and page 2 cleanly
        def paged_get(_url: str, params=None, **_kw):
            page = (params or {}).get("page", 1)
            if page == 1:
                return mock.Mock(
                    status_code=200,
                    json=lambda: {"result": [{"id": "r1", "name": "rule1"}], "result_info": {"total_pages": 2}},
                )
            return mock.Mock(
                status_code=200,
                json=lambda: {"result": [{"id": "r2", "name": "rule2"}], "result_info": {"total_pages": 2}},
            )

        with mock.patch.object(writer._session, "get", side_effect=paged_get):
            all_rules = writer.get_rules()
        self.assertEqual([r["id"] for r in all_rules], ["r1", "r2"])

        # 3. Adaptive list sharding fills capacity up to 1000 and spills into _p2
        summaries = {"Proxies+block": {"id": "uuid-1", "count": 998, "type": "HOSTNAME"}}
        patched_batches = []
        created_names = []

        def fake_patch(url: str, json=None, **_kw):
            patched_batches.append((url.rsplit("/", 1)[-1], [x["value"] for x in json["append"]]))
            return mock.Mock(status_code=200, json=lambda: {"success": True})

        def fake_create(name: str, current_list_count=None):
            created_names.append(name)
            return "uuid-2"

        with mock.patch.object(writer, "get_existing_list_items", return_value=set()), \
             mock.patch.object(writer, "create_block_list", side_effect=fake_create), \
             mock.patch.object(writer._session, "patch", side_effect=fake_patch):
            push_res = writer.push_domains_adaptive(
                "Proxies+block",
                ["a.com", "b.com", "c.com", "d.com"],
                list_summaries=summaries,
            )
        self.assertEqual(push_res["pushed"], 4)
        self.assertEqual(created_names, ["Proxies+block_p2"])
        self.assertEqual(patched_batches[0], ("uuid-1", ["a.com", "b.com"]))
        self.assertEqual(patched_batches[1], ("uuid-2", ["c.com", "d.com"]))

        # 4. DNS policy expression splits across multiple 4090-char policies when >65 lists exist
        many_lists = {f"Proxies+block_p{i}": f"00000000-0000-0000-0000-{i:012d}" for i in range(1, 76)}
        dns_data = {"Proxies+block": {"action": "block", "domains": []}}
        posted_dns = []

        def fake_dns_post(_url: str, json=None, **_kw):
            posted_dns.append(json)
            return mock.Mock(status_code=200, json=lambda: {"success": True, "result": {"id": f"dns-{len(posted_dns)}"}})

        with mock.patch.object(writer, "get_rules", return_value=[]), \
             mock.patch.object(writer._session, "post", side_effect=fake_dns_post):
            synced = writer.sync_dns_block_policy(dns_data, many_lists)
        self.assertTrue(synced)
        self.assertEqual(len(posted_dns), 2)
        self.assertEqual([p["name"] for p in posted_dns], ["automated_block_p1", "automated_block_p2"])
        self.assertTrue(all(len(p["traffic"]) <= 4090 for p in posted_dns))

        # 5. Quota telemetry raises warnings when near account caps
        near_lists = {f"L{i}": {"id": f"id-{i}", "count": 950, "type": "HOSTNAME"} for i in range(88)}
        q = writer.get_quota_telemetry(rules=[], list_summaries=near_lists)
        self.assertEqual(q["lists_used"], 88)
        self.assertEqual(q["lists_limit"], 100)
        self.assertTrue(any("88/100" in w for w in q["warnings"]))
        self.assertTrue(any("Auto-sharding lists near cap" in w for w in q["warnings"]))

    def test_admin_locked_cloudflare_store_acl_and_gemini_setup_seed(self) -> None:
        import os
        import unittest.mock as mock

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            vault_fp = td_path / "AdminLock" / "cf_admin.dpapi"
            ent = b"0123456789abcdef0123456789abcdef"

            # 1. Non-admin cannot save Cloudflare Admin credentials
            with mock.patch("sentinelgate.config.cf_secrets.is_admin_process", return_value=False):
                with self.assertRaises(PermissionError):
                    save_admin_cf_credentials(
                        account_id="acct_x",
                        api_token="tok_secret",
                        vault_path=vault_fp,
                        entropy_bytes=ent,
                    )

            # 2. Real Win32 SDDL Admin-only ACL blocks non-admin reads at the OS kernel level
            acl_fp = td_path / "kernel_locked.dpapi"
            acl_fp.write_bytes(b"locked-secret-blob")
            try:
                lock_path_admin_only(acl_fp, is_dir=False)
                if os.name == "nt":
                    with self.assertRaises(PermissionError):
                        acl_fp.read_bytes()
                    self.assertTrue(is_admin_cf_store_present(vault_path=acl_fp))
            finally:
                # Restore writable DACL so TemporaryDirectory cleans up cleanly
                if os.name == "nt":
                    from sentinelgate.config.cf_secrets import _SE_FILE_OBJECT, _apply_sddl_dacl

                    _apply_sddl_dacl(str(acl_fp), _SE_FILE_OBJECT, "D:P(A;;FA;;;WD)")

            # 3. Admin write -> Machine DPAPI + entropy roundtrip succeeds only when elevated
            with mock.patch("sentinelgate.config.cf_secrets.is_admin_process", return_value=True), \
                 mock.patch("sentinelgate.config.cf_secrets.lock_path_admin_only"):
                save_admin_cf_credentials(
                    account_id="acct_admin_999",
                    api_token="cf_tok_hidden_admin_only_777",
                    vault_path=vault_fp,
                    entropy_bytes=ent,
                )
            raw_blob = vault_fp.read_bytes()
            self.assertNotIn(b"cf_tok_hidden_admin_only_777", raw_blob)
            self.assertNotIn(b"acct_admin_999", raw_blob)

            with mock.patch("sentinelgate.config.cf_secrets.is_admin_process", return_value=True):
                loaded_admin = load_admin_cf_credentials(vault_path=vault_fp, entropy_bytes=ent)
            self.assertTrue(loaded_admin.is_ready())
            self.assertEqual(loaded_admin.mode, "direct")
            self.assertEqual(loaded_admin.account_id, "acct_admin_999")
            self.assertEqual(loaded_admin.api_token, "cf_tok_hidden_admin_only_777")

            with mock.patch("sentinelgate.config.cf_secrets.is_admin_process", return_value=False):
                locked_cfg = load_admin_cf_credentials(vault_path=vault_fp, entropy_bytes=ent)
            self.assertTrue(locked_cfg.is_admin_locked())
            self.assertFalse(locked_cfg.is_ready())
            self.assertEqual(locked_cfg.api_token, "")

            # 4. When Admin store is present, non-admin get_cloudflare_transport_config returns admin_locked even with env vars
            with mock.patch("sentinelgate.config.cf_secrets.is_admin_process", return_value=False), \
                 mock.patch("sentinelgate.config.cf_secrets.is_admin_cf_store_present", return_value=True), \
                 mock.patch.dict(os.environ, {"CF_ACCOUNT_ID": "env_acct", "CF_API_TOKEN": "env_tok"}):
                cfg = get_cloudflare_transport_config()
            self.assertEqual(cfg.mode, "admin_locked")
            self.assertEqual(cfg.api_token, "")

            # 5. Gemini setup seed initializes per-user vault cleanly and keeps Gemini editable
            seed_fp = td_path / "gemini_seed.dpapi"
            user_vault_fp = td_path / "user_vault.dpapi"
            save_gemini_install_seed("AIzaSetupSeedKey999", seed_path=seed_fp)
            user_vault = ApiKeyVault(vault_path=user_vault_fp, seed_path=seed_fp)
            self.assertEqual(user_vault.get_credentials()["GEMINI_API_KEY"], "AIzaSetupSeedKey999")

            # 6. Admin-Vault native sg_seal.dll compiles in mode 3 with zero embedded CF secrets
            dll_vault = td_path / "sg_seal_admin_vault.dll"
            build.compile_native_seal_dll(admin_vault=True, out_dll=dll_vault, write_hash_module=False)
            lib_v = ctypes.CDLL(str(dll_vault))
            lib_v.sg_seal_mode.restype = ctypes.c_int
            lib_v.sg_unseal_slot.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
            lib_v.sg_unseal_slot.restype = ctypes.c_int
            lib_v.sg_wipe_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            self.assertEqual(lib_v.sg_seal_mode(), 3)
            self.assertEqual(_read_native_slot(lib_v, 0), "")
            self.assertEqual(_read_native_slot(lib_v, 1), "")
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(lib_v._handle)

        # 7. UI & API cleanly reflect admin_locked state & relaunch-admin UAC refusal
        app, token = create_app(session_token="admin-lock-test-tok")
        client = app.test_client()
        with mock.patch("sentinelgate.server.get_cloudflare_transport_config", return_value=CloudflareTransportConfig(mode="admin_locked")), \
             mock.patch("sentinelgate.server.is_admin_process", return_value=False):
            ov = client.get("/api/overview", headers={"X-SG-Token": token}).get_json()
            self.assertFalse(ov["is_admin"])
            self.assertTrue(ov["cloudflare"]["admin_locked"])
            self.assertFalse(ov["cloudflare"]["ready"])

            vt = client.post("/api/vault/test", headers={"X-SG-Token": token}).get_json()
            self.assertTrue(vt["cloudflare"]["admin_locked"])
            self.assertFalse(vt["cloudflare"]["ok"])

            with mock.patch("sentinelgate.server.ctypes.windll.shell32.ShellExecuteW", return_value=5):
                rl = client.post("/api/system/relaunch-admin", headers={"X-SG-Token": token})
                self.assertEqual(rl.status_code, 403)


if __name__ == "__main__":
    unittest.main()
