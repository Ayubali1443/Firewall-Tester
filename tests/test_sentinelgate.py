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
    derive_build_handshake_parts,
    execute_sealed_request,
    get_cloudflare_transport_config,
    query_sealed_mode,
    read_cf_from_env_or_dotenv,
    read_worker_from_env_or_dotenv,
    reconstruct_handshake_key,
)
from sentinelgate.config.vault import ApiKeyVault, dpapi_protect, dpapi_unprotect, mask_secret
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
            self.assertLessEqual(len(traffic.encode("utf-8")), 4090)

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

    def test_sealed_cloudflare_native_dll_and_dotenv_isolation(self) -> None:
        import os
        import unittest.mock as mock

        fake_acct = "acct_9876543210fedcba9876543210fedcba"
        fake_tok = "cf_secret_token_ABC123XYZ789_very_sensitive"
        hs_key = os.urandom(32)
        wrong_key = os.urandom(32)

        # Verify split handshake reconstruction
        pa, pb = derive_build_handshake_parts(hs_key)
        self.assertNotIn(hs_key, pa + pb)
        self.assertEqual(reconstruct_handshake_key(pa, pb), hs_key)

        # Verify workspace .env loads ACCOUNT_ID/API_TOKEN cleanly in source mode,
        # but is ignored completely when running compiled binary!
        env_acct, env_tok = read_cf_from_env_or_dotenv()
        self.assertTrue(bool(env_acct and env_tok))
        with mock.patch("sentinelgate.config.cf_secrets.is_compiled_binary", return_value=True), \
             mock.patch("sentinelgate.config.cf_secrets._load_native_seal_dll", return_value=None):
            compiled_cfg = get_cloudflare_transport_config()
        self.assertEqual(compiled_cfg.mode, "none")

        def bind_dll(path: Path) -> ctypes.CDLL:
            lib = ctypes.CDLL(str(path))
            lib.sg_cf_mode.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
            lib.sg_cf_mode.restype = ctypes.c_int
            lib.sg_cf_request.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ]
            lib.sg_cf_request.restype = ctypes.c_int
            return lib

        with tempfile.TemporaryDirectory() as td:
            # 1. Test Direct Native WinHTTP Stripped Rust DLL sealing
            dll_direct = Path(td) / "sg_seal_direct.dll"
            digest_d = build.compile_native_seal_dll(
                account_id=fake_acct,
                api_token=fake_tok,
                handshake_key=hs_key,
                out_dll=dll_direct,
                write_hash_module=False,
            )
            self.assertEqual(len(digest_d), 64)
            dll_bytes = dll_direct.read_bytes()
            self.assertNotIn(fake_acct.encode("utf-8"), dll_bytes)
            self.assertNotIn(fake_tok.encode("utf-8"), dll_bytes)

            lib_d = bind_dll(dll_direct)
            # No plaintext credential-getter exports may exist
            self.assertFalse(hasattr(lib_d, "sg_unseal_slot"))
            self.assertEqual(query_sealed_mode(lib_d, handshake_key=hs_key), 1)
            # Wrong caller handshake fails (-4) even with the copied DLL
            self.assertEqual(query_sealed_mode(lib_d, handshake_key=wrong_key), -4)

            with self.assertRaises(PermissionError):
                execute_sealed_request("GET", "/rules", lib=lib_d, handshake_key=wrong_key)

            # Native Rust block-only policy guard rejects dangerous mutations offline (-3)
            for m, p, body in (
                ("POST", "/rules", {"name": "bypass", "action": "allow", "enabled": True}),
                ("PUT", "/rules/11111111-1111-1111-1111-111111111111", {"action": "block", "enabled": False}),
                ("PATCH", "/lists/11111111-1111-1111-1111-111111111111", {"remove": [{"value": "x.com"}]}),
                ("DELETE", "/lists/11111111-1111-1111-1111-111111111111", None),
                ("GET", "/../admin", None),
            ):
                with self.assertRaises(PermissionError):
                    execute_sealed_request(m, p, json_body=body, lib=lib_d, handshake_key=hs_key)

            kernel32 = ctypes.windll.kernel32
            kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            kernel32.FreeLibrary(lib_d._handle)

            # 1b. Test Worker Relay Native WinHTTP Stripped Rust DLL sealing (CF keys completely absent)
            fake_wurl = "https://sentinelgate-relay.example.workers.dev"
            fake_wsec = "sg_relay_secret_0123456789abcdef0123456789abcdef"
            dll_worker = Path(td) / "sg_seal_worker.dll"
            digest_w = build.compile_native_seal_dll(
                worker_url=fake_wurl,
                relay_secret=fake_wsec,
                handshake_key=hs_key,
                out_dll=dll_worker,
                write_hash_module=False,
            )
            self.assertEqual(len(digest_w), 64)
            w_bytes = dll_worker.read_bytes()
            self.assertNotIn(fake_wurl.encode("utf-8"), w_bytes)
            self.assertNotIn(fake_wsec.encode("utf-8"), w_bytes)
            self.assertNotIn(b"api.cloudflare.com", w_bytes)
            self.assertIn(b"CertGetCertificateChain", w_bytes)

            lib_w = bind_dll(dll_worker)
            self.assertFalse(hasattr(lib_w, "sg_unseal_slot"))
            self.assertEqual(query_sealed_mode(lib_w, handshake_key=hs_key), 2)
            self.assertEqual(query_sealed_mode(lib_w, handshake_key=wrong_key), -4)
            kernel32.FreeLibrary(lib_w._handle)

        # 2. Verify native_sealed & native_worker clients hold ZERO plaintext secrets in Python
        ro_native = CloudflareReadOnlyClient(CloudflareTransportConfig(mode="native_sealed"))
        self.assertTrue(ro_native.is_configured())
        self.assertEqual(ro_native.account_id, "")
        self.assertEqual(ro_native.api_token, "")
        self.assertNotIn("Authorization", ro_native._session.headers)
        with mock.patch("sentinelgate.core.cloudflare.execute_sealed_request", return_value=(200, '{"success":true,"result":[]}')):
            vc = ro_native.verify_connection()
            self.assertTrue(vc["ok"])

        ro_nw = CloudflareReadOnlyClient(CloudflareTransportConfig(mode="native_worker"))
        self.assertTrue(ro_nw.is_configured())
        self.assertEqual(ro_nw.account_id, "")
        self.assertEqual(ro_nw.api_token, "")
        self.assertEqual(ro_nw.worker_token, "")
        self.assertNotIn("X-SG-Relay-Key", ro_nw._session.headers)
        with mock.patch("sentinelgate.core.cloudflare.execute_sealed_request", return_value=(200, '{"ok":true,"rule_count":3,"list_count":4}')):
            vc_nw = ro_nw.verify_connection()
            self.assertTrue(vc_nw["ok"])
            self.assertEqual(vc_nw["rule_count"], 3)
            self.assertEqual(vc_nw["list_count"], 4)

        # 3. Verify Direct & Worker mode redaction + trust_env=False + .env helper
        ro_direct = CloudflareReadOnlyClient(
            CloudflareTransportConfig(mode="direct", account_id=fake_acct, api_token=fake_tok)
        )
        self.assertFalse(ro_direct._session.trust_env)
        redacted = ro_direct._redact(f"Error acct={fake_acct} tok={fake_tok}")
        self.assertNotIn(fake_acct, redacted)
        self.assertNotIn(fake_tok, redacted)

        ro_w = CloudflareReadOnlyClient(
            CloudflareTransportConfig(
                mode="worker",
                worker_url="https://sentinelgate-relay.example.workers.dev",
                worker_token="relay-sec-999",
            )
        )
        self.assertFalse(ro_w._session.trust_env)
        red_w = ro_w._redact("Err https://sentinelgate-relay.example.workers.dev key=relay-sec-999")
        self.assertNotIn("sentinelgate-relay.example.workers.dev", red_w)
        self.assertNotIn("relay-sec-999", red_w)

        with tempfile.TemporaryDirectory() as env_td:
            (Path(env_td) / ".env").write_text(
                'WORKER_URL="https://sentinelgate-relay.test.workers.dev/"\nRELAY_CLIENT_SECRET="sec123"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("WORKER_URL", None)
                os.environ.pop("SG_WORKER_URL", None)
                os.environ.pop("RELAY_URL", None)
                os.environ.pop("RELAY_CLIENT_SECRET", None)
                os.environ.pop("SG_WORKER_TOKEN", None)
                os.environ.pop("WORKER_TOKEN", None)
                w_u, w_s = read_worker_from_env_or_dotenv(Path(env_td))
                self.assertEqual(w_u, "https://sentinelgate-relay.test.workers.dev")
                self.assertEqual(w_s, "sec123")

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
            uninstall_exe = install_target / "Uninstall.exe"
            self.assertTrue(installed_exe.exists())
            self.assertTrue(uninstall_exe.exists())
            self.assertEqual(installed_exe.read_bytes(), dummy_bytes)

            # Verify uninstall cleans installed binary & directory cleanly
            uninst_res = subprocess.run(
                [str(out), "--uninstall", "--silent", "--no-shortcuts", "--install-dir", str(install_target)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(uninst_res.returncode, 0)
            self.assertFalse(installed_exe.exists())
            self.assertFalse(install_target.exists())

            # Verify installer never targets Program Files, ProgramData, HKLM writes, or Admin elevation
            installer_src = (Path(__file__).resolve().parent.parent / "sentinelgate" / "installer" / "src" / "main.rs").read_text(encoding="utf-8")
            self.assertNotIn("Program Files", installer_src)
            self.assertNotIn("ProgramData", installer_src)
            self.assertNotIn("requireAdministrator", installer_src)
            self.assertNotIn("runas", installer_src.lower())
            self.assertIn("HKEY_CURRENT_USER", installer_src)
            self.assertIn(b"asInvoker", out.read_bytes())

            # Verify HKCU Uninstall registration + Uninstall.exe direct cleanup + self-removal
            import os
            import time
            import winreg

            test_reg_key = rf"Software\SentinelGateAI_UnitTest_{os.getpid()}"
            install_target2 = td_path / "installed_app2"
            try:
                subprocess.run(
                    [
                        str(out),
                        "--silent",
                        "--no-shortcuts",
                        "--install-dir",
                        str(install_target2),
                        "--reg-key",
                        test_reg_key,
                    ],
                    check=True,
                    timeout=20,
                )
                uninst2 = install_target2 / "Uninstall.exe"
                self.assertTrue(uninst2.exists())
                self.assertTrue((install_target2 / "SentinelGateAI.exe").exists())

                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_reg_key) as k:
                    self.assertEqual(winreg.QueryValueEx(k, "DisplayName")[0], "SentinelGate AI")
                    self.assertEqual(winreg.QueryValueEx(k, "InstallLocation")[0], str(install_target2))
                    self.assertEqual(winreg.QueryValueEx(k, "UninstallString")[0], f'"{uninst2}" --uninstall')
                    self.assertEqual(
                        winreg.QueryValueEx(k, "QuietUninstallString")[0],
                        f'"{uninst2}" --uninstall --silent',
                    )
                    self.assertEqual(winreg.QueryValueEx(k, "NoModify")[0], 1)
                    self.assertEqual(winreg.QueryValueEx(k, "NoRepair")[0], 1)
                    self.assertGreaterEqual(winreg.QueryValueEx(k, "EstimatedSize")[0], 1)
                    with self.assertRaises(FileNotFoundError):
                        winreg.QueryValueEx(k, "NoRemove")

                res_u2 = subprocess.run(
                    [str(uninst2), "--uninstall", "--silent", "--no-shortcuts", "--reg-key", test_reg_key],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(res_u2.returncode, 0)
                self.assertFalse((install_target2 / "SentinelGateAI.exe").exists())

                with self.assertRaises(FileNotFoundError):
                    winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_reg_key)

                # Wait briefly for detached PowerShell retry loop to remove Uninstall.exe & folder
                for _ in range(25):
                    if not uninst2.exists() and not install_target2.exists():
                        break
                    time.sleep(0.2)
                self.assertFalse(uninst2.exists())
                self.assertFalse(install_target2.exists())
            finally:
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_reg_key)
                except OSError:
                    pass

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
        import unittest.mock as mock

        app, token = create_app(session_token="unit-test-token-123")
        client = app.test_client()

        # Unauthenticated request rejected
        unauth = client.get("/api/overview")
        self.assertEqual(unauth.status_code, 401)

        # Authenticated overview returns ok without leaking seal internals
        with mock.patch("sentinelgate.server.get_cloudflare_transport_config", return_value=CloudflareTransportConfig(mode="none")):
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

        # UI HTML and JS never render 'NOT SEALED' and include Gemini first-launch onboarding modal
        with client.get("/") as r_html:
            ui_html = r_html.get_data(as_text=True)
        with client.get("/assets/app.js") as r_js:
            ui_js = r_js.get_data(as_text=True)
        self.assertIn("SEALED &amp; LOCKED", ui_html)
        self.assertIn("gemini-setup-modal", ui_html)
        self.assertIn("submitGeminiPromptModal", ui_js)
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
        summaries = {"Proxies+block": {"id": "uuid-1", "count": 998, "type": "DOMAIN"}}
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

        # 4. DNS policy expression packs within Cloudflare's current 140,000-character limit
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
        self.assertEqual(len(posted_dns), 1)
        self.assertEqual([p["name"] for p in posted_dns], ["automated_block"])
        self.assertTrue(all(len(p["traffic"].encode("utf-8")) <= 139000 for p in posted_dns))

        # 5. Quota telemetry raises warnings when near account caps
        near_lists = {f"L{i}": {"id": f"id-{i}", "count": 950, "type": "DOMAIN"} for i in range(88)}
        q = writer.get_quota_telemetry(rules=[], list_summaries=near_lists)
        self.assertEqual(q["lists_used"], 88)
        self.assertEqual(q["lists_limit"], 100)
        self.assertTrue(any("88/100" in w for w in q["warnings"]))
        self.assertTrue(any("Auto-sharding lists near cap" in w for w in q["warnings"]))

    def test_prebuild_live_credential_verification_and_env_hardening(self) -> None:
        import os
        import unittest.mock as mock
        from sentinelgate.main import _strip_proxy_env_overrides

        # 1. Invalid Worker / Cloudflare credentials fail pre-build live check before embedding
        with mock.patch("build.CloudflareReadOnlyClient.verify_connection", return_value={"ok": False, "error": "HTTP 401 Unauthorized"}):
            res_bad_w = build.verify_credentials_before_build(
                worker_url="https://sentinelgate-relay.example.workers.dev",
                relay_secret="bad_sec",
            )
        self.assertFalse(res_bad_w["ok"])
        self.assertFalse(res_bad_w["cf_ok"])

        with mock.patch("build.CloudflareReadOnlyClient.verify_connection", return_value={"ok": False, "error": "HTTP 401 Invalid token"}):
            res_bad_cf = build.verify_credentials_before_build(account_id="acct_x", api_token="bad_tok")
        self.assertFalse(res_bad_cf["ok"])
        self.assertFalse(res_bad_cf["cf_ok"])

        # 2. Valid Worker Relay must pass health check AND return 401 when relay secret is wrong
        with mock.patch("build.CloudflareReadOnlyClient.verify_connection", return_value={"ok": True, "rule_count": 4}), \
             mock.patch("build.CloudflareReadOnlyClient.get_lists", return_value={"Proxies+block": "uuid-1", "AI+block": "uuid-2"}), \
             mock.patch("requests.Session.get", return_value=mock.Mock(status_code=401)):
            res_ok = build.verify_credentials_before_build(
                worker_url="https://sentinelgate-relay.example.workers.dev",
                relay_secret="good_sec",
            )
        self.assertTrue(res_ok["ok"])
        self.assertEqual(res_ok["mode"], "worker")
        self.assertEqual(res_ok["rule_count"], 4)
        self.assertEqual(res_ok["list_count"], 2)

        # 2b. Fail closed if Worker endpoint does not enforce 401 auth
        with mock.patch("build.CloudflareReadOnlyClient.verify_connection", return_value={"ok": True, "rule_count": 4}), \
             mock.patch("requests.Session.get", return_value=mock.Mock(status_code=200)):
            res_open_worker = build.verify_credentials_before_build(
                worker_url="https://sentinelgate-relay.example.workers.dev",
                relay_secret="good_sec",
            )
        self.assertFalse(res_open_worker["ok"])

        # 3. Fail-closed: build refuses to embed raw direct CF keys when Worker Relay is unconfigured
        with mock.patch("build.read_worker_from_env_or_dotenv", return_value=("", "")):
            with self.assertRaises(RuntimeError):
                build.prepare_native_seal(skip_live_check=True, allow_unsafe_direct=False)

        # 3b. Non-interactive prepare_native_seal in Worker mode reads .env cleanly with zero input() prompts
        def forbid_prompt(*_a, **_kw):
            raise AssertionError("Build must be 100% non-interactive!")

        try:
            with mock.patch("builtins.input", side_effect=forbid_prompt), \
                 mock.patch(
                     "build.read_worker_from_env_or_dotenv",
                     return_value=("https://sentinelgate-relay.example.workers.dev", "relay_secret_123456"),
                 ), \
                 mock.patch("build.verify_credentials_before_build", return_value={"ok": True, "rule_count": 2, "list_count": 5}):
                build.prepare_native_seal(skip_live_check=False)
        finally:
            build.cleanup_build_artifacts()

        # 4. Startup env hardening removes MITM proxy & debugger injection variables
        with mock.patch.dict(os.environ, {
            "HTTPS_PROXY": "http://127.0.0.1:8080",
            "REQUESTS_CA_BUNDLE": "C:\\evil\\fiddler.pem",
            "PYTHONINSPECT": "1",
            "PYTHONBREAKPOINT": "pdb.set_trace",
        }):
            _strip_proxy_env_overrides()
            for var in ("HTTPS_PROXY", "REQUESTS_CA_BUNDLE", "PYTHONINSPECT", "PYTHONBREAKPOINT"):
                self.assertNotIn(var, os.environ)

    def test_post_install_editable_json_adds_without_cf_deletions(self) -> None:
        import json
        import unittest.mock as mock

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            data_dir = td_path / "installed_app" / "data"
            app_dir = td_path / "local_appdata"

            with mock.patch("sentinelgate.core.storage.is_compiled_binary", return_value=True):
                st = StorageManager(data_dir=data_dir, app_data_dir=app_dir)

            # 1. Starter editable JSON files are materialized even in compiled/installed builds
            for fname in ("dns_blocklist.json", "search_blocklist.json", "dns_uptime_sites.json", "search_uptime_terms.json"):
                self.assertTrue((data_dir / fname).exists(), f"Missing editable JSON: {fname}")

            # 2. User edits dns_blocklist.json to add custom domain (+ ignored allow attempt)
            dns_raw = json.loads((data_dir / "dns_blocklist.json").read_text(encoding="utf-8"))
            dns_raw["Proxies+block"]["domains"].append("custom-added-proxy.org")
            dns_raw["AllowHack+allow"] = {"category": "AllowHack", "action": "allow", "domains": ["google.com"]}
            (data_dir / "dns_blocklist.json").write_text(json.dumps(dns_raw, indent=4), encoding="utf-8")

            loaded_dns = st.load_dns_blocklist()
            self.assertIn("custom-added-proxy.org", loaded_dns["Proxies+block"]["domains"])
            self.assertNotIn("AllowHack+allow", loaded_dns)

            # The edited JSON file is authoritative: removing defaults or custom
            # entries removes them from active local data after reload.
            dns_raw["Proxies+block"]["domains"].remove("croxyproxy.com")
            (data_dir / "dns_blocklist.json").write_text(json.dumps(dns_raw, indent=4), encoding="utf-8")
            loaded_without_default = st.load_dns_blocklist()
            self.assertNotIn("croxyproxy.com", loaded_without_default["Proxies+block"]["domains"])

            del dns_raw["Proxies+block"]
            (data_dir / "dns_blocklist.json").write_text(json.dumps(dns_raw, indent=4), encoding="utf-8")
            loaded_after_del = st.load_dns_blocklist()
            self.assertNotIn("Proxies+block", loaded_after_del)

            # 3. User edits search_blocklist.json to add keyword, then deletes it & category from JSON
            search_raw = json.loads((data_dir / "search_blocklist.json").read_text(encoding="utf-8"))
            search_raw["Web Proxies+block"]["terms"].append("customsearchvector")
            (data_dir / "search_blocklist.json").write_text(json.dumps(search_raw, indent=4), encoding="utf-8")
            loaded_search = st.load_search_blocklist()
            self.assertIn("customsearchvector", loaded_search["Web Proxies+block"]["terms"])

            del search_raw["Web Proxies+block"]
            (data_dir / "search_blocklist.json").write_text(json.dumps(search_raw, indent=4), encoding="utf-8")
            loaded_search_after_del = st.load_search_blocklist()
            self.assertNotIn("Web Proxies+block", loaded_search_after_del)

            # 4. Cloudflare DNS policy sync preserves already-bound $list_ids even if absent from dns_data
            writer = CloudflarePolicyWriter("acct_1", "tok_1")
            existing_cf_rules = [
                {
                    "id": "rule-dns-1",
                    "name": "automated_block",
                    "action": "block",
                    "enabled": True,
                    "traffic": "any(dns.domains[*] in $11111111-1111-1111-1111-111111111111)",
                }
            ]
            captured_puts = []

            def fake_put(_url: str, json=None, **_kw):
                captured_puts.append(json)
                return mock.Mock(status_code=200, json=lambda: {"success": True, "result": {"id": "rule-dns-1"}})

            with mock.patch.object(writer, "get_rules", return_value=existing_cf_rules), \
                 mock.patch.object(writer._session, "put", side_effect=fake_put):
                ok_sync = writer.sync_dns_block_policy(
                    {"Custom+block": {"action": "block", "domains": []}},
                    {"Custom+block": "22222222-2222-2222-2222-222222222222"},
                )
            self.assertTrue(ok_sync)
            self.assertEqual(len(captured_puts), 1)
            self.assertIn("$11111111-1111-1111-1111-111111111111", captured_puts[0]["traffic"])
            self.assertIn("$22222222-2222-2222-2222-222222222222", captured_puts[0]["traffic"])

            # 5. Editable uptime JSONs apply edits immediately after install
            up_raw = json.loads((data_dir / "dns_uptime_sites.json").read_text(encoding="utf-8"))
            up_raw["Tech+allow"]["domains"].append("mycustomdocs.org")
            (data_dir / "dns_uptime_sites.json").write_text(json.dumps(up_raw, indent=4), encoding="utf-8")
            self.assertIn("mycustomdocs.org", st.load_dns_uptime_sites()["Tech+allow"]["domains"])

            # 6. Nuitka __compiled__ / NUITKA_ONEFILE_PARENT resolves persistent install dir instead of temp exe dir
            import os
            import sentinelgate.config.paths as sg_paths

            fake_compiled = types.SimpleNamespace(containing_dir=str(td_path / "perm_install"))
            with mock.patch.dict(sg_paths.__dict__, {"__compiled__": fake_compiled}), \
                 mock.patch.object(sg_paths.sys, "executable", str(td_path / "temp_onefile" / "app.exe")):
                self.assertEqual(sg_paths.get_project_root(), (td_path / "perm_install").resolve())

            # Simulate Nuitka --onefile where submodule containing_dir fell back to temp dir while NUITKA_ONEFILE_PARENT holds parent PID
            temp_fallback = types.SimpleNamespace(containing_dir=str(td_path / "temp_onefile"))
            with mock.patch.dict(sg_paths.__dict__, {"__compiled__": temp_fallback}), \
                 mock.patch.dict(os.environ, {"NUITKA_ONEFILE_PARENT": str(os.getpid())}):
                resolved_parent = sg_paths.get_project_root()
                self.assertEqual(resolved_parent, sg_paths._query_process_dir_win32(os.getpid()))
                self.assertNotEqual(resolved_parent, (td_path / "temp_onefile").resolve())

            # 7. Dataset JSON is read-only in app; only file metadata and reload are exposed
            with mock.patch("sentinelgate.core.storage.get_workspace_data_dir", return_value=data_dir), \
                 mock.patch("sentinelgate.core.storage.get_app_data_dir", return_value=app_dir):
                app, tok = create_app(session_token="json-editor-tok")
                client = app.test_client()
                r_manifest = client.get("/api/storage/files", headers={"X-SG-Token": tok})
                self.assertEqual(r_manifest.status_code, 200)
                self.assertIn("search_blocklist.json", [x["name"] for x in r_manifest.get_json()["files"]])
                r_reload = client.post("/api/storage/reload", headers={"X-SG-Token": tok})
                self.assertEqual(r_reload.status_code, 200)
                r_save = client.post("/api/storage/json/dns_blocklist.json", json={"content": "{}"}, headers={"X-SG-Token": tok})
                self.assertEqual(r_save.status_code, 404)

                ui_html = client.get("/").get_data(as_text=True)
                self.assertIn("view-jsoneditor", ui_html)
                self.assertNotIn("saveJsonEditorFile", ui_html)

    def test_worker_relay_js_auth_and_block_only_rules(self) -> None:
        import json
        import shutil
        import subprocess

        root = Path(__file__).resolve().parent.parent
        worker_js = root / "worker" / "sentinelgate-relay.js"
        self.assertTrue(worker_js.exists())
        self.assertTrue((root / "worker" / "wrangler.toml").exists())
        self.assertTrue((root / "worker" / "setup-worker.ps1").exists())
        self.assertTrue((root / "worker" / "README.md").exists())
        self.assertTrue((root / ".env.example").exists())

        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js not available for executing worker JS tests")

        harness = r"""
import assert from "node:assert/strict";
import worker from %WORKER_URI%;

const ENV = {
  CF_ACCOUNT_ID: "acct-secret-123",
  CF_API_TOKEN: "tok-secret-456",
  RELAY_CLIENT_SECRET: "relay-sec-789",
};

const UPSTREAM_RULES = [
  { id: "11111111-1111-1111-1111-111111111111", name: "automated_http_search_block_p1", action: "block", enabled: true },
  { id: "22222222-2222-2222-2222-222222222222", name: "automated_http_search_block_p2", action: "block", enabled: true },
];

globalThis.fetch = async (url, init = {}) => {
  assert(url.includes("api.cloudflare.com/client/v4/accounts/acct-secret-123/gateway"));
  assert.equal(init.headers?.Authorization, "Bearer tok-secret-456");
  if (url.includes("/rules?per_page=100") && (init.method || "GET") === "GET") {
    return new Response(JSON.stringify({ success: true, result: UPSTREAM_RULES }), { status: 200 });
  }
  if (url.includes("/lists?per_page=100")) {
    return new Response(JSON.stringify({ success: true, result: [{ id: "33333333-3333-3333-3333-333333333333", name: "Proxies+block" }] }), { status: 200 });
  }
  return new Response(JSON.stringify({ success: true, result: { id: "ok" } }), { status: 200 });
};

// 1. Missing or invalid relay secret -> 401
let r = await worker.fetch(new Request("https://w.example/v1/health"), ENV);
assert.equal(r.status, 401);
r = await worker.fetch(new Request("https://w.example/v1/health", { headers: { "X-SG-Relay-Key": "wrong" } }), ENV);
assert.equal(r.status, 401);

// 2. Valid health check returns counts and NEVER exposes CF keys
r = await worker.fetch(new Request("https://w.example/v1/health", { headers: { "X-SG-Relay-Key": "relay-sec-789" } }), ENV);
assert.equal(r.status, 200);
const h = await r.json();
assert.equal(h.ok, true);
assert.equal(h.rule_count, 2);
assert.equal(h.list_count, 1);

// 3. Block-only / append-only enforcement -> 403 on allow, disable, list remove, or primary rule delete
for (const [method, path, body] of [
  ["POST", "/v1/lists", { name: "x", type: "IP" }],
  ["PATCH", "/v1/lists/33333333-3333-3333-3333-333333333333", { remove: [{ value: "x.com" }] }],
  ["POST", "/v1/rules", { name: "bypass", action: "allow", enabled: true }],
  ["PUT", "/v1/rules/11111111-1111-1111-1111-111111111111", { action: "block", enabled: false }],
  ["DELETE", "/v1/rules/11111111-1111-1111-1111-111111111111", null],
]) {
  const req = new Request(`https://w.example${path}`, {
    method,
    headers: { "X-SG-Relay-Key": "relay-sec-789", "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const res = await worker.fetch(req, ENV);
  assert.equal(res.status, 403, `Expected 403 for ${method} ${path}`);
}

// 4. Appends remain allowed; even trailing policy deletion is permanently blocked
r = await worker.fetch(new Request("https://w.example/v1/lists/33333333-3333-3333-3333-333333333333", {
  method: "PATCH",
  headers: { "X-SG-Relay-Key": "relay-sec-789", "Content-Type": "application/json" },
  body: JSON.stringify({ append: [{ value: "bad.example" }] }),
}), ENV);
assert.equal(r.status, 200);

r = await worker.fetch(new Request("https://w.example/v1/rules/22222222-2222-2222-2222-222222222222", {
  method: "DELETE",
  headers: { "X-SG-Relay-Key": "relay-sec-789" },
}), ENV);
assert.equal(r.status, 403);
console.log("WORKER_JS_OK");
""".replace("%WORKER_URI%", json.dumps(worker_js.as_uri()))

        proc = subprocess.run(
            [node_bin, "--input-type=module", "-e", harness],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f"Node Worker test failed:\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("WORKER_JS_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
