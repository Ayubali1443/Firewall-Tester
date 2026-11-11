"""Automated security, core regex logic, storage, vault, and API endpoint tests for SentinelGate AI."""

from __future__ import annotations

import re
import tempfile
import types
from pathlib import Path
import unittest

from sentinelgate.config.cf_secrets import seal_to_module_source, unseal_from_module
from sentinelgate.config.vault import ApiKeyVault, dpapi_protect, dpapi_unprotect, mask_secret
from sentinelgate.core.cleaner import clean_category, get_skeleton, run_virtual_pentest_for_terms
from sentinelgate.core.cloudflare import CloudflareReadOnlyClient
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

    def test_sealed_cloudflare_obfuscation_and_redaction(self) -> None:
        fake_acct = "acct_9876543210fedcba9876543210fedcba"
        fake_tok = "cf_secret_token_ABC123XYZ789_very_sensitive"
        src = seal_to_module_source(fake_acct, fake_tok)
        self.assertNotIn(fake_acct, src)
        self.assertNotIn(fake_tok, src)

        mod = types.SimpleNamespace()
        exec(src, mod.__dict__)
        out_acct, out_tok = unseal_from_module(mod)
        self.assertEqual(out_acct, fake_acct)
        self.assertEqual(out_tok, fake_tok)

        ro = CloudflareReadOnlyClient(fake_acct, fake_tok)
        self.assertFalse(ro._session.trust_env)
        redacted = ro._redact(f"Error calling accounts/{fake_acct} with {fake_tok}")
        self.assertNotIn(fake_acct, redacted)
        self.assertNotIn(fake_tok, redacted)

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

        # Authenticated overview returns ok
        ov = client.get("/api/overview", headers={"X-SG-Token": token})
        self.assertEqual(ov.status_code, 200)
        ov_json = ov.get_json()
        self.assertTrue(ov_json["ok"])
        self.assertTrue(ov_json["integrity"]["block_only_enforced"])
        self.assertNotIn("CF_API_TOKEN", str(ov_json))
        self.assertNotIn("CF_ACCOUNT_ID", str(ov_json))

        # Cloudflare credentials cannot be edited or viewed via Vault API
        cf_edit = client.post(
            "/api/vault/update",
            json={"CF_API_TOKEN": "hack", "CF_ACCOUNT_ID": "hack"},
            headers={"X-SG-Token": token},
        )
        self.assertEqual(cf_edit.status_code, 403)

        # AI key can be checked via vault status without leaking CF metadata
        vs = client.get("/api/vault/status", headers={"X-SG-Token": token}).get_json()
        self.assertIn("cloudflare_sealed", vs)
        self.assertNotIn("CF_API_TOKEN", vs.get("keys", {}))
        self.assertNotIn("CF_ACCOUNT_ID", vs.get("keys", {}))

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


if __name__ == "__main__":
    unittest.main()
