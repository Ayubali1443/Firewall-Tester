# SentinelGate AI

Secondary Strict Web Filter & On-Demand AI Threat Hunter targeting web proxies, CGI proxies, software/media downloaders, and obscure adult slip-throughs beyond Cloudflare Zero Trust, Google SafeSearch, and OS Standard User software restrictions.

## Structure

- `sentinelgate/` — Unified desktop application package
  - `main.py` — PyWebView desktop shell (DevTools disabled) & authenticated local bridge
  - `server.py` — Token-protected Flask API & background job runner
  - `config/cf_secrets.py` — Compile-time multi-layer secret sealing for immutable Cloudflare credentials
  - `config/vault.py` — Windows DPAPI (`CryptProtectData`) vault for editable AI (Gemini) API keys only
  - `core/regex_engine.py` — Exact retained `CHAR_MAP` obfuscator, dynamic chunker & Rust DFA check
  - `core/cleaner.py` — Skeleton clustering deduplicator & 800x virtual brute-forcer
  - `core/cloudflare.py` — Separated `CloudflareReadOnlyClient` & `CloudflarePolicyWriter`
  - `core/gemini_agent.py` — On-demand Gemini slip-through threat hunter with model & backup-key failover
  - `core/storage.py` — Immutable baseline + DPAPI overlay append-only blocklist storage
  - `modules/pentester.py` — Block-only policy writer (DNS + Search Pentester)
  - `modules/uptester.py` — Strictly read-only block enforcement & essential baseline monitor
  - `validator/` — Rust `cf_validator` RE2 512KB DFA compiler check
  - `ui/` — Embedded HTML/CSS/JS desktop interface
- `data/` — Consolidated blocklists, uptime baselines, and cached test states
- `tests/` — Automated verification suite
- `build.py` — Native executable compiler (`SentinelGateAI.exe` via Nuitka / PyInstaller)

## Clean & Reinstall Scripts

- **Clean all regenerable dependencies & build artifacts (production prep)**:
  ```powershell
  .\clean.ps1
  ```
- **Reinstall `.venv`, compile Rust `cf_validator.exe`, and run tests**:
  ```powershell
  .\setup.ps1
  ```
- **Full clean install + production `.exe` compile**:
  ```powershell
  .\setup.ps1 -BuildExe
  ```

## Running from Source

```powershell
python -m sentinelgate.main
```

## Running Tests

```powershell
python -m unittest discover -s tests -v
```

## Compiling Tamper-Proof Desktop Binary

Set `CF_ACCOUNT_ID` and `CF_API_TOKEN` in your build environment (or enter them when prompted by `build.py`), then compile:

```powershell
python build.py --backend nuitka
```

`build.py` seals the Cloudflare credentials into obfuscated integer tables compiled natively into machine code inside `dist/SentinelGateAI.exe` and removes all transient secret files from disk. Only Gemini AI API keys remain editable at runtime.
