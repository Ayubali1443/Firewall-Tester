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

## Single-File Installer & Setup Scripts

- **Build ONE self-contained Windows Setup file (`dist/SentinelGateAI-Setup.exe`)** embedding the desktop app, UI, Python runtime, Rust `cf_validator.exe`, and sealed Rust `sg_seal.dll` (requires no Python/Rust on target PCs):
  ```powershell
  .\setup.ps1 -BuildSetup -SkipCredentials
  ```
  When run interactively, `SentinelGateAI-Setup.exe` prompts for Windows Administrator elevation (UAC), asks for **Cloudflare API** + **Gemini AI API** credentials, encrypts Cloudflare credentials via Windows Machine DPAPI + HKLM entropy, and locks `%ProgramData%\SentinelGateAI\AdminLock` and `HKLM\SOFTWARE\SentinelGateAI` exclusively to `SYSTEM` and `BUILTIN\Administrators` so standard/unelevated desktop users cannot access Cloudflare API.
- **Reinstall dev environment & configure Admin-locked credentials (auto-installs Python/Rust if missing, creates `.venv`, compiles `cf_validator.exe`, runs tests, prompts via UAC for Cloudflare + Gemini APIs)**:
  ```powershell
  .\setup.ps1
  ```
  *(Pass `-SkipCredentials` for unattended developer setup without credential prompts.)*
- **Clean all regenerable dependencies & build artifacts (production Git prep)**:
  ```powershell
  .\clean.ps1
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
