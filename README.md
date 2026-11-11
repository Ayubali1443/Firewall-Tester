# SentinelGate AI

Secondary Strict Web Filter & On-Demand AI Threat Hunter targeting web proxies, CGI proxies, software/media downloaders, and obscure adult slip-throughs beyond Cloudflare Zero Trust, Google SafeSearch, and OS Standard User software restrictions.

## Structure

- `sentinelgate/` — Unified desktop application package
  - `main.py` — PyWebView desktop shell (DevTools disabled) & authenticated local bridge
  - `server.py` — Token-protected Flask API & background job runner
  - `config/cf_secrets.py` — Native Rust WinHTTP secret sealing (`sg_seal.dll`) supporting **Zero-Token Worker Relay** mode (`CF_ACCOUNT_ID` and `CF_API_TOKEN` never touch client PCs), caller HMAC handshake, anti-debugger/hardware-breakpoint detection, `NO_PROXY` TLS with `HCCE_LOCAL_MACHINE` chain validation (blocks `CurrentUser\Root` MITM CAs), volatile heap zeroing, and native block-only policy enforcement
  - `config/vault.py` — Windows DPAPI (`CryptProtectData`) vault for editable AI (Gemini) API keys only
  - `core/regex_engine.py` — Exact retained `CHAR_MAP` obfuscator, dynamic chunker & Rust DFA check
  - `core/cleaner.py` — Skeleton clustering deduplicator & 800x virtual brute-forcer
  - `core/cloudflare.py` — Separated `CloudflareReadOnlyClient` & `CloudflarePolicyWriter` with Zero-Token Worker Relay + full Gateway limit & auto-sharding support
  - `core/gemini_agent.py` — On-demand Gemini slip-through threat hunter with model, key & saturation auto-stop
  - `core/storage.py` — Immutable baseline + DPAPI overlay append-only blocklist storage
  - `modules/pentester.py` — Block-only policy writer (DNS + Search Pentester)
  - `modules/uptester.py` — Strictly read-only block enforcement & essential baseline monitor
  - `validator/` — Rust `cf_validator` RE2 512KB DFA compiler check
  - `installer/` — Single-file per-user Rust Windows installer & uninstaller (`SentinelGateAI-Setup.exe`, zero admin required)
  - `ui/` — Embedded HTML/CSS/JS desktop interface
- `worker/` — **Zero-Token Cloudflare Worker Relay** (`sentinelgate-relay.js`, `wrangler.toml`, `setup-worker.ps1`, [`worker/README.md`](worker/README.md)) so Cloudflare API credentials never ship to client computers
- `data/` — Consolidated blocklists, uptime baselines, and cached test states
- `tests/` — Automated verification suite
- `build.py` — **The single build script**: live-tests the deployed Worker Relay, seals `WORKER_URL` + `RELAY_CLIENT_SECRET` into `sg_seal.dll`, compiles via Nuitka (`--onefile`), and produces `dist/SentinelGateAI-Setup.exe`
- `setup.ps1` — Developer dependency & environment installer (`.venv`, Python packages, Rust `cf_validator.exe`, tests)
- `clean.ps1` — Removes all regenerable dependencies, caches, and build artifacts

## Scripts

### 1. Clean & Reinstall Environment

```powershell
.\clean.ps1
.\setup.ps1
```

### 2. Deploy Zero-Token Worker Relay (Keeps Cloudflare Keys Off Client PCs)

See the full step-by-step setup guide at [`worker/README.md`](worker/README.md). Summary:

1. Put `ACCOUNT_ID` and a least-privilege `API_TOKEN` into root `.env` (used only when uploading encrypted Worker Secrets — never bundled into the client `.exe`).
2. Authenticate Wrangler and deploy the Worker Relay + push all secrets from `.env`:
   ```powershell
   npx wrangler login
   .\worker\setup-worker.ps1
   ```
   This deploys `worker/sentinelgate-relay.js`, uploads `CF_ACCOUNT_ID`, `CF_API_TOKEN`, and `RELAY_CLIENT_SECRET` as encrypted Cloudflare Worker Secrets, and saves `WORKER_URL` & `RELAY_CLIENT_SECRET` into `.env`.

### 3. Build Single-File Installer (`dist/SentinelGateAI-Setup.exe`)

There is one single build script ([`build.py`](build.py)) and it requires **no interactive prompts**. Once `WORKER_URL` and `RELAY_CLIENT_SECRET` are populated in `.env`, run:

```powershell
.\.venv\Scripts\python.exe build.py
```

Before compiling, `build.py` reads `WORKER_URL` and `RELAY_CLIENT_SECRET` from `.env`, live-tests `/v1/health` (and verifies unauthenticated callers get `401`), seals only the Worker Relay endpoint + relay key inside stripped native Rust WinHTTP machine code (`sg_seal.dll`) while leaving `ACCOUNT_ID` and `API_TOKEN` off client builds completely, compiles the desktop shell via Nuitka (`--onefile`), verifies no plaintext secrets exist in the output binary, and outputs `dist/SentinelGateAI-Setup.exe` (zero admin privileges needed). The **Gemini AI API key** is requested only after opening SentinelGate AI and saved per-user in Windows DPAPI.

### 4. Installing, Editing JSONs & Uninstalling

- **Install**: Run `dist\SentinelGateAI-Setup.exe`. It installs `SentinelGateAI.exe` and `Uninstall.exe` to `%LOCALAPPDATA%\Programs\SentinelGateAI`, initializes `%LOCALAPPDATA%\Programs\SentinelGateAI\data\*.json`, ensures WebView2 Runtime is available, creates Desktop & Start Menu shortcuts (including **Uninstall SentinelGate AI**), and registers standard **Windows Installed Apps** uninstall metadata.
- **Edit JSON Files in Production**: Use the built-in **JSON Files Editor** tab inside SentinelGate AI, or open `%LOCALAPPDATA%\Programs\SentinelGateAI\data\` in Explorer (**API Vault & Security → Open JSON Data Folder**) to edit `dns_blocklist.json`, `search_blocklist.json`, `dns_uptime_sites.json`, or `search_uptime_terms.json`. Adding items enables them immediately; deleting entries from JSON never removes existing blocks from Cloudflare.
- **Uninstall**: Uninstall anytime via **Windows Settings → Apps → Installed apps → SentinelGate AI → Uninstall**, via the Start Menu **Uninstall SentinelGate AI** shortcut, or by running:
  ```powershell
  "%LOCALAPPDATA%\Programs\SentinelGateAI\Uninstall.exe" --uninstall
  ```

## Running from Source & Tests

```powershell
.\.venv\Scripts\python.exe -m sentinelgate.main
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

