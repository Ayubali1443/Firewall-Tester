# SentinelGate AI — Zero-Token Cloudflare Worker Relay Setup Guide

Deploying the Cloudflare Worker relay is the **only way to guarantee that `ACCOUNT_ID` and `API_TOKEN` never exist anywhere on end-user computers** — not on disk, not inside `SentinelGateAI.exe`, not inside `sg_seal.dll`, and not in process memory.

Only the Worker URL (`WORKER_URL`) and a server-restricted shared key (`RELAY_CLIENT_SECRET`) are sealed into the desktop binary.

---

## Security Properties Enforced by the Relay (`worker/sentinelgate-relay.js`)

Even if an attacker inspects a client computer, the real Cloudflare API credentials live solely inside Cloudflare's encrypted Worker runtime secrets:

1. **Zero Cloudflare keys on client PCs:** `CF_ACCOUNT_ID` and `CF_API_TOKEN` never leave Cloudflare infrastructure.
2. **Constant-time client auth (`X-SG-Relay-Key`):** Every route rejects missing or wrong relay keys with `401 Unauthorized`.
3. **Server-side Block-Only Policy Firewall (`403 Forbidden`):**
   - `POST /v1/lists`: permits only `type: "DOMAIN"` (Cloudflare Zero Trust Gateway domain lists).
   - `PATCH /v1/lists/:id`: **append-only** (forbids `remove` or overwriting `items`).
   - `POST /v1/rules` & `PUT /v1/rules/:id`: enforces `action === "block"` and `enabled === true` (blocks creating `allow` rules or disabling policies).
   - `DELETE /v1/rules/:id`: strictly blocked except removing trailing shard chunks (`automated_block_p2+` / `automated_http_search_block_p2+`) while an active primary `block` rule still exists.
4. **Native WinHTTP Transport Pinning (`sg_seal.dll`):** Compiled builds also seal `WORKER_URL` and `RELAY_CLIENT_SECRET` inside stripped native Rust code with `WINHTTP_ACCESS_TYPE_NO_PROXY`, `HCCE_LOCAL_MACHINE` TLS certificate-chain verification (ignoring user-added `CurrentUser\Root` MITM certificates), and `volatile_zero` memory clearing.

---

## Prerequisites

1. **Node.js 18+** (for `npx wrangler`) — verify with `node -v`.
2. **Cloudflare Zero Trust Account** + a **least-privilege API Token**:
   - In Cloudflare Dashboard -> **My Profile -> API Tokens -> Create Custom Token**:
     - Permissions:
       - `Account` -> `Zero Trust` -> `Edit`
       - `Account` -> `Account Settings` -> `Read` *(optional)*
     - Account Resources: Include -> your specific Cloudflare Account only.
     - **Do not** grant DNS zones, Billing, Workers Admin, or Account Admin permissions.
   - *(Recommended: if you previously tested or shared an older token in `.env` or chat, revoke it and create a fresh custom token now.)*

---

## Step 1: Configure Root `.env`

In the repository root, open `.env` (or copy `.env.example` to `.env`):

```dotenv
# Used ONLY when pushing encrypted Worker Secrets to Cloudflare (NEVER compiled into the desktop .exe)
ACCOUNT_ID="your-cloudflare-account-id"
API_TOKEN="your-scoped-cloudflare-zero-trust-api-token"

# Filled automatically by worker/setup-worker.ps1 (or set manually)
WORKER_URL="https://sentinelgate-relay.<your-subdomain>.workers.dev"
RELAY_CLIENT_SECRET="strong-random-relay-secret"
```

> Never commit `.env` to Git — `.env` is ignored by `.gitignore`.

---

## Step 2: Authenticate Wrangler & Deploy the Worker Relay

### Option A — Automated Deployment & `.env` Sync (Recommended)

1. Log in to Cloudflare once (opens browser OAuth):
   ```powershell
   npx wrangler login
   ```
2. Run the helper script from the project root — it deploys `worker/sentinelgate-relay.js`, generates `RELAY_CLIENT_SECRET` in `.env` if blank, captures your deployed `WORKER_URL` into `.env`, and pushes all 3 encrypted secrets directly from `.env`:
   ```powershell
   .\worker\setup-worker.ps1
   ```

### Option B — Manual Wrangler Commands

```powershell
cd worker
npx wrangler login
npx wrangler deploy

npx wrangler secret put CF_ACCOUNT_ID
npx wrangler secret put CF_API_TOKEN
npx wrangler secret put RELAY_CLIENT_SECRET
```

Then copy the deployed `https://sentinelgate-relay.<your-subdomain>.workers.dev` URL into `WORKER_URL` inside root `.env` (along with the same `RELAY_CLIENT_SECRET` you entered above).

---

## Step 3: Verify Worker Relay Live

Test from PowerShell (replace values with your `.env` values):

```powershell
# Should return 401 Unauthorized without key:
Invoke-WebRequest -Uri "https://sentinelgate-relay.<your-subdomain>.workers.dev/v1/health" -SkipHttpErrorCheck | Select-Object StatusCode

# Should return 200 OK with {"ok": true, "rule_count": ..., "list_count": ...}:
Invoke-RestMethod -Uri "https://sentinelgate-relay.<your-subdomain>.workers.dev/v1/health" -Headers @{ "X-SG-Relay-Key" = "<RELAY_CLIENT_SECRET>" }
```

---

## Step 4: Build the Zero-Token Desktop Installer

Once `WORKER_URL` and `RELAY_CLIENT_SECRET` are set in `.env`:

```powershell
.\.venv\Scripts\python.exe build.py
```

`build.py` automatically:
1. Reads `WORKER_URL` and `RELAY_CLIENT_SECRET` from `.env` (non-interactively).
2. Verifies live `/v1/health` authentication AND confirms unauthenticated requests return `401`.
3. Compiles native `sg_seal.dll` sealing **only** the Worker URL + relay key (`ACCOUNT_ID` and `API_TOKEN` are **never** included).
4. Builds `dist\SentinelGateAI-Setup.exe` and scans it to verify zero plaintext secrets exist in the output binary.

When users install `SentinelGateAI-Setup.exe`, SentinelGate AI prompts only for their **Gemini AI API key** inside the desktop app UI (stored per-user via Windows DPAPI).

---

## Rotating Keys Later

- **Rotate Cloudflare `API_TOKEN` (no client rebuild needed):** Create a new token in Cloudflare, update `API_TOKEN` in `.env`, run `npx wrangler secret put CF_API_TOKEN` inside `worker/`, and revoke the old token. Existing installed desktop apps keep working seamlessly!
- **Rotate `RELAY_CLIENT_SECRET` (invalidates old installers):** Generate a new `RELAY_CLIENT_SECRET` in `.env`, push it to the Worker (`npx wrangler secret put RELAY_CLIENT_SECRET`), rebuild `build.py`, and redistribute `SentinelGateAI-Setup.exe`.
