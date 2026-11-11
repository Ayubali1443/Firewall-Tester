# SentinelGate AI — Zero-Token Cloudflare Worker Relay Setup Guide

Deploying the Cloudflare Worker relay is the **only way to guarantee that `ACCOUNT_ID` and `API_TOKEN` never exist anywhere on end-user computers** — not on disk, not inside `SentinelGateAI.exe`, not inside `sg_seal.dll`, and not in process memory.

The desktop app stores the Worker URL (`WORKER_URL`) and app-to-Worker shared key (`RELAY_CLIENT_SECRET`) in its per-user Windows DPAPI vault. Both can be edited in **API Vault & Security** without rebuilding the app. The Cloudflare API token is configured only as a Cloudflare Worker Secret.

---

## Security Properties Enforced by the Relay (`worker/sentinelgate-relay.js`)

Even if an attacker inspects a client computer, the real Cloudflare API credentials live solely inside Cloudflare's encrypted Worker runtime secrets:

1. **Zero Cloudflare keys on client PCs:** `CF_ACCOUNT_ID` and `CF_API_TOKEN` never leave Cloudflare infrastructure.
2. **Constant-time client auth (`X-SG-Relay-Key`):** Every route rejects missing or wrong relay keys with `401 Unauthorized`.
3. **Server-side Block-Only Policy Firewall (`403 Forbidden`):**
   - `POST /v1/lists`: permits only `type: "DOMAIN"` (Cloudflare Zero Trust Gateway domain/hostname lists).
   - `PATCH /v1/lists/:id`: **append-only** (forbids `remove` or overwriting `items`).
   - `PUT /v1/lists/:id`: accepts only an `append` array and maps it to Cloudflare's append-only `PATCH`. Cloudflare's native list `PUT` replaces a nonempty `items` array, so replacement payloads are never forwarded.
   - `POST /v1/rules` & `PUT /v1/rules/:id`: enforces `action === "block"` and `enabled === true` (blocks creating `allow` rules or disabling policies).
   - Every `DELETE` request under `/v1/rules` or `/v1/lists` is rejected with `403`, including encoded paths, primary policies, trailing shards, lists, and list items. The relay never forwards a delete operation to Cloudflare.
4. **Client transport:** The app uses HTTPS with environment proxy overrides disabled. The Worker URL is user-configurable in the app; the Cloudflare API token remains exclusively in the Worker runtime.

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

### Updating Worker Code After Initial Setup

For later code-only changes to `sentinelgate-relay.js`, use the update script instead of rerunning the first-time setup. It checks the live relay, runs a JavaScript syntax check and Wrangler dry run, deploys without changing Worker secrets, then verifies health and that policy/list/item DELETE requests return `403`. If post-deploy checks fail, it attempts to roll back to the prior Worker version.

From the repository root:

```powershell
.\worker\deploy-worker-update.ps1 -DryRun
.\worker\deploy-worker-update.ps1
```

The dry run does not deploy. The second command publishes the code update. Neither command creates, edits, or deletes Cloudflare policies, lists, or list items. For changes to `.env` secrets or first-time setup, use `setup-worker.ps1` instead.

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

After deploying the Worker, set `WORKER_URL` and `RELAY_CLIENT_SECRET` in **API Vault & Security** in the app. `.env` is only needed for the Worker setup script; the installer build does not embed or require relay settings.

```powershell
.\.venv\Scripts\python.exe build.py
```

`build.py` builds the installer without Worker credentials. Installed users configure or update their Worker URL and relay client key in the app without rebuilding.

When users install `SentinelGateAI-Setup.exe`, they configure the Worker URL, relay client key, and optional Gemini keys inside the app UI (stored per-user via Windows DPAPI).

---

## Rotating Keys Later

- **Rotate Cloudflare `API_TOKEN`:** Create a new least-privilege token in Cloudflare, update the `CF_API_TOKEN` Worker Secret in the Cloudflare dashboard, verify the relay, then revoke the old token. Existing apps continue working; no source access or rebuild is needed.
- **Rotate `RELAY_CLIENT_SECRET`:** Update the Worker Secret in the Cloudflare dashboard, then enter the matching value in each app's **API Vault & Security** settings. No rebuild is needed.
