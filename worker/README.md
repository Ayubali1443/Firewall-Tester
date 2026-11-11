# SentinelGate AI — Zero-Token Cloudflare Worker Relay

Deploying this Worker ensures your `CF_ACCOUNT_ID` and `CF_API_TOKEN` **never exist on the client PC** at all — not on disk, not in the compiled `.exe`, and not in memory.

## Deployment

```powershell
cd worker
npx wrangler deploy
npx wrangler secret put CF_ACCOUNT_ID
npx wrangler secret put CF_API_TOKEN
npx wrangler secret put RELAY_CLIENT_SECRET
```

Then compile the desktop application in Zero-Token Worker Mode:

```powershell
$env:SG_WORKER_URL="https://sentinelgate-relay.<your-subdomain>.workers.dev"
$env:SG_WORKER_TOKEN="<your RELAY_CLIENT_SECRET>"
python build.py --backend nuitka
```

## Server-Side Enforced Rules
- Rejects `allow` rules and `enabled: false` updates (`403`).
- Rejects list removals or overwrites (`append`-only `PATCH`).
- Blocks deleting `automated_block` or primary search rules (`403`).
- Never returns `CF_ACCOUNT_ID` or `CF_API_TOKEN` in any response.
