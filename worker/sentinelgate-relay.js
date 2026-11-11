/**
 * SentinelGate AI — Zero-Token Cloudflare Gateway Relay Worker
 *
 * Keeps CF_ACCOUNT_ID and CF_API_TOKEN strictly in Cloudflare Worker Secrets
 * so they NEVER exist on client PCs, inside the desktop binary, or in RAM.
 *
 * Required Worker Secrets (push from `.env` via `setup-worker.ps1` or `wrangler secret put`):
 *   - CF_ACCOUNT_ID
 *   - CF_API_TOKEN
 *   - RELAY_CLIENT_SECRET
 */

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) {
    diff |= ab[i] ^ bb[i];
  }
  return diff === 0;
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function readJsonSafe(request) {
  try {
    return { ok: true, body: await request.json() };
  } catch {
    return { ok: false, body: null };
  }
}

async function cfFetch(env, path, init = {}) {
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/gateway${path}`;
  const headers = {
    Authorization: `Bearer ${env.CF_API_TOKEN}`,
    "Content-Type": "application/json",
  };
  const res = await fetch(url, { ...init, headers });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return jsonResp({ success: false, errors: [{ message: "Upstream Cloudflare parse error" }] }, 502);
  }
  return jsonResp(parsed, res.status);
}

export default {
  async fetch(request, env) {
    if (!env.CF_ACCOUNT_ID || !env.CF_API_TOKEN || !env.RELAY_CLIENT_SECRET) {
      return jsonResp({ success: false, error: "Relay secrets not configured on Worker." }, 500);
    }

    const supplied = request.headers.get("X-SG-Relay-Key") || "";
    if (!timingSafeEqual(supplied, env.RELAY_CLIENT_SECRET)) {
      return jsonResp({ success: false, error: "Unauthorized." }, 401);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (method === "GET" && path === "/v1/health") {
      const rulesRes = await cfFetch(env, "/rules?per_page=100", { method: "GET" });
      const rulesData = await rulesRes.json();
      if (rulesRes.status === 200 && rulesData.success) {
        const listsRes = await cfFetch(env, "/lists?per_page=100", { method: "GET" });
        const listsData = listsRes.status === 200 ? await listsRes.json() : { result: [] };
        return jsonResp({
          ok: true,
          rule_count: (rulesData.result || []).length,
          list_count: (listsData.result || []).length,
        });
      }
      return jsonResp({ ok: false, error: "Upstream Gateway check failed." }, 502);
    }

    if (method === "GET" && path === "/v1/lists") {
      return cfFetch(env, `/lists${url.search || ""}`, { method: "GET" });
    }

    const listMatch = path.match(/^\/v1\/lists\/([a-f0-9-]{36})$/);
    if (method === "GET" && listMatch) {
      return cfFetch(env, `/lists/${listMatch[1]}`, { method: "GET" });
    }

    if (method === "POST" && path === "/v1/lists") {
      const parsed = await readJsonSafe(request);
      if (!parsed.ok) return jsonResp({ success: false, error: "Invalid JSON payload." }, 400);
      const body = parsed.body;
      if (body?.type !== "DOMAIN") {
        return jsonResp({ success: false, error: "Only DOMAIN lists are permitted." }, 403);
      }
      return cfFetch(env, "/lists", { method: "POST", body: JSON.stringify(body) });
    }

    if (method === "PATCH" && listMatch) {
      const parsed = await readJsonSafe(request);
      if (!parsed.ok) return jsonResp({ success: false, error: "Invalid JSON payload." }, 400);
      const body = parsed.body;
      // Strictly append-only: forbid removing or overwriting existing blocked items
      if (!Array.isArray(body?.append) || body?.remove || body?.items) {
        return jsonResp({ success: false, error: "Only append operations are permitted." }, 403);
      }
      return cfFetch(env, `/lists/${listMatch[1]}`, {
        method: "PATCH",
        body: JSON.stringify({ append: body.append }),
      });
    }

    if (method === "GET" && path === "/v1/rules") {
      return cfFetch(env, `/rules${url.search || ""}`, { method: "GET" });
    }

    if (method === "POST" && path === "/v1/rules") {
      const parsed = await readJsonSafe(request);
      if (!parsed.ok) return jsonResp({ success: false, error: "Invalid JSON payload." }, 400);
      const body = parsed.body;
      if (body?.action !== "block" || body?.enabled !== true) {
        return jsonResp({ success: false, error: "Only enabled block rules are permitted." }, 403);
      }
      return cfFetch(env, "/rules", { method: "POST", body: JSON.stringify(body) });
    }

    const ruleMatch = path.match(/^\/v1\/rules\/([a-f0-9-]{36})$/);
    if (method === "PUT" && ruleMatch) {
      const parsed = await readJsonSafe(request);
      if (!parsed.ok) return jsonResp({ success: false, error: "Invalid JSON payload." }, 400);
      const body = parsed.body;
      if (body?.action !== "block" || body?.enabled !== true) {
        return jsonResp({ success: false, error: "Only enabled block rules are permitted." }, 403);
      }
      return cfFetch(env, `/rules/${ruleMatch[1]}`, { method: "PUT", body: JSON.stringify(body) });
    }

    if (method === "DELETE" && ruleMatch) {
      // Allow removing ONLY trailing split chunks during regex/DNS consolidation
      // AND only when an active primary block rule remains enabled
      const allRulesRes = await cfFetch(env, "/rules?per_page=100", { method: "GET" });
      const allRules = (await allRulesRes.json())?.result || [];
      const targetRule = allRules.find((r) => r.id === ruleMatch[1]);
      const ruleName = targetRule?.name || "";
      const isTrailingSearch = /^automated_http_search_block_p([2-9]|[1-9]\d+)$/.test(ruleName);
      const isTrailingDns = /^automated_block_p([2-9]|[1-9]\d+)$/.test(ruleName);
      if (!isTrailingSearch && !isTrailingDns) {
        return jsonResp({ success: false, error: "Policy deletion is prohibited." }, 403);
      }
      const primaryPrefix = isTrailingSearch ? "automated_http_search_block" : "automated_block";
      const hasPrimaryBlock = allRules.some(
        (r) =>
          r.id !== ruleMatch[1] &&
          r.enabled === true &&
          r.action === "block" &&
          (r.name === primaryPrefix || r.name === `${primaryPrefix}_p1`)
      );
      if (!hasPrimaryBlock) {
        return jsonResp(
          { success: false, error: "Cannot delete trailing chunk without an active primary block rule." },
          403
        );
      }
      return cfFetch(env, `/rules/${ruleMatch[1]}`, { method: "DELETE" });
    }

    return jsonResp({ success: false, error: "Unsupported relay route." }, 404);
  },
};
