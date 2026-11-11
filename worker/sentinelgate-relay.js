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

function getAppendPayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      Object.keys(body).length !== 1 || !Array.isArray(body.append)) return null;
  const append = [];
  for (const item of body.append) {
    if (!item || typeof item !== "object" || Array.isArray(item) ||
        typeof item.value !== "string" || !item.value.trim() ||
        Object.keys(item).some((key) => key !== "value" && key !== "description") ||
        (item.description !== undefined && typeof item.description !== "string")) return null;
    append.push({
      value: item.value.trim(),
      ...(item.description === undefined ? {} : { description: item.description }),
    });
  }
  return { append };
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

    // Deletion is permanently disabled for every policy, list, and list item.
    // Decode and normalize before checking so encoded or repeated separators do
    // not create an alternate route around this guard.
    let normalizedPath;
    try {
      normalizedPath = decodeURIComponent(path).replace(/\/{2,}/g, "/").replace(/\/+$/, "");
    } catch {
      return jsonResp({ success: false, error: "Malformed resource path." }, 400);
    }
    const protectedResourcePath = /^\/v1\/(?:rules|lists)(?:\/|$)/i.test(normalizedPath);
    if (method === "DELETE" && protectedResourcePath) {
      return jsonResp({ success: false, error: "Policy, list, and list-item deletion is permanently disabled." }, 403);
    }

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
      const appendPayload = getAppendPayload(parsed.body);
      if (!appendPayload) {
        return jsonResp({ success: false, error: "Only append operations are permitted." }, 403);
      }
      return cfFetch(env, `/lists/${listMatch[1]}`, {
        method: "PATCH",
        body: JSON.stringify(appendPayload),
      });
    }

    // App-facing PUT is an append operation. Cloudflare's list PUT replaces
    // items, so translate only this strict append payload to its atomic PATCH.
    if (method === "PUT" && listMatch) {
      const parsed = await readJsonSafe(request);
      if (!parsed.ok) return jsonResp({ success: false, error: "Invalid JSON payload." }, 400);
      const appendPayload = getAppendPayload(parsed.body);
      if (!appendPayload) {
        return jsonResp({ success: false, error: "PUT accepts only an append array; existing list items are preserved." }, 403);
      }
      return cfFetch(env, `/lists/${listMatch[1]}`, {
        method: "PATCH",
        body: JSON.stringify(appendPayload),
      });
    }

    if (method === "PUT" && /^\/v1\/lists(?:\/|$)/i.test(normalizedPath)) {
      return jsonResp({ success: false, error: "Unsupported list route." }, 404);
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

    return jsonResp({ success: false, error: "Unsupported relay route." }, 404);
  },
};
