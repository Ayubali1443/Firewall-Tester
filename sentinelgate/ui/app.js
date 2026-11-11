// SentinelGate AI Desktop UI Controller (Strict Tamper-Proof & Block-Only)

const VIEW_META = {
  dashboard: ["Command Center", "Real-time posture, Cloudflare policy sync status, and slip-through enforcement"],
  autonomous: ["Full Autonomous Pipeline & Final Reports", "Unattended multi-hour 3-stage blocking, verification, and false-positive reporting"],
  dns: ["DNS Domain Shield", "Pentester module: append-only blocklists, DNS/HTTPS penetration tests, and Cloudflare sync"],
  search: ["Search & Regex Engine", "Pentester module: RE2 obfuscation, Rust 512KB DFA validation, chunking & brute-force testing"],
  ai: ["AI Slip-Through Hunter", "On-demand Gemini threat agent focused strictly on proxies, downloaders & obscure adult slip-throughs"],
  uptester: ["Uptester Monitor (Read-Only)", "Strictly read-only verification of necessary blocks and essential daily uptime baselines"],
  settings: ["API Vault & Security", "Windows DPAPI encrypted credential management and tamper-proof architecture diagnostics"]
};

let dnsCategoriesCache = [];
let searchCategoriesCache = [];
let lastDnsRemediationMap = {};
let activeJobId = null;
let activeJobSince = 0;
let jobPollTimer = null;

// Harden shell against casual DevTools inspection
document.addEventListener("contextmenu", (e) => e.preventDefault());
document.addEventListener("keydown", (e) => {
  if (
    e.key === "F12" ||
    (e.ctrlKey && e.shiftKey && ["I", "i", "J", "j", "C", "c"].includes(e.key)) ||
    (e.ctrlKey && ["U", "u"].includes(e.key))
  ) {
    e.preventDefault();
  }
});

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign(
    {
      "Content-Type": "application/json",
      "X-SG-Token": window.__SG_TOKEN__ || ""
    },
    options.headers || {}
  );
  const res = await fetch(path, Object.assign({}, options, { headers }));
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

function switchView(viewId) {
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === viewId);
  });
  document.querySelectorAll(".view").forEach((v) => {
    v.classList.toggle("active", v.id === `view-${viewId}`);
  });
  const meta = VIEW_META[viewId] || ["SentinelGate AI", ""];
  document.getElementById("page-title").textContent = meta[0];
  document.getElementById("page-subtitle").textContent = meta[1];

  if (viewId === "dashboard") refreshOverview();
  if (viewId === "autonomous") loadReportsList();
  if (viewId === "dns") loadDnsDatasets();
  if (viewId === "search") loadSearchDatasets();
  if (viewId === "ai") populateAiCategories();
  if (viewId === "uptester") loadUptesterDatasets();
  if (viewId === "settings") refreshVaultAndSecurity();
}

document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

document.getElementById("real-test-mode").addEventListener("change", (e) => {
  document.getElementById("real-test-custom-wrap").classList.toggle("hidden", e.target.value !== "custom");
});

function setFeedback(elId, msg, isOk) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.className = `feedback ${isOk ? "ok" : "err"}`;
}

// --- Overview ---
async function refreshOverview() {
  try {
    const data = await apiFetch("/api/overview");
    document.getElementById("kpi-dns-domains").textContent = data.stats.dns_domains;
    document.getElementById("kpi-dns-cats").textContent = `${data.stats.dns_categories} block categories`;
    document.getElementById("kpi-search-terms").textContent = data.stats.search_terms;
    document.getElementById("kpi-search-cats").textContent = `${data.stats.search_categories} block categories`;

    const cf = data.cloudflare || {};
    const searchRules = cf.search_rules || [];
    document.getElementById("kpi-cf-search-rules").textContent = searchRules.length;
    document.getElementById("kpi-cf-dns-rule").textContent = cf.dns_rule_active
      ? "DNS automated_block: ACTIVE"
      : "DNS automated_block: Inactive/Missing";

    const cfBadge = document.getElementById("cf-status-badge");
    if (cf.ready) {
      cfBadge.textContent = `Cloudflare Engine: Ready (${cf.total_gateway_rules || 0} Rules)`;
      cfBadge.className = "badge badge-ok";
    } else {
      cfBadge.textContent = "Cloudflare Engine: Offline";
      cfBadge.className = "badge badge-warn";
    }

    const rustBadge = document.getElementById("rust-status-badge");
    if (data.validator && data.validator.ok) {
      rustBadge.textContent = "Rust DFA: Verified";
      rustBadge.className = "badge badge-ok";
    } else {
      rustBadge.textContent = "Rust DFA: Warning";
      rustBadge.className = "badge badge-err";
    }

    const integ = data.integrity || {};
    const allOk = integ.dns_intact && integ.search_intact && integ.block_only_enforced;
    document.getElementById("kpi-integrity").textContent = allOk ? "VERIFIED" : "ALERT";
    document.getElementById("kpi-compiled-mode").textContent = integ.compiled_binary
      ? "Native Compiled Binary + DPAPI Overlay"
      : "Source Mode + Monotonic Baseline";

    const rulesBox = document.getElementById("cf-rules-list");
    if (!cf.ready) {
      rulesBox.innerHTML = `<div class="muted">Cloudflare Engine: Offline</div>`;
    } else {
      const items = [];
      items.push(`<div class="mini-row"><span><code>automated_block</code> (DNS)</span><span class="badge ${cf.dns_rule_active ? "badge-ok" : "badge-warn"}">${cf.dns_rule_active ? "ENABLED" : "NOT ACTIVE"}</span></div>`);
      for (const sr of searchRules) {
        items.push(`<div class="mini-row"><span><code>${escapeHtml(sr.name)}</code> (${sr.traffic_length}/4090 chars)</span><span class="badge ${sr.enabled ? "badge-ok" : "badge-warn"}">${escapeHtml(sr.action).toUpperCase()}</span></div>`);
      }
      if (searchRules.length === 0) {
        items.push(`<div class="muted">No automated_http_search_block rules deployed yet.</div>`);
      }
      rulesBox.innerHTML = items.join("");
    }

    const recentBox = document.getElementById("recent-jobs-list");
    const rj = data.recent_jobs || [];
    if (rj.length === 0) {
      recentBox.innerHTML = `<div class="muted">No operations executed yet in this session.</div>`;
    } else {
      recentBox.innerHTML = rj
        .map((j) => `<div class="mini-row"><span>${escapeHtml(j.title)}</span><span class="badge badge-${j.status === "completed" ? "ok" : j.status === "running" ? "running" : "warn"}">${escapeHtml(j.status).toUpperCase()}</span></div>`)
        .join("");
    }
  } catch (err) {
    appendConsoleLine(`[Overview Error] ${err.message}`);
  }
}

// --- DNS Shield ---
async function loadDnsDatasets() {
  const res = await apiFetch("/api/pentester/dns/datasets");
  dnsCategoriesCache = res.categories || [];

  const addSel = document.getElementById("dns-add-category");
  const testSel = document.getElementById("dns-test-category");
  const prevAdd = addSel.value;
  const prevTest = testSel.value;

  addSel.innerHTML = dnsCategoriesCache
    .map((c) => `<option value="${escapeHtml(c.list_id)}">${escapeHtml(c.list_id)} (${c.count})</option>`)
    .join("");
  testSel.innerHTML = `<option value="">All DNS Block Categories</option>` + dnsCategoriesCache
    .map((c) => `<option value="${escapeHtml(c.list_id)}">${escapeHtml(c.list_id)} (${c.count})</option>`)
    .join("");

  if (prevAdd) addSel.value = prevAdd;
  if (prevTest) testSel.value = prevTest;
  renderDnsCategories();
}

function renderDnsCategories() {
  const q = (document.getElementById("dns-filter-input").value || "").trim().toLowerCase();
  const container = document.getElementById("dns-categories-container");
  const filtered = dnsCategoriesCache.filter((c) => {
    if (!q) return true;
    return c.list_id.toLowerCase().includes(q) || c.domains.some((d) => d.toLowerCase().includes(q));
  });

  container.innerHTML = filtered
    .map((c) => {
      const shownDomains = q
        ? c.domains.filter((d) => d.toLowerCase().includes(q))
        : c.domains.slice(0, 60);
      const pills = shownDomains.map((d) => `<span class="item-pill">${escapeHtml(d)}</span>`).join("");
      const more = c.domains.length > shownDomains.length ? `<span class="item-pill">+${c.domains.length - shownDomains.length} more</span>` : "";
      return `
        <div class="cat-card">
          <div class="cat-card-top">
            <span class="cat-title">${escapeHtml(c.list_id)}</span>
            <span class="tag ${c.scope === "slip_through" ? "tag-cyan" : "tag-amber"}">${c.count} domains</span>
          </div>
          <div class="cat-desc">${escapeHtml(c.description || "Blocklist category")}</div>
          <div class="pill-wrap">${pills || '<span class="muted">No domains yet — run AI Hunter or add above.</span>'}${more}</div>
        </div>
      `;
    })
    .join("");
}

async function addDnsDomains() {
  const customCat = document.getElementById("dns-new-category").value.trim();
  const cat = customCat || document.getElementById("dns-add-category").value;
  const domainsText = document.getElementById("dns-add-input").value;
  try {
    const res = await apiFetch("/api/pentester/dns/add", {
      method: "POST",
      body: JSON.stringify({ category: cat, domains_text: domainsText, action: "block" })
    });
    setFeedback("dns-add-feedback", `Added ${res.added.length} domain(s) to ${res.list_id} (${res.skipped} already present).`, true);
    document.getElementById("dns-add-input").value = "";
    document.getElementById("dns-new-category").value = "";
    await loadDnsDatasets();
  } catch (err) {
    setFeedback("dns-add-feedback", err.message, false);
  }
}

async function runDnsPentest(fullTest) {
  const category = document.getElementById("dns-test-category").value;
  const autoRemediate = document.getElementById("dns-auto-remediate").checked;
  const res = await apiFetch("/api/pentester/dns/test", {
    method: "POST",
    body: JSON.stringify({ full_test: fullTest, category, auto_remediate: autoRemediate })
  });
  watchJob(res.job_id, (job) => {
    if (job.result && job.result.remediation_required && Object.keys(job.result.remediation_required).length > 0 && !job.result.policy_synced) {
      lastDnsRemediationMap = job.result.remediation_required;
      document.getElementById("btn-dns-remediate-last").classList.remove("hidden");
    } else {
      document.getElementById("btn-dns-remediate-last").classList.add("hidden");
    }
    loadDnsDatasets();
    refreshOverview();
  });
}

async function remediateLastDns() {
  const res = await apiFetch("/api/pentester/dns/remediate", {
    method: "POST",
    body: JSON.stringify({ remediation_map: lastDnsRemediationMap })
  });
  watchJob(res.job_id, () => {
    document.getElementById("btn-dns-remediate-last").classList.add("hidden");
    refreshOverview();
  });
}

// --- Search & Regex ---
async function loadSearchDatasets() {
  const res = await apiFetch("/api/pentester/search/datasets");
  searchCategoriesCache = res.categories || [];

  const addSel = document.getElementById("search-add-category");
  const testSel = document.getElementById("search-test-cat");
  const prevAdd = addSel.value;
  const prevTest = testSel.value;

  addSel.innerHTML = searchCategoriesCache
    .filter((c) => c.scope !== "legacy_os_managed")
    .map((c) => `<option value="${escapeHtml(c.list_id)}">${escapeHtml(c.list_id)} (${c.count})</option>`)
    .join("");
  testSel.innerHTML = `<option value="">All Categories</option>` + searchCategoriesCache
    .map((c) => `<option value="${escapeHtml(c.list_id)}">${escapeHtml(c.list_id)} (${c.count})</option>`)
    .join("");

  if (prevAdd) addSel.value = prevAdd;
  if (prevTest) testSel.value = prevTest;
  renderSearchCategories();
}

function renderSearchCategories() {
  const q = (document.getElementById("search-filter-input").value || "").trim().toLowerCase();
  const container = document.getElementById("search-categories-container");
  const filtered = searchCategoriesCache.filter((c) => {
    if (!q) return true;
    return c.list_id.toLowerCase().includes(q) || c.terms.some((t) => t.toLowerCase().includes(q));
  });

  container.innerHTML = filtered
    .map((c) => {
      const shown = q ? c.terms.filter((t) => t.toLowerCase().includes(q)) : c.terms.slice(0, 60);
      const pills = shown.map((t) => `<span class="item-pill">${escapeHtml(t)}</span>`).join("");
      const more = c.terms.length > shown.length ? `<span class="item-pill">+${c.terms.length - shown.length} more</span>` : "";
      const tagClass = c.scope === "legacy_os_managed" ? "tag-amber" : "tag-cyan";
      return `
        <div class="cat-card">
          <div class="cat-card-top">
            <span class="cat-title">${escapeHtml(c.list_id)}</span>
            <span class="tag ${tagClass}">${c.count} terms</span>
          </div>
          <div class="cat-desc">${escapeHtml(c.description || "")}</div>
          <div class="pill-wrap">${pills || '<span class="muted">No terms yet — run AI Hunter or add above.</span>'}${more}</div>
        </div>
      `;
    })
    .join("");
}

async function addSearchTerms() {
  const customCat = document.getElementById("search-new-category").value.trim();
  const cat = customCat || document.getElementById("search-add-category").value;
  const termsText = document.getElementById("search-add-input").value;
  try {
    const res = await apiFetch("/api/pentester/search/add", {
      method: "POST",
      body: JSON.stringify({ category: cat, terms_text: termsText, action: "block" })
    });
    setFeedback("search-add-feedback", `Added ${res.added.length} term(s) to ${res.list_id}. Click 'Compile Chunks & Sync' to deploy.`, true);
    document.getElementById("search-add-input").value = "";
    document.getElementById("search-new-category").value = "";
    await loadSearchDatasets();
  } catch (err) {
    setFeedback("search-add-feedback", err.message, false);
  }
}

async function runSkeletonCleanup() {
  try {
    const res = await apiFetch("/api/pentester/search/cleanup", { method: "POST" });
    setFeedback("search-add-feedback", `Skeleton cleanup complete: merged ${res.merged_count} redundant obfuscations (baseline preserved).`, true);
    await loadSearchDatasets();
  } catch (err) {
    setFeedback("search-add-feedback", err.message, false);
  }
}

async function triggerSearchSync() {
  const res = await apiFetch("/api/pentester/search/sync", { method: "POST" });
  watchJob(res.job_id, () => refreshOverview());
}

async function loadSearchChunks() {
  const res = await apiFetch("/api/pentester/search/chunks");
  const box = document.getElementById("chunks-preview-box");
  box.classList.remove("hidden");
  box.innerHTML = `
    <div><strong>Dynamic Chunk Packing:</strong> ${res.total_terms} unique base terms condensed into <strong>${res.chunk_count}</strong> Cloudflare HTTP rules (max 4090 chars &amp; 512KB Rust DFA).</div>
    ${res.chunks.map((ch) => `
      <div class="mini-row">
        <span>Part ${ch.part}: <strong>${ch.term_count}</strong> terms (${ch.traffic_length}/4090 chars)</span>
        <span class="muted">${escapeHtml(ch.sample_terms.join(", "))}...</span>
      </div>
    `).join("")}
  `;
}

async function previewRegexInspector() {
  const termsText = document.getElementById("regex-test-terms").value;
  const sampleQuery = document.getElementById("regex-sample-query").value;
  try {
    const res = await apiFetch("/api/pentester/search/preview-regex", {
      method: "POST",
      body: JSON.stringify({ terms_text: termsText, sample_query: sampleQuery })
    });
    const d = res.details;
    const matchBadge = res.sample_matched === null
      ? ""
      : `<span class="badge ${res.sample_matched ? "badge-ok" : "badge-err"}">Query Match: ${res.sample_matched ? "BLOCKED" : "MISSED"}</span>`;

    const box = document.getElementById("regex-inspector-output");
    box.classList.remove("hidden");
    box.innerHTML = `
      <div class="btn-row">
        <span class="badge ${d.within_char_limit ? "badge-ok" : "badge-err"}">Traffic Length: ${d.traffic_length} / ${d.max_traffic_length}</span>
        <span class="badge ${d.rust_dfa_ok ? "badge-ok" : "badge-err"}">Rust 512KB DFA: ${d.rust_dfa_ok === null ? "N/A" : d.rust_dfa_ok ? "PASS" : "EXCEEDED"}</span>
        <span class="badge ${d.python_re_ok ? "badge-ok" : "badge-err"}">RE2 Syntax: ${d.python_re_ok ? "VALID" : "ERROR"}</span>
        ${matchBadge}
      </div>
      <div><strong>Compiled Cloudflare Traffic Expression:</strong></div>
      <div class="mono-block">${escapeHtml(d.traffic_condition)}</div>
      <div><strong>Human Variations Preview (caught automatically):</strong></div>
      <div class="pill-wrap">${res.variations_sample.map((v) => `<span class="item-pill">${escapeHtml(v)}</span>`).join("")}</div>
    `;
  } catch (err) {
    appendConsoleLine(`[Regex Inspector] ${err.message}`);
  }
}

async function runVirtualPentest() {
  const listId = document.getElementById("search-test-cat").value;
  const res = await apiFetch("/api/pentester/search/virtual-test", {
    method: "POST",
    body: JSON.stringify({ list_id: listId, variants_per_term: 800 })
  });
  watchJob(res.job_id, (job) => {
    if (job.result && job.result.ok) {
      appendConsoleLine(`\n[Virtual Pentest Result] Tested ${job.result.total_tested} extreme variations -> Block Rate: ${job.result.block_rate}% (${job.result.bypass_count} bypasses).`);
      for (const bp of (job.result.bypasses || []).slice(0, 15)) {
        appendConsoleLine(`  - Base: ${bp.base} | Variant: '${bp.variant}'`);
      }
    }
  });
}

async function runRealSearchTest() {
  const mode = document.getElementById("real-test-mode").value;
  const category = document.getElementById("search-test-cat").value;
  const termsText = document.getElementById("real-test-custom").value;
  try {
    const res = await apiFetch("/api/pentester/search/real-test", {
      method: "POST",
      body: JSON.stringify({ mode, category, terms_text: termsText })
    });
    watchJob(res.job_id);
  } catch (err) {
    appendConsoleLine(`[Real Traffic Test Error] ${err.message}`);
  }
}

// --- AI Slip-Through Hunter ---
async function populateAiCategories() {
  const mode = document.getElementById("ai-mode").value;
  const sel = document.getElementById("ai-category");
  if (mode === "dns") {
    if (dnsCategoriesCache.length === 0) await loadDnsDatasets();
    const targets = dnsCategoriesCache.filter((c) => c.ai_target);
    sel.innerHTML = targets
      .map((c) => `<option value="${escapeHtml(c.list_id)}">${escapeHtml(c.list_id)} (${c.count} domains)</option>`)
      .join("");
  } else {
    if (searchCategoriesCache.length === 0) await loadSearchDatasets();
    const targets = searchCategoriesCache.filter((c) => c.ai_target && c.scope !== "legacy_os_managed");
    sel.innerHTML = targets
      .map((c) => `<option value="${escapeHtml(c.list_id)}">${escapeHtml(c.list_id)} (${c.count} terms)</option>`)
      .join("");
  }
}

async function discoverGeminiModels() {
  const res = await apiFetch("/api/ai/models", { method: "POST" });
  watchJob(res.job_id, (job) => {
    const models = (job.result && job.result.models) || [];
    const sel = document.getElementById("ai-model-select");
    const badges = document.getElementById("ai-models-badges");
    if (models.length === 0) {
      badges.innerHTML = `<span class="badge badge-err">No responsive Gemini models found. Verify API key in Vault.</span>`;
      return;
    }
    sel.innerHTML = models
      .map((m, idx) => `<option value="${escapeHtml(m)}">${idx === 0 ? "★ Best: " : ""}${escapeHtml(m.replace("models/", ""))}</option>`)
      .join("");
    badges.innerHTML = models
      .map((m) => `<span class="item-pill">${escapeHtml(m.replace("models/", ""))}</span>`)
      .join("");
  });
}

async function startAiHunt() {
  const mode = document.getElementById("ai-mode").value;
  const categoryKey = document.getElementById("ai-category").value;
  const durationMinutes = parseFloat(document.getElementById("ai-duration").value || "3");
  const maxIterations = parseInt(document.getElementById("ai-iterations").value || "5", 10);
  const autoDeploy = document.getElementById("ai-auto-deploy").checked;

  const sel = document.getElementById("ai-model-select");
  const allOptions = Array.from(sel.options).map((o) => o.value).filter(Boolean);
  const primary = sel.value;
  const queue = primary ? [primary, ...allOptions.filter((m) => m !== primary)] : allOptions;

  try {
    const res = await apiFetch("/api/ai/hunt", {
      method: "POST",
      body: JSON.stringify({
        mode,
        category_key: categoryKey,
        models: queue,
        duration_minutes: durationMinutes,
        max_iterations: maxIterations,
        auto_deploy: autoDeploy
      })
    });
    watchJob(res.job_id, () => {
      loadDnsDatasets();
      loadSearchDatasets();
      refreshOverview();
    });
  } catch (err) {
    appendConsoleLine(`[AI Hunt Error] ${err.message}`);
  }
}

// --- Uptester (Read-Only) ---
async function loadUptesterDatasets() {
  const res = await apiFetch("/api/uptester/datasets");
  const dnsSel = document.getElementById("uptester-dns-cat");
  const searchSel = document.getElementById("uptester-search-cat");

  dnsSel.innerHTML = `<option value="">All Essential DNS Categories</option>` +
    Object.keys(res.dns_uptime || {}).map((k) => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`).join("");
  searchSel.innerHTML = `<option value="">All Search Categories (25 sample)</option>` +
    Object.keys(res.search_uptime || {}).map((k) => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`).join("");
}

async function runUptesterBlockAudit() {
  const scope = document.getElementById("uptester-block-scope").value;
  const res = await apiFetch("/api/uptester/audit-blocks", {
    method: "POST",
    body: JSON.stringify({ scope })
  });
  watchJob(res.job_id, (job) => {
    const r = job.result || {};
    const box = document.getElementById("uptester-results-box");
    const slips = r.slip_throughs || [];
    box.innerHTML = `
      <div class="btn-row">
        <span class="badge badge-lock">Policy Modified: FALSE (Read-Only)</span>
        <span class="badge badge-ok">Enforced: ${r.enforced || 0}/${r.checked || 0}</span>
        <span class="badge ${slips.length ? "badge-err" : "badge-ok"}">Slip-Throughs Found: ${slips.length}</span>
      </div>
      ${slips.length ? `<div class="mini-list" style="margin-top:10px">${slips.map((s) => `<div class="mini-row"><span>[${escapeHtml(s.kind).toUpperCase()}] <code>${escapeHtml(s.item)}</code> (${escapeHtml(s.category)})</span><button class="btn btn-sm btn-warning" onclick="switchView('${s.kind === "dns" ? "dns" : "search"}')">Escalate to Pentester</button></div>`).join("")}</div>` : '<p class="muted" style="margin-top:8px">All audited critical slip-through targets are actively blocked.</p>'}
    `;
  });
}

async function runUptesterDnsBaseline(fullTest) {
  const category = document.getElementById("uptester-dns-cat").value;
  const res = await apiFetch("/api/uptester/dns-baseline", {
    method: "POST",
    body: JSON.stringify({ full_test: fullTest, category })
  });
  watchJob(res.job_id, (job) => {
    const r = job.result || {};
    const over = r.overblocked || [];
    document.getElementById("uptester-results-box").innerHTML = `
      <div class="btn-row">
        <span class="badge badge-lock">Policy Modified: FALSE (Read-Only)</span>
        <span class="badge badge-ok">Healthy Sites: ${r.healthy || 0}/${r.total || 0}</span>
        <span class="badge ${over.length ? "badge-warn" : "badge-ok"}">Blocked/Unreachable: ${over.length}</span>
      </div>
      ${over.length ? `<div class="mini-list" style="margin-top:10px">${over.map((o) => `<div class="mini-row"><span><code>${escapeHtml(o.domain)}</code> (${escapeHtml(o.category)})</span><span class="muted">${escapeHtml(o.reason)}</span></div>`).join("")}</div>` : ""}
    `;
  });
}

async function runUptesterSearchBaseline() {
  const category = document.getElementById("uptester-search-cat").value;
  const res = await apiFetch("/api/uptester/search-baseline", {
    method: "POST",
    body: JSON.stringify({ category, sample_limit: 25 })
  });
  watchJob(res.job_id, (job) => {
    const r = job.result || {};
    const bq = r.blocked_queries || [];
    document.getElementById("uptester-results-box").innerHTML = `
      <div class="btn-row">
        <span class="badge badge-lock">Policy Modified: FALSE (Read-Only)</span>
        <span class="badge badge-ok">Allowed Queries: ${r.healthy || 0}/${r.tested || 0}</span>
        <span class="badge ${bq.length ? "badge-warn" : "badge-ok"}">Blocked Queries: ${bq.length}</span>
      </div>
      ${bq.length ? `<div class="mini-list" style="margin-top:10px">${bq.map((q) => `<div class="mini-row"><span><code>${escapeHtml(q.term)}</code> (${escapeHtml(q.category)})</span><span class="badge badge-warn">${escapeHtml(q.status)}</span></div>`).join("")}</div>` : ""}
    `;
  });
}

// --- API Vault & Security Settings ---
async function refreshVaultAndSecurity() {
  const overview = await apiFetch("/api/overview");
  const v = overview.vault || {};
  const keys = v.keys || {};

  const setKeyUi = (inputId, badgeId, info) => {
    const inp = document.getElementById(inputId);
    const badge = document.getElementById(badgeId);
    inp.value = "";
    inp.placeholder = info && info.configured ? `Current: ${info.masked} (leave blank to keep)` : "Not configured — enter value...";
    badge.textContent = info && info.configured ? "CONFIGURED" : "MISSING";
    badge.style.color = info && info.configured ? "#6ee7b7" : "#fda4af";
  };

  setKeyUi("vault-gemini-primary", "badge-gem-p", keys.GEMINI_API_KEY);
  setKeyUi("vault-gemini-backup", "badge-gem-b", keys.GEMINI_API_KEY_BACKUP);

  const cfSealedBadge = document.getElementById("badge-cf-sealed");
  cfSealedBadge.textContent = "SEALED & LOCKED";
  cfSealedBadge.className = "badge badge-lock";

  const cf = overview.cloudflare || {};
  const integ = overview.integrity || {};
  const val = overview.validator || {};
  const diagBox = document.getElementById("security-diagnostics-box");
  diagBox.innerHTML = [
    ["Cloudflare API Protection", "Hidden & locked inside sealed native engine (non-editable)", true, "SEALED & LOCKED"],
    ["Cloudflare Engine Connectivity", cf.ready ? `Ready (${cf.total_gateway_rules || 0} Gateway Rules)` : "Offline", Boolean(cf.ready), cf.ready ? "READY" : "OFFLINE"],
    ["AI Key DPAPI Vault", v.vault_encrypted ? "Active (Windows CryptProtectData - AI keys only)" : "Initializing", v.vault_encrypted, v.vault_encrypted ? "SECURE" : "WARN"],
    ["Immutable Baseline Blocklists", `DNS: ${integ.dns_active_count}/${integ.dns_baseline_count} • Search: ${integ.search_active_count}/${integ.search_baseline_count}`, integ.dns_intact && integ.search_intact, (integ.dns_intact && integ.search_intact) ? "SECURE" : "WARN"],
    ["Allow-Listing & Policy Deletion", "Disabled at API, UI & Storage layers", integ.block_only_enforced, integ.block_only_enforced ? "SECURE" : "WARN"],
    ["Uptester Module Isolation", "Strictly Read-Only (CloudflareReadOnlyClient)", true, "SECURE"],
    ["Rust cf_validator SHA-256 Guard", val.ok ? "Checksum Verified" : "Pending Setup", val.ok, val.ok ? "SECURE" : "WARN"]
  ].map(([label, desc, ok, badgeText]) => `
    <div class="mini-row">
      <div>
        <div><strong>${escapeHtml(label)}</strong></div>
        <div class="muted">${escapeHtml(desc)}</div>
      </div>
      <span class="badge ${ok ? "badge-ok" : "badge-warn"}">${escapeHtml(badgeText)}</span>
    </div>
  `).join("");
}

async function saveVaultCredentials() {
  const payload = {
    GEMINI_API_KEY: document.getElementById("vault-gemini-primary").value.trim(),
    GEMINI_API_KEY_BACKUP: document.getElementById("vault-gemini-backup").value.trim()
  };
  try {
    await apiFetch("/api/vault/update", { method: "POST", body: JSON.stringify(payload) });
    setFeedback("vault-feedback", "AI API keys securely sealed in Windows DPAPI Vault.", true);
    await refreshVaultAndSecurity();
    await refreshOverview();
  } catch (err) {
    setFeedback("vault-feedback", err.message, false);
  }
}

async function clearBackupGeminiKey() {
  await apiFetch("/api/vault/clear-backup", { method: "POST" });
  setFeedback("vault-feedback", "Backup Gemini key cleared.", true);
  await refreshVaultAndSecurity();
}

async function testVaultConnections() {
  setFeedback("vault-feedback", "Testing Cloudflare & Gemini API connections...", true);
  try {
    const res = await apiFetch("/api/vault/test", { method: "POST" });
    const cfMsg = res.cloudflare.ok ? `Cloudflare OK (${res.cloudflare.rule_count} rules)` : `Cloudflare Error: ${res.cloudflare.error}`;
    const gpMsg = res.gemini_primary.ok ? `Gemini Primary OK (${res.gemini_primary.models_found} models)` : `Gemini Primary Error: ${res.gemini_primary.error}`;
    const gbMsg = res.gemini_backup ? (res.gemini_backup.ok ? ` • Backup OK` : ` • Backup Err`) : "";
    const allGood = res.cloudflare.ok && res.gemini_primary.ok;
    setFeedback("vault-feedback", `${cfMsg} • ${gpMsg}${gbMsg}`, allGood);
  } catch (err) {
    setFeedback("vault-feedback", err.message, false);
  }
}

// --- Full Autonomous Multi-Hour Pipeline & Reports ---
let currentReportObj = null;

function setAutonomousMinutes(mins) {
  document.getElementById("auto-duration-mins").value = mins;
  updateAutoHoursHint();
}

function updateAutoHoursHint() {
  const mins = parseFloat(document.getElementById("auto-duration-mins").value || "120");
  const hrs = (mins / 60).toFixed(2);
  document.getElementById("auto-hours-hint").textContent = mins >= 60 ? `= ${hrs} hrs` : `= ${Math.round(mins)} min`;
}

function updateStepperUi(stage, doneAll = false) {
  for (let i = 1; i <= 3; i++) {
    const el = document.getElementById(`step-stage-${i}`);
    el.classList.remove("active", "done");
    if (doneAll || (stage && i < stage)) {
      el.classList.add("done");
    } else if (stage && i === stage) {
      el.classList.add("active");
    }
  }
}

async function startAutonomousPipeline() {
  const mins = parseFloat(document.getElementById("auto-duration-mins").value || "120");
  const enableS1 = document.getElementById("auto-stage1").checked;
  const enableS2 = document.getElementById("auto-stage2").checked;
  const enableS3 = document.getElementById("auto-stage3").checked;
  const fullDns = document.getElementById("auto-full-dns").checked;

  updateStepperUi(1, false);
  const badge = document.getElementById("auto-stage-badge");
  badge.textContent = "RUNNING";
  badge.className = "badge badge-running";
  document.getElementById("auto-live-metrics").classList.remove("hidden");

  try {
    const res = await apiFetch("/api/autonomous/start", {
      method: "POST",
      body: JSON.stringify({
        duration_minutes: mins,
        enable_stage1_dns: enableS1,
        enable_stage2_search: enableS2,
        enable_stage3_uptester: enableS3,
        full_dns_baseline_reprobe: fullDns
      })
    });

    watchJob(
      res.job_id,
      (job) => {
        const doneOk = job.status === "completed";
        updateStepperUi(null, doneOk);
        badge.textContent = job.status.toUpperCase();
        badge.className = `badge ${doneOk ? "badge-ok" : "badge-warn"}`;
        loadDnsDatasets();
        loadSearchDatasets();
        refreshOverview();
        loadReportsList();
        if (job.result && job.result.report) {
          renderReportDetail(job.result.report);
        }
      },
      (prog) => {
        if (prog.stage) updateStepperUi(prog.stage, false);
        const hrsElapsed = ((prog.elapsed_seconds || 0) / 60).toFixed(1);
        const totMins = ((prog.total_seconds || 0) / 60).toFixed(0);
        document.getElementById("auto-live-metric-text").textContent =
          `${prog.stage_label || "Running"} • Elapsed ${hrsElapsed}m / ${totMins}m` +
          (prog.ai_sites_added ? ` • +${prog.ai_sites_added} sites` : "") +
          (prog.ai_terms_added ? ` • +${prog.ai_terms_added} terms` : "");
      }
    );
  } catch (err) {
    badge.textContent = "ERROR";
    badge.className = "badge badge-err";
    appendConsoleLine(`[Autonomous Start Error] ${err.message}`);
  }
}

async function loadReportsList() {
  try {
    const res = await apiFetch("/api/reports");
    const box = document.getElementById("reports-history-list");
    const reps = res.reports || [];
    if (reps.length === 0) {
      box.innerHTML = `<div class="muted">No autonomous reports generated yet.</div>`;
      return;
    }
    box.innerHTML = reps
      .map((r) => {
        const mins = (Number(r.duration_seconds || 0) / 60).toFixed(1);
        return `
          <button class="mini-row report-btn" onclick="openReport('${escapeHtml(r.report_id)}')">
            <div>
              <div><strong>${escapeHtml(r.report_id)}</strong></div>
              <div class="muted">${mins}m • +${r.new_sites_blocked} sites • +${r.new_terms_blocked} terms</div>
            </div>
            <span class="badge ${r.overblocked_dns + r.overblocked_search > 0 ? "badge-warn" : "badge-ok"}">
              ${r.overblocked_dns + r.overblocked_search} Over-Blk
            </span>
          </button>
        `;
      })
      .join("");
  } catch (err) {
    appendConsoleLine(`[Reports List Error] ${err.message}`);
  }
}

async function openReport(reportId) {
  const res = await apiFetch(`/api/reports/${encodeURIComponent(reportId)}`);
  if (res.report) renderReportDetail(res.report);
}

function renderReportDetail(rep) {
  currentReportObj = rep;
  document.getElementById("btn-export-report").classList.remove("hidden");
  const s1 = rep.stage1_dns || {};
  const s2 = rep.stage2_search || {};
  const s3 = rep.stage3_uptester || {};
  const mins = (Number(rep.duration_seconds || 0) / 60).toFixed(1);

  const overDns = s3.dns_overblocked || [];
  const overSearch = s3.search_overblocked || [];
  const slips = s3.critical_slip_throughs || [];

  document.getElementById("report-detail-view").innerHTML = `
    <div class="btn-row" style="margin-bottom:10px;">
      <span class="badge badge-lock">${escapeHtml(rep.report_id)}</span>
      <span class="badge badge-ok">Elapsed: ${mins} min</span>
      <span class="badge ${rep.stopped_early ? "badge-warn" : "badge-ok"}">${rep.stopped_early ? "STOPPED EARLY" : "COMPLETED"}</span>
    </div>
    <div class="mini-list">
      <div class="mini-row">
        <span><strong>Stage 1 (DNS Sites Blocked)</strong></span>
        <span>+${s1.ai_new_domains_added || 0} AI domains (${s1.ai_domains_pushed_to_cf || 0} pushed) • ${s1.ai_rejected_low_value || 0} filtered • ${s1.stopped_on_saturation ? "Saturated Stop" : "Timer Done"}</span>
      </div>
      <div class="mini-row">
        <span><strong>Stage 2 (Search Terms Blocked)</strong></span>
        <span>+${s2.ai_new_terms_added || 0} AI terms • ${s2.ai_rejected_low_value || 0} filtered • ${s2.final_chunk_count || 0} chunks synced • ${s2.stopped_on_saturation ? "Saturated Stop" : "Timer Done"}</span>
      </div>
      <div class="mini-row">
        <span><strong>Stage 3A (Essential Sites Not Supposed To Be Blocked)</strong></span>
        <span class="badge ${overDns.length ? "badge-warn" : "badge-ok"}">${s3.dns_healthy || 0}/${s3.dns_total || 0} Healthy (${overDns.length} Over-Blocked)</span>
      </div>
      <div class="mini-row">
        <span><strong>Stage 3B (Essential Searches Not Supposed To Be Blocked)</strong></span>
        <span class="badge ${overSearch.length ? "badge-warn" : "badge-ok"}">${s3.search_healthy || 0}/${s3.search_tested || 0} Allowed (${overSearch.length} Over-Blocked)</span>
      </div>
      <div class="mini-row">
        <span><strong>Stage 3C (Critical Block Enforcement Audit)</strong></span>
        <span class="badge ${slips.length ? "badge-err" : "badge-ok"}">${s3.critical_enforced || 0}/${s3.critical_checked || 0} Enforced (${slips.length} Slip-Throughs)</span>
      </div>
    </div>
    ${overDns.length ? `<div style="margin-top:10px;"><strong>Over-Blocked Essential Domains (False Positives):</strong><div class="pill-wrap" style="margin-top:4px;">${overDns.map((o) => `<span class="item-pill">${escapeHtml(o.domain)} (${escapeHtml(o.category)})</span>`).join("")}</div></div>` : ""}
    ${overSearch.length ? `<div style="margin-top:10px;"><strong>Over-Blocked Essential Search Queries (False Positives):</strong><div class="pill-wrap" style="margin-top:4px;">${overSearch.map((q) => `<span class="item-pill">${escapeHtml(q.term)} (${escapeHtml(q.category)})</span>`).join("")}</div></div>` : ""}
    ${slips.length ? `<div style="margin-top:10px;"><strong>Critical Slip-Throughs Requiring Pentester Sync:</strong><div class="pill-wrap" style="margin-top:4px;">${slips.map((x) => `<span class="item-pill">${escapeHtml(x.kind)}: ${escapeHtml(x.item)}</span>`).join("")}</div></div>` : ""}
  `;
}

function downloadCurrentReport() {
  if (!currentReportObj) return;
  const blob = new Blob([JSON.stringify(currentReportObj, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${currentReportObj.report_id || "sentinelgate_report"}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// --- Live Job Console ---
function appendConsoleLine(line) {
  const pre = document.getElementById("console-output");
  pre.textContent += (pre.textContent ? "\n" : "") + line;
  pre.scrollTop = pre.scrollHeight;
}

function clearConsole() {
  document.getElementById("console-output").textContent = "";
}

function toggleConsoleHeight() {
  document.getElementById("job-console").classList.toggle("expanded");
}

function watchJob(jobId, onComplete, onProgress) {
  if (jobPollTimer) clearInterval(jobPollTimer);
  activeJobId = jobId;
  activeJobSince = 0;

  document.getElementById("console-output").textContent = "";
  document.getElementById("job-status-pill").textContent = "RUNNING";
  document.getElementById("job-status-pill").className = "badge badge-running";
  document.getElementById("btn-stop-job").classList.remove("hidden");
  document.getElementById("job-progress-bar").style.width = "5%";

  const poll = async () => {
    try {
      const data = await apiFetch(`/api/jobs/${jobId}?since=${activeJobSince}`);
      document.getElementById("job-title").textContent = data.title;
      if (data.logs && data.logs.length) {
        const pre = document.getElementById("console-output");
        pre.textContent += (pre.textContent ? "\n" : "") + data.logs.join("\n");
        const lines = pre.textContent.split("\n");
        if (lines.length > 1500) {
          pre.textContent = lines.slice(-1500).join("\n");
        }
        pre.scrollTop = pre.scrollHeight;
        activeJobSince = data.total_logs;
      }

      const prog = data.progress || {};
      if (onProgress && Object.keys(prog).length > 0) {
        onProgress(prog);
      }
      if (prog.total && prog.current) {
        const pct = Math.min(100, Math.round((prog.current / prog.total) * 100));
        document.getElementById("job-progress-bar").style.width = `${pct}%`;
        document.getElementById("job-progress-text").textContent = `${prog.current}/${prog.total} (${pct}%)`;
      } else if (prog.iteration && prog.max_iterations) {
        const pct = Math.min(100, Math.round((prog.iteration / prog.max_iterations) * 100));
        document.getElementById("job-progress-bar").style.width = `${pct}%`;
        document.getElementById("job-progress-text").textContent = `Iter ${prog.iteration}/${prog.max_iterations} • Added: ${prog.total_added || 0}`;
      }

      if (data.status !== "running") {
        clearInterval(jobPollTimer);
        jobPollTimer = null;
        document.getElementById("btn-stop-job").classList.add("hidden");
        document.getElementById("job-progress-bar").style.width = "100%";
        const pill = document.getElementById("job-status-pill");
        pill.textContent = data.status.toUpperCase();
        pill.className = `badge ${data.status === "completed" ? "badge-ok" : data.status === "stopped" ? "badge-warn" : "badge-err"}`;
        if (onComplete) onComplete(data);
      }
    } catch (err) {
      clearInterval(jobPollTimer);
      jobPollTimer = null;
      appendConsoleLine(`[Polling Error] ${err.message}`);
    }
  };

  poll();
  jobPollTimer = setInterval(poll, 700);
}

async function stopActiveJob() {
  if (!activeJobId) return;
  await apiFetch(`/api/jobs/${activeJobId}/stop`, { method: "POST" });
  appendConsoleLine("[!] Stop requested — finishing current check cleanly...");
}

// Initial boot
refreshOverview();
loadDnsDatasets();
loadSearchDatasets();
