// YL Agent Runtime console. Plain ES module: no build step, no framework.
//
// Authentication: bearer token in sessionStorage. Pairing generates an ed25519
// keypair with WebCrypto (requires a secure context: https:// on the LAN, or
// http://127.0.0.1 on the host) and keeps the CryptoKeyPair in IndexedDB, so
// the private key is never readable by this script.

const TOKEN_KEY = "yl_token";
const KEY_DB = "yl-console";
const KEY_STORE = "keys";
const KEY_ID = "device-key";

const state = {
  token: sessionStorage.getItem(TOKEN_KEY) || "",
  facts: null,
  pane: "roots",
  browse: { rootId: "", path: "" },
  manageWorkspaceId: null,
  poll: { approvals: 0, devices: 0 },
  view: "grid",
  filter: { query: "", type: "", status: "", sort: "name" },
  roots: [],
  workspaces: [],
  approvals: [],
  pairings: [],
  devices: [],
};

const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));

function toast(message, isError = false) {
  const el = $("toast-container");
  const t = document.createElement("div");
  t.className = `toast ${isError ? "err" : "success"}`;
  t.textContent = message;
  el.appendChild(t);
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.remove(); }, 4000);
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (response.status === 401) {
    signOut("Session expired — pair again or paste a new token.");
    throw new Error(data?.error || "unauthorized");
  }
  if (!response.ok) throw new Error(data?.error || `HTTP ${response.status}`);
  return data;
}

// ---- token / session ----

function signedIn() { return Boolean(state.token); }

function signOut(message) {
  state.token = "";
  sessionStorage.removeItem(TOKEN_KEY);
  $("signin-pane").hidden = false;
  $("app-body").hidden = true;
  $("fingerprint-row")?.classList.add("hidden");
  $("signout")?.classList.add("hidden");
  if (message) {
    const el = $("signin-error");
    el.textContent = message;
    el.hidden = false;
  }
}

function useToken(token) {
  state.token = token.trim();
  sessionStorage.setItem(TOKEN_KEY, state.token);
  $("signin-pane").hidden = true;
  $("app-body").hidden = false;
  signInUI();
}

async function pairBrowser() {
  try {
    const facts = await api("/device");
    state.facts = facts;
    signInUI();
  } catch (e) {
    toast("Pairing failed: " + e.message, true);
  }
}

async function signInUI() {
  try {
    const [facts, roots, workspaces, approvals, pairings, devices] = await Promise.all([
      api("/device").catch(() => null),
      api("/discovery/roots").catch(() => ({ roots: [] })),
      api("/workspaces").catch(() => ({ workspaces: [] })),
      api("/approvals").catch(() => ({ approvals: [] })),
      api("/devices").catch(() => ({ devices: [] })),
      api("/pairings").catch(() => ({ pairings: [] })),
    ]);
    state.facts = facts;
    state.roots = roots?.roots || [];
    state.workspaces = workspaces?.workspaces || [];
    state.approvals = approvals?.approvals || [];
    state.pairings = pairings?.pairings || [];
    state.devices = devices?.devices || [];
    renderHeader();
    renderSidebar();
    renderStats();
    UI.filter();
  } catch (e) {
    toast("Load failed: " + e.message, true);
  }
}

function renderHeader() {
  const dot = $("transport-dot");
  const badge = $("transport-badge");
  const yolo = $("yolo-badge");
  const signout = $("signout");
  const brand = $("brand-sub");
  if (dot) {
    dot.className = "dot " + (state.facts?.tls?.enabled ? "lan" : "local");
  }
  if (badge) badge.textContent = state.facts?.tls?.enabled ? "LAN (TLS)" : "loopback";
  if (yolo) yolo.hidden = !state.facts?.yolo;
  if (signout) signout.hidden = !signedIn();
  if (signout) signout.onclick = () => signOut("");
  if (brand && state.facts) {
    const urls = state.facts.tls?.urls || [];
    brand.textContent = urls[0] || "127.0.0.1:8081";
    brand.title = urls.join("\n") || "";
  }
  const foot = $("foot-info");
  if (foot) foot.textContent = "roots=" + state.roots.length + "  workspaces=" + state.workspaces.length;
}

// ---- Sidebar nav ----

function renderSidebar() {
  const nav = $("sidebar-nav");
  const active = state.pane;
  const items = [
    { id: "roots", label: "Discovery roots", icon: "●", level: 1 },
    { id: "browse", label: "Browse", icon: "○", level: 1 },
    { id: "workspaces", label: "Workspaces", icon: "◈", level: 1 },
    { id: "approvals", label: "Approvals", icon: "✦", level: 1, count: state.approvals.length },
    { id: "devices", label: "Devices & pairings", icon: "☁", level: 1 },
  ];
  nav.innerHTML = items.map(it => {
    const sel = active === it.id ? " active" : "";
    const cnt = it.count ? `<span class="count-tag">${it.count}</span>` : "";
    return `<div class="tree-item${sel}" onclick="UI.setPane('${it.id}')">
      <span class="tree-left"><span class="tree-ico">${it.icon}</span><span class="tree-name">${esc(it.label)}</span></span>${cnt}
    </div>`;
  }).join("");
}

function setPane(pane) {
  state.pane = pane;
  state.view = "grid";
  $("view-grid")?.classList.toggle("active", pane !== "approvals" && pane !== "devices");
  $("view-list")?.classList.toggle("active", false);
  renderSidebar();
  renderPane();
}

function renderPane() {
  // hide all panes, show only the active section content inside grid
  const grid = $("grid");
  if (!grid) return;
  switch (state.pane) {
    case "roots": renderRoots(); break;
    case "browse": renderBrowse(); break;
    case "workspaces": renderWorkspaces(); break;
    case "approvals": renderApprovals(); break;
    case "devices": renderDevices(); break;
  }
}

// ---- Stats strip ----

function renderStats() {
  const s = { project_count: state.workspaces.length };
  const types = {};
  state.workspaces.forEach(w => { types[w.origin || "registered"] = (types[w.origin || "registered"] || 0) + 1; });
  const top = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const el = $("stats-strip");
  if (!el) return;
  el.innerHTML = `
    <div class="stat-node"><span class="stat-label">Workspaces</span><span class="stat-value">${s.project_count}</span></div>
    <div class="stat-node"><span class="stat-label">Roots</span><span class="stat-value">${state.roots.length}</span></div>
    <div class="stat-node"><span class="stat-label">Pending approvals</span><span class="stat-value">${state.approvals.length}</span></div>
    ${top.map(([t, n]) => `<div class="stat-node"><span class="stat-label">${esc(t)}</span><span class="stat-value">${n}</span></div>`).join('')}
  `;
}

// ---- Filter / view ----

function setView(v) {
  state.view = v;
  $("view-grid")?.classList.toggle("active", v === "grid");
  $("view-list")?.classList.toggle("active", v === "list");
  renderPane();
}

function filter() {
  state.filter.query = ($("search-input")?.value || "").toLowerCase();
  state.filter.type = ($("filter-type")?.value || "");
  state.filter.status = ($("filter-status")?.value || "");
  state.filter.sort = ($("sort-by")?.value || "name");
  renderPane();
}

const UI = {
  setPane,
  setView,
  filter,
  openDrawer() {
    $("sidebar")?.classList.add("open");
    $("drawer-overlay")?.classList.add("open");
  },
  closeDrawer() {
    $("sidebar")?.classList.remove("open");
    $("drawer-overlay")?.classList.remove("open");
  },
  closeDetail() { $("detail-sheet")?.classList.remove("open"); },
  closeModal() { $("modal-overlay")?.classList.remove("open"); },
  esc,
};

// wire global
window.UI = UI;
window.setPane = setPane;
window.setView = setView;
window.filter = filter;

// ---- Roots pane ----

function renderRoots() {
  const grid = $("grid");
  const crumb = $("crumb-bar");
  if (crumb) crumb.innerHTML = `<b>Discovery roots</b> — ${state.roots.length} root${state.roots.length === 1 ? "" : "s"}`;
  if (!state.roots.length) {
    grid.innerHTML = `<div class="empty"><div class="e-title">No roots yet.</div><div>Add a folder from the sidebar so the console can browse, register and create inside it.</div></div>`;
    return;
  }
  grid.className = "project-grid";
  grid.innerHTML = state.roots.map(root => {
    const activeCls = root.enabled ? "" : "disabled";
    return `
      <div class="card ${activeCls}" style="--tc:${root.enabled ? varAc(root.enabled) : '#666'};--hover:${root.enabled ? '#22d3ee14' : 'transparent'}" onclick="UI.toggleRoot('${esc(root.id)}')">
        <div class="card-meta">
          <span class="status-pill">
            <span class="status-dot ${root.enabled ? 'active' : ''}"></span>
            ${esc(root.enabled ? 'enabled' : 'disabled')}
          </span>
          <span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">root</span>
        </div>
        <div class="card-title">${esc(root.label || root.id)}</div>
        <div class="card-desc">${esc(root.path)}</div>
        <div class="tag-row">
          ${[root.browse&&'browse', root.register&&'register', root.create&&'create', root.import&&'import', root.clone&&'clone'].filter(Boolean).map(t => `<span class="micro-tag" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">${t}</span>`).join('')}
        </div>
        <div class="card-foot">
          <span class="card-path">${esc(root.id)} · ${root.synthetic ? 'from workspace root' : 'operator-granted'}</span>
          <span class="card-stats"><span>${root.enabled ? 'enabled' : 'disabled'}</span></span>
        </div>
      </div>`;
  }).join("");
}

function varAc(b) { return b ? 'var(--accent)' : 'var(--text-low)'; }

async function toggleRoot(id) {
  const root = state.roots.find(r => r.id === id);
  if (!root) return;
  try {
    await api(`/discovery/roots/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: { enabled: !root.enabled },
    });
    toast(`Root ${id} ${!root.enabled ? "enabled" : "disabled"}`);
    await signInUI();
  } catch (e) { toast(e.message, true); }
}

// ---- Browse pane ----

async function renderBrowse() {
  const grid = $("grid");
  const crumb = $("crumb-bar");
  if (crumb) crumb.innerHTML = `<b>Browse</b> — pick a root`;
  grid.innerHTML = `<div class="empty"><div class="e-title">Browse a root</div><div>Select a discovery root from the sidebar, then browse folders here.</div></div>`;
}

// ---- Workspaces pane ----

async function renderWorkspaces() {
  const grid = $("grid");
  const crumb = $("crumb-bar");
  if (crumb) crumb.innerHTML = `<b>Workspaces</b> — ${state.workspaces.length}`;
  let list = state.workspaces;
  const q = state.filter.query;
  const type = state.filter.type;
  const status = state.filter.status;
  if (q) list = list.filter(w => `${w.display_name || w.id} ${w.root_id || ""} ${w.tags?.join(" ") || ""}`.toLowerCase().includes(q));
  if (type) list = list.filter(w => w.origin === type);
  const by = { name: (a,b) => (a.display_name||a.id).localeCompare(b.display_name||b.id), recent: (a,b) => (b.registered_at||"").localeCompare(a.registered_at||"") };
  list = list.sort(by[state.filter.sort] || by.name);
  if (!list.length) {
    grid.innerHTML = `<div class="empty"><div class="e-title">No workspaces.</div><div>Register a folder or clone a git repo to get started.</div></div>`;
    return;
  }
  grid.className = state.view === "list" ? "project-grid list" : "project-grid";
  grid.innerHTML = list.map(w => {
    const c = typeColor(w.origin || "registered");
    const tags = (w.tags || []).slice(0, 5).map(t => `<span class="micro-tag" style="${tagStyle(t)}">${esc(t)}</span>`).join('');
    return `
      <div class="card" style="--tc:${c};--hover:${c}14" onclick="UI.showDetail('${esc(w.id)}')">
        <div class="card-meta">
          <span class="status-pill"><span class="status-dot active"></span> ${esc(w.origin || 'registered')}</span>
          <span class="type-badge" style="color:${c};border-color:${c}55;background:${c}14">${esc(w.profile || 'development')}</span>
        </div>
        <div class="card-title">${esc(w.display_name || w.id)}</div>
        <div class="card-desc">${w.root_id}/${esc(w.relative_path || '')}</div>
        ${tags ? `<div class="tag-row">${tags}</div>` : ''}
        <div class="card-foot">
          <span class="card-path">${esc(w.id)}</span>
          <span class="card-stats"><span>${esc(w.registered_at || '')}</span></span>
        </div>
      </div>`;
  }).join("");
}

// ---- Approvals pane ----

async function renderApprovals() {
  const grid = $("grid");
  const crumb = $("crumb-bar");
  if (crumb) crumb.innerHTML = `<b>Approvals</b> — ${state.approvals.length} pending`;
  if (!state.approvals.length) {
    grid.innerHTML = `<div class="empty"><div class="e-title">No pending approvals.</div><div>Agent requests appear here when they need human consent.</div></div>`;
    return;
  }
  grid.className = "project-grid list";
  grid.innerHTML = state.approvals.map(a => `
    <div class="card" onclick="UI.approveDetail('${esc(a.id)}')">
      <div class="card-meta">
        <span class="status-pill"><span class="status-dot wip"></span> pending</span>
        <span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">approval</span>
      </div>
      <div class="card-title">${esc(a.capability || 'request')}</div>
      <div class="card-desc">${esc(a.justification || '')} · ${esc(a.resource || '')}</div>
      <div class="card-foot">
        <span class="card-path">${esc(a.id)}</span>
        <span class="card-stats"><span>${esc(a.created_at || '')}</span></span>
      </div>
      <div class="card-actions" style="margin-top:auto;display:flex;gap:8px;">
        <button class="btn btn-secondary" onclick="event.stopPropagation(); UI.approveOne('${esc(a.id)}', true)">Approve</button>
        <button class="btn btn-danger" onclick="event.stopPropagation(); UI.approveOne('${esc(a.id)}', false)">Deny</button>
      </div>
    </div>`).join("");
}

async function approveOne(id, approve) {
  try {
    await api(`/approvals/${encodeURIComponent(id)}/${approve ? 'approve' : 'reject'}`, { method: "POST" });
    toast(approve ? "Approved" : "Denied");
    await signInUI();
  } catch (e) { toast(e.message, true); }
}

async function approveDetail(id) {
  // show in detail sheet
  const a = state.approvals.find(x => x.id === id);
  if (!a) return;
  const el = $("detail-content");
  el.innerHTML = `
    <span class="detail-header-label">Approval // ${esc(a.id)}</span>
    <h1 class="card-title">${esc(a.capability || 'request')}</h1>
    <div class="detail-grid">
      <div class="stat-node"><span class="stat-label">Capability</span><span class="stat-value">${esc(a.capability)}</span></div>
      <div class="stat-node"><span class="stat-label">Resource</span><span class="stat-value">${esc(a.resource || '—')}</span></div>
      <div class="stat-node"><span class="stat-label">Justification</span><span class="stat-value">${esc(a.justification || '—')}</span></div>
      <div class="stat-node"><span class="stat-label">Created</span><span class="stat-value">${esc(a.created_at || '—')}</span></div>
    </div>
    <div class="detail-actions">
      <button class="btn btn-primary" onclick="UI.approveOne('${esc(a.id)}', true); UI.closeDetail()">Approve</button>
      <button class="btn btn-danger" onclick="UI.approveOne('${esc(a.id)}', false); UI.closeDetail()">Deny</button>
      <button class="btn btn-secondary" onclick="UI.closeDetail()">Close</button>
    </div>`;
  $("detail-sheet").classList.add("open");
}

// ---- Devices pane ----

async function renderDevices() {
  const grid = $("grid");
  const crumb = $("crumb-bar");
  if (crumb) crumb.innerHTML = `<b>Devices</b> — ${state.devices.length} paired`;
  if (!state.devices.length) {
    grid.innerHTML = `<div class="empty"><div class="e-title">No paired devices.</div><div>Pair a phone or another host to access the console remotely.</div></div>`;
    return;
  }
  grid.className = "project-grid list";
  grid.innerHTML = state.devices.map(d => `
    <div class="card">
      <div class="card-meta">
        <span class="status-pill"><span class="status-dot active"></span> paired</span>
        <span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">device</span>
      </div>
      <div class="card-title">${esc(d.name || d.id)}</div>
      <div class="card-desc">${esc(d.fingerprint || '')}</div>
      <div class="card-foot">
        <span class="card-path">${esc(d.id)}</span>
        <span class="card-stats"><span>${esc(d.paired_at || '')}</span></span>
      </div>
    </div>`).join("");
}

// ---- Detail sheet (workspace) ----

async function showDetail(id) {
  const w = state.workspaces.find(x => x.id === id);
  if (!w) return;
  const c = typeColor(w.origin || "registered");
  const el = $("detail-content");
  el.innerHTML = `
    <span class="detail-header-label">Workspace // ${esc(w.id)}</span>
    <h1 class="card-title" style="font-size: clamp(32px, 5vw, 48px); margin-bottom: 8px;">${esc(w.display_name || w.id)}</h1>
    <span class="type-badge" style="color:${c};border-color:${c}55;background:${c}14">${esc(w.origin || 'registered')}</span>
    <div class="detail-grid">
      <div class="stat-node"><span class="stat-label">Profile</span><span class="stat-value">${esc(w.profile || 'development')}</span></div>
      <div class="stat-node"><span class="stat-label">Root</span><span class="stat-value">${esc(w.root_id || '—')}</span></div>
      <div class="stat-node"><span class="stat-label">Path</span><span class="stat-value">${esc(w.relative_path || '—')}</span></div>
      <div class="stat-node"><span class="stat-label">Registered</span><span class="stat-value">${esc(w.registered_at || '—')}</span></div>
    </div>
    <div class="detail-path">${esc(w.relative_path || '')}</div>
    <div class="nav-section-label" style="padding:0 0 8px 0">Tags</div>
    <div class="tag-row" style="margin-bottom:24px;">${(w.tags || []).map(t => `<span class="micro-tag" style="${tagStyle(t)}">${esc(t)}</span>`).join('') || '<span style="color:var(--text-low);font-size:12px">None</span>'}</div>
    <div class="detail-actions">
      <button class="btn btn-primary" onclick="UI.openManage('${esc(w.id)}')">Manage</button>
      <button class="btn btn-danger" onclick="UI.unregister('${esc(w.id)}')">Unregister</button>
      <button class="btn btn-secondary" onclick="UI.closeDetail()">Close</button>
    </div>`;
  $("detail-sheet").classList.add("open");
}

async function unregister(id) {
  if (!confirm("Unregister this workspace? Files are never deleted.")) return;
  try {
    await api(`/workspaces/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast("Workspace unregistered");
    await signInUI();
    UI.closeDetail();
  } catch (e) { toast(e.message, true); }
}

// ---- Modals ----

async function openModal(kind) {
  const box = $("modal-box");
  const overlay = $("modal-overlay");
  overlay.classList.add("open");
  switch (kind) {
    case "pairing":
      box.innerHTML = `
        <div class="modal-title">Pair this browser</div>
        <div class="modal-sub">ed25519 key · never leaves this browser</div>
        <button class="btn btn-primary" style="width:100%" onclick="pairBrowser(); UI.closeModal()">Generate key & pair</button>
        <div class="form-row" style="margin-top:16px;">
          <label>Or paste bearer token</label>
          <form id="token-form" onsubmit="event.preventDefault(); UI.useTokenFromForm()">
            <input id="token-input" type="password" placeholder="bearer token" />
            <button type="submit" class="btn btn-primary">Use token</button>
          </form>
        </div>`;
      break;
    case "settings":
      box.innerHTML = `
        <div class="modal-title">Console settings</div>
        <div class="modal-sub">Theme & behavior (stored locally)</div>
        <div class="field"><label>Auto-refresh approvals</label><select id="auto-refresh"><option value="5s">Every 5 seconds</option><option value="10s">Every 10 seconds</option><option value="off">Off</option></select></div>
        <div class="modal-actions"><button class="btn btn-secondary" onclick="UI.closeModal()">Close</button></div>`;
      break;
    default:
      overlay.classList.remove("open");
  }
}

async function useTokenFromForm() {
  const input = $("token-input");
  if (!input || !input.value) return;
  useToken(input.value);
  UI.closeModal();
  input.value = "";
}

async function openManage(id) {
  UI.closeDetail();
  const w = state.workspaces.find(x => x.id === id);
  if (!w) return;
  const box = $("modal-box");
  const overlay = $("modal-overlay");
  overlay.classList.add("open");
  box.innerHTML = `
    <div class="modal-title">Manage // ${esc(w.display_name || w.id)}</div>
    <div class="modal-sub">Settings · devices · bindings</div>
    <div class="field"><label>Display name</label><input id="m-display" value="${esc(w.display_name || '')}" /></div>
    <div class="field"><label>Profile</label><select id="m-profile"><option value="development">development</option><option value="inspect">inspect</option><option value="edit">edit</option></select></div>
    <div class="field"><label>Framework hint</label><input id="m-framework" placeholder="e.g. rust, node" /></div>
    <div class="field"><label>Toolchain hint</label><input id="m-toolchain" placeholder="e.g. stable, 18" /></div>
    <div class="field"><label>Allow (comma-separated)</label><input id="m-allow" placeholder="workspace.read, workspace.write" /></div>
    <div class="field"><label>Deny (comma-separated)</label><input id="m-deny" placeholder="process.exec, network.direct" /></div>
    <div class="modal-actions" style="display:flex;gap:8px;">
      <button class="btn btn-primary" onclick="UI.saveSettings('${esc(w.id)}')">Save</button>
      <button class="btn btn-secondary" onclick="UI.closeModal()">Close</button>
    </div>`;
}

async function saveSettings(id) {
  const allow = ($("m-allow")?.value || "").split(",").map(s => s.trim()).filter(Boolean);
  const deny = ($("m-deny")?.value || "").split(",").map(s => s.trim()).filter(Boolean);
  try {
    await api(`/workspaces/${encodeURIComponent(id)}/settings`, {
      method: "PATCH",
      body: { allow, deny, framework: $("m-framework")?.value, toolchain: $("m-toolchain")?.value },
    });
    toast("Settings saved");
    UI.closeModal();
    await signInUI();
  } catch (e) { toast(e.message, true); }
}

// ---- Type color & tag style ----

function typeColor(t) {
  const m = { registered: '#22d3ee', cloned: '#34d399', created: '#a78bfa', imported: '#fb923c' };
  return m[t] || '#9ca3af';
}
function tagStyle(tag) {
  let h = 0;
  for (const c of String(tag)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const pal = [['#a78bfa','rgba(139,92,246,.12)'],['#22d3ee','rgba(34,211,238,.10)'],['#34d399','rgba(16,185,129,.12)'],['#fb923c','rgba(249,115,22,.12)'],['#f472b6','rgba(236,72,153,.12)'],['#60a5fa','rgba(59,130,246,.12)'],['#fbbf24','rgba(245,158,11,.12)'],['#2dd4bf','rgba(20,184,166,.12)']];
  const [fg, bg] = pal[h % pal.length];
  return `color:${fg};background:${bg};border-color:${fg}44`;
}

// ---- Boot ----

async function boot() {
  if (!signedIn()) {
    $("signin-pane").hidden = false;
    $("app-body").hidden = true;
    return;
  }
  $("signin-pane").hidden = true;
  $("app-body").hidden = false;
  await signInUI();
}

function wire() {
  $("pair-browser")?.addEventListener("click", pairBrowser);
  $("token-form")?.addEventListener("submit", (e) => { e.preventDefault(); useTokenFromForm(); });
  $("signout")?.addEventListener("click", () => signOut(""));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      state.poll.approvals = setInterval(() => { if (state.pane === "approvals" && signedIn()) { api("/approvals/pending").then(d => { state.approvals = d?.approvals || []; renderApprovals(); }).catch(() => {}); }, 5000);
    } else { clearInterval(state.poll.approvals); }
  });
}

wire();
boot();
