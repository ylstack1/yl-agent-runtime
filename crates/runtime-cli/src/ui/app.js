// YL Agent Runtime Console — robust admin web UI
// ES module, zero framework. Sidebar clicks use direct onclick to global functions.

const TOKEN_KEY = "yl_token";

const state = {
  token: sessionStorage.getItem(TOKEN_KEY) || "",
  pane: "roots",
  view: "grid",
  roots: [],
  workspaces: [],
  approvals: [],
  devices: [],
  pendingApprovals: new Map(),
  poll: { approvals: 0, devices: 0 },
  initialized: false,
  facts: null,
};

const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg, err = false) {
  const el = $("toast-container");
  const t = document.createElement("div");
  t.className = `toast ${err ? "err" : "success"}`;
  t.textContent = msg;
  el.appendChild(t);
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.remove(), 4000);
}

function busy(btnId, b) {
  const btn = $(btnId);
  if (!btn) return;
  if (b) { btn.disabled = true; btn.dataset.orig = btn.textContent; btn.textContent = "⏳…"; }
  else { btn.disabled = false; btn.textContent = btn.dataset.orig || btn.textContent; }
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  const r = await fetch(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (r.status === 401) { signOut("Session expired"); throw new Error(data?.error || "unauthorized"); }
  if (!r.ok) throw new Error(data?.error || `HTTP ${r.status}`);
  return data;
}

function signedIn() { return Boolean(state.token); }

function signOut(msg) {
  state.token = "";
  sessionStorage.removeItem(TOKEN_KEY);
  state.initialized = false;
  $("signin-pane").hidden = false;
  $("app-body").hidden = true;
  if (msg) { const e = $("signin-error"); if (e) { e.textContent = msg; e.hidden = false; } }
}

function useToken(token) {
  state.token = token.trim();
  sessionStorage.setItem(TOKEN_KEY, state.token);
  state.initialized = true;
  $("signin-pane").hidden = true;
  $("app-body").hidden = false;
  loadAll();
}

async function pairBrowser() {
  try {
    const f = await api("/device");
    state.facts = f;
    useToken(state.token);
    toast("Paired: " + (f?.lan_urls?.[0] || "runtime"));
  } catch (e) { toast("Pair failed: " + e.message, true); }
}

async function loadAll() {
  try {
    const [f, r, w, a, p, d] = await Promise.all([
      api("/device").catch(() => null),
      api("/discovery/roots").catch(() => ({ roots: [] })),
      api("/workspaces").catch(() => ({ workspaces: [] })),
      api("/approvals").catch(() => ({ approvals: [] })),
      api("/devices").catch(() => ({ devices: [] })),
      api("/pairings").catch(() => ({ pairings: [] })),
    ]);
    state.facts = f;
    state.roots = r?.roots || [];
    state.workspaces = w?.workspaces || [];
    state.approvals = a?.approvals || [];
    state.pairings = p?.pairings || [];
    state.devices = d?.devices || [];
    state.initialized = true;
    renderHeader();
    renderSidebar();
    renderStats();
    renderPane();
  } catch (e) { toast("Load failed: " + e.message, true); signOut("Load failed"); }
}

function renderHeader() {
  const dot = $("transport-dot");
  const badge = $("transport-badge");
  const yolo = $("yolo-badge");
  const signout = $("signout");
  const brand = $("brand-sub");
  if (dot) dot.className = "dot " + (state.facts?.tls?.enabled ? "lan" : "local");
  if (badge) badge.textContent = state.facts?.tls?.enabled ? "LAN (TLS)" : "loopback";
  if (yolo) yolo.hidden = !state.facts?.yolo;
  if (signout) { signout.hidden = !signedIn(); signout.onclick = () => signOut(""); }
  if (brand && state.facts) {
    const u = state.facts.tls?.urls || [];
    brand.textContent = u[0] || "127.0.0.1:8077";
    brand.title = u.join("\n") || "";
  }
  const foot = $("foot-info");
  if (foot) foot.textContent = "roots=" + state.roots.length + "  workspaces=" + state.workspaces.length;
}

function renderSidebar() {
  const nav = $("sidebar-nav");
  if (!nav) return;
  const active = state.pane;
  const items = [
    { id: "roots", label: "Discovery roots", icon: "●" },
    { id: "browse", label: "Browse", icon: "○" },
    { id: "workspaces", label: "Workspaces", icon: "◈" },
    { id: "approvals", label: "Approvals", icon: "✦", count: state.approvals.length },
    { id: "devices", label: "Devices & pairings", icon: "☁" },
  ];
  nav.innerHTML = items.map(it => {
    const sel = active === it.id ? " active" : "";
    const cnt = it.count ? `<span class="count-tag">${it.count}</span>` : "";
    return `<div class="tree-item${sel}" onclick="goto('${esc(it.id)}')">
      <span class="tree-left"><span class="tree-ico">${it.icon}</span><span class="tree-name">${esc(it.label)}</span></span>${cnt}
    </div>`;
  }).join("");
}

window.goto = function(pane) {
  state.pane = pane;
  state.view = "grid";
  const vg = $("view-grid");
  const vl = $("view-list");
  if (vg) vg.classList.toggle("active", pane !== "approvals" && pane !== "devices");
  if (vl) vl.classList.toggle("active", false);
  renderSidebar();
  renderPane();
};

function renderPane() {
  const g = $("grid");
  if (!g) return;
  switch (state.pane) {
    case "roots": renderRoots(); break;
    case "browse": renderBrowse(); break;
    case "workspaces": renderWorkspaces(); break;
    case "approvals": renderApprovals(); break;
    case "devices": renderDevices(); break;
  }
}

function renderStats() {
  const el = $("stats-strip");
  if (!el) return;
  const types = {};
  state.workspaces.forEach(w => { types[w.origin || "registered"] = (types[w.origin || "registered"] || 0) + 1; });
  const top = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 4);
  el.innerHTML = `
    <div class="stat-node"><span class="stat-label">Workspaces</span><span class="stat-value">${state.workspaces.length}</span></div>
    <div class="stat-node"><span class="stat-label">Roots</span><span class="stat-value">${state.roots.length}</span></div>
    <div class="stat-node"><span class="stat-label">Pending approvals</span><span class="stat-value">${state.approvals.length}</span></div>
    ${top.map(([t, n]) => `<div class="stat-node"><span class="stat-label">${esc(t)}</span><span class="stat-value">${n}</span></div>`).join("")}
  `;
}

window.setView = function(v) {
  state.view = v;
  const vg = $("view-grid");
  const vl = $("view-list");
  if (vg) vg.classList.toggle("active", v === "grid");
  if (vl) vl.classList.toggle("active", false);
  renderPane();
};

window.filter = function() {
  state.filter = { query: ($("search-input")?.value || "").toLowerCase(), type: ($("filter-type")?.value || ""), sort: ($("sort-by")?.value || "name") };
  renderPane();
};

const UI = {
  setPane: window.goto,
  setView: window.setView,
  filter: window.filter,
  openDrawer() { $("sidebar")?.classList.add("open"); $("drawer-overlay")?.classList.add("open"); },
  closeDrawer() { $("sidebar")?.classList.remove("open"); $("drawer-overlay")?.classList.remove("open"); },
  closeDetail() { $("detail-sheet")?.classList.remove("open"); },
  closeModal() { $("modal-overlay")?.classList.remove("open"); },
  esc,
  async openModal(kind) { return openModal(kind); },
  async showDetail(id) { return showDetail(id); },
  async approveDetail(id) { return approveDetail(id); },
  async approveOne(id, approve) { return approveOne(id, approve); },
  async unregister(id) { return unregister(id); },
  async saveSettings(id) { return saveSettings(id); },
  async openManage(id) { return openManage(id); },
  async toggleRoot(id) { return toggleRoot(id); },
  async pairBrowser() { return pairBrowser(); },
  async useTokenFromForm() { return useTokenFromForm(); },
  async testConnection() { return testConnection(); },
  async pollApprovalStatus(id) { return pollApprovalStatus(id); },
  async stopPollApproval(id) { return stopPollApproval(id); },
  async renderRoots() { return renderRoots(); },
  async renderWorkspaces() { return renderWorkspaces(); },
  async renderApprovals() { return renderApprovals(); },
  async renderBrowse() { return renderBrowse(); },
  async renderDevices() { return renderDevices(); },
  async renderStats() { return renderStats(); },
  async renderSidebar() { return renderSidebar(); },
  async signInUI() { return loadAll(); },
  async renderHeader() { return renderHeader(); },
};

window.UI = UI;
window.openModal = openModal;
window.showDetail = showDetail;
window.approveOne = approveOne;
window.approveDetail = approveDetail;
window.unregister = unregister;
window.saveSettings = saveSettings;
window.openManage = openManage;
window.toggleRoot = toggleRoot;
window.pairBrowser = pairBrowser;
window.useTokenFromForm = useTokenFromForm;
window.testConnection = testConnection;
window.pollApprovalStatus = pollApprovalStatus;
window.stopPollApproval = stopPollApproval;
window.handleAddRoot = handleAddRoot;
window.closeModal = UI.closeModal;
window.openDrawer = UI.openDrawer;
window.closeDrawer = UI.closeDrawer;
window.closeDetail = UI.closeDetail;
window.deleteRoot = deleteRoot;
window.openAddDeviceModal = openAddDeviceModal;
window.showDeviceDetail = showDeviceDetail;
window.toggleDevice = toggleDevice;
window.deleteDevice = deleteDevice;
window.createDevice = createDevice;
window.createDeviceFromForm = createDeviceFromForm;
window.copyKey = copyKey;

function renderRoots() {
  const g = $("grid");
  const c = $("crumb-bar");
  if (c) c.innerHTML = `<b>Discovery roots</b> — ${state.roots.length}`;
  if (!state.roots.length) {
    g.innerHTML = `<div class="empty"><div class="e-title">No roots yet</div><div>Add a folder from the sidebar so the console can browse, register and create inside it.</div></div>`;
    return;
  }
  g.className = "project-grid";
  const items = state.roots.map(r => {
    const tags = [r.browse&&"browse", r.register&&"register", r.create&&"create", r.import&&"import", r.clone&&"clone"].filter(Boolean).map(t => `<span class="micro-tag" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">${esc(t)}</span>`).join("");
    return `
      <div class="card ${r.enabled ? "" : "disabled"}" style="--tc:${r.enabled ? varAc(r.enabled) : "#666"};--hover:${r.enabled ? "#22d3ee14" : "transparent"}">
        <div class="card-meta">
          <span class="status-pill"><span class="status-dot ${r.enabled ? "active" : ""}"></span>${esc(r.enabled ? "enabled" : "disabled")}</span>
          <span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">root</span>
        </div>
        <div class="card-title">${esc(r.label || r.id)}</div>
        <div class="card-desc">${esc(r.path)}</div>
        <div class="tag-row">${tags}</div>
        <div class="card-foot">
          <span class="card-path">${esc(r.id)} · ${r.synthetic ? "from workspace root" : "operator-granted"}</span>
          <span class="card-stats"><span>${r.enabled ? "enabled" : "disabled"}</span></span>
        </div>
        <div class="card-actions">
          <button class="btn btn-secondary" onclick="event.stopPropagation(); toggleRoot('${esc(r.id)}')">${r.enabled ? "Disable" : "Enable"}</button>
          <button class="btn btn-danger" onclick="event.stopPropagation(); deleteRoot('${esc(r.id)}')">Remove</button>
        </div>
      </div>`;
  }).join("");
  g.innerHTML = items;
}

function varAc(b) { return b ? "var(--accent)" : "var(--text-low)"; }

async function toggleRoot(id) {
  const r = state.roots.find(x => x.id === id);
  if (!r) return;
  try {
    await api(`/discovery/roots/${encodeURIComponent(id)}`, { method: "PATCH", body: { enabled: !r.enabled } });
    toast(`Root ${id} ${!r.enabled ? "enabled" : "disabled"}`);
    await loadAll();
  } catch (e) { toast(e.message, true); }
}

async function deleteRoot(id) {
  if (!confirm("Remove this discovery root? Registered workspaces using it will lose access.")) return;
  try {
    await api(`/discovery/roots/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast("Root removed");
    await loadAll();
  } catch (e) { toast(e.message, true); }
}

async function addRoot(loc, label, en, br, re, cr) {
  const existing = state.roots.find(r => r.path === loc || r.label === label || r.id === loc);
  if (existing) {
    toast(`Root "${esc(label || loc)}" already exists`, true);
    return;
  }
  try {
    await api("/discovery/roots", { method: "POST", body: { id: loc, label, path: loc, enabled: en, browse: br, register: re, create: cr } });
    toast(`Root "${esc(label || loc)}" added`);
    await loadAll();
    $("add-root-form-modal")?.reset();
  } catch (e) { toast(e.message, true); }
}

async function renderBrowse() {
  const g = $("grid");
  const c = $("crumb-bar");
  if (c) c.innerHTML = `<b>Browse</b> — pick a root`;
  g.innerHTML = `<div class="empty"><div class="e-title">Browse a root</div><div>Select a discovery root from the sidebar, then browse folders here.</div></div>`;
}

async function renderWorkspaces() {
  const g = $("grid");
  const c = $("crumb-bar");
  if (c) c.innerHTML = `<b>Workspaces</b> — ${state.workspaces.length}`;
  let list = state.workspaces;
  const q = state.filter?.query || "";
  const type = state.filter?.type || "";
  if (q) list = list.filter(w => `${w.display_name || w.id} ${w.root_id || ""} ${w.tags?.join(" ") || ""}`.toLowerCase().includes(q));
  if (type) list = list.filter(w => w.origin === type);
  list.sort((a, b) => (a.display_name || a.id).localeCompare(b.display_name || b.id));
  if (!list.length) {
    g.innerHTML = `<div class="empty"><div class="e-title">No workspaces.</div><div>Register a folder or clone a git repo to get started.</div></div>`;
    return;
  }
  g.className = state.view === "list" ? "project-grid list" : "project-grid";
  g.innerHTML = list.map(w => {
    const c2 = typeColor(w.origin || "registered");
    const tags = (w.tags || []).slice(0, 5).map(t => `<span class="micro-tag" style="${tagStyle(t)}">${esc(t)}</span>`).join("");
    return `
      <div class="card" style="--tc:${c2};--hover:${c2}14" onclick="showDetail('${esc(w.id)}')">
        <div class="card-meta">
          <span class="status-pill"><span class="status-dot active"></span>${esc(w.origin || "registered")}</span>
          <span class="type-badge" style="color:${c2};border-color:${c2}55;background:${c2}14">${esc(w.profile || "development")}</span>
        </div>
        <div class="card-title">${esc(w.display_name || w.id)}</div>
        <div class="card-desc">${w.root_id}/${esc(w.relative_path || "")}</div>
        ${tags ? `<div class="tag-row">${tags}</div>` : ""}
        <div class="card-foot">
          <span class="card-path">${esc(w.id)}</span>
          <span class="card-stats"><span>${esc(w.registered_at || "")}</span></span>
        </div>
      </div>`;
  }).join("");
}

async function renderApprovals() {
  const g = $("grid");
  const c = $("crumb-bar");
  if (c) c.innerHTML = `<b>Approvals</b> — ${state.approvals.length} pending`;
  if (!state.approvals.length) {
    g.innerHTML = `<div class="empty"><div class="e-title">No pending approvals.</div><div>Agent requests appear here when they need human consent.</div></div>`;
    return;
  }
  g.className = "project-grid list";
  g.innerHTML = state.approvals.map(a => {
    const pol = state.pendingApprovals.has(a.id);
    return `
      <div class="card" onclick="showDetail('${esc(a.id)}')">
        <div class="card-meta">
          <span class="status-pill"><span class="status-dot ${pol ? "wip" : ""}"></span>${pol ? "waiting…" : "pending"}</span>
          <span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">approval</span>
        </div>
        <div class="card-title">${esc(a.capability || "request")}</div>
        <div class="card-desc">${esc(a.justification || "")} · ${esc(a.resource || "")}</div>
        <div class="card-foot"><span class="card-path">${esc(a.id)}</span></div>
        <div class="card-actions" style="margin-top:auto;display:flex;gap:8px;">
          <button class="btn btn-secondary" onclick="event.stopPropagation(); approveOne('${esc(a.id)}', true)">Approve</button>
          <button class="btn btn-danger" onclick="event.stopPropagation(); approveOne('${esc(a.id)}', false)">Deny</button>
          ${pol ? `<button class="btn btn-secondary" onclick="event.stopPropagation(); stopPollApproval('${esc(a.id)}')">Stop waiting</button>` : `<button class="btn btn-secondary" onclick="event.stopPropagation(); pollApprovalStatus('${esc(a.id)}')">Check status</button>`}
        </div>
      </div>`;
  }).join("");
}

async function approveOne(id, approve) {
  try {
    await api(`/approvals/${encodeURIComponent(id)}/${approve ? "approve" : "reject"}`, { method: "POST" });
    toast(approve ? "Approved" : "Denied");
    await loadAll();
  } catch (e) { toast(e.message, true); }
}

async function approveDetail(id) {
  const a = state.approvals.find(x => x.id === id);
  if (!a) return;
  const pol = state.pendingApprovals.has(id);
  const el = $("detail-content");
  el.innerHTML = `
    <span class="detail-header-label">Approval // ${esc(a.id)}</span>
    <h1 class="card-title">${esc(a.capability || "request")}</h1>
    <div class="detail-grid">
      <div class="stat-node"><span class="stat-label">Capability</span><span class="stat-value">${esc(a.capability)}</span></div>
      <div class="stat-node"><span class="stat-label">Resource</span><span class="stat-value">${esc(a.resource || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Justification</span><span class="stat-value">${esc(a.justification || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Created</span><span class="stat-value">${esc(a.created_at || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Status</span><span class="stat-value">${pol ? "waiting for decision…" : "pending"}</span></div>
    </div>
    <div class="detail-actions">
      <button class="btn btn-primary" onclick="approveOne('${esc(a.id)}', true); closeDetail()">Approve</button>
      <button class="btn btn-danger" onclick="approveOne('${esc(a.id)}', false); closeDetail()">Deny</button>
      ${!pol ? `<button class="btn btn-secondary" onclick="pollApprovalStatus('${esc(a.id)}')">Check status</button>` : `<button class="btn btn-secondary" onclick="stopPollApproval('${esc(a.id)}')">Stop waiting</button>`}
      <button class="btn btn-secondary" onclick="closeDetail()">Close</button>
    </div>`;
  $("detail-sheet").classList.add("open");
}

async function pollApprovalStatus(id) {
  const a = state.approvals.find(x => x.id === id);
  if (!a) return;
  if (state.pendingApprovals.has(id)) return;
  const ctrl = new AbortController();
  state.pendingApprovals.set(id, { controller: ctrl });
  renderApprovals();
  try {
    while (!ctrl.signal.aborted) {
      await new Promise(r => setTimeout(r, 3000));
      if (ctrl.signal.aborted) break;
      const d = await api("/approvals", { signal: ctrl.signal });
      const up = d?.approvals?.find(x => x.id === id);
      state.approvals = state.approvals.map(x => x.id === id ? (up || x) : x);
      renderApprovals();
      if (up && up.state && up.state !== "pending") {
        toast(`Approval ${esc(id)} → ${esc(up.state)}`);
        state.pendingApprovals.delete(id);
        renderApprovals();
        return;
      }
    }
  } catch (e) {
    if (e.name !== "AbortError") toast("Poll failed: " + e.message, true);
    state.pendingApprovals.delete(id);
    renderApprovals();
  }
}

async function stopPollApproval(id) {
  const e = state.pendingApprovals.get(id);
  if (e) { e.controller.abort(); state.pendingApprovals.delete(id); toast("Stopped waiting for " + esc(id)); renderApprovals(); }
}

async function renderDevices() {
  const g = $("grid");
  const c = $("crumb-bar");
  const pending = state.pairings.filter(p => p.state === "Pending");
  if (c) c.innerHTML = `<b>Devices</b> — ${state.devices.length} total · ${pending.length} pairing request${pending.length === 1 ? "" : "s"} pending`;
  if (!state.devices.length && !pending.length) {
    g.innerHTML = `
      <div class="empty">
        <div class="e-title">No devices yet.</div>
        <div>Add a device from the sidebar, then pair your phone or host with its key.</div>
        <div style="margin-top:12px;"><button class="btn btn-primary" onclick="openAddDeviceModal()">+ Add device</button></div>
      </div>`;
    return;
  }
  g.className = "project-grid list";
  let html = "";

  // Pending pairing requests section
  if (pending.length) {
    html += `<div style="margin-bottom:16px;">
      <div style="font-weight:600;margin-bottom:8px;color:var(--accent)">Pairing requests — waiting for approval</div>
      ${pending.map(p => `
        <div class="card" style="--tc:var(--accent);--hover:var(--accent)14">
          <div class="card-meta">
            <span class="status-pill"><span class="status-dot"></span>pending</span>
            <span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">pairing</span>
          </div>
          <div class="card-title">${esc(p.device_name || "Unknown device")}</div>
          <div class="card-desc">Pairing code: <span style="font-family:monospace;font-weight:700">${esc(p.pairing_code)}</span></div>
          <div class="card-foot"><span class="card-path">${esc(p.pairing_code)}</span></div>
          <div class="card-actions" style="margin-top:auto;display:flex;gap:8px;">
            <button class="btn btn-secondary" onclick="event.stopPropagation(); approvePairingFromDevices('${esc(p.pairing_code)}')">Approve</button>
            <button class="btn btn-danger" onclick="event.stopPropagation(); rejectPairingFromDevices('${esc(p.pairing_code)}')">Deny</button>
          </div>
        </div>`).join("")}
    </div>`;
  }

  // Registered devices section
  const items = state.devices.map(d => {
    const isActive = d.is_active !== false && !d.is_revoked;
    const isRevoked = d.is_revoked === true;
    const status = isRevoked ? "revoked" : (isActive ? "active" : "pending");
    const statusColor = isRevoked ? "var(--danger)" : (isActive ? "var(--ok)" : "var(--accent)");
    return `
      <div class="card" style="--tc:${statusColor};--hover:${statusColor}14" onclick="showDeviceDetail('${esc(d.id)}')">
        <div class="card-meta"><span class="status-pill"><span class="status-dot ${isActive ? "active" : ""}"></span>${esc(status)}</span><span class="type-badge" style="color:var(--accent);border-color:var(--accent)55;background:var(--accent-dim)">device</span></div>
        <div class="card-title">${esc(d.name || d.id)}</div>
        <div class="card-desc">${esc(d.fingerprint || "")}</div>
        <div class="card-foot"><span class="card-path">${esc(d.id)}</span></div>
        <div class="card-actions" style="margin-top:auto;display:flex;gap:8px;">
          <button class="btn btn-secondary" onclick="event.stopPropagation(); toggleDevice('${esc(d.id)}')">${isRevoked ? "Unrevoke" : "Revoke"}</button>
          <button class="btn btn-danger" onclick="event.stopPropagation(); deleteDevice('${esc(d.id)}')">Delete</button>
        </div>
      </div>`;
  }).join("");
  g.innerHTML = html + items;
}

async function approvePairingFromDevices(code) {
  try {
    await api(`/pairings/${encodeURIComponent(code)}/approve`, { method: "POST" });
    toast(`Pairing ${code} approved`);
    await loadAll();
  } catch (e) { toast(e.message, true); }
}

async function rejectPairingFromDevices(code) {
  try {
    await api(`/pairings/${encodeURIComponent(code)}/reject`, { method: "POST" });
    toast(`Pairing ${code} denied`);
    await loadAll();
  } catch (e) { toast(e.message, true); }
}

async function showDeviceDetail(id) {
  const d = state.devices.find(x => x.id === id);
  if (!d) return;
  const isActive = d.is_active !== false && !d.is_revoked;
  const isRevoked = d.is_revoked === true;
  const status = isRevoked ? "Revoked" : (isActive ? "Active" : "Pending — waiting for device to pair");
  const statusColor = isRevoked ? "var(--danger)" : (isActive ? "var(--ok)" : "var(--accent)");
  const el = $("detail-content");
  const keyHtml = d.private_key ? `
    <div class="field" style="margin:16px 0;">
      <label>Private key (copyable — save it now)</label>
      <div style="display:flex;gap:8px;">
        <input id="dev-key-${esc(d.id)}" type="text" value="${esc(d.private_key)}" readonly style="flex:1;font-family:monospace;font-size:11px;background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:8px;" />
        <button class="btn btn-secondary" onclick="copyKey('dev-key-${esc(d.id)}')">Copy</button>
      </div>
      <div class="muted" style="margin-top:4px;font-size:11px">The device uses this key to authenticate. Store it securely.</div>
    </div>` : `<div class="muted" style="margin:16px 0;">No private key available (device was created without one).</div>`;
  el.innerHTML = `
    <span class="detail-header-label">Device // ${esc(d.id)}</span>
    <h1 class="card-title" style="font-size: clamp(28px, 5vw, 40px); margin-bottom: 8px;">${esc(d.name || d.id)}</h1>
    <span class="type-badge" style="color:${statusColor};border-color:${statusColor}55;background:${statusColor}14">${esc(status)}</span>
    <div class="detail-grid">
      <div class="stat-node"><span class="stat-label">Device ID</span><span class="stat-value">${esc(d.id)}</span></div>
      <div class="stat-node"><span class="stat-label">Name</span><span class="stat-value">${esc(d.name || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Fingerprint</span><span class="stat-value">${esc(d.fingerprint || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Status</span><span class="stat-value" style="color:${statusColor};font-weight:700">${esc(status)}</span></div>
      <div class="stat-node"><span class="stat-label">Created</span><span class="stat-value">${esc(d.created_at || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">MCP compatible</span><span class="stat-value">Yes — use bearer token from /pair/authenticate</span></div>
    </div>
    ${keyHtml}
    <div class="nav-section-label" style="padding:0 0 8px 0">Mobile setup guide</div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px;">
      <div style="font-weight:600;margin-bottom:8px;">Connect a phone or host to this device:</div>
      <div style="font-size:12px;line-height:1.5;color:var(--text-low);">
        1. On the mobile device, generate an ed25519 keypair (or use the private key above).<br>
        2. Sign the device ID string with the private key.<br>
        3. Call <code>POST /pair/authenticate</code> with device_id and signature_hex.<br>
        4. Use the returned bearer token for <code>/mcp</code> and <code>/api/v1</code> calls.<br>
        <br>
        The device key never expires. Revoke it here to invalidate all sessions.
      </div>
    </div>
    <div class="detail-actions">
      <button class="btn btn-secondary" onclick="event.stopPropagation(); toggleDevice('${esc(d.id)}')">${isRevoked ? "Unrevoke" : "Revoke key"}</button>
      <button class="btn btn-danger" onclick="event.stopPropagation(); deleteDevice('${esc(d.id)}')">Delete device</button>
      <button class="btn btn-secondary" onclick="closeDetail()">Close</button>
    </div>`;
  $("detail-sheet").classList.add("open");
}

async function toggleDevice(id) {
  const d = state.devices.find(x => x.id === id);
  if (!d) return;
  const isRevoked = d.is_revoked === true;
  try {
    if (isRevoked) {
      await api(`/devices/${encodeURIComponent(id)}/revoke`, { method: "POST" });
      toast("Device key re-activated");
    } else {
      await api(`/devices/${encodeURIComponent(id)}/revoke`, { method: "POST" });
      toast("Device key revoked — sessions invalidated");
    }
    await loadAll();
    closeDetail();
  } catch (e) { toast(e.message, true); }
}

async function deleteDevice(id) {
  if (!confirm("Delete this device? Its key and all sessions will be removed.")) return;
  try {
    await api(`/devices/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast("Device deleted");
    await loadAll();
    closeDetail();
  } catch (e) { toast(e.message, true); }
}

async function openAddDeviceModal() {
  const box = $("modal-box");
  const ov = $("modal-overlay");
  ov.classList.add("open");
  box.innerHTML = `
    <div class="modal-title">Add device</div>
    <div class="modal-sub">Create a device entry. Name is required; device ID is optional (auto-generated if omitted).</div>
    <form id="add-device-form" onsubmit="event.preventDefault(); createDeviceFromForm()">
      <div class="field"><label>Device name (required)</label><input id="ad-name" type="text" placeholder="e.g. My Phone" required /></div>
      <div class="field"><label>Device ID (optional — leave blank to auto-generate)</label><input id="ad-id" type="text" placeholder="auto-generated UUID" /></div>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
        <button class="btn btn-primary" onclick="createDeviceFromForm()">Create device</button>
      </div>
    </form>`;
}

async function createDeviceFromForm() {
  const name = $("ad-name")?.value.trim();
  const deviceId = $("ad-id")?.value.trim() || undefined;
  if (!name) { toast("Enter a device name", true); return; }
  try {
    const result = await createDevice(name, deviceId);
    // Directly add the created device to state.devices so it appears
    // in the cards view immediately, even if /api/v1/devices is host-only.
    state.devices.push({
      id: result.id,
      name: name,
      fingerprint: "",
      is_active: false,
      is_revoked: false,
      created_at: "",
      private_key: result.private_key,
    });
    // Refresh from server too (works on loopback)
    await loadAll().catch(() => {});
    // Navigate to devices pane first so the card is visible under the modal
    goto("devices");
    // Show key modal on top of the devices view
    const ov = $("modal-overlay");
    const keyBox = $("modal-box");
    ov.classList.add("open");
    keyBox.innerHTML = `
      <div class="modal-title">Device created</div>
      <div class="modal-sub">Save the private key now — it will not be shown again.</div>
      <div class="field"><label>Device ID</label><input type="text" value="${esc(result.id)}" readonly style="flex:1;font-family:monospace;font-size:11px;background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:8px;" /></div>
      <div class="field"><label>Private key (copy)</label><div style="display:flex;gap:8px;"><input id="ad-private-key" type="text" value="${esc(result.private_key)}" readonly style="flex:1;font-family:monospace;font-size:11px;background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:8px;" /><button class="btn btn-secondary" onclick="copyKey('ad-private-key')">Copy</button></div></div>
      <div class="muted" style="margin-top:8px;font-size:11px">Device status: <span style="color:var(--accent);font-weight:600">Pending</span> — waiting for a device to authenticate with this key.</div>
      <div class="modal-actions" style="display:flex;gap:8px;">
        <button class="btn btn-secondary" onclick="closeModal()">Done</button>
      </div>`;
  } catch (e) { toast(e.message, true); }
}

async function createDevice(name, deviceId) {
  const body = { name };
  if (deviceId) body.device_id = deviceId;
  return api("/devices", { method: "POST", body });
}

async function copyKey(inputId) {
  const input = $(inputId);
  if (!input) return;
  input.select();
  document.execCommand("copy");
  toast("Key copied to clipboard");
}

async function showDetail(id) {
  const w = state.workspaces.find(x => x.id === id);
  if (!w) return;
  const c2 = typeColor(w.origin || "registered");
  const el = $("detail-content");
  el.innerHTML = `
    <span class="detail-header-label">Workspace // ${esc(w.id)}</span>
    <h1 class="card-title" style="font-size: clamp(28px, 5vw, 40px); margin-bottom: 8px;">${esc(w.display_name || w.id)}</h1>
    <span class="type-badge" style="color:${c2};border-color:${c2}55;background:${c2}14">${esc(w.origin || "registered")}</span>
    <div class="detail-grid">
      <div class="stat-node"><span class="stat-label">Profile</span><span class="stat-value">${esc(w.profile || "development")}</span></div>
      <div class="stat-node"><span class="stat-label">Root</span><span class="stat-value">${esc(w.root_id || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Path</span><span class="stat-value">${esc(w.relative_path || "—")}</span></div>
      <div class="stat-node"><span class="stat-label">Registered</span><span class="stat-value">${esc(w.registered_at || "—")}</span></div>
    </div>
    <div class="detail-path">${esc(w.relative_path || "")}</div>
    <div class="nav-section-label" style="padding:0 0 8px 0">Tags</div>
    <div class="tag-row" style="margin-bottom:24px;">${(w.tags || []).map(t => `<span class="micro-tag" style="${tagStyle(t)}">${esc(t)}</span>`).join("") || "<span style=\"color:var(--text-low);font-size:12px\">None</span>"}</div>
    <div class="detail-actions">
      <button class="btn btn-primary" onclick="openManage('${esc(w.id)}')">Manage</button>
      <button class="btn btn-danger" onclick="unregister('${esc(w.id)}')">Unregister</button>
      <button class="btn btn-secondary" onclick="closeDetail()">Close</button>
    </div>`;
  $("detail-sheet").classList.add("open");
}

async function unregister(id) {
  if (!confirm("Unregister this workspace? Files are never deleted.")) return;
  try {
    await api(`/workspaces/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast("Workspace unregistered");
    await loadAll();
    closeDetail();
  } catch (e) { toast(e.message, true); }
}

async function openModal(kind) {
  const box = $("modal-box");
  const ov = $("modal-overlay");
  ov.classList.add("open");
  switch (kind) {
    case "pairing":
      box.innerHTML = `
        <div class="modal-title">Pair this browser</div>
        <div class="modal-sub">ed25519 key · never leaves this browser</div>
        <button class="btn btn-primary" style="width:100%" onclick="pairBrowser(); closeModal()">Generate key & pair</button>
        <div class="form-row" style="margin-top:16px;">
          <label>Or paste bearer token</label>
          <form id="token-form" onsubmit="event.preventDefault(); useTokenFromForm()">
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
        <div class="modal-actions"><button class="btn btn-secondary" onclick="closeModal()">Close</button></div>`;
      break;
    case "add-root":
      box.innerHTML = `
        <div class="modal-title">Add discovery root</div>
        <div class="modal-sub">Folder the runtime may browse, register or create inside</div>
        <form id="add-root-form-modal" onsubmit="event.preventDefault(); handleAddRoot()">
          <div class="field"><label>Folder path</label><input id="ar-path" type="text" placeholder="C:\\Users\\you\\Projects" required /></div>
          <div class="field"><label>Display name</label><input id="ar-label" type="text" placeholder="My Projects" /></div>
          <div class="field"><label>Root ID (optional)</label><input id="ar-id" type="text" placeholder="projects" /></div>
          <div class="row">
            <label class="toggle"><input type="checkbox" id="ar-browse" checked /> browse</label>
            <label class="toggle"><input type="checkbox" id="ar-register" checked /> register</label>
            <label class="toggle"><input type="checkbox" id="ar-create" checked /> create</label>
          </div>
          <div class="modal-actions">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="handleAddRoot()">Add root</button>
          </div>
        </form>`;
      break;
    case "add-device":
      openAddDeviceModal();
      break;
    default:
      ov.classList.remove("open");
  }
}

async function handleAddRoot() {
  const path = $("ar-path")?.value.trim();
  const label = $("ar-label")?.value.trim() || "";
  const id = $("ar-id")?.value.trim() || "";
  if (!path) { toast("Enter a folder path", true); return; }
  try {
    await api("/discovery/roots", {
      method: "POST",
      body: { id, label, path, enabled: true, browse: $("ar-browse")?.checked, register: $("ar-register")?.checked, create: $("ar-create")?.checked },
    });
    toast(`Root "${esc(label || path)}" added`);
    await loadAll();
    closeModal();
    $("add-root-form-modal")?.reset();
  } catch (e) { toast(e.message, true); }
}

async function useTokenFromForm() {
  const i = $("token-input");
  if (!i || !i.value) return;
  useToken(i.value);
  closeModal();
  i.value = "";
}

async function openManage(id) {
  closeDetail();
  const w = state.workspaces.find(x => x.id === id);
  if (!w) return;
  const box = $("modal-box");
  const ov = $("modal-overlay");
  ov.classList.add("open");
  box.innerHTML = `
    <div class="modal-title">Manage // ${esc(w.display_name || w.id)}</div>
    <div class="modal-sub">Settings · devices · bindings</div>
    <div class="field"><label>Display name</label><input id="m-display" value="${esc(w.display_name || "")}" /></div>
    <div class="field"><label>Profile</label><select id="m-profile"><option value="development">development</option><option value="inspect">inspect</option><option value="edit">edit</option></select></div>
    <div class="field"><label>Framework hint</label><input id="m-framework" placeholder="e.g. rust, node" /></div>
    <div class="field"><label>Toolchain hint</label><input id="m-toolchain" placeholder="e.g. stable, 18" /></div>
    <div class="field"><label>Allow (comma-separated)</label><input id="m-allow" placeholder="workspace.read, workspace.write" /></div>
    <div class="field"><label>Deny (comma-separated)</label><input id="m-deny" placeholder="process.exec, network.direct" /></div>
    <div class="modal-actions" style="display:flex;gap:8px;">
      <button class="btn btn-primary" onclick="saveSettings('${esc(w.id)}')">Save</button>
      <button class="btn btn-secondary" onclick="closeModal()">Close</button>
    </div>`;
}

async function saveSettings(id) {
  const allow = ($("m-allow")?.value || "").split(",").map(s => s.trim()).filter(Boolean);
  const deny = ($("m-deny")?.value || "").split(",").map(s => s.trim()).filter(Boolean);
  try {
    await api(`/workspaces/${encodeURIComponent(id)}/settings`, { method: "PATCH", body: { allow, deny, framework: $("m-framework")?.value, toolchain: $("m-toolchain")?.value } });
    toast("Settings saved");
    closeModal();
    await loadAll();
  } catch (e) { toast(e.message, true); }
}

async function testConnection() {
  try {
    toast("Testing connection…");
    const f = await api("/device");
    toast(`Connection OK — ${f?.tls?.enabled ? "LAN (TLS)" : "loopback"}, ${f.workspace_count} workspaces`);
    state.facts = f;
    renderHeader();
  } catch (e) { toast("Connection failed: " + e.message, true); }
}

function typeColor(t) {
  const m = { registered: "#22d3ee", cloned: "#34d399", created: "#a78bfa", imported: "#fb923c" };
  return m[t] || "#9ca3af";
}
function tagStyle(tag) {
  let h = 0;
  for (const c of String(tag)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const pal = [["#a78bfa","rgba(139,92,246,.12)"],["#22d3ee","rgba(34,211,238,.10)"],["#34d399","rgba(16,185,129,.12)"],["#fb923c","rgba(249,115,22,.12)"],["#f472b6","rgba(236,72,153,.12)"],["#60a5fa","rgba(59,130,246,.12)"],["#fbbf24","rgba(245,158,11,.12)"],["#2dd4bf","rgba(20,184,166,.12)"]];
  const [fg, bg] = pal[h % pal.length];
  return `color:${fg};background:${bg};border-color:${fg}44`;
}

async function boot() {
  if (!signedIn()) {
    $("signin-pane").hidden = false;
    $("app-body").hidden = true;
    return;
  }
  $("signin-pane").hidden = true;
  $("app-body").hidden = false;
  state.initialized = true;
  await loadAll();
}

function wire() {
  $("pair-browser")?.addEventListener("click", pairBrowser);
  $("token-form")?.addEventListener("submit", (e) => { e.preventDefault(); useTokenFromForm(); });
  $("signout")?.addEventListener("click", () => signOut(""));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      if (!state.poll.approvals && signedIn()) state.poll.approvals = setInterval(pollApprovals, 5000);
    } else {
      clearInterval(state.poll.approvals);
      state.poll.approvals = 0;
    }
  });
}

async function pollApprovals() {
  if (state.pane !== "approvals" || !signedIn()) return;
  api("/approvals").then(d => { state.approvals = d?.approvals || []; renderApprovals(); }).catch(() => {});
}

wire();
boot();