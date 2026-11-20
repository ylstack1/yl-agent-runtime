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
};

const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.className = isError ? "toast err" : "toast";
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 4000);
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

// ---- token / session ----------------------------------------------------

function signedIn() { return Boolean(state.token); }

function signOut(message) {
  state.token = "";
  sessionStorage.removeItem(TOKEN_KEY);
  $("signin").hidden = false;
  $("tabs").hidden = true;
  $("fingerprint-row").hidden = true;
  for (const pane of document.querySelectorAll(".pane")) pane.hidden = true;
  $("signout").hidden = true;
  if (message) showSigninError(message);
}

function showSigninError(message) {
  const el = $("signin-error");
  el.textContent = message;
  el.hidden = !message;
}

function useToken(token) {
  state.token = token.trim();
  sessionStorage.setItem(TOKEN_KEY, state.token);
  showSigninError("");
  boot();
}

// ---- pairing ------------------------------------------------------------

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function idb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(KEY_STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet(id) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(KEY_STORE, "readonly").objectStore(KEY_STORE).get(id);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function idbPut(id, value) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readwrite");
    tx.objectStore(KEY_STORE).put(value, id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadOrCreateKey() {
  const existing = await idbGet(KEY_ID);
  if (existing?.privateKey && existing?.publicKey) return existing;
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto unavailable — this origin is not a secure context. Use https:// or the paste-token form.");
  }
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  await idbPut(KEY_ID, pair);
  return pair;
}

function progress(text) {
  const el = $("pair-progress");
  el.hidden = false;
  el.textContent = text;
}

async function pairBrowser() {
  $("pair-browser").disabled = true;
  try {
    progress("Generating an ed25519 key in this browser…");
    const pair = await loadOrCreateKey();
    const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
    const deviceName = navigator.platform || "browser";

    progress("Requesting a pairing code…");
    const request = await fetch("/pair/request", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ device_name: deviceName, public_key_hex: hex(raw) }),
    }).then((r) => r.json());
    if (!request.pairing_code) throw new Error(request.error || "pairing request failed");

    const code = request.pairing_code;
    progress(
      `On the host run:  yl pairing approve ${code}\n\nWaiting for approval…`,
    );

    let status = null;
    for (let i = 0; i < 120; i += 1) {
      await new Promise((r) => setTimeout(r, 3000));
      const response = await fetch(`/pair/status?pairing_code=${encodeURIComponent(code)}`, {
        headers: { accept: "application/json" },
      });
      status = await response.json();
      if (status.state === "approved" && status.device_id) break;
      if (status.state === "rejected" || status.state === "expired") {
        throw new Error(`pairing ${status.state}`);
      }
    }
    if (!status?.device_id) throw new Error("pairing was not approved in time");

    progress("Signing the device challenge…");
    const signature = await crypto.subtle.sign(
      { name: "Ed25519" },
      pair.privateKey,
      new TextEncoder().encode(status.device_id),
    );
    const auth = await fetch("/pair/authenticate", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ device_id: status.device_id, signature_hex: hex(signature) }),
    }).then((r) => r.json());
    if (!auth.token) throw new Error(auth.error || "authentication failed");

    $("pair-progress").hidden = true;
    useToken(auth.token);
    scheduleRefresh();
  } catch (error) {
    progress(`Pairing failed: ${error.message}`);
  } finally {
    $("pair-browser").disabled = false;
  }
}

// Silent re-sign every 19 minutes so an open console never expires mid-use.
function scheduleRefresh() {
  clearInterval(scheduleRefresh.timer);
  scheduleRefresh.timer = setInterval(async () => {
    try {
      const pair = await idbGet(KEY_ID);
      if (!pair) return;
      const me = await api("/device").catch(() => null);
      if (!me) return;
      const response = await fetch("/api/v1/device", {
        headers: { authorization: `Bearer ${state.token}`, accept: "application/json" },
      });
      if (response.status !== 401) return;
      // Fall through: sign in again with the stored key.
      const status = await fetch("/pair/list", { headers: { accept: "application/json" } });
      if (!status.ok) return;
    } catch {
      /* keep the token; the next call will 401 and show the sign-in view */
    }
  }, 19 * 60 * 1000);
}

// ---- header -------------------------------------------------------------

function renderHeader() {
  const facts = state.facts;
  if (!facts) return;
  $("version").textContent = `v${facts.version} · ${facts.os}/${facts.arch}`;
  const secure = location.protocol === "https:";
  const isLoopback = ["127.0.0.1", "localhost", "::1"].includes(location.hostname);
  const badge = $("transport-badge");
  const dot = $("transport-dot");
  if (isLoopback) {
    badge.textContent = `Local · ${location.origin}`;
    badge.className = "badge ok";
    dot.className = "dot local";
  } else if (secure) {
    badge.textContent = `LAN · ${location.origin} (self-signed)`;
    badge.className = "badge ok";
    dot.className = "dot lan";
  } else {
    badge.textContent = `LAN · ${location.origin} (PLAINTEXT)`;
    badge.className = "badge warn";
    dot.className = "dot offline";
  }
  $("yolo-badge").hidden = !facts.yolo;
  const fingerprint = facts.tls?.fingerprint;
  if (fingerprint) {
    $("fingerprint").textContent = fingerprint;
    $("fingerprint-row").hidden = false;
  }
}

// ---- panes --------------------------------------------------------------

async function showPane(name) {
  state.pane = name;
  for (const button of document.querySelectorAll("#tabs button")) {
    button.classList.toggle("active", button.dataset.pane === name);
  }
  for (const pane of document.querySelectorAll(".pane")) {
    pane.hidden = pane.id !== `pane-${name}`;
  }
  try {
    if (name === "roots") await renderRoots();
    if (name === "browse") await renderBrowse();
    if (name === "workspaces") await renderWorkspaces();
    if (name === "approvals") await renderApprovals();
    if (name === "devices") await renderDevices();
    if (name === "manage") await renderWorkspaceManage();
  } catch (error) {
    toast(error.message, true);
  }
}

function chip(text, on = false, extra = "") {
  return `<span class="chip ${on ? "on" : ""} ${extra}">${esc(text)}</span>`;
}

async function renderRoots() {
  const { roots } = await api("/discovery/roots");
  const list = $("roots-list");
  loadRootSuggestions().catch(() => {});
  if (!roots.length) {
    list.innerHTML = `<div class="empty">No roots yet. Add a folder above to get started.</div>`;
    return;
  }
  list.innerHTML = roots.map((root) => `
    <div class="card ${root.enabled ? "" : "disabled"}">
      <div class="title">
        <strong>${esc(root.label)}</strong>
        <label class="toggle">
          <input type="checkbox" data-root-toggle="${esc(root.id)}" ${root.enabled ? "checked" : ""} />
          enabled
        </label>
      </div>
      <div class="meta">
        <span><code>${esc(root.id)}</code></span>
        ${root.synthetic ? chip("from workspace root", false, "synthetic") : ""}
      </div>
      <div class="meta">
        ${chip("browse", root.browse)}${chip("register", root.register)}${chip("create", root.create)}${chip("import", root.import)}${chip("clone", root.clone)}
      </div>
      <div class="actions">
        <button class="secondary" data-browse-root="${esc(root.id)}" ${root.enabled && root.browse ? "" : "disabled"}>Browse</button>
        ${root.synthetic ? "" : `<button class="danger" data-remove-root="${esc(root.id)}">Remove root</button>`}
      </div>
    </div>`).join("");

  for (const input of list.querySelectorAll("[data-root-toggle]")) {
    input.addEventListener("change", async () => {
      const id = input.dataset.rootToggle;
      try {
        await api(`/discovery/roots/${encodeURIComponent(id)}`, {
          method: "PATCH",
          body: { enabled: input.checked },
        });
        toast(`Root ${id} ${input.checked ? "enabled" : "disabled"} (saved)`);
        await renderRoots();
      } catch (error) {
        input.checked = !input.checked;
        toast(error.message, true);
      }
    });
  }
  for (const button of list.querySelectorAll("[data-browse-root]")) {
    button.addEventListener("click", () => {
      state.browse = { rootId: button.dataset.browseRoot, path: "" };
      showPane("browse");
    });
  }
  for (const button of list.querySelectorAll("[data-remove-root]")) {
    button.addEventListener("click", async () => {
      const id = button.dataset.removeRoot;
      if (!confirm(`Remove root "${id}"? Workspaces already registered from it stay registered.`)) return;
      try {
        await api(`/discovery/roots/${encodeURIComponent(id)}`, { method: "DELETE" });
        toast(`Root ${id} removed`);
        await renderRoots();
      } catch (error) {
        toast(error.message, true);
      }
    });
  }
}

async function loadRootSuggestions() {
  const datalist = $("root-suggestions");
  if (!datalist || datalist.dataset.loaded) return;
  const { suggestions } = await api("/discovery/roots/suggestions");
  datalist.innerHTML = (suggestions || [])
    .map((item) => `<option value="${esc(item.path)}">${esc(item.label)}</option>`)
    .join("");
  datalist.dataset.loaded = "1";
}

function suggestRootId(label) {
  return String(label || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
}

async function addRoot(event) {
  event.preventDefault();
  const path = $("root-path").value.trim();
  if (!path) {
    toast("Enter a folder path", true);
    return;
  }
  const parts = path.replace(/[\\/]+$/, "").split(/[\\/]/);
  const fallbackLabel = parts[parts.length - 1] || "Root";
  const label = $("root-label").value.trim() || fallbackLabel;
  const id = $("root-id").value.trim() || suggestRootId(label) || `root-${Date.now()}`;
  try {
    await api("/discovery/roots", {
      method: "POST",
      body: {
        id,
        label,
        path,
        enabled: true,
        browse: $("root-browse").checked,
        register: $("root-register").checked,
        create: $("root-create").checked,
      },
    });
    $("add-root-form").reset();
    toast(`Root ${id} added`);
    await renderRoots();
  } catch (error) {
    toast(error.message, true);
  }
}

async function renderBrowse() {
  const { rootId, path } = state.browse;
  if (!rootId) {
    $("entries").innerHTML = `<div class="empty">Pick a root in the Roots tab.</div>`;
    $("breadcrumb").innerHTML = "";
    return;
  }
  const query = new URLSearchParams({ path });
  const data = await api(`/discovery/roots/${encodeURIComponent(rootId)}/entries?${query}`);
  const parts = path ? path.split("/") : [];
  const crumbs = [`<button data-crumb="">${esc(rootId)}</button>`];
  parts.forEach((part, index) => {
    const target = parts.slice(0, index + 1).join("/");
    crumbs.push(`<span>/</span><button data-crumb="${esc(target)}">${esc(part)}</button>`);
  });
  $("breadcrumb").innerHTML = crumbs.join(" ");
  for (const crumb of $("breadcrumb").querySelectorAll("[data-crumb]")) {
    crumb.addEventListener("click", () => {
      state.browse.path = crumb.dataset.crumb;
      renderBrowse().catch((e) => toast(e.message, true));
    });
  }

  const entries = data.entries || [];
  if (!entries.length) {
    $("entries").innerHTML = `<div class="empty">Empty directory.</div>`;
    return;
  }
  $("entries").innerHTML = entries.map((entry) => {
    const next = path ? `${path}/${entry.name}` : entry.name;
    const isDir = entry.kind === "directory";
    return `<button class="entry" data-kind="${esc(entry.kind)}" data-path="${esc(next)}">
      <span class="kind">${isDir ? "▸" : "·"}</span>
      <span class="name">${esc(entry.name)}</span>
      <span class="size">${isDir ? "" : formatSize(entry.size)}</span>
    </button>`;
  }).join("");
  for (const button of $("entries").querySelectorAll(".entry")) {
    button.addEventListener("click", () => {
      if (button.dataset.kind !== "directory") return;
      state.browse.path = button.dataset.path;
      renderBrowse().catch((e) => toast(e.message, true));
    });
  }
}

function formatSize(bytes) {
  if (bytes === null || bytes === undefined) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

async function renderWorkspaces() {
  const [{ workspaces }, { roots }] = await Promise.all([
    api("/workspaces"),
    api("/discovery/roots"),
  ]);
  fillRootSelect($("create-root"), roots);
  fillRootSelect($("clone-root"), roots);
  const list = $("workspaces-list");
  if (!workspaces.length) {
    list.innerHTML = `<div class="empty">No workspaces registered yet.</div>`;
    return;
  }
  list.innerHTML = workspaces.map((workspace) => `
    <div class="card">
      <div class="title"><strong>${esc(workspace.display_name)}</strong>${chip(workspace.profile)}</div>
      <div class="meta"><code>${esc(workspace.root_id ?? "?")}/${esc(workspace.relative_path ?? "")}</code></div>
      <div class="meta"><span>registered ${esc(workspace.registered_at)}</span></div>
      <div class="actions">
        <button class="secondary" data-manage="${esc(workspace.id)}">Manage</button>
        <button class="danger" data-unregister="${esc(workspace.id)}">Unregister</button>
      </div>
    </div>`).join("");
  for (const button of list.querySelectorAll("[data-manage]")) {
    button.addEventListener("click", () => {
      state.manageWorkspaceId = button.dataset.manage;
      showPane("manage");
    });
  }
  for (const button of list.querySelectorAll("[data-unregister]")) {
    button.addEventListener("click", async () => {
      if (!confirm("Unregister this workspace? Files are never deleted.")) return;
      try {
        await api(`/workspaces/${encodeURIComponent(button.dataset.unregister)}`, { method: "DELETE" });
        toast("Workspace unregistered");
        await renderWorkspaces();
      } catch (error) {
        toast(error.message, true);
      }
    });
  }
}

async function renderWorkspaceManage() {
  const id = state.manageWorkspaceId;
  if (!id) {
    showPane("workspaces");
    return;
  }
  let workspace;
  try {
    workspace = await api(`/workspaces/${encodeURIComponent(id)}`);
  } catch (error) {
    toast(error.message, true);
    showPane("workspaces");
    return;
  }
  $("manage-breadcrumb").textContent = `${esc(workspace.display_name)} · ${esc(workspace.root_id ?? "?")}/${esc(workspace.relative_path ?? "")}`;
  $("manage-display-name").value = workspace.display_name || "";
  $("manage-profile").value = workspace.profile || "development";

  // Settings
  let settings;
  try {
    settings = await api(`/workspaces/${encodeURIComponent(id)}/settings`);
  } catch (error) {
    settings = { allow: [], deny: [], framework: null, toolchain: null };
  }
  $("manage-framework").value = settings.framework || "";
  $("manage-toolchain").value = settings.toolchain || "";
  $("manage-allow").value = Array.isArray(settings.allow) ? settings.allow.join(", ") : "";
  $("manage-deny").value = Array.isArray(settings.deny) ? settings.deny.join(", ") : "";

  // Devices
  let devices;
  try {
    devices = await api(`/workspaces/${encodeURIComponent(id)}/devices`);
  } catch (error) {
    devices = { device_ids: [] };
  }
  const deviceList = $("manage-devices");
  const ids = Array.isArray(devices.device_ids) ? devices.device_ids : [];
  if (!ids.length) {
    deviceList.innerHTML = `<div class="empty">No devices bound to this workspace.</div>`;
  } else {
    deviceList.innerHTML = ids.map((did) => `
      <div class="card">
        <div class="title"><code>${esc(did)}</code></div>
        <div class="actions">
          <button class="danger" data-unbind="${esc(did)}">Unbind</button>
        </div>
      </div>`).join("");
    for (const button of deviceList.querySelectorAll("[data-unbind]")) {
      button.addEventListener("click", async () => {
        try {
          await api(`/workspaces/${encodeURIComponent(id)}/devices/${encodeURIComponent(button.dataset.unbind)}`, { method: "DELETE" });
          toast("Device unbound");
          await renderWorkspaceManage();
        } catch (error) {
          toast(error.message, true);
        }
      });
    }
  }

  // Form submit
  $("manage-settings-form").onsubmit = async (event) => {
    event.preventDefault();
    const allow = $("manage-allow").value.split(",").map((s) => s.trim()).filter(Boolean);
    const deny = $("manage-deny").value.split(",").map((s) => s.trim()).filter(Boolean);
    try {
      await api(`/workspaces/${encodeURIComponent(id)}/settings`, {
        method: "PATCH",
        body: {
          allow,
          deny,
          framework: $("manage-framework").value || null,
          toolchain: $("manage-toolchain").value || null,
        },
      });
      toast("Settings saved");
    } catch (error) {
      toast(error.message, true);
    }
  };

  $("manage-bind-btn").onclick = async () => {
    const deviceId = $("manage-bind-device").value.trim();
    if (!deviceId) return;
    try {
      await api(`/workspaces/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}`, { method: "POST", body: {} });
      toast("Device bound");
      $("manage-bind-device").value = "";
      await renderWorkspaceManage();
    } catch (error) {
      toast(error.message, true);
    }
  };

  $("manage-unregister").onclick = async () => {
    if (!confirm("Unregister this workspace? Files are never deleted.")) return;
    try {
      await api(`/workspaces/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast("Workspace unregistered");
      state.manageWorkspaceId = null;
      await renderWorkspaces();
      showPane("workspaces");
    } catch (error) {
      toast(error.message, true);
    }
  };
}

async function renderApprovals() {
  const { approvals } = await api("/approvals");
  const list = $("approvals-list");
  if (!approvals.length) {
    list.innerHTML = `<div class="empty">No pending approvals.</div>`;
    return;
  }
  list.innerHTML = approvals.map((approval) => `
    <div class="card">
      <div class="title"><strong>${esc(approval.justification || approval.capability)}</strong></div>
      <div class="meta"><code>${esc(approval.resource ?? "")}</code></div>
      <div class="meta"><span>${esc(approval.capability)}</span><span>expires ${esc(approval.expires_at ?? "—")}</span></div>
      <div class="actions">
        <button class="primary" data-approve="${esc(approval.id)}">Approve</button>
        <button class="danger" data-reject="${esc(approval.id)}">Reject</button>
      </div>
    </div>`).join("");
  for (const button of list.querySelectorAll("[data-approve]")) {
    button.addEventListener("click", () => decide(button.dataset.approve, "approve"));
  }
  for (const button of list.querySelectorAll("[data-reject]")) {
    button.addEventListener("click", () => decide(button.dataset.reject, "reject"));
  }
}

async function decide(id, action) {
  try {
    await api(`/approvals/${encodeURIComponent(id)}/${action}`, { method: "POST", body: {} });
    toast(action === "approve" ? "Approved" : "Rejected");
    await renderApprovals();
  } catch (error) {
    toast(error.message, true);
  }
}

async function renderDevices() {
  const loopback = ["127.0.0.1", "localhost", "::1"].includes(location.hostname);
  $("devices-note").textContent = loopback
    ? "Host view: approving a pairing here is allowed."
    : "Device and pairing management is host-only. Open the console on the host to approve pairings.";
  try {
    const { pairings } = await api("/pairings");
    const list = $("pairings-list");
    const pending = (pairings || []).filter((p) => p.state === "pending");
    list.innerHTML = pending.length
      ? pending.map((pairing) => `
        <div class="card">
          <div class="title"><strong>${esc(pairing.device_name)}</strong><span><code>${esc(pairing.pairing_code)}</code></span></div>
          <div class="meta"><span>expires ${esc(pairing.expires_at)}</span></div>
          <div class="actions">
            <button class="primary" data-approve-code="${esc(pairing.pairing_code)}" ${loopback ? "" : "disabled"}>Approve</button>
            <button class="danger" data-reject-code="${esc(pairing.pairing_code)}" ${loopback ? "" : "disabled"}>Reject</button>
          </div>
        </div>`).join("")
      : `<div class="empty">No pending pairings.</div>`;
    for (const button of list.querySelectorAll("[data-approve-code]")) {
      button.addEventListener("click", () => decidePairing(button.dataset.approveCode, "approve"));
    }
    for (const button of list.querySelectorAll("[data-reject-code]")) {
      button.addEventListener("click", () => decidePairing(button.dataset.rejectCode, "reject"));
    }
  } catch (error) {
    $("pairings-list").innerHTML = `<div class="empty">${esc(error.message)}</div>`;
  }

  try {
    const { devices } = await api("/devices");
    const list = $("devices-list");
    list.innerHTML = (devices || []).map((device) => `
      <div class="card ${device.is_revoked ? "disabled" : ""}">
        <div class="title"><strong>${esc(device.name)}</strong>${chip(device.is_revoked ? "revoked" : "active", !device.is_revoked)}</div>
        <div class="meta"><code>${esc(device.fingerprint)}</code></div>
        <div class="actions">
          <button class="danger" data-revoke="${esc(device.id)}" ${device.is_revoked ? "disabled" : ""}>Revoke</button>
        </div>
      </div>`).join("") || `<div class="empty">No paired devices.</div>`;
    for (const button of list.querySelectorAll("[data-revoke]")) {
      button.addEventListener("click", async () => {
        if (!confirm("Revoke this device? Its sessions stop working immediately.")) return;
        try {
          await api(`/devices/${encodeURIComponent(button.dataset.revoke)}/revoke`, { method: "POST", body: {} });
          toast("Device revoked");
          await renderDevices();
        } catch (error) {
          toast(error.message, true);
        }
      });
    }
  } catch (error) {
    $("devices-list").innerHTML = `<div class="empty">${esc(error.message)}</div>`;
  }
}

async function decidePairing(code, action) {
  try {
    await api(`/pairings/${encodeURIComponent(code)}/${action}`, { method: "POST", body: {} });
    toast(action === "approve" ? "Pairing approved" : "Pairing rejected");
    await renderDevices();
  } catch (error) {
    toast(error.message, true);
  }
}

// ---- browse actions -----------------------------------------------------

async function registerHere() {
  const { rootId, path } = state.browse;
  if (!rootId) return toast("Pick a root first", true);
  try {
    const result = await api("/workspaces/register", {
      method: "POST",
      body: { root_id: rootId, relative_path: path, profile: "development" },
    });
    toast(result.already_registered
      ? "Already registered — reused the existing workspace"
      : "Registered (agents see it after yl serve restarts)");
  } catch (error) {
    toast(error.message, true);
  }
}

async function detectHere() {
  const { rootId, path } = state.browse;
  if (!rootId) return toast("Pick a root first", true);
  try {
    const result = await api("/projects/detect", {
      method: "POST",
      body: { root_id: rootId, relative_path: path },
    });
    const panel = $("detect-result");
    panel.hidden = false;
    panel.innerHTML = `
      <div><strong>${esc(result.project_types.join(", ") || "unknown")}</strong></div>
      <div class="muted">markers: ${esc(result.markers.join(", ") || "none")}</div>
      <div class="muted">git: ${result.git_present ? esc(result.git_branch || "yes") : "no"} · confidence ${esc(result.confidence)}</div>`;
  } catch (error) {
    toast(error.message, true);
  }
}

async function createHere() {
  const { rootId, path } = state.browse;
  if (!rootId) return toast("Pick a root first", true);
  const name = prompt("New project directory name");
  if (!name) return;
  try {
    const result = await api("/workspaces/create", {
      method: "POST",
      body: { root_id: rootId, relative_path: path, name, profile: "development" },
    });
    toast(result.already_registered ? "Created and registered" : "Project created");
    await renderBrowse();
  } catch (error) {
    toast(error.message, true);
  }
}

async function newWorkspace(event) {
  event.preventDefault();
  const rootId = $("create-root").value;
  const name = $("create-name").value.trim();
  if (!rootId) return toast("Add a discovery root first", true);
  if (!name) return toast("Enter a folder name", true);
  try {
    const result = await api("/workspaces/create", {
      method: "POST",
      body: { root_id: rootId, relative_path: "", name, profile: "development" },
    });
    $("create-name").value = "";
    toast(result.already_registered ? "Folder existed — registered it" : "Workspace created");
    await renderWorkspaces();
  } catch (error) {
    toast(error.message, true);
  }
}

async function cloneWorkspace(event) {
  event.preventDefault();
  const rootId = $("clone-root").value;
  const gitUrl = $("clone-url").value.trim();
  const into = $("clone-dir").value.trim();
  if (!rootId) return toast("Add a discovery root first", true);
  if (!gitUrl) return toast("Enter a git URL", true);
  const submit = event.target.querySelector("button[type=submit]");
  submit.disabled = true;
  submit.textContent = "Cloning…";
  try {
    // The root itself is the parent workspace; the clone lands one level
    // below it and is registered as its own workspace.
    const parent = await api("/workspaces/register", {
      method: "POST",
      body: { root_id: rootId, relative_path: "", profile: "development" },
    });
    await api(`/workspaces/${encodeURIComponent(parent.workspace_id)}/clone`, {
      method: "POST",
      body: { git_url: gitUrl, into_subdir: into },
    });
    $("clone-url").value = "";
    $("clone-dir").value = "";
    toast("Repository cloned and registered");
    await renderWorkspaces();
  } catch (error) {
    toast(error.message, true);
  } finally {
    submit.disabled = false;
    submit.textContent = "Clone and register";
  }
}

function fillRootSelect(select, roots) {
  const usable = roots.filter((root) => root.enabled && root.create);
  select.innerHTML = usable.length
    ? usable.map((root) => `<option value="${esc(root.id)}">${esc(root.label)} (${esc(root.id)})</option>`).join("")
    : `<option value="">No root allows create</option>`;
}

// ---- boot ---------------------------------------------------------------

async function boot() {
  if (!signedIn()) {
    $("signin").hidden = false;
    return;
  }
  $("signin").hidden = true;
  $("tabs").hidden = false;
  $("signout").hidden = false;
  try {
    state.facts = await api("/device");
  } catch {
    return;
  }
  renderHeader();
  await showPane(state.pane || "roots");
}

function wire() {
  $("token-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const token = $("token-input").value.trim();
    if (token) useToken(token);
  });
  $("pair-browser").addEventListener("click", pairBrowser);
  $("signout").addEventListener("click", () => signOut(""));
  $("copy-fingerprint").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("fingerprint").textContent);
      toast("Fingerprint copied");
    } catch {
      toast("Copy failed", true);
    }
  });
  $("register-here").addEventListener("click", registerHere);
  $("add-root-form").addEventListener("submit", addRoot);
  $("detect-project").addEventListener("click", detectHere);
  $("create-here").addEventListener("click", createHere);
  $("create-workspace-form").addEventListener("submit", newWorkspace);
  $("clone-workspace-form").addEventListener("submit", cloneWorkspace);
  $("manage-back").addEventListener("click", () => {
    state.manageWorkspaceId = null;
    showPane("workspaces");
  });
  $("manage-clone").addEventListener("click", async () => {
    const id = state.manageWorkspaceId;
    if (!id) return;
    const gitUrl = prompt("Git repository URL to clone");
    if (!gitUrl) return;
    const into = prompt("Clone into subdirectory name (leave empty for auto)");
    try {
      await api(`/workspaces/${encodeURIComponent(id)}/clone`, {
        method: "POST",
        body: { git_url: gitUrl, into_subdir: into || "" },
      });
      toast("Workspace cloned");
      await renderWorkspaceManage();
    } catch (error) {
      toast(error.message, true);
    }
  });

  for (const button of document.querySelectorAll("#tabs button")) {
    button.addEventListener("click", () => showPane(button.dataset.pane));
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearInterval(state.poll.approvals);
      clearInterval(state.poll.devices);
      return;
    }
    state.poll.approvals = setInterval(() => {
      if (state.pane === "approvals" && signedIn()) renderApprovals().catch(() => {});
    }, 5000);
    state.poll.devices = setInterval(() => {
      if (state.pane === "devices" && signedIn()) renderDevices().catch(() => {});
    }, 10000);
  });
}

wire();
boot();
