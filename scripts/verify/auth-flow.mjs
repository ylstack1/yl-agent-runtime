// YL Agent Runtime — Stage 1 auth-flow verification (Node + MCP SDK)
//
// Verifies the pairing / session / MCP flow end-to-end over Streamable HTTP.
// Base URL comes from YL_RUNTIME_URL, defaulting to http://127.0.0.1:8077.
//
// Usage:
//   YL_RUNTIME_URL=http://127.0.0.1:8081 node scripts/verify/auth-flow.mjs
//
// Requires @modelcontextprotocol/sdk to be resolvable (run from a directory
// that has it in node_modules, e.g. the mcp-verify sandbox, or set NODE_PATH).

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { execFileSync } from 'node:child_process';

const baseUrl = (process.env.YL_RUNTIME_URL || 'http://127.0.0.1:8077').replace(/\/$/, '');
const port = new URL(baseUrl).port;
const YL = 'target\\debug\\yl.exe';
const env = { ...process.env, YL_RUNTIME_URL: baseUrl };
const yl = (...args) => execFileSync(YL, args, { env, encoding: 'utf8' });

const results = [];
const ok = (name, pass, detail) => {
  results.push({ name, pass: !!pass, detail: String(detail).slice(0, 300) });
};

async function connect(url, headers) {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: headers ? { headers } : undefined,
  });
  const client = new Client({ name: 'yl-auth-flow', version: '1.0.0' });
  await client.connect(transport);
  return client;
}

function makeCaller(client) {
  return async (name, args = {}) => {
    try {
      const r = await client.callTool({ name, arguments: args });
      const text = (r.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('');
      let json = null;
      try { json = JSON.parse(text); } catch {}
      return { isError: !!r.isError, text, json };
    } catch (e) {
      return { isError: true, text: String(e.message || e), json: null };
    }
  };
}

const LAN = `http://192.168.1.130:${port}/mcp`;

// --- 1. loopback MCP client works with no token (host trust) ----------------
const host = await connect(`${baseUrl}/mcp`);
const hostTools = await host.listTools();
ok('loopback client connects without a token', hostTools.tools.length > 30, `${hostTools.tools.length} tools`);

const callHost = makeCaller(host);
const roots = await callHost('workspace.allowed_roots');
ok('loopback tool call succeeds', !roots.isError, roots.text.slice(0, 160));

const read = await callHost('workspace.read', { path: 'hello.txt' });
ok(
  'workspace.read returns file content',
  !read.isError && /hello from auth test/i.test(read.text),
  read.text.slice(0, 160),
);
await host.close();

// --- 2. LAN client without a token is rejected ------------------------------
let lanDenied = false;
let lanDetail = '';
try {
  const bad = await connect(LAN);
  await bad.listTools();
  lanDetail = 'connected unexpectedly';
  await bad.close();
} catch (e) {
  lanDenied = /401|unauthor|bearer/i.test(String(e.message || e));
  lanDetail = String(e.message || e);
}
ok('LAN client without token rejected', lanDenied, lanDetail);

// --- 3. pair + authenticate, then LAN MCP client works with the token -------
const req = yl('pairing', 'request', '--name', 'verify-phone');
const code = /Pairing code:\s*(\d{6})/.exec(req)?.[1];
const seed = /Device private key \(keep secret\):\s*([0-9a-f]{64})/.exec(req)?.[1];
ok('pairing request issued', !!code && !!seed, `code=${code}`);

const approve = yl('pairing', 'approve', code);
const deviceId = /Device id:\s*([0-9a-f-]{36})/.exec(approve)?.[1];
ok('host approved pairing', !!deviceId, `device=${deviceId}`);

const auth = yl('pairing', 'authenticate', deviceId, '--key-hex', seed);
const token = /Session token:\s*(\S+)/.exec(auth)?.[1];
ok('device authenticated', !!token, `token=${token}`);

const dev = await connect(LAN, { Authorization: `Bearer ${token}` });
const devTools = await dev.listTools();
ok('LAN client connects with token', devTools.tools.length > 30, `${devTools.tools.length} tools`);

const callDev = makeCaller(dev);
const devList = await callDev('workspace.list');
ok('LAN tool call succeeds with token', !devList.isError, devList.text.slice(0, 160));
await dev.close();

// --- 4. revoke -> same token must stop working ------------------------------
yl('devices', 'revoke', deviceId);
let afterRevokeDenied = false;
let afterDetail = '';
try {
  const stale = await connect(LAN, { Authorization: `Bearer ${token}` });
  await stale.listTools();
  afterDetail = 'connected unexpectedly';
  await stale.close();
} catch (e) {
  afterRevokeDenied = /401|unauthor|revoked/i.test(String(e.message || e));
  afterDetail = String(e.message || e);
}
ok('revoked token can no longer connect', afterRevokeDenied, afterDetail);

// --- 5. host-only endpoints refuse a LAN peer -------------------------------
let pairingsDenied = false;
try {
  const p = await connect(`http://192.168.1.130:${port}/api/v1/pairings`);
  // /api/v1/pairings is a plain HTTP route, not MCP; expect a connect/listTools failure or HTTP 403.
  pairingsDenied = false;
} catch (e) {
  pairingsDenied = /401|403|unauthor|forbidden|refused/i.test(String(e.message || e));
}
ok('LAN /api/v1/pairings refused (host-only)', pairingsDenied, String(pairingsDenied ? '403/401' : 'connected'));

const failed = results.filter((r) => !r.pass);
console.log(JSON.stringify({ total: results.length, passed: results.length - failed.length, failed, results }, null, 2));
process.exit(failed.length ? 1 : 0);
