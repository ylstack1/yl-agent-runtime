# YL Agent Runtime — Android Client Integration Guide

Connect an Android app to a remote `yl serve` instance over **MCP (Streamable HTTP)** and the **management API** (`/api/v1`). Covers networking, TLS/self-signed cert, pairing + bearer auth, workspace browse/choose/open/clone, and a ready-to-use Kotlin client.

---

## 1. Architecture

```
Android app
  ├─ OKHttp + Coroutines
  ├─ MCP client  (POST https://<lan-ip>:8077/mcp, JSON-RPC)
  └─ Mgmt API client (GET/POST https://<lan-ip>:8077/api/v1/*)
        │
        ▼
yl serve (host)  ←  loopback: plain HTTP  |  LAN IPv4: TLS (self-signed cert)
```

- **MCP** = the agent tool surface (`workspace.read`, `process.exec`, `git.status`, …).
- **Management API** = admin surface (`workspaces`, `discovery/roots`, `approvals`, `devices`, `pairings`).
- Loopback (`127.0.0.1`) bypasses auth; LAN clients need **TLS + bearer token** (pairing required by default).

Start the runtime on the host:

```powershell
# one command: admin console + MCP on the same port (8077)
# opens console at http://127.0.0.1:8077/ui
# MCP at http://127.0.0.1:8077/mcp
yl admin --port 8077 --root .
```

For Android on the same Wi-Fi, bind to LAN:

```powershell
yl serve --port 8077 --root .          # binds 127.0.0.1 (plain) + 192.168.x.x (TLS)
```

Then Android dials `https://192.168.1.130:8077`.

---

## 2. Networking & TLS (Android)

`yl serve` generates a self-signed cert at `<data_dir>/tls/cert.pem` with SANs for `localhost`, `127.0.0.1`, hostname, and each LAN IPv4. Android does **not** trust self-signed certs by default.

### Option A — Trust the runtime cert (recommended)

Export the cert from the host and bundle it in `res/raw/yl_ca.pem`, then configure an `OkHttpClient` with a custom `CertificatePinner` or `X509TrustManager` that pins it:

```kotlin
val caCert = resources.openRawResource(R.raw.yl_ca).bufferedReader().use { it.readText() }
val ca = CertificateFactory.getInstance("X.509")
    .generateCertificate(caCert.byteInputStream()) as X509Certificate
val trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    .apply { init(keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).also { it.setCertificateEntry("yl", ca) }) }
    .trustManagers[0] as X509TrustManager

val client = OkHttpClient.Builder()
    .sslSocketFactory(SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }.socketFactory, trustManager)
    .hostnameVerifier { _, _ -> true } // or strict match against 192.168.1.130
    .readTimeout(30, TimeUnit.SECONDS)
    .build()
```

### Option B — Trust all (debug only)

```kotlin
// NEVER ship this to production
client = OkHttpClient.Builder()
    .hostnameVerifier { _, _ -> true }
    .certificatePinner(CertificatePinner.DEFAULT) // no pinning
    .build()
```

---

## 3. Authentication (pairing → bearer token)

LAN requests require `Authorization: Bearer <token>`. Bootstrap once:

| Step | Where | Action |
|------|-------|--------|
| 1 | Host console `yl serve --port 8077` | Note LAN IP shown at startup (`LAN console: https://192.168.1.130:8077/...`) |
| 2 | Host console UI (`/ui`) → Devices & pairings | Pair a device, copy the bearer token |
| 3 | Android | Store token in `EncryptedSharedPreferences` |
| 4 | Android | Send `Authorization: Bearer <token>` on every request |

If you want in-app pairing instead of the console, the host exposes:

```
GET    /api/v1/device          # facts (tls, pairing_required, lan_urls, fingerprint)
POST   /api/v1/pairings        # list pairings (host-only)
POST   /api/v1/pairings/{code}/approve   # host CLI: yl pairing approve CODE
```

The device-side keypair (ed25519) and token exchange mirror what the web console does with WebCrypto. For a first integration, copy the token from the host console into Android; automate pairing later.

---

## 4. Kotlin client (OKHttp + Coroutines)

Add to `build.gradle` (module):

```kotlin
implementation("com.squareup.okhttp3:okhttp:4.12.0")
implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")
implementation("com.google.code.gson:gson:2.10.1")
```

### `YlRuntimeClient.kt`

```kotlin
package com.example.ylclient

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.*
import kotlinx.coroutines.*
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.io.InputStream
import java.security.KeyStore

data class McpRequest(
    val jsonrpc: String = "2.0",
    val id: Int,
    val method: String,
    val params: Map<String, Any> = emptyMap()
)

data class McpResponse<T>(
    val jsonrpc: String?,
    val id: Int?,
    val result: T?,
    val error: Map<String, Any>?
)

data class Workspace(
    val id: String,
    val display_name: String,
    val root_id: String,
    val relative_path: String,
    val profile: String,
    val tags: List<String>,
    val registered_at: String?,
    val origin: String?,
    val available_to_agents_after_restart: Boolean?
)

data class DiscoveryRoot(
    val id: String,
    val label: String,
    val path: String,
    val enabled: Boolean,
    val browse: Boolean,
    val create: Boolean,
    val register: Boolean,
    val import: Boolean = false,
    val clone: Boolean = false,
    val synthetic: Boolean = false
)

data class DeviceFacts(
    val version: String,
    val os: String,
    val arch: String,
    val yolo: Boolean,
    val pairing_required: Boolean,
    val tls: TlsFacts,
    val workspace_count: Int,
    val discovery_roots: List<DiscoveryRoot>
) {
    data class TlsFacts(
        val enabled: Boolean,
        val fingerprint: String?,
        val urls: List<String>
    )
}

class YlRuntimeClient private constructor(
    private val client: OkHttpClient,
    private val baseUrl: String,
    private val tokenProvider: () -> String?,
    private val gson: Gson = Gson()
) {

    companion object {
        fun create(
            baseUrl: String = "https://192.168.1.130:8077",
            tokenProvider: () -> String? = { null },
            caCertInputStream: InputStream? = null
        ): YlRuntimeClient {
            val builder = OkHttpClient.Builder()
                .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
                .writeTimeout(15, java.util.concurrent.TimeUnit.SECONDS)

            caCertInputStream?.use { is ->
                val cf = CertificateFactory.getInstance("X.509")
                val ca = cf.generateCertificate(is) as X509Certificate
                val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
                ks.setCertificateEntry("yl-runtime", ca)
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
                val sslCtx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
                builder.sslSocketFactory(sslCtx.socketFactory, tmf.trustManagers[0] as javax.net.ssl.X509TrustManager)
                builder.hostnameVerifier { _, _ -> true } // relax; tighten to IP match in prod
            }

            return YlRuntimeClient(builder.build(), baseUrl, tokenProvider)
        }
    }

    private fun authHeaders(): Map<String, String> = buildMap {
        put("Content-Type", "application/json")
        put("Accept", "application/json, text/event-stream")
        tokenProvider.invoke()?.let { put("Authorization", "Bearer $it") }
    }

    // ──────── MCP ────────

    suspend fun mcpListTools(): McpResponse<List<Map<String, Any>>> =
        mcpCall("tools/list", emptyMap())

    suspend fun mcpCall(method: String, params: Map<String, Any>): McpResponse<Any> {
        val body = gson.toJson(McpRequest(id = (Math.random() * 100000).toInt(), method = method, params = params))
        val req = Request.Builder()
            .url("$baseUrl/mcp")
            .post(RequestBody.create(body, MediaType.get("application/json")!!))
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            val text = response.body?.string() ?: ""
            if (!response.isSuccessful) throw RuntimeException("MCP HTTP ${response.code}: $text")
            val parsed = gson.fromJson<McpResponse<Any>>(text, object : TypeToken<McpResponse<Any>>() {}.type)
            return parsed
        }
    }

    suspend fun mcpWorkspaceList(projectId: String, path: String = "."): McpResponse<Any> =
        mcpCall("workspace.list", mapOf("project_id" to projectId, "path" to path))

    suspend fun mcpWorkspaceRead(projectId: String, path: String, head: Int = 50): McpResponse<Any> =
        mcpCall("workspace.read", mapOf("project_id" to projectId, "path" to path, "head" to head))

    suspend fun mcpWorkspaceWrite(projectId: String, path: String, content: String, overwrite: Boolean = true): McpResponse<Any> =
        mcpCall("workspace.write", mapOf("project_id" to projectId, "path" to path, "content" to content, "overwrite" to overwrite))

    suspend fun mcpWorkspaceEdit(projectId: String, path: String, oldText: String, newText: String): McpResponse<Any> =
        mcpCall("workspace.edit", mapOf(
            "project_id" to projectId,
            "path" to path,
            "edits" to listOf(mapOf("old_text" to oldText, "new_text" to newText)),
            "expected_occurrences" to 1
        ))

    suspend fun mcpProcessExec(projectId: String, command: String, args: List<String>, timeoutSec: Int = 30): McpResponse<Any> =
        mcpCall("process.exec", mapOf("project_id" to projectId, "command" to command, "args" to args, "timeout_seconds" to timeoutSec))

    suspend fun mcpProcessDiscoverTools(): McpResponse<Any> = mcpCall("process.discover_tools", emptyMap())

    suspend fun mcpRuntimeStatus(): McpResponse<Any> = mcpCall("runtime.status", emptyMap())

    suspend fun mcpRuntimeCapabilities(): McpResponse<Any> = mcpCall("runtime.capabilities", emptyMap())

    // ──────── Management API ────────

    suspend fun getWorkspaces(): List<Workspace> {
        val req = Request.Builder()
            .url("$baseUrl/api/v1/workspaces")
            .get()
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw RuntimeException("Workspaces HTTP ${response.code}")
            val text = response.body?.string() ?: "{}"
            val map = gson.fromJson<Map<String, Any>>(text)
            val wsList = map?.get("workspaces") as? List<*> ?: emptyList()
            return wsList.mapNotNull { it as? Map<*, *> ->
                gson.fromJson(gson.toJson(it), Workspace::class.java)
            }
        }
    }

    suspend fun registerWorkspace(rootId: String, relativePath: String): Map<String, Any> {
        val body = gson.toJson(mapOf("root_id" to rootId, "relative_path" to relativePath))
        val req = Request.Builder()
            .url("$baseUrl/api/v1/workspaces/register")
            .post(RequestBody.create(body, MediaType.get("application/json")!!))
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw RuntimeException("Register HTTP ${response.code}")
            return gson.fromJson<Map<String, Any>>(response.body!!.string(), object : TypeToken<Map<String, Any>>() {}.type)
        }
    }

    suspend fun createWorkspace(rootId: String, name: String, profile: String = "development"): Map<String, Any> {
        val body = gson.toJson(mapOf("root_id" to rootId, "relative_path" to "", "name" to name, "profile" to profile))
        val req = Request.Builder()
            .url("$baseUrl/api/v1/workspaces/create")
            .post(RequestBody.create(body, MediaType.get("application/json")!!))
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw RuntimeException("Create HTTP ${response.code}")
            return gson.fromJson<Map<String, Any>>(response.body!!.string(), object : TypeToken<Map<String, Any>>() {}.type)
        }
    }

    suspend fun listRoots(): List<DiscoveryRoot> {
        val req = Request.Builder()
            .url("$baseUrl/api/v1/discovery/roots")
            .get()
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw RuntimeException("Roots HTTP ${response.code}")
            val text = response.body?.string() ?: "{}"
            val map = gson.fromJson<Map<String, Any>>(text)
            val roots = map?.get("roots") as? List<*> ?: emptyList()
            return roots.mapNotNull { it as? Map<*, *> ->
                gson.fromJson(gson.toJson(it), DiscoveryRoot::class.java)
            }
        }
    }

    suspend fun getDeviceFacts(): DeviceFacts {
        val req = Request.Builder()
            .url("$baseUrl/api/v1/device")
            .get()
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw RuntimeException("Device HTTP ${response.code}")
            return gson.fromJson<DeviceFacts>(response.body!!.string(), DeviceFacts::class.java)
        }
    }

    // clone: POST /api/v1/workspaces/{id}/clone  (needs project_id of a registered workspace root)
    suspend fun cloneGitRepo(projectId: String, gitUrl: String, intoSubdir: String? = null): Map<String, Any> {
        val args = mutableMapOf<String, Any>("git_url" to gitUrl)
        if (intoSubdir.isNotBlank()) args["into_subdir"] = intoSubdir
        val body = gson.toJson(args)
        val req = Request.Builder()
            .url("$baseUrl/api/v1/workspaces/$projectId/clone")
            .post(RequestBody.create(body, MediaType.get("application/json")!!))
            .headers(Headers.of(authHeaders()))
            .build()
        client.newCall(req).execute().use { response ->
            if (!response.isSuccessful) throw RuntimeException("Clone HTTP ${response.code}")
            return gson.fromJson<Map<String, Any>>(response.body!!.string(), object : TypeToken<Map<String, Any>>() {}.type)
        }
    }
}
```

### Usage in a ViewModel

```kotlin
class YlViewModel : ViewModel() {
    private val client = YlRuntimeClient.create(
        baseUrl = "https://192.168.1.130:8077",
        tokenProvider = { tokenStore.getToken() }, // EncryptedSharedPreferences
        caCertInputStream = resources.openRawResource(R.raw.yl_ca)
    )

    fun loadWorkspaces() = viewModelScope.launch {
        try {
            val ws = client.getWorkspaces()
            _uiState.value = _uiState.value?.copy(workspaces = ws)
        } catch (e: Exception) {
            _uiState.value = _uiState.value?.copy(error = e.message)
        }
    }

    fun chooseWorkspace(ws: Workspace) = viewModelScope.launch {
        // store chosen project_id for subsequent MCP calls
        _selectedWorkspace.value = ws
    }

    fun listFilesInWorkspace(ws: Workspace) = viewModelScope.launch {
        val result = client.mcpWorkspaceList(ws.id, ".")
        // parse result.content[0].text as JSON list of entries
    }
}
```

---

## 5. Feature map — what to expose in the Android app

| Android feature | API / MCP call | Notes |
|-----------------|---------------|-------|
| Dashboard / status | `GET /api/v1/device`, `runtime.status` | version, TLS on/off, LAN URLs, workspace count |
| Add a workspace root (folder grant) | `POST /api/v1/discovery/roots` | id, label, path, browse/create/register flags |
| Browse folders under a root | `GET /api/v1/discovery/roots/{id}/entries?path=` | path containment enforced server-side |
| Pick & register a workspace | `POST /api/v1/workspaces/register` | root_id + relative_path → workspace_id |
| New empty project folder | `POST /api/v1/workspaces/create` | name + root |
| Clone git repo into workspace | `POST /api/v1/workspaces/{id}/clone` | git_url + optional into_subdir |
| List workspace files | MCP `workspace.list` | project_id = workspace UUID |
| Read / write / edit a file | MCP `workspace.read` / `write` / `edit` | project_id + path |
| Run a command | MCP `process.exec` | project_id + command + args (needs approval first) |
| Approve / deny a request | `POST /api/v1/approvals/{id}/approve\|reject` | human consent gate |
| List paired devices | `GET /api/v1/devices`, `GET /api/v1/pairings` | host-only on loopback; remote needs token |

---

## 6. Suggested Android UI flow

1. **Connect screen** — enter LAN IP (default `192.168.1.130`) and port `8077`, test `GET /health`. Save in `SharedPreferences`.
2. **Auth screen** — if no token, show the bearer token from the host console (`/ui` → Devices) for the user to paste. Save encrypted.
3. **Workspace picker** — `GET /api/v1/workspaces` → list cards (name, path, tags, profile). Tap to select.
4. **Workspace detail** — MCP `workspace.list` on the chosen `project_id` → file tree / list. Tap a file → `workspace.read`.
5. **Actions** — "New folder" (`/workspaces/create`), "Clone git repo" (`/workspaces/{id}/clone`), "Run command" (`process.exec`).
6. **Approvals** — when `process.exec` returns approval-required, list pending via `GET /api/v1/approvals` and show Approve/Deny buttons calling `/api/v1/approvals/{id}/approve`.

---

## 7. Key gotchas

1. **`project_id` is a UUID, not a path.** After `workspace.register`, use the returned `workspace_id` as `project_id` in all MCP calls. Empty `project_id` is rejected (`invalid length: found 0`).
2. **Paths are root-relative.** `workspace.list` takes `path="."` relative to the workspace root. Absolute host paths are never exposed to the client (§7.4).
3. **Loopback bypasses auth; LAN does not.** Test on emulator with `10.0.2.2:8077` (loopback) without a token. On a real phone on Wi-Fi, use `https://192.168.x.x:8077` with a bearer token.
4. **Self-signed cert.** Bundle `cert.pem` in `res/raw` and pin it; or disable verification only in debug.
5. **PowerShell mangles JSON on the host.** When configuring the host from scripts, write JSON bodies to files and use `curl --data-binary @file`.
6. **`git.clone` and `workspace.register` need setup.** `git.clone` needs a real URL; `workspace.register` needs a real existing path under an enabled discovery root with `register: true`.

---

## 8. Minimal first-run checklist

- [ ] Host: `yl serve --port 8077 --root .` is running
- [ ] Host: note LAN IP + confirm `https://<ip>:8077/health` returns 200 (with `-k`)
- [ ] Host console: pair a device, copy bearer token
- [ ] Android: add OKHttp + Gson + coroutines
- [ ] Android: bundle `yl_ca.pem`, build pinned `OkHttpClient`
- [ ] Android: `GET /api/v1/workspaces` returns a list with token
- [ ] Android: MCP `workspace.list` with `project_id` from a registered workspace
- [ ] Android: `process.discover_tools` returns `[cargo, git, node, …]`

Save this guide as `docs/android-client-integration.md` in the repo and keep it updated as the API evolves.
