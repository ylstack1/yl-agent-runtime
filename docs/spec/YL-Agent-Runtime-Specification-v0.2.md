# YL Agent Runtime

## Unified Portable Agent Execution Runtime --- Product Requirements & Technical Specification

**Document status:** Proposed architecture / implementation-ready PRD\
**Version:** 0.2.0\
**Date:** 2026-11-16\
**Product:** YL Agent Runtime (YL Stack)\
**Relationship:** Reusable execution layer for YLAgentsOS and
third-party AI agents\
**Primary development host:** Windows 10/11 x64\
**Target platforms:** Windows, Linux, macOS\
**Core implementation:** Rust\
**Desktop control center:** Tauri 2\
**Agent protocol:** MCP first, versioned local/remote runtime API\
**Networking:** Iroh optional transport\
**Default execution mode:** Native host execution with explicit policy
enforcement\
**Strong isolation:** OS-native sandbox backend; optional VM/microVM
backend

------------------------------------------------------------------------

# 1. Executive Summary

YL Agent Runtime is a lightweight, portable execution service that gives
AI agents controlled access to real development environments. It is not
an AI model, coding agent, IDE, container manager, or remote desktop
product. It is the execution and policy layer between an agent and the
operating system.

An authorized agent must be able to:

-   Inspect repositories and project structure.
-   Read, create, edit, move and delete project files.
-   Search source code and inspect Git state.
-   Run CMD, PowerShell, Bash, Zsh or other available shells as
    appropriate.
-   Discover and use installed toolchains without bundling them.
-   Install project dependencies when policy permits.
-   Build, test, lint, format, debug and run applications.
-   Manage long-running development processes and interactive terminal
    sessions.
-   Receive structured stdout, stderr, exit codes, process state and
    resource information.
-   Request additional capabilities and obtain human approval when
    required.
-   Connect locally or remotely from compatible agents and trusted
    devices.

The runtime must preserve the user's actual host development
environment. On Windows, this means native Windows paths, installed
Node.js/Bun/Python/Git/Rust/Java/Android tooling, CMD and
PowerShell---not a Linux compatibility layer pretending to be Windows.

## 1.1 Core product principle

**One portable runtime API, multiple platform-specific execution
backends.**

Agents use the same capability model on every platform. The runtime
selects the strongest supported native enforcement backend for that host
and reports exactly what protections are active. Portability must never
mean silently weakening security.

## 1.2 Product positioning

-   A standalone background runtime and tray application.
-   A reusable engine that other agent products can embed or connect to.
-   A local MCP server for coding agents.
-   An optional secure remote execution endpoint.
-   A backend for YLAgentsOS and other compatible clients.

------------------------------------------------------------------------

# 2. Product Goals and Non-Goals

## 2.1 Goals

1.  Native development execution on Windows, Linux and macOS.
2.  Windows 10 remains a first-class target; Windows 11-only features
    are optional.
3.  Consistent project, process, terminal and approval APIs across
    platforms.
4.  Real repository editing, dependency installation, builds and tests.
5.  OS-enforced isolation where the platform supports it.
6.  Explicit capability reporting and fail-closed behavior for required
    security controls.
7.  Per-agent, per-device, per-session and per-project authorization.
8.  Local-first operation; remote connectivity is optional.
9.  Small idle footprint, fast startup and no mandatory language
    runtimes.
10. Open protocol compatibility through MCP and documented APIs.
11. Pluggable backends, terminal providers and transport providers.
12. Auditable, testable and maintainable Rust architecture.

## 2.2 Non-goals

-   Building an LLM or autonomous coding agent.
-   Replacing Git, IDEs, terminals, package managers or build systems.
-   Bundling Node.js, Python, Java, Rust, Android SDK or other developer
    toolchains.
-   Requiring Docker, WSL, SSH, Kubernetes or a cloud account.
-   Treating a project working directory as a complete security sandbox.
-   Providing unrestricted remote desktop access.
-   Running normal agent work as Administrator, root or SYSTEM.
-   Making a VM mandatory for ordinary trusted local development.
-   Reimplementing mature open-source sandbox, transport or protocol
    projects without a demonstrated need.

------------------------------------------------------------------------

# 3. Design Principles

## 3.1 Reuse before reimplementation

Use mature libraries and projects when their license, maintenance,
security model, platform support and API fit are verified. Borrow
architecture and tested patterns; do not copy code without reviewing the
exact license and notices.

## 3.2 Separate policy from enforcement

The policy engine decides what is allowed. Platform backends enforce
those decisions. A policy decision is not proof of enforcement: the
runtime must return a machine-readable enforcement report.

## 3.3 Native first, isolated when needed

Trusted development tasks should use native host toolchains under
controlled permissions. Untrusted repositories, agent-generated scripts
and risky build hooks should use a stronger sandbox profile or
disposable VM.

## 3.4 No silent downgrade

If a requested policy requires filesystem isolation, network denial or
resource limits and the host cannot enforce it, reject the execution or
ask the user to explicitly choose a weaker profile. Never label an
unsandboxed process as sandboxed.

## 3.5 Capability-oriented API

Agents request named capabilities such as `workspace.read`,
`workspace.write`, `process.exec`, `terminal.interactive`,
`network.proxy` or `git.commit`. They do not receive ambient
unrestricted access by default.

## 3.6 Keep the core small

The daemon must not contain an LLM, browser engine, package manager,
language runtime or VM image. Desktop UI and optional integrations must
not be required for headless execution.

------------------------------------------------------------------------

# 4. Target Platforms and Portability

  ---------------------------------------------------------------------------
  Platform          Native execution    Isolation backend   Initial support
  ----------------- ------------------- ------------------- -----------------
  Windows 10 x64    CMD, PowerShell,    Restricted token /  P0
                    native Win32        Job Objects;        
                    processes           AppContainer where  
                                        supported and       
                                        verified            

  Windows 11 x64    Same as Windows 10  AppContainer, Job   P0
                                        Objects, restricted 
                                        tokens and          
                                        mitigation policies 

  Linux x64/ARM64   Native shells and   Landlock, seccomp,  P1
                    processes           namespaces, cgroups 
                                        v2 where available  

  macOS Apple       Native shells and   Seatbelt sandbox    P1
  Silicon/Intel     processes           profiles and        
                                        process limits      

  Android           Not a general host  Client/controller   Later
                    build-execution     only initially      
                    target                                  

  iOS               Client/controller   No local arbitrary  Later
                    only                process execution   
  ---------------------------------------------------------------------------

Portability is defined at the API and policy level. The implementation
is allowed---and expected---to use different kernel primitives on each
operating system.

## 4.1 Platform capability probing

At startup, each backend must probe and report:

-   OS and version.
-   Architecture.
-   Available sandbox mechanisms.
-   Filesystem restriction support.
-   Network restriction support.
-   Process-tree and resource limit support.
-   Interactive terminal support.
-   Required privileges or setup.
-   Unsupported policy fields.
-   Whether enforcement is active, partial, unavailable or not
    requested.

Example report:

``` json
{
  "platform": "windows",
  "sandbox_backend": "restricted_token_job",
  "filesystem_write_isolation": "enforced",
  "filesystem_read_isolation": "partial",
  "network_isolation": "unavailable",
  "process_tree_limit": "enforced",
  "memory_limit": "enforced",
  "overall": "partial"
}
```

Do not use a single boolean `sandboxed` field.

------------------------------------------------------------------------

# 5. Open-Source Research and Reuse Strategy

The following projects are architectural references or integration
candidates. Their exact versions, licenses, maintenance state, supported
OS versions and transitive dependencies must be rechecked before pinning
them in the implementation.

## 5.1 Reuse matrix

  ------------------------------------------------------------------------------
  Project           Borrow / reuse        Proposed role     Important caveat
  ----------------- --------------------- ----------------- --------------------
  GAL               Product architecture, Reference agent   GAL is a complete
                    safe-mode UX, policy  and integration   agent application,
                    hooks, audit and      target            not assumed to be a
                    privilege escalation                    reusable runtime
                    patterns; optional                      library. Verify
                    integration                             source/API
                                                            availability before
                                                            attempting engine
                                                            embedding.

  Anthropic Sandbox Sandbox policy        Security          It is
  Runtime           concepts,             architecture      TypeScript-based and
                    filesystem/network    reference;        platform-specific.
                    dual enforcement,     possible          Do not make the Rust
                    violation reporting   subprocess        core depend on it
                                          integration where without a strong
                                          appropriate       reason.

  Arapuca           High-priority Rust    Evaluate as an    Verify actual
                    sandbox backend       embeddable        Windows 10
                    candidate             cross-platform    compatibility, API
                                          process sandbox   stability, feature
                                                            maturity and license
                                                            before adoption.
                                                            MicroVM support is
                                                            experimental and
                                                            Linux-specific in
                                                            the documented
                                                            design.

  skarn-sandbox     Rust unified policy   Alternative       Compare Windows
                    abstraction and       sandbox crate     behavior,
                    backend-report        candidate         maintenance, license
                    pattern                                 and required kernel
                                                            features against
                                                            Arapuca.

  LocalForge MCP    Workspace APIs,       Reference         Python
                    process lifecycle,    implementation    implementation;
                    command handling,     and test-case     application-level
                    path validation and   source            mediation is not an
                    security                                OS boundary. MIT
                    documentation                           license reported;
                                                            verify repository
                                                            license.

  Iroh              Encrypted peer        Optional remote   Not an authorization
                    connectivity, relay   transport         system. Runtime
                    fallback, endpoint                      still needs pairing,
                    identity                                identity binding,
                                                            permissions, replay
                                                            protection and
                                                            revocation.

  Official Rust MCP Protocol              MCP server/client Pin a stable release
  SDK (`rmcp`)      implementation        integration       and track protocol
                                                            compatibility.

  Tauri 2           Desktop shell,        Optional desktop  Keep UI outside the
                    tray/control-center   application       daemon's trusted
                    UI                                      computing base where
                                                            possible.

  ConPTY / portable Terminal session      Windows ConPTY    Compare maintenance
  PTY libraries     implementation        and Unix PTY      and interactive
                                          adapters          behavior; avoid
                                                            custom terminal
                                                            emulation.

  Virtx             Disposable Linux      Optional Windows  Not a Windows 10
                    execution             11+ /             baseline dependency.
                    environments          supported-host    Verify host
                                          Linux VM backend  requirements and
                                                            mount dependencies.
  ------------------------------------------------------------------------------

## 5.2 Project links

-   GAL: https://agent-home.ai/
-   GAL documentation: https://agent-home.ai/docs/core-features.html
-   Anthropic Sandbox Runtime:
    https://github.com/anthropics/sandbox-runtime
-   Arapuca: https://github.com/LeGambiArt/arapuca
-   skarn-sandbox: https://docs.rs/skarn-sandbox/latest/skarn_sandbox/
-   LocalForge MCP: https://github.com/takattowo/localforge-mcp
-   Iroh: https://github.com/n0-computer/iroh
-   Official Rust MCP SDK:
    https://github.com/modelcontextprotocol/rust-sdk
-   Tauri: https://github.com/tauri-apps/tauri
-   Virtx: https://github.com/brekkylab/virtx
-   ConPTY Rust candidate: https://github.com/zhiburt/conpty

## 5.3 Mandatory reuse due diligence

Before adopting any repository or crate:

1.  Verify the canonical upstream repository and owner.
2.  Read the exact LICENSE file at the pinned commit/tag.
3.  Record SPDX identifier and required notices.
4.  Review dependency licenses and native binaries.
5.  Inspect release cadence, open security issues and maintainer
    activity.
6.  Confirm OS/version support on actual hardware and CI.
7.  Review unsafe Rust, FFI, process creation and path handling.
8.  Run upstream tests and our own threat-focused tests.
9.  Pin versions and checksums; maintain an SBOM.
10. Document whether code is vendored, linked as a dependency, invoked
    as a subprocess, or used only as design inspiration.

No code may be copied from a project with an incompatible or unclear
license. Do not assume a GitHub repository is open source merely because
it is public.

------------------------------------------------------------------------

# 6. System Architecture

``` text
                    AI AGENTS / DEVELOPER TOOLS
        OpenCode | Codex | Claude Code | GAL | YLAgentsOS
                              |
                  MCP stdio / Streamable HTTP
                    Local API / Remote API
                              |
                 AUTHENTICATION + SESSION GATE
                              |
                POLICY ENGINE + APPROVAL BROKER
                              |
                 CAPABILITY / TASK DISPATCHER
                              |
        +---------------------+----------------------+
        |                     |                      |
  Native Host Backend   OS Sandbox Backend      VM Backend
  Windows / Linux /     AppContainer /          Virtx or another
  macOS process APIs    Landlock / Seatbelt     optional VM provider
        |                     |                      |
        +---------------------+----------------------+
                              |
                   PROCESS + FILESYSTEM LAYER
                              |
             Real OS, projects, toolchains and Git
```

## 6.1 Core services

-   **Runtime daemon:** lifecycle, configuration, session registry and
    IPC.
-   **Identity service:** local agent identities, trusted devices,
    pairing and revocation.
-   **Policy engine:** evaluates every operation.
-   **Approval broker:** requests user approval for sensitive
    operations.
-   **Workspace service:** safe project discovery and file operations.
-   **Process service:** command execution, process trees, cancellation
    and limits.
-   **Terminal service:** interactive PTY/ConPTY sessions.
-   **Sandbox manager:** chooses and applies platform enforcement.
-   **Toolchain discovery:** discovers existing installed tools.
-   **Audit service:** append-only structured operation records.
-   **MCP adapter:** exposes tools and resources to agents.
-   **Transport service:** local IPC and optional remote connectivity.
-   **Desktop controller:** tray, sessions, approvals, logs and
    settings.

## 6.2 Process separation

Preferred process model:

-   `yl-runtime`: small privileged-minimum daemon and policy authority.
-   `yl-worker`: short-lived worker that launches and supervises child
    processes.
-   `yl-desktop`: optional Tauri UI.
-   `yl-cli`: diagnostics, pairing and administration.
-   `yl-mcp`: may be hosted in the daemon or launched as a thin stdio
    adapter.

Do not run the UI as the policy authority. A compromised renderer must
not be able to bypass authorization.

------------------------------------------------------------------------

# 7. Policy and Permission Model

## 7.1 Permission dimensions

Every grant is scoped by:

-   Agent identity.
-   Device identity.
-   User identity.
-   Project/workspace ID.
-   Session ID.
-   Capability.
-   Resource/path.
-   Time or expiry.
-   Execution profile.
-   Approval state.

## 7.2 Default profiles

  --------------------------------------------------------------------------
  Profile        Files          Process        Network        Intended use
                                execution                     
  -------------- -------------- -------------- -------------- --------------
  Inspect        Workspace read Disabled       Disabled       Repository
                                                              review

  Edit           Workspace      Disabled       Disabled       File editing
                 read/write                                   

  Development    Workspace      Allowlisted    Configurable   Normal
                 read/write     development                   build/test
                                tools                         

  Sandboxed      Explicit       Sandboxed      Deny or proxy  Untrusted
  Development    read/write     child process                 project work
                 paths                                        

  Elevated       Explicit       Specific       Explicit       Exceptional
  One-shot       approval       elevated                      system task
                                operation                     
  --------------------------------------------------------------------------

Never expose an unrestricted `YOLO` profile as the default. If a
permissive profile exists, it must be visibly dangerous, separately
enabled and logged.

## 7.3 Example policy

``` yaml
version: 1
project: zartlan-ai

agents:
  default:
    profile: development
    permissions:
      workspace.read: allow
      workspace.write: allow
      process.exec: ask
      terminal.interactive: ask
      git.read: allow
      git.commit: ask
      network: proxy
      secrets.read: deny

paths:
  workspace:
    root: "D:/ylstack-space/Developments/ai/llm_saas_app/zartlan-ai"
    access: read_write
  deny:
    - "%USERPROFILE%/.ssh"
    - "%USERPROFILE%/.aws"
    - "%APPDATA%/Microsoft/Credentials"

process:
  allowed_executables:
    - node
    - pnpm
    - bun
    - python
    - git
    - cargo
  max_runtime_seconds: 1800
  max_processes: 128
  memory_limit_mb: 4096
```

The policy format is illustrative. Paths, executable resolution,
environment expansion and inheritance must be validated by the runtime,
not trusted as raw agent input.

## 7.4 Approval flow

Approval is required for configurable sensitive actions, including:

-   Access outside registered workspaces.
-   Reading or writing sensitive directories.
-   Running an unknown executable.
-   Installing global packages or modifying system configuration.
-   Administrator/root elevation.
-   Changing firewall, network or service settings.
-   Git push, destructive reset or force operations.
-   Starting persistent background services.
-   Accessing a new remote device.
-   Expanding network permissions.

Approval grants must be narrowly scoped: one operation, one process
tree, one session or a time-limited capability. Avoid indefinite blanket
grants.

------------------------------------------------------------------------

# 8. Security Architecture

## 8.1 Threat model

Assume an agent may be manipulated by prompt injection, malicious
repository content, compromised dependencies, build scripts, package
lifecycle hooks, Git hooks or malicious binaries. Treat agent-generated
commands and repository scripts as untrusted unless the user has
explicitly trusted the project and profile.

Protect against:

-   Workspace path escape.
-   Symlink, junction and reparse-point escape.
-   UNC and device path abuse.
-   Alternate data stream abuse on Windows.
-   Environment variable and executable search-path hijacking.
-   Credential theft.
-   Process-tree escape and orphaned processes.
-   Resource exhaustion and fork bombs.
-   Unauthorized network access and exfiltration.
-   Remote impersonation and replay.
-   Approval spoofing and confused-deputy behavior.
-   Audit tampering by child processes.

## 8.2 Path safety

Every filesystem operation must:

-   Normalize and canonicalize paths where possible.
-   Resolve symlinks, junctions and reparse points.
-   Enforce allowed roots after resolution.
-   Reject device namespaces and unexpected UNC paths unless explicitly
    permitted.
-   Validate each path component.
-   Use handle-based operations where practical to reduce TOCTOU races.
-   Re-check access at operation time.
-   Avoid trusting a previously validated string path.
-   Apply atomic write/replace where practical.
-   Enforce file size and traversal limits.

A workspace `cwd` is not a sandbox. A shell command can access any
resource available to its security token unless OS-level enforcement
prevents it.

## 8.3 Process security

-   Launch child processes with explicit executable paths.
-   Use controlled environment inheritance and PATH.
-   Set a defined working directory.
-   Apply process-tree/job limits before exposing the process.
-   Capture stdout and stderr with bounded buffers.
-   Enforce timeouts and cancellation.
-   Kill the entire process tree on cancellation or runtime shutdown.
-   Prevent unintended handle inheritance.
-   Record resolved executable path, arguments, environment policy and
    parent session.
-   Do not invoke a shell when direct executable + argument execution is
    sufficient.
-   When a shell is requested, make the shell and profile explicit.

## 8.4 Platform enforcement

### Windows

Preferred evaluation order:

1.  AppContainer with explicit filesystem and network capabilities when
    compatible.
2.  Restricted token / write-restricted token and dedicated
    low-privilege worker account where appropriate.
3.  Job Objects for process-tree lifetime, CPU and memory controls.
4.  Process mitigation policies and explicit handle inheritance.
5.  Windows Firewall/WFP or controlled proxy for network enforcement.
6.  Windows Sandbox or optional VM for stronger disposable isolation
    where available.

Windows 10 is a required baseline. Do not assume Windows 11-only APIs or
third-party crates work on Windows 10. Probe every feature at runtime
and test on the actual minimum Windows build.

### Linux

Evaluate:

-   Landlock for filesystem access control.
-   seccomp-BPF for syscall filtering.
-   namespaces for mount, PID and network isolation.
-   cgroups v2 for resource limits.
-   unprivileged user namespaces where available.
-   bubblewrap as an optional subprocess backend.

### macOS

Evaluate:

-   Seatbelt sandbox profiles for filesystem and network policy.
-   Separate low-privilege user where appropriate.
-   Process lifecycle and resource controls.
-   Explicitly report limitations of deprecated or changing platform
    APIs.

## 8.5 Isolation levels

Expose an honest, machine-readable isolation report:

-   `none`: no OS-level sandbox.
-   `process_limited`: process lifetime/resource controls only.
-   `write_restricted`: writes constrained, reads may remain broad.
-   `filesystem_restricted`: read/write allowlists enforced.
-   `network_restricted`: network denied or controlled by an enforceable
    proxy.
-   `strong_isolation`: OS sandbox with filesystem, network and process
    restrictions.
-   `vm_isolated`: separate guest kernel / VM boundary.

Never describe GAL-style write-restricted token behavior as full
filesystem isolation. A child may still read files permitted to the user
unless the backend denies them.

------------------------------------------------------------------------

# 9. Execution Backends

## 9.1 Backend interface

Define a stable Rust trait boundary. Exact signatures are implementation
decisions, but the conceptual API must support:

``` rust
trait ExecutionBackend {
    fn capabilities(&self) -> BackendCapabilities;
    async fn prepare(&self, request: ExecutionRequest)
        -> Result<PreparedExecution>;
    async fn spawn(&self, prepared: PreparedExecution)
        -> Result<ProcessHandle>;
    async fn inspect(&self, id: ProcessId)
        -> Result<ProcessStatus>;
    async fn terminate(&self, id: ProcessId, mode: TerminationMode)
        -> Result<()>;
}
```

Do not let a backend silently ignore policy fields. It must return an
enforcement report or reject the request.

## 9.2 Native host backend

Purpose: fast, compatible execution for trusted local development.

-   Uses installed host executables.
-   Supports native shells.
-   Uses process supervision and explicit environment policy.
-   Enforces workspace-level API restrictions.
-   Applies available process resource controls.
-   Does not claim to be a security sandbox when no kernel boundary is
    active.

## 9.3 OS sandbox backend

Purpose: execute untrusted code with kernel-enforced restrictions.

-   Evaluate Arapuca first as a Rust integration candidate.
-   Evaluate skarn-sandbox as an alternative abstraction.
-   Compare with Anthropic Sandbox Runtime for security design and
    behavior.
-   Keep a project-owned `SandboxPolicy` independent of any one vendor
    crate.
-   Build conformance tests for all policy fields.
-   Fail closed when required isolation cannot be applied.

The project-owned policy API must make it possible to replace one
backend without changing MCP tools or agent integrations.

## 9.4 VM backend

Purpose: stronger isolation for hostile code, risky dependency
installation or Linux-only workflows.

-   Virtx is an optional candidate for supported Windows 11+, Linux and
    macOS hosts.
-   Keep VM images, snapshots and guest toolchains outside the base
    install.
-   Start VM resources on demand.
-   Provide explicit host-folder mounts with read-only/read-write modes.
-   Disable networking by default; provide a controlled proxy option.
-   Never require VM support for ordinary Windows 10 native development.

Arapuca's experimental Linux microVM capability may also be evaluated
separately. Do not combine two VM providers into the first release.

## 9.5 Backend selection

Selection must be explicit or policy-driven:

``` text
trusted local project       -> native backend
unknown repository          -> OS sandbox backend
hostile build/test workload -> VM backend if available
required backend missing    -> reject or ask user; never silently downgrade
```

------------------------------------------------------------------------

# 10. Workspace and Repository Services

Required operations:

-   `workspace.list`
-   `workspace.stat`
-   `workspace.read_file`
-   `workspace.read_range`
-   `workspace.write_file`
-   `workspace.replace_text`
-   `workspace.create_directory`
-   `workspace.move`
-   `workspace.copy`
-   `workspace.delete`
-   `workspace.search`
-   `workspace.find_files`
-   `workspace.get_tree`
-   `workspace.register`
-   `workspace.unregister`

Requirements:

-   Configurable maximum file size and result size.
-   Binary file detection.
-   Encoding-aware text handling.
-   Atomic file writes.
-   Safe recursive traversal with ignore rules.
-   Respect `.gitignore` as a search convenience, not as a security
    boundary.
-   Never follow links outside allowed roots.
-   Structured errors with path and policy context.
-   No hidden file upload or remote transfer without explicit
    capability.

------------------------------------------------------------------------

# 11. Process, Build and Test Services

Required operations:

-   `process.discover_tools`
-   `process.exec`
-   `process.start`
-   `process.wait`
-   `process.output`
-   `process.status`
-   `process.terminate`
-   `process.list`
-   `process.resource_usage`
-   `terminal.open`
-   `terminal.write`
-   `terminal.resize`
-   `terminal.read`
-   `terminal.close`

## 11.1 Development workflow support

The runtime must support agents performing complete development loops:

1.  Inspect project metadata and scripts.
2.  Discover package manager and toolchain.
3.  Ask permission when dependencies or network access are needed.
4.  Install dependencies.
5.  Run formatting, lint and static checks.
6.  Run unit/integration tests.
7.  Build the application.
8.  Launch and monitor a development server or app.
9.  Read logs and diagnose errors.
10. Modify source files and repeat.
11. Return a structured final report with commands, exit codes, test
    results and changed files.

The runtime does not need framework-specific knowledge to run these
commands. Higher-level agents decide which commands to execute.

## 11.2 Toolchain discovery

Discover, do not bundle:

-   Windows: `cmd.exe`, `powershell.exe`, `pwsh.exe`, Git, Node, npm,
    pnpm, Bun, Python, pyenv-win, Rust/Cargo, Java/JDK, Gradle, Android
    SDK tools, CMake, Ninja, Go, .NET.
-   Linux/macOS: available shells, Git, Node, package managers, Python,
    Rust, Java, Go, CMake and platform build tools.

Return absolute executable paths, versions, architecture and detection
source. Never assume `PATH` is trustworthy for elevated or remote
sessions.

------------------------------------------------------------------------

# 12. Interactive Terminal

-   Windows: ConPTY-backed terminal sessions.
-   Linux/macOS: PTY-backed sessions.
-   Support stdin/stdout streaming, resize, Ctrl-C, EOF and exit status.
-   Keep terminal sessions attached to an authorized project/session.
-   Apply the same process policy and sandbox as non-interactive
    commands.
-   Limit scrollback and output bytes.
-   Handle disconnect/reconnect with expiring session tokens.
-   Do not expose arbitrary terminal sessions to unauthenticated network
    clients.

Evaluate maintained ConPTY and cross-platform PTY crates before writing
custom FFI.

------------------------------------------------------------------------

# 13. MCP and Agent Integrations

## 13.1 MCP first

Use the official Rust SDK (`rmcp`) for MCP protocol handling.

Expose focused tools rather than a single unrestricted shell tool.
Example tools:

-   `runtime.status`
-   `runtime.capabilities`
-   `workspace.list`
-   `workspace.read_file`
-   `workspace.write_file`
-   `workspace.search`
-   `process.discover_tools`
-   `process.exec`
-   `process.start`
-   `process.wait`
-   `process.terminate`
-   `terminal.open`
-   `terminal.write`
-   `terminal.read`
-   `git.status`
-   `git.diff`
-   `git.commit`
-   `approval.request`

Each tool must have a JSON schema, permission requirement, timeout,
output limit, audit event and structured error format.

## 13.2 Integration targets

-   YLAgentsOS.
-   GAL.
-   OpenCode.
-   Claude Code.
-   Codex and other compatible coding agents.
-   Custom MCP clients.
-   Local automation agents.

Do not make any single agent's private tool schema the runtime's
internal API. Use adapters.

## 13.3 Transport modes

-   MCP stdio for local agent processes.
-   MCP Streamable HTTP for authenticated local/remote clients.
-   Local named pipe / Unix domain socket for desktop-to-daemon IPC.
-   Optional Iroh transport for peer-to-peer connectivity.

------------------------------------------------------------------------

# 14. Remote Connectivity

Remote access is optional and disabled by default.

## 14.1 Iroh candidate

Use Iroh as an optional encrypted peer transport, not as the
authorization layer. It provides peer connectivity with relay fallback;
the runtime still owns identity, access policy and audit.

## 14.2 Pairing

-   Pair devices using a QR code or one-time pairing code.
-   Bind device identity to a cryptographic key.
-   Require explicit approval on the host.
-   Display device name, identity fingerprint and permissions.
-   Support revoke, rotate and expire.
-   Require re-pairing after identity reset.

## 14.3 Remote security

-   Mutual authentication.
-   Per-device and per-agent capability grants.
-   Short-lived session tokens.
-   Replay protection and request IDs.
-   Rate limits and request-size limits.
-   No public unauthenticated listener.
-   No implicit LAN trust.
-   Explicit remote approval for high-risk actions.
-   Audit remote identity and operation origin.

Remote execution must use the same policy engine as local execution.

------------------------------------------------------------------------

# 15. Audit, Observability and Diagnostics

Every sensitive action records:

-   Timestamp.
-   User, agent and device identity.
-   Project and session.
-   Requested capability.
-   Resolved resource path or executable.
-   Policy decision and approval ID.
-   Backend and enforcement report.
-   Process ID and exit status.
-   Duration and resource usage.
-   Output truncation indicator.
-   Error and termination reason.

Logs must not store secrets, environment values or file contents by
default. Redact tokens, credentials and sensitive command arguments
where possible.

Provide:

-   Local audit viewer.
-   Export to JSONL.
-   Retention configuration.
-   Diagnostic bundle with secrets removed.
-   Backend capability report.
-   Process tree viewer.
-   Sandbox violation events.

------------------------------------------------------------------------

# 16. Configuration and Data Storage

Suggested layout:

``` text
YL-Agent-Runtime/
  config/
    runtime.toml
    policies/
    agents/
    devices/
  state/
    runtime.db
    audit/
    sessions/
  cache/
  logs/
```

Use SQLite for durable metadata and audit indexing. Use TOML or JSON for
human-editable policy files. Never store long-lived plaintext API keys
or remote pairing secrets in ordinary config files.

Configuration must support schema versions and safe migrations. Invalid
policy configuration must fail closed and retain a recoverable backup.

------------------------------------------------------------------------

# 17. Desktop Control Center

Tauri 2 desktop app is optional; the runtime must remain usable without
it.

Screens:

1.  Overview: daemon state, host, backend capability status and resource
    use.
2.  Projects: registered workspaces and assigned policies.
3.  Agents: connected agents, devices and permission grants.
4.  Sessions: running processes, terminals, builds and tests.
5.  Approvals: pending requests with clear scope and risk.
6.  Audit: searchable operation history.
7.  Backends: native/sandbox/VM availability and limitations.
8.  Settings: startup, remote access, logs and policies.

UI direction:

-   Premium, restrained dark interface.
-   Near-black/charcoal surfaces with slate text.
-   Cyan/blue as functional accent; violet reserved for secondary state.
-   Compact, information-dense developer UX.
-   Clear security state; never use a green badge to imply safety when
    enforcement is partial.
-   Tray-first, no unnecessary always-open window.

------------------------------------------------------------------------

# 18. Performance and Resource Targets

These are project engineering targets, not measured benchmarks of GAL or
any referenced repository.

  Metric                                                               Initial target
  ------------------------ ----------------------------------------------------------
  Idle CPU                                           Near zero when no work is active
  Idle RAM                       Target under 50 MB for headless core; measure per OS
  Cold startup                            Target under 1 second on reference hardware
  UI memory                  Separate budget; UI is not required for headless runtime
  Base install                              No language runtimes or VM images bundled
  Process spawn overhead                         Measure per backend; publish results
  Audit overhead                  Bounded, asynchronous, no blocking on normal output
  Output memory                                        Bounded buffers with streaming

Benchmark on Windows 10, Windows 11, Linux and macOS. Publish release
build measurements with hardware, OS, build profile and test method.

------------------------------------------------------------------------

# 19. Recommended Rust Workspace

Illustrative modular layout:

``` text
yl-agent-runtime/
  Cargo.toml
  crates/
    runtime-core/
    runtime-daemon/
    runtime-cli/
    runtime-protocol/
    runtime-policy/
    runtime-identity/
    runtime-approval/
    runtime-workspace/
    runtime-process/
    runtime-terminal/
    runtime-toolchain/
    runtime-audit/
    runtime-mcp/
    runtime-transport/
    runtime-backend-api/
    backend-native/
    backend-windows/
    backend-linux/
    backend-macos/
    backend-arapuca/
    backend-virtx/
    runtime-config/
    runtime-testkit/
  apps/
    desktop-tauri/
  docs/
    architecture/
    threat-model/
    decisions/
    integrations/
  tests/
    conformance/
    security/
    cross-platform/
```

Only create backend crates that are justified by supported targets.
Avoid empty abstraction layers and premature plugin systems.

## 19.1 Dependency policy

-   Prefer maintained Rust crates with clear licenses.
-   Keep platform-specific dependencies behind target-specific Cargo
    features.
-   Minimize `unsafe`; isolate and document every unsafe block.
-   Avoid Node.js or Python in the daemon.
-   Avoid `nodejs_compat` and unrelated cloud dependencies.
-   Keep optional networking and VM dependencies out of the minimal
    local build.
-   Pin versions and use reproducible builds.
-   Run `cargo audit`, `cargo deny`, formatting, clippy and tests in CI.
-   Generate SBOMs for releases.

------------------------------------------------------------------------

# 20. Development Phases

## Phase 0 --- Feasibility and reuse audit

-   Confirm Windows 10 minimum build and API requirements.
-   Build small proof-of-concepts for Windows process supervision, Job
    Objects and ConPTY.
-   Evaluate Arapuca and skarn-sandbox on Windows 10/11.
-   Evaluate Iroh pairing and transport.
-   Evaluate `rmcp` stdio and Streamable HTTP.
-   Compare PTY libraries.
-   Produce license and dependency matrix.
-   Decide which components are reused, wrapped or implemented
    internally.

**Exit criteria:** tested technical choices, no unsupported security
claims, architecture decision records.

## Phase 1 --- Native Windows MVP

-   Rust daemon and CLI.
-   Project registry.
-   Workspace read/write/search.
-   Toolchain discovery.
-   Native process execution.
-   Job Object process-tree supervision.
-   Output streaming and cancellation.
-   Audit log.
-   Local MCP stdio server.
-   Minimal policy and approval system.

**Exit criteria:** an MCP coding agent can inspect a project, edit
files, run a build and tests, fix failures and return results on Windows
10.

## Phase 2 --- Interactive development runtime

-   ConPTY.
-   Long-running process sessions.
-   Terminal resize/input.
-   Process status and resource metrics.
-   Git helpers.
-   Better approval UX.
-   Tauri tray/control center.

**Exit criteria:** reliable interactive development sessions and clean
process cleanup after cancellation, crash or shutdown.

## Phase 3 --- OS sandbox

-   Integrate selected Rust sandbox backend.
-   Capability probing.
-   Filesystem/network enforcement reports.
-   Windows 10/11 conformance tests.
-   Linux Landlock/seccomp backend.
-   macOS Seatbelt backend.
-   Fail-closed policy behavior.

**Exit criteria:** security tests prove each claimed control;
unsupported controls are reported accurately.

## Phase 4 --- Remote runtime

-   Device pairing.
-   Identity and revocation.
-   Iroh transport.
-   Authenticated remote MCP/API.
-   Remote approval and audit.
-   Rate limiting and reconnect behavior.

**Exit criteria:** trusted remote agent can execute only its granted
project capabilities; revoked device loses access.

## Phase 5 --- Optional VM backend and ecosystem

-   Evaluate Virtx integration on supported hosts.
-   Disposable VM profiles and cached images.
-   Controlled host mounts and network proxy.
-   Integration adapters for GAL, OpenCode, Codex and YLAgentsOS.
-   Public API/SDK and extension documentation.

**Exit criteria:** VM execution is optional, isolated from the core and
never silently substituted for native execution.

------------------------------------------------------------------------

# 21. Testing and Quality Gates

## 21.1 Functional tests

-   Register and remove workspaces.
-   Read/write/search files.
-   Detect and report toolchains.
-   Run Node, Python, Rust and Git commands when installed.
-   Build and test representative projects.
-   Interactive terminal lifecycle.
-   Process cancellation and timeout.
-   Daemon crash recovery.
-   Remote disconnect/reconnect.

## 21.2 Security tests

-   `..` path traversal.
-   Symlink/junction/reparse-point escape.
-   UNC and device paths.
-   Windows ADS.
-   Executable path hijacking.
-   Environment variable injection.
-   Malicious package lifecycle scripts.
-   Git hooks.
-   Child process spawning.
-   Process-tree termination.
-   Memory/CPU/PID exhaustion.
-   Credential path access.
-   Network egress and DNS.
-   Remote replay, spoofing and revoked identity.
-   Approval expiration and scope escalation.
-   Audit log tampering.

## 21.3 Compatibility matrix

Every release candidate must test:

-   Windows 10 minimum supported build.
-   Current Windows 11.
-   Ubuntu LTS x64.
-   One ARM64 Linux target where feasible.
-   Current supported macOS Intel/Apple Silicon versions.
-   No optional sandbox backend installed.
-   Sandbox backend unavailable or partially supported.
-   Headless mode without Tauri.
-   Local-only mode without network.

------------------------------------------------------------------------

# 22. Release and Distribution

-   Windows installer and portable ZIP.
-   Linux package and standalone binary.
-   macOS signed/notarized app and CLI.
-   Optional Tauri desktop UI.
-   No bundled language toolchains.
-   No VM images in base installer.
-   No mandatory account or cloud backend.
-   Signed releases and checksums.
-   SBOM and third-party notices.
-   Clear minimum OS versions and sandbox capability matrix.
-   Upgrade and rollback path for daemon and policy schema.

------------------------------------------------------------------------

# 23. Acceptance Criteria

The product is ready for its first stable release when:

1.  It runs as a normal user on Windows 10 and Windows 11.
2.  It can use real installed Windows development tools.
3.  A connected MCP agent can inspect, edit, build and test a real
    repository.
4.  It supports interactive and non-interactive process execution.
5.  Process cancellation reliably cleans up descendants.
6.  Every operation is authenticated, policy-checked and audited.
7.  Project boundaries are enforced for filesystem APIs.
8.  Shell execution is accurately distinguished from API-level file
    access.
9.  Security capability reports reflect actual OS enforcement.
10. Required isolation failures never silently fall back to unrestricted
    execution.
11. Remote access is opt-in, authenticated and revocable.
12. The headless core works without Tauri, Node, Python, Docker, WSL or
    SSH.
13. Optional backends can be omitted without breaking the core.
14. License and dependency notices are complete.

------------------------------------------------------------------------

# 24. Instructions for the Coding Agent Building This Project

Before writing implementation code:

1.  Read this specification completely.
2.  Inspect the existing repository and report its current state.
3.  Create an architecture decision record for every major dependency.
4.  Verify upstream licenses and platform support at pinned revisions.
5.  Prototype Windows 10 process supervision and sandbox capabilities
    first.
6.  Do not assume Windows 11 APIs are available on Windows 10.
7.  Do not implement a fake sandbox based only on working-directory
    checks.
8.  Do not copy source code without license review.
9.  Keep the runtime headless and modular.
10. Build a working vertical slice before adding remote connectivity or
    a VM backend.

Implementation sequence:

-   Repository audit and ADRs.
-   Windows 10 native process MVP.
-   Workspace service and policy engine.
-   MCP adapter.
-   Build/test workflow verification.
-   Interactive terminal.
-   OS sandbox backend.
-   Desktop control center.
-   Remote connectivity.
-   Optional VM integration.

At every milestone, run tests, report exact commands and results, list
changed files, document known limitations and update the security
capability matrix. Never claim a feature is implemented merely because
an interface or placeholder exists.

------------------------------------------------------------------------

# 25. Final Architecture Decision

The recommended product is **not a GAL clone, not a Virtx wrapper and
not a shell-only MCP server**.

Build a project-owned Rust runtime with:

-   A stable cross-platform capability and policy API.
-   Native host execution as the compatibility baseline.
-   A replaceable OS sandbox backend, with Arapuca as the first
    candidate to validate.
-   Optional VM isolation for workloads requiring a separate kernel.
-   Official Rust MCP SDK for agent interoperability.
-   Iroh as optional encrypted remote transport.
-   Tauri 2 as an optional desktop control center.
-   GAL and LocalForge as reference implementations and integration
    targets.

This gives YL Stack control over the long-term architecture while
reusing mature components wherever practical. The result should be small
when idle, useful for real software development, portable across desktop
operating systems, and honest about the security guarantees available on
each host.
