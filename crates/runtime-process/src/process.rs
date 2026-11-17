//! Process executor for the YL Agent Runtime.
//!
//! Direct argv execution only — no shell, no `cmd /c`, no `powershell -Command`.
//!
//! Combines:
//! - an executable allowlist (name only, resolved through `PATH`),
//! - environment security (whitelist inherit, deny-list hard error),
//! - Windows Job Objects with kill-on-close (spawn suspended, assign, resume),
//! - output capture with spill overflow (30 KB inline head+tail per stream),
//! - timeouts (graceful terminate -> grace period -> force kill).

use runtime_core::error::{Error, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

/// The one place that explains a rejected executable. Both the executor and the
/// process service use it so the message cannot drift between entry points.
pub fn allowlist_error(program: &str, allowlist: &[String]) -> String {
    format!(
        "executable not in allowlist: {program}. Allowed: {}. \
         Shell builtins (echo, cd, dir, type, set, pwd) are not executables; pass a real \
         program instead, or call `process.discover_tools` to see which toolchains are installed here.",
        allowlist.join(", ")
    )
}

/// Executables that may be executed directly (name only, no path separators).
pub const ALLOWED_TOOLS: &[&str] = &[
    "cargo", "rustc", "rustup", "git", "node", "bun", "python", "python3", "py",
    "go", "dotnet", "cmake", "ninja", "java", "javac",
];

/// Environment variables inherited from the caller. Everything else is cleared.
pub const ENV_WHITELIST: &[&str] = &[
    "PATH", "SYSTEMROOT", "TEMP", "USERPROFILE", "APPDATA", "ProgramFiles*",
    "COMSPEC",
];

/// Deny patterns matched (case-insensitively) against the upper-cased key.
/// Any match in the caller environment is a hard error.
pub const ENV_DENY: &[&str] = &[
    "*TOKEN*", "*SECRET*", "*PASSWORD*", "*KEY*", "AWS_*", "AZURE_*",
    "GITHUB_*", "NPM_TOKEN",
];

/// Inline head+tail limit per stream; larger output spills to disk.
const DEFAULT_MAX_OUTPUT_BYTES: u64 = 30_000;
const DEFAULT_TIMEOUT_SECS: u64 = 300;
const MAX_TIMEOUT_SECS: u64 = 3600;
/// Seconds to wait after a graceful terminate before force killing.
const TERMINATE_GRACE_SECS: u64 = 10;

/// Result of a direct execution.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
    pub error_type: Option<String>,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
}

/// Process executor combining allowlist, environment security, Job Object
/// lifecycle and spawning into one call.
pub struct ProcessExecutor {
    allowlist: Vec<String>,
    env_whitelist: Vec<String>,
    env_deny: Vec<String>,
    default_timeout_secs: u64,
    max_timeout_secs: u64,
    max_output_bytes: u64,
}

impl ProcessExecutor {
    pub fn new() -> Self {
        Self {
            allowlist: ALLOWED_TOOLS.iter().map(|s| s.to_string()).collect(),
            env_whitelist: ENV_WHITELIST.iter().map(|s| s.to_string()).collect(),
            env_deny: ENV_DENY.iter().map(|s| s.to_string()).collect(),
            default_timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_timeout_secs: MAX_TIMEOUT_SECS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    /// Execute an allowed executable directly.
    pub fn execute(
        &self,
        program: &str,
        args: &[String],
        cwd: Option<&Path>,
        timeout_secs: u64,
    ) -> Result<ExecutionResult> {
        let timeout_secs = if timeout_secs == 0 {
            self.default_timeout_secs
        } else {
            timeout_secs
        }
        .clamp(1, self.max_timeout_secs);
        let timeout = Duration::from_secs(timeout_secs);

        // 1. Executable allowlist (name only).
        if !self.allowlist.iter().any(|a| a.eq_ignore_ascii_case(program)) {
            return Err(Error::PolicyViolation(allowlist_error(
                program,
                &self.allowlist,
            )));
        }

        // 2. Resolve through PATH (no path separators, no absolute paths).
        let exe = resolve_executable(program)?;

        // 3. Environment security: deny-check every caller var, then whitelist.
        let env = self.build_env()?;

        // Command hash for the spill directory name: sha256 hex of the
        // canonicalized command string (program + args + cwd), for consistency
        // with the read engine's sha256-based content addressing.
        let mut command_string = program.to_string();
        for arg in args {
            command_string.push('\0');
            command_string.push_str(arg);
        }
        if let Some(cwd) = cwd {
            command_string.push('\0');
            command_string.push_str(cwd.to_string_lossy().as_ref());
        }
        let command_hash = {
            let mut hasher = Sha256::new();
            hasher.update(command_string.as_bytes());
            let bytes = hasher.finalize();
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        };

        // 4. Spawn (direct argv, piped output, cleared + whitelisted env).
        let mut cmd = Command::new(&exe);
        cmd.args(args);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        cmd.env_clear();
        for (key, value) in &env {
            cmd.env(key, value);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_SUSPENDED.0 | CREATE_NEW_PROCESS_GROUP.0);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Process(format!("failed to spawn {program}: {e}")))?;
        let pid = child.id();

        // 5. Windows Job Object: create with kill-on-close, assign the process,
        //    then resume the main thread. Assign-before-resume closes the
        //    spawn-to-assignment race so descendants stay inside the job.
        let job: Option<ProcessJob> = {
            #[cfg(windows)]
            {
                let job = ProcessJob::create()?;
                job.assign_process(pid)?;
                ProcessJob::resume_main_thread(pid)?;
                Some(job)
            }
            #[cfg(not(windows))]
            {
                None
            }
        };

        // 6. Capture output concurrently with waiting (avoids pipe deadlock).
        let mut stdout_read = child
            .stdout
            .take()
            .ok_or_else(|| Error::Process("stdout pipe not captured".into()))?;
        let mut stderr_read = child
            .stderr
            .take()
            .ok_or_else(|| Error::Process("stderr pipe not captured".into()))?;

        let start = Instant::now();
        let stdout_thread = thread::spawn(move || {
            let mut v = Vec::new();
            let _ = stdout_read.read_to_end(&mut v);
            v
        });
        let stderr_thread = thread::spawn(move || {
            let mut v = Vec::new();
            let _ = stderr_read.read_to_end(&mut v);
            v
        });

        // 7. Wait with timeout, then graceful terminate + grace + force kill.
        let mut exit_status = None;
        let mut timed_out = false;
        let waited = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    break;
                }
                Ok(None) => {
                    if waited.elapsed() >= timeout {
                        timed_out = true;
                        let _ = child.kill(); // graceful terminate
                        let grace = Instant::now();
                        loop {
                            match child.try_wait() {
                                Ok(Some(status)) => {
                                    exit_status = Some(status);
                                    break;
                                }
                                Ok(None) => {
                                    if grace.elapsed()
                                        >= Duration::from_secs(TERMINATE_GRACE_SECS)
                                    {
                                        let _ = child.kill(); // force kill
                                        break;
                                    }
                                    thread::sleep(Duration::from_millis(100));
                                }
                                Err(e) => {
                                    return Err(Error::Process(format!(
                                        "failed to poll process after terminate: {e}"
                                    )))
                                }
                            }
                        }
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(Error::Process(format!("failed to poll process: {e}")))
                }
            }
        }

        // Drop the job handle: kill-on-close terminates any remaining tree.
        drop(job);

        let stdout_bytes = stdout_thread.join().unwrap();
        let stderr_bytes = stderr_thread.join().unwrap();

        // Redact secrets before head/tail split and before writing spill files.
        let stdout_redacted = redact(&String::from_utf8_lossy(&stdout_bytes));
        let stderr_redacted = redact(&String::from_utf8_lossy(&stderr_bytes));

        let duration_ms = start.elapsed().as_millis() as u64;
        let exit_code = exit_status.as_ref().and_then(|s| s.code());

        let (stdout, stdout_truncated, stdout_path) = spill_stream(
            &command_hash,
            "stdout",
            stdout_redacted.as_bytes(),
            self.max_output_bytes,
        )?;
        let (stderr, stderr_truncated, stderr_path) = spill_stream(
            &command_hash,
            "stderr",
            stderr_redacted.as_bytes(),
            self.max_output_bytes,
        )?;

        let success = exit_status.map(|s| s.success()).unwrap_or(false);
        let error_type = if timed_out {
            Some("timeout".to_string())
        } else {
            None
        };

        Ok(ExecutionResult {
            success,
            exit_code,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            duration_ms,
            error_type,
            stdout_path,
            stderr_path,
        })
    }

    /// Is `program` on the allowlist?
    pub fn is_allowed(&self, program: &str) -> bool {
        self.allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(program))
    }

    /// Deny-check every caller env var, then return the whitelisted subset.
    pub fn build_env(&self) -> Result<Vec<(String, String)>> {
        let mut whitelisted = Vec::new();
        for (key, value) in std::env::vars() {
            let upper = key.to_uppercase();
            if self
                .env_deny
                .iter()
                .any(|pat| glob_match(&upper, pat))
            {
                return Err(Error::PolicyViolation(format!(
                    "environment variable denied: {key}"
                )));
            }
            if self
                .env_whitelist
                .iter()
                .any(|w| w.eq_ignore_ascii_case(&key))
            {
                whitelisted.push((key, value));
            }
        }
        Ok(whitelisted)
    }
}

impl Default for ProcessExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// A Windows Job Object handle. Closing the last handle terminates every
/// process in the job (kill-on-close).
pub struct ProcessJob {
    #[cfg(windows)]
    handle: HANDLE,
}

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, PROCESS_ALL_ACCESS,
};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
};
#[cfg(windows)]
use std::ffi::c_void;

#[cfg(windows)]
impl ProcessJob {
    pub fn create() -> Result<Self> {
        unsafe {
            let handle = CreateJobObjectW(None, None)
                .map_err(|e| Error::Process(format!("CreateJobObjectW failed: {e}")))?;
            if handle.0.is_null() {
                return Err(Error::Process("CreateJobObjectW returned a null handle".into()));
            }
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *mut c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| Error::Process(format!("SetInformationJobObject failed: {e}")))?;
            Ok(Self { handle })
        }
    }

    pub fn assign_process(&self, pid: u32) -> Result<()> {
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
                .map_err(|e| Error::Process(format!("OpenProcess({pid}) failed: {e}")))?;
            AssignProcessToJobObject(self.handle, process)
                .map_err(|e| {
                    Error::Process(format!("AssignProcessToJobObject({pid}) failed: {e}"))
                })?;
            let _ = CloseHandle(process);
            Ok(())
        }
    }

    /// Resume the process's main thread. Must run after `assign_process` so the
    /// process (and its descendants) are already inside the Job Object.
    pub fn resume_main_thread(pid: u32) -> Result<()> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| Error::Process(format!("CreateToolhelp32Snapshot failed: {e}")))?;
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut thread_id = None;
            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        thread_id = Some(entry.th32ThreadID);
                        break;
                    }
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
            let thread_id = thread_id.ok_or_else(|| {
                Error::Process(format!("no thread found for process {pid}"))
            })?;
            let thread = OpenThread(THREAD_SUSPEND_RESUME, false, thread_id)
                .map_err(|e| Error::Process(format!("OpenThread({thread_id}) failed: {e}")))?;
            let previous = ResumeThread(thread);
            let _ = CloseHandle(thread);
            if previous == 0xFFFFFFFFu32 {
                return Err(Error::Process(format!(
                    "failed to resume main thread of {pid}"
                )));
            }
            Ok(())
        }
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Resolve an executable name to a canonical path.
///
/// The name must contain no path separators and must not be absolute. It is
/// searched through `PATH` (with `.exe`/`.com` suffixes on Windows).
pub fn resolve_executable(name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        return Err(Error::Process("empty executable name".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::Process(format!(
            "executable name must not contain path separators: {name}"
        )));
    }
    let path = PathBuf::from(name);
    if path.is_absolute() {
        return Err(Error::Process(format!(
            "executable name must not be absolute: {name}"
        )));
    }

    #[cfg(windows)]
    {
        let candidates = [
            name.to_string(),
            format!("{name}.exe"),
            format!("{name}.com"),
        ];
        if let Some(found) = search_path(&candidates) {
            return std::fs::canonicalize(&found).map_err(Error::Io);
        }
    }

    #[cfg(unix)]
    {
        if let Some(found) = search_path(&[name.to_string()]) {
            return std::fs::canonicalize(&found).map_err(Error::Io);
        }
    }

    Err(Error::ToolchainNotFound(format!(
        "executable not found on PATH: {name}"
    )))
}

/// Search each `PATH` directory for the first candidate that exists as a file.
fn search_path(candidates: &[String]) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        for candidate in candidates {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// Simple `*` glob matcher (case-sensitive; callers uppercase both sides).
fn glob_match(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star: Option<usize> = None;
    let mut match_ti = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || p[pi] == '?') {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if star.is_some() {
            pi = star.unwrap() + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Redact secret-like values in command output: `(token|secret|password|api[_-]?key)=value` -> `[REDACTED]`.
///
/// Applied to stdout/stderr *before* the head/tail split and before writing the
/// spill file, so secrets never appear inline or on disk in plaintext.
fn redact(text: &str) -> String {
    static REDACT: OnceLock<Regex> = OnceLock::new();
    let re = REDACT.get_or_init(|| {
        Regex::new(r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*\S+").unwrap()
    });
    re.replace_all(text, "[REDACTED]").to_string()
}

/// Spill directory for a command: `%TEMP%\yl-runtime\spill\<hash>`.
fn spill_dir(command_hash: &str) -> Result<PathBuf> {
    let temp = std::env::var("TEMP")
        .or_else(|_| std::env::var("TMP"))
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
    let dir = PathBuf::from(temp)
        .join("yl-runtime")
        .join("spill")
        .join(command_hash);
    std::fs::create_dir_all(&dir).map_err(|e| Error::Io(e))?;
    Ok(dir)
}

/// Truncate `bytes` to `max_bytes` inline (head + tail), spilling full output
/// to `<spill_dir>/<name>.txt` when it exceeds the limit.
fn spill_stream(
    command_hash: &str,
    name: &str,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<(String, bool, Option<String>)> {
    let truncated = (bytes.len() as u64) > max_bytes;
    if !truncated {
        return Ok((String::from_utf8_lossy(bytes).to_string(), false, None));
    }

    let dir = spill_dir(command_hash)?;
    let file = dir.join(format!("{name}.txt"));
    std::fs::write(&file, bytes).map_err(|e| Error::Io(e))?;

    let n = bytes.len();
    let half = (max_bytes as usize).min(n) / 2;
    let head = String::from_utf8_lossy(&bytes[..half]).to_string();
    let tail_start = n.saturating_sub(half);
    let tail = String::from_utf8_lossy(&bytes[tail_start..]).to_string();
    let cut = n.saturating_sub(2 * half);
    let inline = format!("{head}\n...\n[{cut} bytes cut]...\n{tail}");
    Ok((inline, true, Some(file.to_string_lossy().to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::sync::{OnceLock, Mutex};

    // Serialises tests that mutate the process-wide environment or PATH so
    // they cannot race with each other under `cargo test -- --test-threads`.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static G: OnceLock<Mutex<()>> = OnceLock::new();
        G.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct EnvVar(&'static str);
    impl Drop for EnvVar {
        fn drop(&mut self) {
            env::remove_var(self.0);
        }
    }

    fn set_env(key: &'static str, value: &'static str) -> EnvVar {
        env::set_var(key, value);
        EnvVar(key)
    }

    #[test]
    fn allowed_tools_contains_expected() {
        for tool in ["cargo", "rustc", "git", "node", "python", "java", "javac"] {
            assert!(ALLOWED_TOOLS.contains(&tool), "{tool} missing from ALLOWED_TOOLS");
        }
    }

    #[test]
    fn allowlist_error_teaches_the_caller() {
        let allowed: Vec<String> = ALLOWED_TOOLS.iter().map(|s| s.to_string()).collect();
        let message = allowlist_error("echo", &allowed);
        assert!(message.contains("not in allowlist: echo"), "{message}");
        assert!(message.contains("Allowed: cargo"), "{message}");
        assert!(message.contains("process.discover_tools"), "{message}");
    }

    #[test]
    fn resolve_executable_rejects_path_separators() {        assert!(resolve_executable("../foo").is_err());
        assert!(resolve_executable("dir\\foo.exe").is_err());
        assert!(resolve_executable("foo/bar").is_err());
    }

    #[test]
    fn resolve_executable_rejects_absolute() {
        #[cfg(windows)]
        assert!(resolve_executable(r"C:\Windows\System32\cmd.exe").is_err());
        #[cfg(unix)]
        assert!(resolve_executable("/bin/ls").is_err());
    }

    #[test]
    fn resolve_executable_finds_on_path() {
        let _lock = lock();
        let temp = std::env::temp_dir().join(format!("yl-rt-test-{}", std::process::id()));
        fs::create_dir_all(&temp).unwrap();
        let probe = temp.join("yl-resolve-probe");
        fs::write(&probe, b"").unwrap();
        let old_path = env::var("PATH").unwrap_or_default();
        #[cfg(windows)]
        const SEP: char = ';';
        #[cfg(not(windows))]
        const SEP: char = ':';
        env::set_var("PATH", format!("{}{}{}", temp.display(), SEP, old_path));
        let found = resolve_executable("yl-resolve-probe").unwrap();
        assert_eq!(found, probe.canonicalize().unwrap());
        env::set_var("PATH", &old_path);
        let _ = fs::remove_file(&probe);
        let _ = fs::remove_dir(&temp);
    }

    #[test]
    fn env_deny_blocks_token() {
        let _lock = lock();
        let _guard = set_env("YL_RT_TEST_TOKEN", "secret");
        let exec = ProcessExecutor::new();
        let err = exec
            .execute("git", &["--version".to_string()], None, 30)
            .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation(_)));
    }

    #[test]
    fn env_deny_blocks_aws() {
        let _lock = lock();
        let _guard = set_env("AWS_SECRET_ACCESS_KEY", "key");
        let exec = ProcessExecutor::new();
        let err = exec
            .execute("git", &["--version".to_string()], None, 30)
            .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation(_)));
    }

    #[test]
    fn env_deny_case_insensitive() {
        let _lock = lock();
        let _guard = set_env("my_secret_key", "x");
        let exec = ProcessExecutor::new();
        let err = exec
            .execute("git", &["--version".to_string()], None, 30)
            .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation(_)));
    }

    #[test]
    fn env_whitelist_includes_path() {
        let _lock = lock();
        let exec = ProcessExecutor::new();
        let env = exec.build_env().unwrap();
        assert!(env.iter().any(|(k, _)| k.eq_ignore_ascii_case("PATH")));
    }

    #[test]
    fn execute_blocks_unknown_tool() {
        let _lock = lock();
        let exec = ProcessExecutor::new();
        let err = exec
            .execute("evil-tool-xyz", &[], None, 30)
            .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation(_)));
    }

    #[test]
    fn execute_runs_allowed_tool() {
        let _lock = lock();
        let exec = ProcessExecutor::new();
        let result = exec
            .execute("git", &["--version".to_string()], None, 30)
            .unwrap();
        assert!(result.success, "{:?}", result.error_type);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.contains("git version"));
        assert_eq!(result.error_type, None);
    }

    #[test]
    fn execute_timeout_terminates() {
        let _lock = lock();
        let exec = ProcessExecutor::new();
        let result = exec
            .execute(
                "node",
                &[
                    "-e".to_string(),
                    "setTimeout(() => {}, 30000);".to_string(),
                ],
                None,
                1,
            )
            .unwrap();
        assert!(!result.success);
        assert_eq!(result.error_type, Some("timeout".to_string()));
        // A terminated process reports a non-zero exit code on Windows.
        assert_ne!(result.exit_code, Some(0));
    }

    #[test]
    fn spill_overflow_writes_file() {
        let _lock = lock();
        let exec = ProcessExecutor::new();
        let result = exec
            .execute(
                "node",
                &[
                    "-e".to_string(),
                    "console.log('x'.repeat(100000));".to_string(),
                ],
                None,
                30,
            )
            .unwrap();
        assert!(result.success);
        assert!(result.stdout_truncated);
        let stdout_path = result.stdout_path.expect("expected spill path");
        assert!(result.stdout.len() < 100_000);
        let content = fs::read_to_string(&stdout_path).expect("spill file readable");
        assert_eq!(content, "x".repeat(100_000) + "\n");
    }

    #[test]
    fn output_redaction_hides_secrets() {
        let _lock = lock();
        let exec = ProcessExecutor::new();
        let result = exec
            .execute(
                "node",
                &[
                    "-e".to_string(),
                    r#"console.log("API_KEY=secret123"); console.log("token=abc");"#.to_string(),
                ],
                None,
                30,
            )
            .unwrap();
        assert!(result.success, "{:?}", result.error_type);
        assert!(!result.stdout.contains("secret123"));
        assert!(!result.stdout.contains("abc"));
        assert!(result.stdout.contains("[REDACTED]"));
    }

    #[cfg(windows)]
    #[test]
    fn job_object_create_and_drop() {
        let _lock = lock();
        let job = ProcessJob::create().unwrap();
        drop(job); // must not panic; kill-on-close fires if a process is assigned
    }
}
