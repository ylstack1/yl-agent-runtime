//! Sensitive-file matcher
//!
//! Classifies a path as `Allowed` or `Blocked` for filesystem access before
//! any I/O happens. Three tiers of glob patterns are consulted in a fixed
//! resolution order (PRD section 8.2, safe-by-default file policy):
//!
//! 1. operator **deny** — a match blocks, nothing can relieve it (`Blocked`
//!    carries the deny pattern text);
//! 2. operator **allow** — a match relieves a *builtin* block and returns
//!    `Allowed`;
//! 3. builtin patterns (`BUILTIN_SENSITIVE_PATTERNS`) — a match blocks with
//!    the builtin pattern text;
//! 4. otherwise `Allowed`.
//!
//! Pattern→glob rule: a pattern containing `/` is compiled as-is **and** with
//! a `**/` prefix (matches at any depth); a bare pattern compiles as
//! `**/<pat>` (basename match at any depth). Every glob is built
//! case-insensitively with `literal_separator(true)`, so `*` never crosses a
//! directory boundary and `**/` alone supplies the any-depth semantics.
//! Candidates are matched against the full path string AND the file name.
//!
//! Before matching, an NTFS alternate-data-stream suffix is stripped
//! (`"notes.txt:ads"` → `"notes.txt"`): the only legal `:` in a path is the
//! single-letter drive prefix at offset 0, so the last `:` marks where a
//! stream begins and the tail is dropped. `C:` itself is left intact.

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use std::path::Path;

/// Built-in sensitive-file patterns blocked unless an operator allow rule
/// relieves them. Kept as plain gitignore-style glob text (all with `/`
/// separators) so they can be surfaced in errors and configuration.
pub const BUILTIN_SENSITIVE_PATTERNS: &[&str] = &[
    ".env", ".env.*", ".envrc", ".htpasswd", ".npmrc", ".pypirc", ".netrc", "_netrc",
    ".git-credentials", ".pgpass", ".ssh/**", ".gnupg/**", ".aws/**", ".kube/**",
    ".vault-token", ".terraform.d/credentials*", ".cargo/credentials*",
    ".docker/config.json", ".dockercfg", ".s3cfg",
    "*.tfstate", "*.tfstate.*", "*.tfvars", "*.tfvars.json", ".dev.vars",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.ppk", "*.jks", "*.keystore",
    "*id_rsa*", "*id_dsa*", "*id_ecdsa*", "*id_ed25519*",
];

/// The matcher's decision for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitiveVerdict {
    /// No sensitive-pattern tier matched (or an operator allow relieved the
    /// builtins).
    Allowed,
    /// A deny or builtin pattern matched; `pattern` is the pattern text that
    /// matched (the first one in resolution/declaration order).
    Blocked { pattern: String },
}

/// Glob-based sensitive-file classifier (deny → allow → builtin → allowed).
///
/// Construction panics on a malformed pattern: an invalid `deny` glob must
/// fail loudly rather than silently fail-open the path.
pub struct SensitiveMatcher {
    builtin: GlobSet,
    builtin_patterns: Vec<&'static str>,
    deny: GlobSet,
    deny_patterns: Vec<String>,
    allow: GlobSet,
}

impl SensitiveMatcher {
    /// A matcher with only the builtin patterns.
    pub fn new() -> Self {
        let mut builder = GlobSetBuilder::new();
        let mut builtin_patterns = Vec::new();
        for pattern in BUILTIN_SENSITIVE_PATTERNS {
            for glob in compile_pattern(pattern) {
                builder.add(glob);
                builtin_patterns.push(*pattern);
            }
        }
        let builtin = builder.build().expect("builtin sensitive patterns must compile");
        Self {
            builtin,
            builtin_patterns,
            deny: GlobSet::empty(),
            deny_patterns: Vec::new(),
            allow: GlobSet::empty(),
        }
    }

    /// Replace the operator deny tier with `patterns` (deny beats everything).
    pub fn with_operator_deny(mut self, patterns: &[String]) -> Self {
        (self.deny, self.deny_patterns) = build_tier(patterns);
        self
    }

    /// Replace the operator allow tier with `patterns` (relieves builtins
    /// only; a deny match still blocks).
    pub fn with_operator_allow(mut self, patterns: &[String]) -> Self {
        (self.allow, _) = build_tier(patterns);
        self
    }

    /// Classify `path` against the tiers: operator deny → operator allow →
    /// builtin → allowed. Case-insensitive; matched against the file name AND
    /// the path; the ADS suffix is stripped first. Never panics: degenerate
    /// inputs (empty path, `C:`-only, trailing separator, stray colons) simply
    /// match nothing.
    pub fn verdict(&self, path: &Path) -> SensitiveVerdict {
        let raw = path.to_string_lossy();
        let full = strip_ads_suffix(&raw);
        let name = Path::new(full).file_name().map(|n| n.to_string_lossy());

        if let Some(pattern) = first_match(&self.deny, &self.deny_patterns, full, name.as_deref()) {
            return SensitiveVerdict::Blocked { pattern };
        }
        if any_match(&self.allow, full, name.as_deref()) {
            return SensitiveVerdict::Allowed;
        }
        if let Some(pattern) = first_match(&self.builtin, &self.builtin_patterns, full, name.as_deref()) {
            return SensitiveVerdict::Blocked { pattern };
        }
        SensitiveVerdict::Allowed
    }
}

impl Default for SensitiveMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile one tier: each pattern per the pattern→glob rule, paired with a
/// pattern-text vec parallel to the produced `GlobSet` sequence order.
fn build_tier(patterns: &[String]) -> (GlobSet, Vec<String>) {
    let mut builder = GlobSetBuilder::new();
    let mut texts = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        for glob in compile_pattern(pattern) {
            builder.add(glob);
            texts.push(pattern.clone());
        }
    }
    (builder.build().expect("operator patterns must compile"), texts)
}

/// Compile one rule application: a pattern containing `/` is compiled as-is
/// and with a `**/` prefix; a bare pattern compiles as `**/<pat>`.
fn compile_pattern(pattern: &str) -> Vec<Glob> {
    let compile = |text: &str| {
        GlobBuilder::new(text)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
            .unwrap_or_else(|err| panic!("invalid sensitive-file glob pattern {pattern:?}: {err}"))
    };
    if pattern.contains('/') {
        vec![compile(pattern), compile(&format!("**/{pattern}"))]
    } else {
        vec![compile(&format!("**/{pattern}"))]
    }
}

/// First matching pattern (glob sequence order = first declared pattern), over
/// the full path and then the file name.
fn first_match<P: AsRef<str>>(
    set: &GlobSet,
    patterns: &[P],
    full: &str,
    name: Option<&str>,
) -> Option<String> {
    for candidate in [Some(full), name] {
        let Some(text) = candidate else { continue };
        if let Some(&index) = set.matches(text).first() {
            return Some(patterns[index].as_ref().to_string());
        }
    }
    None
}

/// Whether any pattern of the set matches the full path or the file name.
fn any_match(set: &GlobSet, full: &str, name: Option<&str>) -> bool {
    set.is_match(full) || name.is_some_and(|name| set.is_match(name))
}

/// Strip an NTFS alternate-data-stream suffix: `"notes.txt:ads"` ->
/// `"notes.txt"`. The only legal `:` is the single-letter drive prefix at
/// offset 0, so the LAST `:` marks the stream head; a colon that is itself the
/// drive prefix (`C:`) is kept. Slicing at a `:` is always a char boundary.
fn strip_ads_suffix(raw: &str) -> &str {
    match raw.rfind(':') {
        Some(index) if !(index == 1 && raw.as_bytes()[0].is_ascii_alphabetic()) => &raw[..index],
        _ => raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn m() -> SensitiveMatcher {
        SensitiveMatcher::new()
    }

    #[test]
    fn builtin_env_blocked() {
        assert_eq!(
            m().verdict(Path::new("C:/ws/.env")),
            SensitiveVerdict::Blocked { pattern: ".env".into() }
        );
        assert_eq!(
            m().verdict(Path::new("C:/ws/app/.env.local")),
            SensitiveVerdict::Blocked { pattern: ".env.*".into() }
        );
    }

    #[test]
    fn builtin_key_case_insensitive() {
        assert!(matches!(
            m().verdict(Path::new("C:/ws/KEY.PEM")),
            SensitiveVerdict::Blocked { .. }
        ));
    }

    #[test]
    fn builtin_ssh_dir_blocked_and_nested() {
        assert!(matches!(
            m().verdict(Path::new("C:/ws/.ssh/id_rsa")),
            SensitiveVerdict::Blocked { .. }
        ));
    }

    #[test]
    fn plain_file_allowed() {
        assert_eq!(m().verdict(Path::new("C:/ws/notes.txt")), SensitiveVerdict::Allowed);
    }

    #[test]
    fn operator_allow_relieves_builtin_but_not_deny() {
        let a = m().with_operator_allow(&[".env".to_string()]);
        assert_eq!(a.verdict(Path::new("C:/ws/.env")), SensitiveVerdict::Allowed);

        let d = m()
            .with_operator_deny(&["secrets/**".to_string()])
            .with_operator_allow(&["secrets/tokens.txt".to_string()]);
        assert!(matches!(
            d.verdict(Path::new("C:/ws/secrets/tokens.txt")),
            SensitiveVerdict::Blocked { .. }
        ));
    }

    #[test]
    fn ads_suffix_stripped_before_match() {
        assert_eq!(m().verdict(Path::new("C:/ws/notes.txt:hidden")), SensitiveVerdict::Allowed);
        assert!(matches!(
            m().verdict(Path::new("C:/ws/.env:hidden")),
            SensitiveVerdict::Blocked { .. }
        ));
    }

    // --- Self-review hardening (Task 3 step 6) -------------------------------

    #[test]
    fn verdict_never_panics_on_degenerate_paths() {
        let matcher = m();
        for weird in [
            "", ":", "::", "C:", "/", "\\", "C:/", "C:/ws/", "..", ".",
            "C::x", "s://host/KEY.PEM", "É:/ws/.env", ".env", "BACKUP/key.pem",
        ] {
            let _ = matcher.verdict(Path::new(weird)); // must not panic
        }
    }

    #[test]
    fn case_insensitivity_applies_to_operator_tiers_too() {
        let d = m().with_operator_deny(&["SECRETS/**".to_string()]);
        assert!(matches!(
            d.verdict(Path::new("C:/ws/secrets/db.kdbx")),
            SensitiveVerdict::Blocked { .. }
        ));
    }

    #[test]
    fn resolution_order_deny_allow_builtin_allowed() {
        // deny beats both the operator allow tier and the builtins: all three
        // tiers match here, and the reported pattern text proves the DENY tier
        // fired ("keys/**", not the builtin "*.pem").
        let denier = m()
            .with_operator_deny(&["keys/**".to_string()])
            .with_operator_allow(&["keys/**".to_string()]);
        assert_eq!(
            denier.verdict(Path::new("C:/ws/keys/server.pem")),
            SensitiveVerdict::Blocked { pattern: "keys/**".into() }
        );
        // allow relieves the builtin for the same file
        let reliever = m().with_operator_allow(&["*.pem".to_string()]);
        assert_eq!(
            reliever.verdict(Path::new("C:/ws/keys/server.pem")),
            SensitiveVerdict::Allowed
        );
        // with no allow, the builtin still blocks
        assert_eq!(
            m().verdict(Path::new("C:/ws/keys/server.pem")),
            SensitiveVerdict::Blocked { pattern: "*.pem".into() }
        );
    }

    #[test]
    fn trailing_separator_and_nested_dotenv_edge_cases() {
        // A directory-like path matching a builtin is blocked (fail-closed)...
        assert!(matches!(
            m().verdict(Path::new("C:/ws/.ssh/")),
            SensitiveVerdict::Blocked { .. }
        ));
        // ...but `*` does not cross separators: a file *inside* a directory
        // whose name happens to match `.env.*` is not blocked by `.env.*`
        // (it would need its own sensitive name).
        assert_eq!(
            m().verdict(Path::new("C:/ws/.env.local/notes.txt")),
            SensitiveVerdict::Allowed
        );
    }
}
