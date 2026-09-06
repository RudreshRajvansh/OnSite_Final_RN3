pub mod generate;
pub mod lint;
pub mod model;

pub mod mutate;

pub use lint::{lint, Diagnostic, LintReport, Severity};
pub use model::{
    classify, glob_match, BindMode, EffectTemplate, Invariant, InvariantKind, Pattern, Place,
    Principal, PrincipalClass, RelationObligation, RelationSchema, Spec, TokenSpec, Transition,
};
pub use mutate::{apply, mutants, Mutant, Mutation};

use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum WslError {
    #[error("cannot read spec `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse spec: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("spec `{workflow}` is not sound: {count} error(s)")]
    Unsound { workflow: String, count: usize },
    #[error("unsupported spec_version {0}")]
    Version(u32),
}

#[derive(Debug, Clone)]
pub struct LoadedSpec {
    pub spec: Spec,
    pub hash: String,
    pub report: LintReport,
}

impl LoadedSpec {
    pub fn short_hash(&self) -> String {
        format!("{}@sha256:{}", self.spec.workflow, &self.hash[..12])
    }
}

pub fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn parse_str(raw: &str) -> Result<LoadedSpec, WslError> {
    let spec: Spec = serde_yaml::from_str(raw)?;
    if spec.spec_version != 1 {
        return Err(WslError::Version(spec.spec_version));
    }
    let report = lint(&spec);
    Ok(LoadedSpec {
        hash: digest(raw.as_bytes()),
        spec,
        report,
    })
}

pub fn load(path: impl AsRef<Path>) -> Result<LoadedSpec, WslError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|source| WslError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_str(&raw)
}

pub fn load_checked(path: impl AsRef<Path>) -> Result<LoadedSpec, WslError> {
    let loaded = load(path)?;
    if !loaded.report.is_sound() {
        return Err(WslError::Unsound {
            workflow: loaded.spec.workflow.clone(),
            count: loaded.report.errors().len(),
        });
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> LoadedSpec {
        load("../../spec/release.wsl.yaml").expect("spec parses")
    }

    #[test]
    fn reference_spec_is_sound() {
        let loaded = fixture();
        let errors: Vec<String> = loaded
            .report
            .errors()
            .iter()
            .map(|d| format!("{} {}", d.code, d.message))
            .collect();
        assert!(errors.is_empty(), "{:#?}", errors);
    }

    #[test]
    fn reference_spec_reports_free_choice_escape_hatch() {
        let loaded = fixture();
        assert!(loaded.report.warnings().iter().any(|d| d.code == "W013"));
    }

    #[test]
    fn dead_transition_is_rejected() {
        let raw = r#"
spec_version: 1
workflow: dead
principals:
  bot: { class: service_account, id_pattern: "bot@*" }
places:
  - { id: start, tokens: [{ type: repo, value: app }] }
  - { id: orphan }
  - { id: done }
final: [done]
transitions:
  - { id: go, principal: bot, consumes: [start], produces: [done] }
  - { id: never, principal: bot, consumes: [orphan], produces: [done] }
"#;
        let loaded = parse_str(raw).unwrap();
        assert!(loaded.report.errors().iter().any(|d| d.code == "W009"));
    }

    #[test]
    fn unbound_variable_is_rejected() {
        let raw = r#"
spec_version: 1
workflow: unbound
principals:
  bot: { class: service_account, id_pattern: "bot@*" }
places:
  - { id: start, tokens: [{ type: repo, value: app }] }
  - { id: done }
final: [done]
transitions:
  - id: go
    principal: bot
    consumes: [start]
    produces: [done]
    emits:
      - { effect: registry_write, digest: $digest }
"#;
        let loaded = parse_str(raw).unwrap();
        assert!(loaded.report.errors().iter().any(|d| d.code == "W018"));
    }

    #[test]
    fn glob_matches_principal_patterns() {
        assert!(glob_match("ci-bot@*", "ci-bot@ci.internal"));
        assert!(glob_match("*@corp.example", "sre@corp.example"));
        assert!(!glob_match("*@corp.example", "ci-bot@ci.internal"));
        assert!(glob_match("registry://prod/*", "registry://prod/app"));
        assert!(!glob_match("registry://prod/*", "registry://staging/app"));
    }
}
