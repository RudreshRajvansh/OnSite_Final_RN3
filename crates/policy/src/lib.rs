use engine::Observation;
use serde::Deserialize;
use wsl::glob_match;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Credential {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub issued: String,
    #[serde(default)]
    pub last_rotated: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BotPolicy {
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub credential: Credential,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub allowed_steps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyFinding {
    pub subject: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    pub checked_identities: usize,
    pub checked_actions: usize,
    pub findings: Vec<PolicyFinding>,
}

impl PolicyOutcome {
    pub fn allowed(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn messages(&self) -> Vec<String> {
        self.findings.iter().map(|f| f.detail.clone()).collect()
    }
}

pub fn load(path: impl AsRef<std::path::Path>) -> Result<BotPolicy, String> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {}", path.display(), e))
}

fn identity_of(principal: &str) -> String {
    if principal.contains('@') {
        principal.to_string()
    } else {
        format!("{}@ci.internal", principal)
    }
}

/// The legacy check every existing tool already runs: is each action one this
/// identity is permitted to perform? It knows nothing about whether the run as
/// a whole was possible, which is the entire point of the comparison.
///
/// The identity is a glob, so a policy written as `*` admits any principal.
/// That is not laxness for its own sake: it is what a stolen but genuine
/// credential looks like to an identity checker, and the demo depends on this
/// check passing a run that reachability then rejects.
pub fn evaluate(policy: &BotPolicy, obs: &Observation) -> PolicyOutcome {
    let mut findings = Vec::new();
    let mut checked_identities = 0usize;
    let mut checked_actions = 0usize;

    for record in &obs.records {
        checked_identities += 1;
        if !policy.identity.is_empty() {
            let identity = identity_of(&record.principal);
            if identity != policy.identity && !glob_match(&policy.identity, &identity) {
                findings.push(PolicyFinding {
                    subject: record.id.clone(),
                    detail: format!("`{}` is not the authorised identity", identity),
                });
            }
        }
        if let Some(step) = &record.step {
            if !policy.allowed_steps.is_empty() && !policy.allowed_steps.contains(step) {
                findings.push(PolicyFinding {
                    subject: record.id.clone(),
                    detail: format!("step `{}` is not permitted for this identity", step),
                });
            }
        }
        for effect in &record.effects {
            checked_actions += 1;
            if !policy.allowed_actions.is_empty() && !policy.allowed_actions.contains(&effect.kind)
            {
                findings.push(PolicyFinding {
                    subject: effect.id.clone(),
                    detail: format!("action `{}` is not permitted", effect.kind),
                });
                continue;
            }
            let Some(scope) = effect.args.get("scope") else {
                continue;
            };
            if !policy.allowed_scopes.is_empty()
                && !policy.allowed_scopes.iter().any(|p| glob_match(p, scope))
            {
                findings.push(PolicyFinding {
                    subject: effect.id.clone(),
                    detail: format!("scope `{}` is outside the permitted scopes", scope),
                });
            }
        }
    }

    PolicyOutcome {
        checked_identities,
        checked_actions,
        findings,
    }
}
