use engine::Observation;
use serde::Deserialize;
use wsl::glob_match;

#[derive(Debug, Clone, Deserialize)]
pub struct BotPolicy {
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
}

fn identity_of(principal: &str) -> String {
    if principal.contains('@') {
        principal.to_string()
    } else {
        format!("{}@ci.internal", principal)
    }
}

/// The legacy check every existing tool runs: is each action one this identity
/// is permitted to perform? It knows nothing about whether the run was possible.
pub fn evaluate(policy: &BotPolicy, obs: &Observation) -> (bool, Vec<String>) {
    let mut findings = Vec::new();
    for record in &obs.records {
        if !policy.identity.is_empty() {
            let id = identity_of(&record.principal);
            if id != policy.identity && !glob_match(&policy.identity, &id) {
                findings.push(format!("{} is not the authorised identity", id));
            }
        }
        for effect in &record.effects {
            if !policy.allowed_actions.is_empty() && !policy.allowed_actions.contains(&effect.kind)
            {
                findings.push(format!("action {} is not permitted", effect.kind));
                continue;
            }
            if let Some(scope) = effect.args.get("scope") {
                if !policy.allowed_scopes.is_empty()
                    && !policy.allowed_scopes.iter().any(|p| glob_match(p, scope))
                {
                    findings.push(format!("scope {} is outside the permitted scopes", scope));
                }
            }
        }
    }
    (findings.is_empty(), findings)
}

pub fn load(path: impl AsRef<std::path::Path>) -> Option<BotPolicy> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}
