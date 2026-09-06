use engine::Observation;
use serde::Deserialize;
use wsl::glob_match;

#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub issued: String,
    #[serde(default)]
    pub last_rotated: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BotPolicy {
    pub identity: String,
    #[serde(default)]
    pub description: String,
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
}

pub fn load(path: impl AsRef<std::path::Path>) -> Result<BotPolicy, String> {
    let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn identity_of(principal: &str) -> String {
    if principal.contains('@') {
        principal.to_string()
    } else {
        format!("{}@ci.internal", principal)
    }
}

pub fn evaluate(policy: &BotPolicy, obs: &Observation) -> PolicyOutcome {
    let mut findings = Vec::new();
    let mut checked_identities = 0usize;
    let mut checked_actions = 0usize;

    for record in &obs.records {
        checked_identities += 1;
        let identity = identity_of(&record.principal);
        if identity != policy.identity {
            findings.push(PolicyFinding {
                subject: record.id.clone(),
                detail: format!("`{}` is not the authorised identity", identity),
            });
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
            if !policy.allowed_actions.is_empty() && !policy.allowed_actions.contains(&effect.kind) {
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
