use engine::{EffectInstance, Observation, ObservedEdge, Plane, Record};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdapterMap {
    #[serde(default)]
    pub planes: BTreeMap<String, Plane>,
    #[serde(default = "default_runner_principal")]
    pub runner_principal: String,
    #[serde(default)]
    pub jobs: BTreeMap<String, StepRule>,
    #[serde(default)]
    pub registry_actions: BTreeMap<String, EffectRule>,
    #[serde(default)]
    pub audit_actions: BTreeMap<String, StepRule>,
}

fn default_runner_principal() -> String {
    "${actor}".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRule {
    pub step: String,
    #[serde(default)]
    pub effects: Vec<EffectRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectRule {
    pub kind: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Bundle {
    pub run_id: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub runner: RunnerPlane,
    #[serde(default)]
    pub registry: RegistryPlane,
    #[serde(default)]
    pub cloud_audit: AuditPlane,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RunnerPlane {
    #[serde(default)]
    pub jobs: Vec<Job>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub outputs: BTreeMap<String, String>,
    #[serde(default = "default_conclusion")]
    pub conclusion: String,
}

fn default_conclusion() -> String {
    "success".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegistryPlane {
    #[serde(default)]
    pub events: Vec<RegistryEvent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryEvent {
    pub id: String,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub provenance: Option<Provenance>,
    #[serde(flatten)]
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Provenance {
    pub build_digest: String,
    #[serde(default)]
    pub issuer: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuditPlane {
    #[serde(default)]
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    #[serde(default)]
    pub ts: String,
    pub principal: String,
    pub action: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum AdapterError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::Io(m) => write!(f, "cannot read input: {}", m),
            AdapterError::Parse(m) => write!(f, "cannot parse input: {}", m),
        }
    }
}

impl std::error::Error for AdapterError {}

pub fn load_map(path: impl AsRef<std::path::Path>) -> Result<AdapterMap, AdapterError> {
    let raw = std::fs::read_to_string(path).map_err(|e| AdapterError::Io(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| AdapterError::Parse(e.to_string()))
}

pub fn load_bundle(path: impl AsRef<std::path::Path>) -> Result<Bundle, AdapterError> {
    let raw = std::fs::read_to_string(path).map_err(|e| AdapterError::Io(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| AdapterError::Parse(e.to_string()))
}

fn substitute(template: &str, context: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let Some(end) = tail.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let key = &tail[..end];
        match context.get(key) {
            Some(value) => out.push_str(value),
            None => out.push_str(&format!("<unresolved:{}>", key)),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

fn render_effects(
    rules: &[EffectRule],
    context: &BTreeMap<String, String>,
    record_id: &str,
) -> Vec<EffectInstance> {
    rules
        .iter()
        .enumerate()
        .map(|(i, rule)| EffectInstance {
            id: format!("{}.{}", record_id, i),
            kind: rule.kind.clone(),
            args: rule
                .args
                .iter()
                .map(|(k, v)| (k.clone(), substitute(v, context)))
                .collect(),
        })
        .collect()
}

pub fn normalize(bundle: &Bundle, map: &AdapterMap) -> Observation {
    let repository_name = bundle
        .repository
        .rsplit('/')
        .next()
        .unwrap_or(&bundle.repository)
        .to_string();

    let mut records: Vec<Record> = Vec::new();

    for job in &bundle.runner.jobs {
        if job.conclusion != "success" {
            continue;
        }
        let Some(rule) = map.jobs.get(&job.name) else {
            continue;
        };
        let mut context: BTreeMap<String, String> = BTreeMap::new();
        context.insert("repository".to_string(), bundle.repository.clone());
        context.insert("repository_name".to_string(), repository_name.clone());
        context.insert("actor".to_string(), job.actor.clone());
        context.insert("job".to_string(), job.name.clone());
        context.insert("ts".to_string(), job.ts.clone());
        for (k, v) in &job.outputs {
            context.insert(format!("outputs.{}", k), v.clone());
        }
        records.push(Record {
            id: job.id.clone(),
            plane: "runner".to_string(),
            principal: substitute(&map.runner_principal, &context),
            step: Some(rule.step.clone()),
            ts: job.ts.clone(),
            effects: render_effects(&rule.effects, &context, &job.id),
        });
    }

    for entry in &bundle.cloud_audit.entries {
        let Some(rule) = map.audit_actions.get(&entry.action) else {
            continue;
        };
        let mut context: BTreeMap<String, String> = BTreeMap::new();
        context.insert("principal".to_string(), entry.principal.clone());
        context.insert("action".to_string(), entry.action.clone());
        context.insert("ts".to_string(), entry.ts.clone());
        for (k, v) in &entry.attributes {
            context.insert(format!("attributes.{}", k), v.clone());
        }
        records.push(Record {
            id: entry.id.clone(),
            plane: "audit".to_string(),
            principal: entry.principal.clone(),
            step: Some(rule.step.clone()),
            ts: entry.ts.clone(),
            effects: render_effects(&rule.effects, &context, &entry.id),
        });
    }

    let mut edges: Vec<ObservedEdge> = Vec::new();

    for event in &bundle.registry.events {
        let Some(rule) = map.registry_actions.get(&event.action) else {
            continue;
        };
        let mut context: BTreeMap<String, String> = BTreeMap::new();
        context.insert("actor".to_string(), event.actor.clone());
        context.insert("action".to_string(), event.action.clone());
        context.insert("ts".to_string(), event.ts.clone());
        for (k, v) in &event.fields {
            context.insert(k.clone(), v.clone());
        }
        let effects = render_effects(std::slice::from_ref(rule), &context, &event.id);
        if let (Some(provenance), Some(effect)) = (&event.provenance, effects.first()) {
            let target = records
                .iter()
                .flat_map(|r| r.effects.iter())
                .find(|e| {
                    e.kind == "artifact_create"
                        && e.args.get("digest") == Some(&provenance.build_digest)
                });
            if let Some(target) = target {
                edges.push(ObservedEdge {
                    ty: "derives_from".to_string(),
                    from: effect.id.clone(),
                    to: target.id.clone(),
                });
            }
        }
        records.push(Record {
            id: event.id.clone(),
            plane: "registry".to_string(),
            principal: event.actor.clone(),
            step: None,
            ts: event.ts.clone(),
            effects,
        });
    }

    records.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.id.cmp(&b.id)));

    Observation {
        run_id: bundle.run_id.clone(),
        planes: map.planes.clone(),
        records,
        edges,
    }
}
