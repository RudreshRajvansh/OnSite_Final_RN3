use crate::{render_effects, substitute, AdapterError, AdapterMap, Provenance};
use engine::{Observation, ObservedEdge, Record};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Run {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub head_sha: String,
    #[serde(default)]
    pub run_started_at: String,
    #[serde(default)]
    pub actor: Option<Actor>,
    #[serde(default)]
    pub repository: Option<Repository>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Actor {
    pub login: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Repository {
    pub full_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jobs {
    #[serde(default)]
    pub jobs: Vec<Job>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    #[serde(default)]
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    pub name: String,
    #[serde(default)]
    pub number: u32,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub started_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Fact {
    pub step: String,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(untagged)]
pub enum Facts {
    List(Vec<Fact>),
    #[default]
    None,
}

impl Facts {
    pub fn items(&self) -> &[Fact] {
        match self {
            Facts::List(v) => v,
            Facts::None => &[],
        }
    }
}

fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, AdapterError> {
    let raw = std::fs::read_to_string(path).map_err(|e| AdapterError::Io(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| AdapterError::Parse(format!("{}: {}", path.display(), e)))
}

pub fn load_run(path: impl AsRef<std::path::Path>) -> Result<Run, AdapterError> {
    read(path.as_ref())
}

pub fn load_jobs(path: impl AsRef<std::path::Path>) -> Result<Jobs, AdapterError> {
    read(path.as_ref())
}

pub fn load_facts(path: impl AsRef<std::path::Path>) -> Result<Vec<Fact>, AdapterError> {
    let facts: Facts = read(path.as_ref())?;
    Ok(facts.items().to_vec())
}


fn slugify(name: &str) -> String {
    // Collapse runs of separators: "Build, test, publish" and "build-test-publish"
    // must both reduce to the same key.
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            sep = false;
        } else if !sep {
            out.push('_');
            sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Match a runtime job name against the declared jobs, tolerating the shapes
/// GitHub actually produces: "Caller / inner job" for reusable workflows and
/// "job (param)" for matrix legs.
fn resolve_rule<'a>(map: &'a AdapterMap, job_name: &str) -> Option<&'a crate::StepRule> {
    if let Some(r) = map.jobs.get(job_name) {
        return Some(r);
    }
    let tail = job_name.rsplit('/').next().unwrap_or(job_name).trim();
    if let Some(r) = map.jobs.get(tail) {
        return Some(r);
    }
    let base = tail.split(" (").next().unwrap_or(tail).trim();
    if let Some(r) = map.jobs.get(base) {
        return Some(r);
    }
    let want = slugify(base);
    let head = slugify(job_name.split('/').next().unwrap_or(job_name).trim());
    map.jobs
        .iter()
        .find(|(k, _)| slugify(k) == want || slugify(k) == head)
        .map(|(_, v)| v)
}

pub fn normalize(run: &Run, jobs: &Jobs, facts: &[Fact], map: &AdapterMap) -> Observation {
    let actor = run
        .actor
        .as_ref()
        .map(|a| a.login.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let repository = run
        .repository
        .as_ref()
        .map(|r| r.full_name.clone())
        .unwrap_or_default();
    let repository_name = repository
        .rsplit('/')
        .next()
        .unwrap_or(&repository)
        .to_string();

    let mut records: Vec<Record> = Vec::new();
    let mut edges: Vec<ObservedEdge> = Vec::new();
    let mut pending: Vec<(String, String)> = Vec::new();
    // A reusable-workflow call (or a matrix leg) reports many runtime jobs that
    // all resolve to one declared job. The model describes the declared job, so
    // those collapse into a single firing rather than N.
    let mut seen_transitions: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // Map by JOB name: each successful job is one transition firing. Step names
    // in real workflows are freeform, but the job is the unit the spec models.
    for job in &jobs.jobs {
        if job.conclusion.as_deref() != Some("success") {
            continue;
        }
        // Resolve a runtime job name to a declared job. Reusable workflows report
        // jobs as "Caller display name / inner job", and matrix jobs append
        // parameters, so fall back to the trailing segment and a slug compare.
        let Some(rule) = resolve_rule(map, &job.name) else {
            continue;
        };
        if !seen_transitions.insert(rule.step.clone()) {
            continue;
        }
        let tail = job.name.rsplit('/').next().unwrap_or(&job.name).trim();
        let fact = facts.iter().find(|f| f.step == job.name || f.step == tail);

        let mut context: BTreeMap<String, String> = BTreeMap::new();
        context.insert("actor".to_string(), actor.clone());
        context.insert("repository".to_string(), repository.clone());
        context.insert("repository_name".to_string(), repository_name.clone());
        context.insert("job".to_string(), job.name.clone());
        context.insert("commit".to_string(), run.head_sha.clone());
        context.insert("ts".to_string(), job.started_at.clone());
        if let Some(f) = fact {
            if let Some(d) = &f.digest {
                context.insert("digest".to_string(), d.clone());
                context.insert("outputs.digest".to_string(), d.clone());
            }
            if let Some(sc) = &f.scope {
                context.insert("scope".to_string(), sc.clone());
                context.insert("outputs.scope".to_string(), sc.clone());
            }
        }

        let record_id = format!("gha-{}", job.id);
        let effects = render_effects(&rule.effects, &context, &record_id);

        if let (Some(f), Some(effect)) = (fact, effects.first()) {
            if let Some(p) = &f.provenance {
                pending.push((effect.id.clone(), p.build_digest.clone()));
            }
        }

        records.push(Record {
            id: record_id,
            plane: "runner".to_string(),
            principal: substitute(&map.runner_principal, &context),
            step: Some(rule.step.clone()),
            ts: job.started_at.clone(),
            effects,
        });
    }

    for (from, build_digest) in pending {
        let target = records
            .iter()
            .flat_map(|r| r.effects.iter())
            .find(|e| e.kind == "artifact_create" && e.args.get("digest") == Some(&build_digest));
        if let Some(target) = target {
            edges.push(ObservedEdge {
                ty: "derives_from".to_string(),
                from,
                to: target.id.clone(),
            });
        }
    }

    records.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.id.cmp(&b.id)));

    Observation {
        run_id: format!("gha-{}-{}", run.name, run.id),
        planes: map.planes.clone(),
        records,
        edges,
    }
}
