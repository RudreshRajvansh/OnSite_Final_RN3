use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
pub struct Workflow {
    #[serde(default)]
    pub name: Option<String>,
    pub jobs: BTreeMap<String, WfJob>,
}

#[derive(Debug, Deserialize)]
pub struct WfJob {
    #[serde(default)]
    pub needs: Needs,
    #[serde(default)]
    pub steps: Vec<WfStep>,
}

#[derive(Debug, Deserialize)]
pub struct WfStep {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub run: Option<String>,
    #[serde(default)]
    pub uses: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum Needs {
    One(String),
    Many(Vec<String>),
    #[default]
    None,
}

impl Needs {
    fn ids(&self) -> Vec<String> {
        match self {
            Needs::One(s) => vec![s.clone()],
            Needs::Many(v) => v.clone(),
            Needs::None => Vec::new(),
        }
    }
}

/// Turn a job name into a workflow-net transition id.
pub fn slug(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect()
}

pub fn guess_effect(job: &WfJob) -> Option<&'static str> {
    // Score every step, then keep the strongest signal in the job:
    // a publishing job that also checks out is a publish, not a read.
    let mut best = 0u8;
    let mut effect = None;
    for step in &job.steps {
        // Match on the human-meaningful label and the action used, not the
        // shell body: a `run:` block often interpolates other jobs' outputs
        // (e.g. needs.build.*), which would misclassify the step.
        let hay = format!(
            "{} {}",
            step.name.clone().unwrap_or_default().to_lowercase(),
            step.uses.clone().unwrap_or_default().to_lowercase()
        );
        let (rank, kind): (u8, &'static str) =
            if hay.contains("publish") || hay.contains("release to") || hay.contains("npm publish") || hay.contains("docker push") || hay.contains("cargo publish") {
                (4, "registry_write")
            } else if hay.contains("build") || hay.contains("compile") {
                (3, "artifact_create")
            } else if hay.contains("test") {
                (2, "ci_report")
            } else if hay.contains("checkout") {
                (1, "vcs_read")
            } else {
                (0, "")
            };
        if rank > best {
            best = rank;
            effect = Some(kind);
        }
    }
    effect
}

pub fn generate(wf: &Workflow) -> String {
    let name = wf.name.clone().unwrap_or_else(|| "workflow".to_string());
    let mut out = String::new();
    out.push_str("# GENERATED SKELETON. Review every TODO before trusting a verdict.\n");
    out.push_str("# The job graph and identities are inferred from the workflow file.\n");
    out.push_str("# A human must still add: digests, effect arguments, and the\n");
    out.push_str("# `requires_relation` links that actually catch tampering.\n");
    out.push_str("spec_version: 1\n");
    out.push_str(&format!("workflow: {}\n\n", slug(&name)));

    out.push_str("principals:\n");
    out.push_str("  gha_runner:\n");
    out.push_str("    class: service_account\n");
    out.push_str("    id_pattern: \"*\"        # TODO restrict to your bot identity\n\n");

    // Places: a start place, plus one place produced by each job.
    out.push_str("places:\n");
    out.push_str("  - id: start\n");
    out.push_str("    tokens:\n");
    out.push_str("      - { type: repository, value: \"*\" }\n");
    let mut job_ids: Vec<&String> = wf.jobs.keys().collect();
    job_ids.sort();
    // A digest only exists if some job actually builds one. Without a build,
    // nothing can carry or bind it, so the spec must not reference $digest.
    let has_build = job_ids
        .iter()
        .any(|j| guess_effect(&wf.jobs[*j]) == Some("artifact_create"));
    for id in &job_ids {
        let carries = match guess_effect(&wf.jobs[*id]) {
            Some("artifact_create") => "\n    carries: [digest]",
            Some("ci_report") | Some("registry_write") if has_build => "\n    carries: [digest]",
            _ => "",
        };
        out.push_str(&format!("  - id: p_{}{}\n", slug(id), carries));
    }
    out.push('\n');

    // Final marking: places nothing depends on.
    let depended: std::collections::BTreeSet<String> = wf
        .jobs
        .values()
        .flat_map(|j| j.needs.ids())
        .collect();
    let finals: Vec<String> = job_ids
        .iter()
        .filter(|id| !depended.contains(**id))
        .map(|id| format!("p_{}", slug(id)))
        .collect();
    out.push_str(&format!("final: [{}]\n\n", finals.join(", ")));

    out.push_str("transitions:\n");
    for id in &job_ids {
        let job = &wf.jobs[*id];
        let needs = job.needs.ids();
        let consumes: Vec<String> = if needs.is_empty() {
            vec!["start".to_string()]
        } else {
            needs.iter().map(|n| format!("p_{}", slug(n))).collect()
        };
        out.push_str(&format!("  - id: {}\n", slug(id)));
        out.push_str("    principal: gha_runner\n");
        out.push_str(&format!("    consumes: [{}]\n", consumes.join(", ")));
        out.push_str(&format!("    produces: [p_{}]\n", slug(id)));

        match guess_effect(job) {
            Some("artifact_create") => {
                out.push_str("    binds:\n      digest: fresh\n");
                out.push_str("    emits:\n");
                out.push_str("      - effect: artifact_create\n        digest: $digest\n");
            }
            Some("registry_write") => {
                out.push_str("    emits:\n");
                out.push_str("      - effect: registry_write\n");
                out.push_str("        scope: \"registry://prod/*\"   # TODO tighten scope\n");
                out.push_str(if has_build {
                    "        digest: $digest\n"
                } else {
                    "        digest: \"*\"   # no build job in this workflow to mint one\n"
                });
                // Only demand a producing build when the workflow actually has one.
                if has_build {
                    out.push_str("        requires_relation:\n");
                    out.push_str("          - type: derives_from\n");
                    out.push_str("            target: artifact_create   # TODO name the producing build\n");
                    out.push_str("            bind: { digest: $digest }\n");
                }
            }
            Some("ci_report") => {
                out.push_str("    emits:\n      - effect: ci_report\n        digest: $digest\n");
            }
            Some("vcs_read") => {
                out.push_str("    emits:\n      - effect: vcs_read\n        scope: \"repo/*\"\n");
            }
            _ => {
                out.push_str("    # TODO declare what this job emits\n");
                out.push_str("    emits: []\n");
            }
        }
        out.push('\n');
    }

    let effects: std::collections::BTreeSet<&str> =
        job_ids.iter().filter_map(|id| guess_effect(&wf.jobs[*id])).collect();
    if effects.contains("registry_write") && effects.contains("artifact_create") {
        out.push_str("relations:\n");
        out.push_str("  derives_from:\n");
        out.push_str("    from: registry_write\n");
        out.push_str("    to: artifact_create\n");
        out.push_str("    constraint: \"from.digest == to.digest\"\n");
    } else {
        out.push_str("# No build->publish pair detected, so no derives_from relation was\n");
        out.push_str("# generated. This pipeline only reads and commits; anything it published\n");
        out.push_str("# would be an effect with no producing transition, and rejected.\n");
    }

    out
}
