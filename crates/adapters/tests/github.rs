use adapters::github::{normalize, Fact, Job, Jobs, Run};
use adapters::{AdapterMap, EffectRule, Provenance, StepRule};
use std::collections::BTreeMap;

fn map() -> AdapterMap {
    let mut jobs = BTreeMap::new();
    jobs.insert(
        "checkout".to_string(),
        StepRule {
            step: "checkout".into(),
            effects: vec![EffectRule {
                kind: "vcs_read".into(),
                args: [("scope".to_string(), "repo/${repository_name}".to_string())].into(),
            }],
        },
    );
    jobs.insert(
        "build".to_string(),
        StepRule {
            step: "build".into(),
            effects: vec![EffectRule {
                kind: "artifact_create".into(),
                args: [("digest".to_string(), "${outputs.digest}".to_string())].into(),
            }],
        },
    );
    jobs.insert(
        "publish".to_string(),
        StepRule {
            step: "publish".into(),
            effects: vec![EffectRule {
                kind: "registry_write".into(),
                args: [
                    (
                        "scope".to_string(),
                        "registry://prod/${repository_name}".to_string(),
                    ),
                    ("digest".to_string(), "${outputs.digest}".to_string()),
                ]
                .into(),
            }],
        },
    );
    jobs.insert(
        "build-test-publish".to_string(),
        StepRule {
            step: "build_test_publish".into(),
            effects: vec![],
        },
    );
    AdapterMap {
        jobs,
        runner_principal: "${actor}@github".into(),
        ..Default::default()
    }
}

fn run() -> Run {
    serde_json::from_value(serde_json::json!({
        "id": 42,
        "name": "release",
        "head_sha": "abc123",
        "actor": { "login": "ci-bot" },
        "repository": { "full_name": "acme/widgets" }
    }))
    .unwrap()
}

fn job(id: u64, name: &str, conclusion: &str, ts: &str) -> Job {
    serde_json::from_value(serde_json::json!({
        "id": id, "name": name, "conclusion": conclusion, "started_at": ts, "steps": []
    }))
    .unwrap()
}

#[test]
fn maps_jobs_to_transitions_and_substitutes_repository() {
    let jobs = Jobs {
        jobs: vec![
            job(1, "checkout", "success", "2026-01-01T00:00:00Z"),
            job(2, "build", "success", "2026-01-01T00:01:00Z"),
        ],
    };
    let facts = vec![Fact {
        step: "build".into(),
        digest: Some("sha256:AA11".into()),
        scope: None,
        provenance: None,
    }];
    let obs = normalize(&run(), &jobs, &facts, &map());

    let steps: Vec<String> = obs.records.iter().filter_map(|r| r.step.clone()).collect();
    assert_eq!(steps, vec!["checkout", "build"]);
    assert_eq!(obs.records[0].principal, "ci-bot@github");
    assert_eq!(
        obs.records[0].effects[0]
            .args
            .get("scope")
            .map(String::as_str),
        Some("repo/widgets"),
        "repository_name must be substituted from the full name"
    );
    assert_eq!(
        obs.records[1].effects[0]
            .args
            .get("digest")
            .map(String::as_str),
        Some("sha256:AA11"),
        "the fact's digest must reach the effect"
    );
}

#[test]
fn failed_jobs_are_not_observed() {
    let jobs = Jobs {
        jobs: vec![
            job(1, "checkout", "success", "2026-01-01T00:00:00Z"),
            job(2, "build", "failure", "2026-01-01T00:01:00Z"),
        ],
    };
    let obs = normalize(&run(), &jobs, &[], &map());
    let steps: Vec<String> = obs.records.iter().filter_map(|r| r.step.clone()).collect();
    assert_eq!(steps, vec!["checkout"], "a failed job produces no evidence");
}

#[test]
fn unmapped_jobs_are_skipped_rather_than_guessed() {
    let jobs = Jobs {
        jobs: vec![job(1, "lint-and-format", "success", "2026-01-01T00:00:00Z")],
    };
    let obs = normalize(&run(), &jobs, &[], &map());
    assert!(
        obs.records.is_empty(),
        "a job the model does not declare must not be invented"
    );
}

#[test]
fn reusable_workflow_job_names_resolve_to_the_declared_job() {
    // GitHub reports a reusable-workflow call as "Caller display name / inner job".
    let jobs = Jobs {
        jobs: vec![
            job(
                1,
                "Build, test, publish / build, test, package",
                "success",
                "2026-01-01T00:00:00Z",
            ),
            job(
                2,
                "Build, test, publish / Run simple test",
                "success",
                "2026-01-01T00:01:00Z",
            ),
            job(
                3,
                "Build, test, publish / Create release",
                "success",
                "2026-01-01T00:02:00Z",
            ),
        ],
    };
    let obs = normalize(&run(), &jobs, &[], &map());
    let steps: Vec<String> = obs.records.iter().filter_map(|r| r.step.clone()).collect();
    assert_eq!(
        steps,
        vec!["build_test_publish"],
        "many expanded jobs resolving to one declared job are a single firing"
    );
}

#[test]
fn matrix_leg_parameters_are_stripped() {
    let jobs = Jobs {
        jobs: vec![job(
            1,
            "build (ubuntu-latest, 1.75)",
            "success",
            "2026-01-01T00:00:00Z",
        )],
    };
    let obs = normalize(&run(), &jobs, &[], &map());
    let steps: Vec<String> = obs.records.iter().filter_map(|r| r.step.clone()).collect();
    assert_eq!(steps, vec!["build"]);
}

#[test]
fn provenance_creates_an_edge_only_when_the_build_is_observed() {
    let jobs = Jobs {
        jobs: vec![
            job(1, "build", "success", "2026-01-01T00:00:00Z"),
            job(2, "publish", "success", "2026-01-01T00:01:00Z"),
        ],
    };
    let with_real_build = vec![
        Fact {
            step: "build".into(),
            digest: Some("sha256:AA11".into()),
            scope: None,
            provenance: None,
        },
        Fact {
            step: "publish".into(),
            digest: Some("sha256:AA11".into()),
            scope: None,
            provenance: Some(Provenance {
                build_digest: "sha256:AA11".into(),
                issuer: String::new(),
            }),
        },
    ];
    let obs = normalize(&run(), &jobs, &with_real_build, &map());
    assert_eq!(
        obs.edges.len(),
        1,
        "provenance naming an observed build links them"
    );
    assert_eq!(obs.edges[0].ty, "derives_from");

    // Provenance that names a build nobody observed must NOT be believed.
    let with_phantom_build = vec![
        Fact {
            step: "build".into(),
            digest: Some("sha256:AA11".into()),
            scope: None,
            provenance: None,
        },
        Fact {
            step: "publish".into(),
            digest: Some("sha256:BEEF".into()),
            scope: None,
            provenance: Some(Provenance {
                build_digest: "sha256:BEEF".into(),
                issuer: String::new(),
            }),
        },
    ];
    let obs = normalize(&run(), &jobs, &with_phantom_build, &map());
    assert!(
        obs.edges.is_empty(),
        "the adapter must never synthesise a causal link to a build it did not see"
    );
}

#[test]
fn unresolved_template_values_are_visible_not_silent() {
    // No fact supplies the digest, so the template cannot be filled.
    let jobs = Jobs {
        jobs: vec![job(1, "build", "success", "2026-01-01T00:00:00Z")],
    };
    let obs = normalize(&run(), &jobs, &[], &map());
    let digest = obs.records[0].effects[0].args.get("digest").unwrap();
    assert!(
        digest.starts_with("<unresolved:"),
        "a missing value must be loud, not silently dropped: {}",
        digest
    );
}

#[test]
fn records_are_ordered_by_time() {
    let jobs = Jobs {
        jobs: vec![
            job(2, "build", "success", "2026-01-01T00:05:00Z"),
            job(1, "checkout", "success", "2026-01-01T00:00:00Z"),
        ],
    };
    let obs = normalize(&run(), &jobs, &[], &map());
    let steps: Vec<String> = obs.records.iter().filter_map(|r| r.step.clone()).collect();
    assert_eq!(steps, vec!["checkout", "build"]);
}

#[test]
fn a_run_still_in_progress_parses() {
    // A gate that verifies a run from inside that run always sees itself
    // unfinished, and the API writes null — not an absent field — for a step
    // that has not started. serde's `default` does not cover an explicit null,
    // so this shape used to abort the import and read, from the outside, as a
    // rejection of a perfectly healthy pipeline.
    let live = serde_json::json!({
        "jobs": [
            { "id": 1, "name": "checkout", "conclusion": "success",
              "started_at": "2026-01-01T00:00:00Z", "steps": [] },
            { "id": 2, "name": "maskedrunner / verify", "conclusion": null,
              "status": "in_progress", "started_at": "2026-01-01T00:01:00Z",
              "steps": [ { "name": "Complete job", "status": "queued",
                           "conclusion": null, "number": 9, "started_at": null } ] }
        ]
    });
    let jobs: Jobs = serde_json::from_value(live).expect("a live payload must parse");

    let partial_run: Run = serde_json::from_value(serde_json::json!({
        "id": 42, "name": null, "head_sha": null, "run_started_at": null,
        "actor": { "login": "ci-bot" },
        "repository": { "full_name": "acme/widgets" }
    }))
    .expect("a run with null scalars must parse");

    let obs = normalize(&partial_run, &jobs, &[], &map());
    let steps: Vec<String> = obs.records.iter().filter_map(|r| r.step.clone()).collect();
    assert_eq!(
        steps,
        vec!["checkout"],
        "the gate's own unfinished job contributes no evidence, and the rest still imports"
    );
}
