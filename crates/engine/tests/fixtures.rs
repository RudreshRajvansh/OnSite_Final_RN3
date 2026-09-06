use engine::{verify, Net, Observation, VerifyOptions};

const SPEC: &str = "../../spec/release.wsl.yaml";

fn net() -> Net {
    let loaded = wsl::load_checked(SPEC).expect("specification must load and lint clean");
    Net::compile(&loaded.spec)
}

fn run(fixture: &str, slack: usize) -> engine::VerifyOutcome {
    let obs = Observation::load(format!("../../fixtures/{}", fixture)).expect("fixture must load");
    let net = net();
    verify(&net, &obs, VerifyOptions::for_observation(&obs, slack))
}

#[test]
fn case1_legitimate_release_is_accepted() {
    let outcome = run("case1.json", 0);
    assert!(outcome.accepted(), "{:?}", outcome.failures);
    assert_eq!(
        outcome.witness_path(),
        "checkout -> build -> test -> publish_standard"
    );
}

#[test]
fn case2_swapped_digest_is_rejected() {
    let outcome = run("case2.json", 0);
    assert!(!outcome.accepted());
    let rendered: Vec<String> = outcome.failures.iter().map(|f| f.render()).collect();
    assert!(
        rendered.iter().any(|f| f.contains("derives_from")),
        "expected the unmet effect relation to be named: {:?}",
        rendered
    );
}

#[test]
fn case2_rejection_survives_maximum_slack() {
    let outcome = run("case2.json", 12);
    assert!(
        !outcome.accepted(),
        "no amount of assumed missing logging may explain a swapped digest"
    );
}

#[test]
fn case3_breakglass_hotfix_is_accepted() {
    let outcome = run("case3.json", 0);
    assert!(outcome.accepted(), "{:?}", outcome.failures);
    let witness = outcome.witness.expect("acceptance must carry a witness");
    assert!(witness
        .iter()
        .any(|s| s.transition == "grant_emergency_approval"));
    assert!(witness.iter().any(|s| s.transition == "publish_breakglass"));
    assert_eq!(
        witness.iter().filter(|s| s.transition == "build").count(),
        2,
        "the retried build must appear in the witness"
    );
}

#[test]
fn case3_approval_token_is_single_use() {
    let mut obs = Observation::load("../../fixtures/case3.json").expect("fixture must load");
    let publish = obs
        .records
        .iter()
        .find(|r| r.step.as_deref() == Some("publish_breakglass"))
        .cloned()
        .expect("fixture must contain a break-glass publish");
    let mut replay = publish.clone();
    replay.id = "r6".to_string();
    replay.ts = "2026-09-05T11:30:00Z".to_string();
    replay.effects = publish
        .effects
        .iter()
        .cloned()
        .map(|mut e| {
            e.id = format!("{}b", e.id);
            e
        })
        .collect();
    let extra_edges: Vec<engine::ObservedEdge> = obs
        .edges
        .iter()
        .filter(|e| publish.effects.iter().any(|p| p.id == e.from))
        .map(|e| engine::ObservedEdge {
            ty: e.ty.clone(),
            from: format!("{}b", e.from),
            to: e.to.clone(),
        })
        .collect();
    obs.records.push(replay);
    obs.edges.extend(extra_edges);

    let net = net();
    let outcome = verify(&net, &obs, VerifyOptions::for_observation(&obs, 0));
    assert!(
        !outcome.accepted(),
        "a second publish on one approval must find no token"
    );
}

#[test]
fn capjs_publish_without_a_producing_run_is_rejected() {
    let outcome = run("attack-capjs.json", 0);
    assert!(!outcome.accepted());
    let robust = run("attack-capjs.json", 8);
    assert!(
        !robust.accepted(),
        "the rejection must survive assumed missing logging"
    );
}

#[test]
fn capjs_with_genuine_provenance_is_accepted_under_slack() {
    let strict = run("attack-capjs-provenance.json", 0);
    assert!(!strict.accepted());
    let relaxed = run("attack-capjs-provenance.json", 1);
    assert!(
        relaxed.accepted(),
        "a publish with real provenance and one unlogged step must verify: {:?}",
        relaxed.failures
    );
}

#[test]
fn held_out_forged_provenance_edge_is_rejected() {
    let outcome = run("attack-forged-provenance.json", 0);
    assert!(!outcome.accepted());
    let rendered: Vec<String> = outcome.failures.iter().map(|f| f.render()).collect();
    assert!(
        rendered
            .iter()
            .any(|f| f.contains("violates the declared constraint")),
        "a fabricated relation edge must fail the relation schema: {:?}",
        rendered
    );
}

#[test]
fn held_out_self_approval_is_rejected() {
    let outcome = run("attack-self-approval.json", 0);
    assert!(!outcome.accepted());
    let rendered: Vec<String> = outcome.failures.iter().map(|f| f.render()).collect();
    assert!(
        rendered.iter().any(|f| f.contains("*@corp.example")),
        "the service account may not issue its own approval: {:?}",
        rendered
    );
}

#[test]
fn rejection_reports_the_longest_legal_prefix() {
    let outcome = run("case2.json", 0);
    assert!(!outcome.accepted());
    let prefix: Vec<String> = outcome
        .explained
        .iter()
        .map(|s| s.transition.clone())
        .collect();
    assert_eq!(prefix, vec!["checkout", "build", "test"]);
    assert_eq!(outcome.observed_steps, 4);
    let blocked = outcome.blocked.expect("a blocked step must be named");
    assert_eq!(blocked.step, "publish_standard");
    assert_eq!(blocked.record, "r4");
}

#[test]
fn unmatched_effect_explains_every_step_and_blocks_none() {
    let outcome = run("attack-capjs.json", 0);
    assert!(!outcome.accepted());
    assert_eq!(outcome.explained.len(), 3);
    assert!(
        outcome.blocked.is_none(),
        "every recorded step is legal here; the effect is what has no cause"
    );
}

fn run_with_evidence(fixture: &str, digests: &[&str]) -> engine::VerifyOutcome {
    let obs = Observation::load(format!("../../fixtures/{}", fixture)).expect("fixture must load");
    let mut net = net();
    net.present_evidence(digests.iter().map(|d| d.to_string()));
    verify(&net, &obs, VerifyOptions::for_observation(&obs, 0))
}

#[test]
fn rollback_without_a_certificate_is_rejected() {
    let outcome = run("case4-rollback.json", 0);
    assert!(!outcome.accepted());
    let rendered: Vec<String> = outcome.failures.iter().map(|f| f.render()).collect();
    assert!(
        rendered
            .iter()
            .any(|f| f.contains("no presented certificate attests")),
        "the rejection must name the missing evidence: {:?}",
        rendered
    );
}

#[test]
fn rollback_with_a_certificate_for_that_digest_is_accepted() {
    let outcome = run_with_evidence("case4-rollback.json", &["sha256:AA11"]);
    assert!(outcome.accepted(), "{:?}", outcome.failures);
    assert_eq!(
        outcome.witness_path(),
        "checkout -> restore_prior_artifact -> publish_standard"
    );
}

#[test]
fn a_certificate_admits_only_the_digest_it_attests() {
    // Presenting real evidence must not become a skeleton key: the attested
    // digest is the only one that can be restored under it.
    let outcome = run_with_evidence("case5-rollback-forged.json", &["sha256:AA11"]);
    assert!(!outcome.accepted());
    let rendered: Vec<String> = outcome.failures.iter().map(|f| f.render()).collect();
    assert!(
        rendered.iter().any(|f| f.contains("sha256:DEAD")),
        "the rejection must name the digest that was never produced: {:?}",
        rendered
    );
}

#[test]
fn rollback_cannot_be_smuggled_in_as_an_unobserved_step() {
    // The slack path fires transitions nobody logged. An attested binding must
    // not be satisfiable by a fresh variable, or maximum slack would silently
    // authorise every rollback.
    let outcome = run("case5-rollback-forged.json", 12);
    assert!(
        !outcome.accepted(),
        "an unobserved restore must not be inventable under slack"
    );
}
