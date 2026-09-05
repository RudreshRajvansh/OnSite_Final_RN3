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
