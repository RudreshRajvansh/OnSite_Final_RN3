use engine::{EffectInstance, Observation, Record};
use policy::{evaluate, BotPolicy};
use std::collections::BTreeMap;

fn obs(principal: &str, step: Option<&str>, kind: &str, scope: Option<&str>) -> Observation {
    let mut args = BTreeMap::new();
    if let Some(s) = scope {
        args.insert("scope".to_string(), s.to_string());
    }
    Observation {
        run_id: "t".to_string(),
        planes: BTreeMap::new(),
        records: vec![Record {
            id: "r1".to_string(),
            plane: "runner".to_string(),
            principal: principal.to_string(),
            step: step.map(str::to_string),
            ts: "2026-01-01T00:00:00Z".to_string(),
            effects: vec![EffectInstance {
                id: "e1".to_string(),
                kind: kind.to_string(),
                args,
            }],
        }],
        edges: Vec::new(),
    }
}

fn policy() -> BotPolicy {
    BotPolicy {
        identity: "*".to_string(),
        allowed_actions: vec!["vcs_read".to_string(), "registry_write".to_string()],
        allowed_scopes: vec!["repo/*".to_string(), "registry://prod/*".to_string()],
        allowed_steps: vec!["checkout".to_string(), "build".to_string()],
        ..Default::default()
    }
}

#[test]
fn a_wildcard_identity_admits_any_principal() {
    // The whole comparison rests on this. A stolen but genuine credential looks
    // valid to an identity checker, so the legacy lane must ACCEPT the run that
    // reachability goes on to reject. An exact-match implementation denied
    // every record here and inverted the demo.
    let out = evaluate(
        &policy(),
        &obs("ci-bot", Some("checkout"), "vcs_read", Some("repo/app")),
    );
    assert!(out.allowed(), "{:?}", out.messages());
    assert_eq!(out.checked_identities, 1);
    assert_eq!(out.checked_actions, 1);
}

#[test]
fn a_bare_principal_is_qualified_before_matching() {
    let mut p = policy();
    p.identity = "ci-bot@ci.internal".to_string();
    let out = evaluate(
        &p,
        &obs("ci-bot", Some("checkout"), "vcs_read", Some("repo/app")),
    );
    assert!(out.allowed(), "{:?}", out.messages());
}

#[test]
fn a_different_identity_is_denied() {
    let mut p = policy();
    p.identity = "ci-bot@ci.internal".to_string();
    let out = evaluate(
        &p,
        &obs(
            "mallory@evil.test",
            Some("checkout"),
            "vcs_read",
            Some("repo/app"),
        ),
    );
    assert!(!out.allowed());
    assert!(out.messages()[0].contains("not the authorised identity"));
}

#[test]
fn an_undeclared_step_is_denied() {
    let out = evaluate(
        &policy(),
        &obs("ci-bot", Some("exfiltrate"), "vcs_read", Some("repo/app")),
    );
    assert!(!out.allowed());
    assert!(out
        .messages()
        .iter()
        .any(|m| m.contains("not permitted for this identity")));
}

#[test]
fn a_record_with_no_step_is_not_judged_on_its_step() {
    let out = evaluate(
        &policy(),
        &obs("ci-bot", None, "vcs_read", Some("repo/app")),
    );
    assert!(out.allowed(), "{:?}", out.messages());
}

#[test]
fn an_out_of_scope_write_is_denied() {
    let out = evaluate(
        &policy(),
        &obs(
            "ci-bot",
            Some("build"),
            "registry_write",
            Some("registry://staging/app"),
        ),
    );
    assert!(!out.allowed());
    assert!(out.messages()[0].contains("outside the permitted scopes"));
}

#[test]
fn an_empty_policy_judges_nothing() {
    let out = evaluate(
        &BotPolicy::default(),
        &obs("anyone", Some("whatever"), "anything", Some("anywhere")),
    );
    assert!(
        out.allowed(),
        "an unconfigured policy must not invent findings"
    );
}
