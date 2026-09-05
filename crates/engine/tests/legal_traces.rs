use engine::{verify, EffectInstance, Net, Observation, ObservedEdge, Record, VerifyOptions};
use std::collections::{BTreeMap, BTreeSet};
use wsl::{classify, Pattern};

const SPEC: &str = "../../spec/release.wsl.yaml";
const MAX_STEPS: usize = 14;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn concrete(raw: &str, env: &BTreeMap<String, String>) -> String {
    match classify(raw) {
        Pattern::Lit(v) => v,
        Pattern::Glob(p) => p.replace('*', "app"),
        Pattern::Var(name) => env.get(&name).cloned().unwrap_or_else(|| "unbound".to_string()),
    }
}

fn identity_for(net: &Net, key: &str) -> String {
    net.spec
        .principals
        .get(key)
        .map(|p| p.id_pattern.replace('*', "gen"))
        .unwrap_or_else(|| key.to_string())
}

fn generate(net: &Net, seed: u64) -> Option<Observation> {
    let mut rng = Rng::new(seed);
    let mut marking = net.initial.clone();
    let mut records: Vec<Record> = Vec::new();
    let mut edges: Vec<ObservedEdge> = Vec::new();
    let mut minted = 0usize;

    for step in 0..MAX_STEPS {
        if net.is_final(&marking) {
            break;
        }
        let mut candidates = Vec::new();
        for transition in &net.transitions {
            if net.missing_place(&marking, transition).is_some() {
                continue;
            }
            for choice in net.choices(&marking, transition) {
                if net.merge_env(&marking, transition, &choice).is_some() {
                    candidates.push((transition, choice));
                }
            }
        }
        if candidates.is_empty() {
            return None;
        }
        let (transition, choice) = candidates[rng.below(candidates.len())].clone();
        let mut env = net.merge_env(&marking, transition, &choice)?;
        for bind in &transition.binds {
            minted += 1;
            env.insert(bind.clone(), format!("sha256:GEN{:04}", minted));
        }

        let record_id = format!("s{}", step);
        let mut effects = Vec::new();
        for (index, template) in transition.emits.iter().enumerate() {
            let effect = EffectInstance {
                id: format!("{}.{}", record_id, index),
                kind: template.effect.clone(),
                args: template
                    .args
                    .iter()
                    .map(|(k, raw)| (k.clone(), concrete(raw, &env)))
                    .collect(),
            };
            for obligation in &template.requires_relation {
                let wanted: BTreeMap<String, String> = obligation
                    .bind
                    .iter()
                    .map(|(k, raw)| (k.clone(), concrete(raw, &env)))
                    .collect();
                let target = records
                    .iter()
                    .flat_map(|r| r.effects.iter())
                    .rev()
                    .find(|candidate| {
                        candidate.kind == obligation.target
                            && wanted
                                .iter()
                                .all(|(k, v)| candidate.args.get(k) == Some(v))
                    })?;
                edges.push(ObservedEdge {
                    ty: obligation.ty.clone(),
                    from: effect.id.clone(),
                    to: target.id.clone(),
                });
            }
            effects.push(effect);
        }

        records.push(Record {
            id: record_id,
            plane: "runner".to_string(),
            principal: identity_for(net, &transition.principal),
            step: Some(transition.id.clone()),
            ts: format!("2026-01-01T00:{:02}:00Z", step),
            effects,
        });
        marking = net.fire(&marking, transition, &choice, &env);
    }

    if !net.is_final(&marking) {
        return None;
    }

    Some(Observation {
        run_id: format!("generated-{}", seed),
        planes: BTreeMap::new(),
        records,
        edges,
    })
}

fn net() -> Net {
    let loaded = wsl::load_checked(SPEC).expect("specification must load and lint clean");
    Net::compile(&loaded.spec)
}

#[test]
fn every_legal_trace_is_accepted() {
    let net = net();
    let mut generated = 0usize;
    let mut shapes: BTreeSet<String> = BTreeSet::new();

    for seed in 1..=4000u64 {
        let Some(obs) = generate(&net, seed) else {
            continue;
        };
        obs.validate().expect("generated observation must be well formed");
        let outcome = verify(&net, &obs, VerifyOptions::for_observation(&obs, 0));
        assert!(
            outcome.accepted(),
            "legal trace {} was rejected: {:?}",
            obs.records
                .iter()
                .filter_map(|r| r.step.clone())
                .collect::<Vec<String>>()
                .join(" -> "),
            outcome.failures
        );
        shapes.insert(
            obs.records
                .iter()
                .filter_map(|r| r.step.clone())
                .collect::<Vec<String>>()
                .join(" -> "),
        );
        generated += 1;
    }

    println!(
        "generated {} legal traces, {} structurally distinct, all accepted",
        generated,
        shapes.len()
    );
    assert!(generated >= 1000, "expected a large legal corpus, got {}", generated);
    assert!(
        shapes.len() >= 100,
        "expected many structurally distinct legal traces, got {}",
        shapes.len()
    );
}

#[test]
fn generated_traces_are_not_enumerated_by_the_spec() {
    let net = net();
    let mut longest = 0usize;
    for seed in 1..=4000u64 {
        if let Some(obs) = generate(&net, seed) {
            longest = longest.max(obs.records.len());
        }
    }
    assert!(
        longest > net.transitions.len(),
        "expected accepted traces longer than the transition count, got {}",
        longest
    );
}
