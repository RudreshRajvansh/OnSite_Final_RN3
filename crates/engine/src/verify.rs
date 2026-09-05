use crate::net::{
    check_edges, check_obligations, eval_guard, match_template, resolve, structural_gaps, Env,
    Failure, Marking, Net,
};
use crate::observation::Observation;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    pub bound: usize,
    pub slack: usize,
    pub max_states: usize,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            bound: 16,
            slack: 0,
            max_states: 200_000,
        }
    }
}

impl VerifyOptions {
    pub fn for_observation(obs: &Observation, slack: usize) -> Self {
        VerifyOptions {
            bound: obs.step_records().len().max(1) + slack,
            slack,
            max_states: 200_000,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessStep {
    pub transition: String,
    pub principal: String,
    pub record: Option<String>,
    pub observed: bool,
    pub bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyOutcome {
    pub verdict: Verdict,
    pub witness: Option<Vec<WitnessStep>>,
    pub failures: Vec<Failure>,
    pub bound: usize,
    pub slack: usize,
    pub states_explored: usize,
    pub exhausted: bool,
}

impl VerifyOutcome {
    pub fn accepted(&self) -> bool {
        self.verdict == Verdict::Accept
    }

    pub fn witness_path(&self) -> String {
        self.witness
            .as_ref()
            .map(|w| {
                w.iter()
                    .map(|s| s.transition.clone())
                    .collect::<Vec<String>>()
                    .join(" -> ")
            })
            .unwrap_or_default()
    }
}

#[derive(Clone)]
struct SearchState {
    marking: Marking,
    consumed: Vec<bool>,
    matched: BTreeSet<String>,
    slack_used: usize,
    depth: usize,
    fresh: usize,
    path: Vec<WitnessStep>,
}

impl SearchState {
    fn score(&self) -> (usize, usize) {
        (
            self.consumed.iter().filter(|c| **c).count(),
            self.matched.len(),
        )
    }
}

#[derive(Default)]
struct FailureLog {
    score: (usize, usize),
    items: Vec<Failure>,
}

impl FailureLog {
    fn push(&mut self, score: (usize, usize), failure: Failure) {
        if score > self.score {
            self.score = score;
            self.items.clear();
        }
        if score == self.score && !self.items.contains(&failure) {
            self.items.push(failure);
        }
    }
}

pub fn verify(net: &Net, obs: &Observation, options: VerifyOptions) -> VerifyOutcome {
    let mut log = FailureLog::default();

    let edge_failures = check_edges(&net.spec, obs);
    if !edge_failures.is_empty() {
        return VerifyOutcome {
            verdict: Verdict::Reject,
            witness: None,
            failures: edge_failures,
            bound: options.bound,
            slack: options.slack,
            states_explored: 0,
            exhausted: false,
        };
    }

    let preds = match obs.order() {
        Ok(p) => p,
        Err(_) => vec![Vec::new(); obs.records.len()],
    };
    let all_effects: BTreeSet<String> = obs.effects().map(|e| e.id.clone()).collect();
    let initial_consumed: Vec<bool> = obs.records.iter().map(|r| r.step.is_none()).collect();

    let mut best = SearchState {
        marking: net.initial.clone(),
        consumed: initial_consumed.clone(),
        matched: BTreeSet::new(),
        slack_used: 0,
        depth: 0,
        fresh: 0,
        path: Vec::new(),
    };

    let mut stack = vec![best.clone()];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut states = 0usize;
    let mut exhausted = false;

    while let Some(state) = stack.pop() {
        states += 1;
        if states > options.max_states {
            exhausted = true;
            break;
        }
        if state.depth > options.bound {
            continue;
        }
        let key = format!(
            "{}|{}|{}|{}",
            net.canonical(&state.marking),
            state
                .consumed
                .iter()
                .map(|c| if *c { '1' } else { '0' })
                .collect::<String>(),
            state.matched.iter().cloned().collect::<Vec<String>>().join(","),
            state.slack_used
        );
        if !seen.insert(key) {
            continue;
        }
        if state.score() > best.score() {
            best = state.clone();
        }

        let complete = state.consumed.iter().all(|c| *c) && state.matched == all_effects;
        if complete && net.is_final(&state.marking) {
            return VerifyOutcome {
                verdict: Verdict::Accept,
                witness: Some(state.path),
                failures: Vec::new(),
                bound: options.bound,
                slack: options.slack,
                states_explored: states,
                exhausted: false,
            };
        }

        expand_observed(net, obs, &preds, &state, &mut stack, &mut log);
        if state.slack_used < options.slack {
            expand_slack(net, obs, &state, &mut stack, &mut log);
        }
    }

    let mut failures = log.items;
    if failures.is_empty() {
        for (i, consumed) in best.consumed.iter().enumerate() {
            if !consumed {
                if let Some(step) = &obs.records[i].step {
                    failures.push(Failure::StepNotExplained {
                        step: step.clone(),
                        record: obs.records[i].id.clone(),
                    });
                }
            }
        }
        for id in all_effects.difference(&best.matched) {
            if let Some(effect) = obs.effect(id) {
                failures.push(Failure::UnmatchedEffect {
                    effect: id.clone(),
                    kind: effect.kind.clone(),
                    detail: "no transition of the workflow emits it on any accepting path"
                        .to_string(),
                });
            }
        }
        if failures.is_empty() {
            failures.push(Failure::NoFinalMarking {
                detail: format!(
                    "every path consistent with the observation stops at marking {}",
                    net.canonical(&best.marking)
                ),
            });
        }
    }

    VerifyOutcome {
        verdict: Verdict::Reject,
        witness: None,
        failures,
        bound: options.bound,
        slack: options.slack,
        states_explored: states,
        exhausted,
    }
}

fn expand_observed(
    net: &Net,
    obs: &Observation,
    preds: &[Vec<usize>],
    state: &SearchState,
    stack: &mut Vec<SearchState>,
    log: &mut FailureLog,
) {
    let score = state.score();
    for index in obs.step_records() {
        if state.consumed[index] {
            continue;
        }
        if !preds[index].iter().all(|p| state.consumed[*p]) {
            continue;
        }
        let record = &obs.records[index];
        let step = record.step.clone().unwrap_or_default();
        let Some(transition) = net.transition_by_id(&step) else {
            log.push(score, Failure::UnknownStep { step });
            continue;
        };
        if !net.spec.principal_matches(&transition.principal, &record.principal) {
            let expected = net
                .spec
                .principals
                .get(&transition.principal)
                .map(|p| p.id_pattern.clone())
                .unwrap_or_default();
            log.push(
                score,
                Failure::IdentityMismatch {
                    step,
                    principal: record.principal.clone(),
                    expected,
                },
            );
            continue;
        }
        if let Some(place) = net.missing_place(&state.marking, transition) {
            log.push(score, Failure::NotEnabled { step, place });
            continue;
        }
        if transition.emits.len() != record.effects.len() {
            log.push(
                score,
                Failure::EffectShapeMismatch {
                    step,
                    detail: format!(
                        "transition emits {} effect(s), record carries {}",
                        transition.emits.len(),
                        record.effects.len()
                    ),
                },
            );
            continue;
        }

        for (template, effect) in transition.emits.iter().zip(record.effects.iter()) {
            for failure in structural_gaps(template, &transition.id, &effect.id, obs) {
                log.push(score, failure);
            }
        }

        for choice in net.choices(&state.marking, transition) {
            let Some(base) = net.merge_env(&state.marking, transition, &choice) else {
                continue;
            };
            let mut env = base;
            let mut failed = false;
            for (template, effect) in transition.emits.iter().zip(record.effects.iter()) {
                match match_template(template, effect, &env, &step) {
                    Ok(next) => env = next,
                    Err(failure) => {
                        log.push(score, failure);
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                continue;
            }
            let mut fresh = state.fresh;
            for bind in &transition.binds {
                if !env.contains_key(bind) {
                    fresh += 1;
                    env.insert(bind.clone(), format!("~fresh{}", fresh));
                }
            }
            if let Some(guard) = &transition.guard {
                if !eval_guard(guard, &env) {
                    log.push(
                        score,
                        Failure::GuardFalse {
                            transition: transition.id.clone(),
                            guard: guard.clone(),
                        },
                    );
                    continue;
                }
            }
            let mut obligation_failed = false;
            for (template, effect) in transition.emits.iter().zip(record.effects.iter()) {
                if let Err(failure) = check_obligations(
                    template,
                    &transition.id,
                    &effect.id,
                    &env,
                    obs,
                    &state.matched,
                ) {
                    log.push(score, failure);
                    obligation_failed = true;
                    break;
                }
            }
            if obligation_failed {
                continue;
            }

            let mut next = state.clone();
            next.marking = net.fire(&state.marking, transition, &choice, &env);
            next.consumed[index] = true;
            for effect in &record.effects {
                next.matched.insert(effect.id.clone());
            }
            next.depth += 1;
            next.fresh = fresh;
            next.path.push(WitnessStep {
                transition: transition.id.clone(),
                principal: record.principal.clone(),
                record: Some(record.id.clone()),
                observed: true,
                bindings: env,
            });
            stack.push(next);
        }
    }
}

fn expand_slack(
    net: &Net,
    obs: &Observation,
    state: &SearchState,
    stack: &mut Vec<SearchState>,
    log: &mut FailureLog,
) {
    let score = state.score();
    for transition in &net.transitions {
        if transition
            .emits
            .iter()
            .any(|e| obs.plane_carries(&e.effect))
        {
            continue;
        }
        if net.missing_place(&state.marking, transition).is_some() {
            continue;
        }
        for choice in net.choices(&state.marking, transition) {
            let Some(base) = net.merge_env(&state.marking, transition, &choice) else {
                continue;
            };
            let mut targets: Vec<Option<String>> = vec![None];
            if transition.emits.len() == 1 {
                let kind = &transition.emits[0].effect;
                for effect in obs.dangling_effects() {
                    if &effect.kind == kind && !state.matched.contains(&effect.id) {
                        targets.push(Some(effect.id.clone()));
                    }
                }
            }
            for target in &targets {
                let mut env = base.clone();
                let mut fresh = state.fresh;
                let mut matched_id = None;
                if let Some(id) = target {
                    let Some(effect) = obs.effect(id) else { continue };
                    match match_template(&transition.emits[0], effect, &env, &transition.id) {
                        Ok(next) => {
                            env = next;
                            matched_id = Some(id.clone());
                        }
                        Err(failure) => {
                            log.push(score, failure);
                            continue;
                        }
                    }
                } else {
                    for template in &transition.emits {
                        for raw in template.args.values() {
                            let _ = resolve(raw, &env, &mut fresh);
                        }
                    }
                }
                for bind in &transition.binds {
                    if !env.contains_key(bind) {
                        fresh += 1;
                        env.insert(bind.clone(), format!("~fresh{}", fresh));
                    }
                }
                if let Some(guard) = &transition.guard {
                    if !eval_guard(guard, &env) {
                        continue;
                    }
                }
                if let Some(id) = &matched_id {
                    if let Err(failure) = check_obligations(
                        &transition.emits[0],
                        &transition.id,
                        id,
                        &env,
                        obs,
                        &state.matched,
                    ) {
                        log.push(score, failure);
                        continue;
                    }
                }

                let mut next = state.clone();
                next.marking = net.fire(&state.marking, transition, &choice, &env);
                next.slack_used += 1;
                next.depth += 1;
                next.fresh = fresh;
                if let Some(id) = matched_id {
                    next.matched.insert(id);
                }
                next.path.push(WitnessStep {
                    transition: transition.id.clone(),
                    principal: transition.principal.clone(),
                    record: None,
                    observed: false,
                    bindings: env,
                });
                stack.push(next);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Permissiveness {
    pub depth: usize,
    pub shapes: usize,
    pub truncated: bool,
}

pub fn permissiveness(net: &Net, depth: usize, cap: usize) -> Permissiveness {
    let mut shapes: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<(Marking, Vec<String>, usize, usize)> =
        vec![(net.initial.clone(), Vec::new(), 0, 0)];
    let mut truncated = false;

    while let Some((marking, trace, level, fresh)) = stack.pop() {
        if shapes.len() >= cap {
            truncated = true;
            break;
        }
        if net.is_final(&marking) && !trace.is_empty() {
            let mut sorted = trace.clone();
            sorted.sort();
            shapes.insert(sorted.join("+"));
        }
        if level >= depth {
            continue;
        }
        let key = format!("{}|{}|{}", net.canonical(&marking), trace.join("+"), level);
        if !seen.insert(key) {
            continue;
        }
        for transition in &net.transitions {
            if net.missing_place(&marking, transition).is_some() {
                continue;
            }
            for choice in net.choices(&marking, transition) {
                let Some(base) = net.merge_env(&marking, transition, &choice) else {
                    continue;
                };
                let mut env = base;
                let mut next_fresh = fresh;
                for bind in &transition.binds {
                    next_fresh += 1;
                    env.insert(bind.clone(), format!("v{}", next_fresh));
                }
                let mut emitted = trace.clone();
                for template in &transition.emits {
                    let args: Vec<String> = template
                        .args
                        .iter()
                        .map(|(k, raw)| format!("{}={}", k, abstract_value(raw, &env)))
                        .collect();
                    emitted.push(format!("{}({})", template.effect, args.join(",")));
                }
                stack.push((
                    net.fire(&marking, transition, &choice, &env),
                    emitted,
                    level + 1,
                    next_fresh,
                ));
            }
        }
    }

    Permissiveness {
        depth,
        shapes: shapes.len(),
        truncated,
    }
}

fn abstract_value(raw: &str, env: &Env) -> String {
    let mut fresh = 0usize;
    resolve(raw, env, &mut fresh)
}
