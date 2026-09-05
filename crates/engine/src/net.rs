use crate::observation::{EffectInstance, Observation};
use indexmap::IndexMap;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use wsl::{classify, glob_match, EffectTemplate, Pattern, Spec};

pub type Env = BTreeMap<String, String>;
pub type Token = Env;
pub type Marking = Vec<Vec<Token>>;

#[derive(Debug, Clone)]
pub struct CompiledTransition {
    pub id: String,
    pub index: usize,
    pub principal: String,
    pub consumes: Vec<usize>,
    pub produces: Vec<usize>,
    pub binds: Vec<String>,
    pub guard: Option<String>,
    pub emits: Vec<EffectTemplate>,
}

#[derive(Debug, Clone)]
pub struct Net {
    pub spec: Spec,
    pub place_names: Vec<String>,
    pub place_index: IndexMap<String, usize>,
    pub place_carries: Vec<Vec<String>>,
    pub finals: Vec<usize>,
    pub initial: Marking,
    pub transitions: Vec<CompiledTransition>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Failure {
    UnknownStep {
        step: String,
    },
    IdentityMismatch {
        step: String,
        principal: String,
        expected: String,
    },
    NotEnabled {
        step: String,
        place: String,
    },
    EffectShapeMismatch {
        step: String,
        detail: String,
    },
    EffectArgMismatch {
        step: String,
        effect: String,
        arg: String,
        expected: String,
        observed: String,
    },
    ObligationUnmet {
        transition: String,
        relation: String,
        effect: String,
        target: String,
        detail: String,
    },
    UnmatchedEffect {
        effect: String,
        kind: String,
        detail: String,
    },
    EdgeIllTyped {
        relation: String,
        from: String,
        to: String,
        detail: String,
    },
    ConstraintViolated {
        relation: String,
        from: String,
        to: String,
        constraint: String,
    },
    StepNotExplained {
        step: String,
        record: String,
    },
    NoFinalMarking {
        detail: String,
    },
    GuardFalse {
        transition: String,
        guard: String,
    },
}

impl Failure {
    pub fn render(&self) -> String {
        match self {
            Failure::UnknownStep { step } => {
                format!("step `{}` is not a transition of this workflow", step)
            }
            Failure::IdentityMismatch {
                step,
                principal,
                expected,
            } => format!(
                "`{}` was performed by `{}` but the transition admits only `{}`",
                step, principal, expected
            ),
            Failure::NotEnabled { step, place } => format!(
                "`{}` is not enabled: no token available in place `{}`",
                step, place
            ),
            Failure::EffectShapeMismatch { step, detail } => {
                format!("`{}` emitted effects the schema does not permit: {}", step, detail)
            }
            Failure::EffectArgMismatch {
                step,
                effect,
                arg,
                expected,
                observed,
            } => format!(
                "`{}` emitted {} with {}={} where the schema requires {}",
                step, effect, arg, observed, expected
            ),
            Failure::ObligationUnmet {
                transition,
                relation,
                effect,
                target,
                detail,
            } => format!(
                "transition `{}` requires {}({} -> {}) which the observation does not contain: {}",
                transition, relation, effect, target, detail
            ),
            Failure::UnmatchedEffect {
                effect,
                kind,
                detail,
            } => format!("{} `{}` has no producing transition: {}", kind, effect, detail),
            Failure::EdgeIllTyped {
                relation,
                from,
                to,
                detail,
            } => format!("edge {}({} -> {}) is ill-typed: {}", relation, from, to, detail),
            Failure::ConstraintViolated {
                relation,
                from,
                to,
                constraint,
            } => format!(
                "edge {}({} -> {}) violates the declared constraint `{}`",
                relation, from, to, constraint
            ),
            Failure::StepNotExplained { step, record } => format!(
                "no accepting path of the workflow explains record `{}` (`{}`)",
                record, step
            ),
            Failure::NoFinalMarking { detail } => {
                format!("no accepting path reaches a final marking: {}", detail)
            }
            Failure::GuardFalse { transition, guard } => {
                format!("guard `{}` on transition `{}` is false", guard, transition)
            }
        }
    }
}

impl Net {
    pub fn compile(spec: &Spec) -> Net {
        let mut place_index = IndexMap::new();
        let mut place_names = Vec::new();
        for (i, p) in spec.places.iter().enumerate() {
            place_index.insert(p.id.clone(), i);
            place_names.push(p.id.clone());
        }
        let mut initial: Marking = vec![Vec::new(); spec.places.len()];
        for (i, p) in spec.places.iter().enumerate() {
            for t in &p.tokens {
                let mut token = Token::new();
                token.insert("_type".to_string(), t.ty.clone());
                token.insert("_value".to_string(), t.value.clone());
                initial[i].push(token);
            }
        }
        let place_carries = spec.places.iter().map(|p| p.carries.clone()).collect();
        let finals = spec
            .final_places
            .iter()
            .filter_map(|f| place_index.get(f).copied())
            .collect();
        let transitions = spec
            .transitions
            .iter()
            .enumerate()
            .map(|(index, t)| CompiledTransition {
                id: t.id.clone(),
                index,
                principal: t.principal.clone(),
                consumes: t
                    .consumes
                    .iter()
                    .filter_map(|p| place_index.get(p).copied())
                    .collect(),
                produces: t
                    .produces
                    .iter()
                    .filter_map(|p| place_index.get(p).copied())
                    .collect(),
                binds: t.binds.keys().cloned().collect(),
                guard: t.guard.clone(),
                emits: t.emits.clone(),
            })
            .collect();
        Net {
            spec: spec.clone(),
            place_names,
            place_index,
            place_carries,
            finals,
            initial,
            transitions,
        }
    }

    pub fn transition_by_id(&self, id: &str) -> Option<&CompiledTransition> {
        self.transitions.iter().find(|t| t.id == id)
    }

    pub fn missing_place(&self, marking: &Marking, t: &CompiledTransition) -> Option<String> {
        let mut needed: BTreeMap<usize, usize> = BTreeMap::new();
        for p in &t.consumes {
            *needed.entry(*p).or_insert(0) += 1;
        }
        for (place, count) in needed {
            if marking[place].len() < count {
                return Some(self.place_names[place].clone());
            }
        }
        None
    }

    pub fn choices(&self, marking: &Marking, t: &CompiledTransition) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut current = vec![0usize; t.consumes.len()];
        let mut used: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        self.walk_choices(marking, t, 0, &mut current, &mut used, &mut out);
        out
    }

    fn walk_choices(
        &self,
        marking: &Marking,
        t: &CompiledTransition,
        slot: usize,
        current: &mut Vec<usize>,
        used: &mut BTreeMap<usize, BTreeSet<usize>>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if out.len() >= 512 {
            return;
        }
        if slot == t.consumes.len() {
            out.push(current.clone());
            return;
        }
        let place = t.consumes[slot];
        for token_index in 0..marking[place].len() {
            let taken = used.entry(place).or_default();
            if taken.contains(&token_index) {
                continue;
            }
            taken.insert(token_index);
            current[slot] = token_index;
            self.walk_choices(marking, t, slot + 1, current, used, out);
            used.entry(place).or_default().remove(&token_index);
        }
    }

    pub fn merge_env(
        &self,
        marking: &Marking,
        t: &CompiledTransition,
        choice: &[usize],
    ) -> Option<Env> {
        let mut env = Env::new();
        for (slot, place) in t.consumes.iter().enumerate() {
            let token = &marking[*place][choice[slot]];
            for (k, v) in token {
                if k.starts_with('_') {
                    continue;
                }
                match env.get(k) {
                    Some(existing) if existing != v => return None,
                    _ => {
                        env.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        Some(env)
    }

    pub fn fire(
        &self,
        marking: &Marking,
        t: &CompiledTransition,
        choice: &[usize],
        env: &Env,
    ) -> Marking {
        let mut next = marking.clone();
        let mut removals: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (slot, place) in t.consumes.iter().enumerate() {
            removals.entry(*place).or_default().push(choice[slot]);
        }
        for (place, mut indices) in removals {
            indices.sort_unstable();
            indices.reverse();
            for i in indices {
                next[place].remove(i);
            }
        }
        for place in &t.produces {
            let mut token = Token::new();
            for key in &self.place_carries[*place] {
                if let Some(value) = env.get(key) {
                    token.insert(key.clone(), value.clone());
                }
            }
            next[*place].push(token);
        }
        next
    }

    pub fn is_final(&self, marking: &Marking) -> bool {
        self.finals.iter().any(|p| !marking[*p].is_empty())
    }

    pub fn canonical(&self, marking: &Marking) -> String {
        let mut parts = Vec::with_capacity(marking.len());
        for (i, tokens) in marking.iter().enumerate() {
            let mut rendered: Vec<String> = tokens
                .iter()
                .map(|t| {
                    t.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<String>>()
                        .join(",")
                })
                .collect();
            rendered.sort();
            parts.push(format!("{}:[{}]", self.place_names[i], rendered.join("|")));
        }
        parts.join(";")
    }
}

pub fn match_template(
    template: &EffectTemplate,
    observed: &EffectInstance,
    env: &Env,
    step: &str,
) -> Result<Env, Failure> {
    if template.effect != observed.kind {
        return Err(Failure::EffectShapeMismatch {
            step: step.to_string(),
            detail: format!(
                "expected `{}` but observed `{}`",
                template.effect, observed.kind
            ),
        });
    }
    let mut next = env.clone();
    for (key, raw) in &template.args {
        let Some(value) = observed.args.get(key) else {
            return Err(Failure::EffectShapeMismatch {
                step: step.to_string(),
                detail: format!("effect `{}` carries no `{}`", observed.kind, key),
            });
        };
        match classify(raw) {
            Pattern::Lit(expected) => {
                if &expected != value {
                    return Err(Failure::EffectArgMismatch {
                        step: step.to_string(),
                        effect: observed.kind.clone(),
                        arg: key.clone(),
                        expected,
                        observed: value.clone(),
                    });
                }
            }
            Pattern::Glob(pattern) => {
                if !glob_match(&pattern, value) {
                    return Err(Failure::EffectArgMismatch {
                        step: step.to_string(),
                        effect: observed.kind.clone(),
                        arg: key.clone(),
                        expected: pattern,
                        observed: value.clone(),
                    });
                }
            }
            Pattern::Var(name) => match next.get(&name) {
                Some(bound) if bound != value => {
                    return Err(Failure::EffectArgMismatch {
                        step: step.to_string(),
                        effect: observed.kind.clone(),
                        arg: key.clone(),
                        expected: format!("${} = {}", name, bound),
                        observed: value.clone(),
                    })
                }
                _ => {
                    next.insert(name, value.clone());
                }
            },
        }
    }
    Ok(next)
}

pub fn resolve(raw: &str, env: &Env, fresh: &mut usize) -> String {
    match classify(raw) {
        Pattern::Lit(v) => v,
        Pattern::Glob(pattern) => pattern.replace('*', &format!("~any{}", fresh)),
        Pattern::Var(name) => env.get(&name).cloned().unwrap_or_else(|| {
            *fresh += 1;
            format!("~fresh{}", fresh)
        }),
    }
}

pub fn check_obligations(
    template: &EffectTemplate,
    transition: &str,
    effect_id: &str,
    env: &Env,
    obs: &Observation,
    matched: &BTreeSet<String>,
) -> Result<(), Failure> {
    for obligation in &template.requires_relation {
        let candidates: Vec<&crate::observation::ObservedEdge> = obs
            .edges
            .iter()
            .filter(|e| e.ty == obligation.ty && e.from == effect_id)
            .collect();
        if candidates.is_empty() {
            return Err(Failure::ObligationUnmet {
                transition: transition.to_string(),
                relation: obligation.ty.clone(),
                effect: effect_id.to_string(),
                target: obligation.target.clone(),
                detail: format!("no `{}` edge leaves this effect", obligation.ty),
            });
        }
        let mut satisfied = false;
        let mut detail = String::new();
        for edge in candidates {
            let Some(target) = obs.effect(&edge.to) else {
                continue;
            };
            if target.kind != obligation.target {
                detail = format!(
                    "edge points at `{}` but the obligation names `{}`",
                    target.kind, obligation.target
                );
                continue;
            }
            if !matched.contains(&target.id) {
                detail = format!(
                    "target `{}` has no producing transition on any accepting path",
                    target.id
                );
                continue;
            }
            let mut ok = true;
            for (key, raw) in &obligation.bind {
                let expected = match classify(raw) {
                    Pattern::Var(name) => env.get(&name).cloned(),
                    Pattern::Lit(v) => Some(v),
                    Pattern::Glob(p) => Some(p),
                };
                let Some(expected) = expected else {
                    ok = false;
                    detail = format!("`{}` is unbound at this point", raw);
                    break;
                };
                match target.args.get(key) {
                    Some(actual) if actual == &expected => {}
                    Some(actual) => {
                        ok = false;
                        detail = format!(
                            "binding mismatch: {} is {} on the target but {} here",
                            key, actual, expected
                        );
                        break;
                    }
                    None => {
                        ok = false;
                        detail = format!("target carries no `{}`", key);
                        break;
                    }
                }
            }
            if ok {
                satisfied = true;
                break;
            }
        }
        if !satisfied {
            return Err(Failure::ObligationUnmet {
                transition: transition.to_string(),
                relation: obligation.ty.clone(),
                effect: effect_id.to_string(),
                target: obligation.target.clone(),
                detail,
            });
        }
    }
    Ok(())
}

pub fn structural_gaps(
    template: &EffectTemplate,
    transition: &str,
    effect_id: &str,
    obs: &Observation,
) -> Vec<Failure> {
    let mut out = Vec::new();
    for obligation in &template.requires_relation {
        let present = obs.edges.iter().any(|e| {
            e.ty == obligation.ty
                && e.from == effect_id
                && obs
                    .effect(&e.to)
                    .map(|t| t.kind == obligation.target)
                    .unwrap_or(false)
        });
        if !present {
            out.push(Failure::ObligationUnmet {
                transition: transition.to_string(),
                relation: obligation.ty.clone(),
                effect: effect_id.to_string(),
                target: obligation.target.clone(),
                detail: format!(
                    "the observation contains no `{}` edge from this effect to any `{}`",
                    obligation.ty, obligation.target
                ),
            });
        }
    }
    out
}

pub fn check_edges(spec: &Spec, obs: &Observation) -> Vec<Failure> {
    let mut out = Vec::new();
    for edge in &obs.edges {
        let Some(schema) = spec.relations.get(&edge.ty) else {
            out.push(Failure::EdgeIllTyped {
                relation: edge.ty.clone(),
                from: edge.from.clone(),
                to: edge.to.clone(),
                detail: "relation is not declared by the specification".to_string(),
            });
            continue;
        };
        let (Some(from), Some(to)) = (obs.effect(&edge.from), obs.effect(&edge.to)) else {
            continue;
        };
        if from.kind != schema.from || to.kind != schema.to {
            out.push(Failure::EdgeIllTyped {
                relation: edge.ty.clone(),
                from: edge.from.clone(),
                to: edge.to.clone(),
                detail: format!(
                    "declared as {} -> {} but observed as {} -> {}",
                    schema.from, schema.to, from.kind, to.kind
                ),
            });
            continue;
        }
        if !eval_constraint(&schema.constraint, from, to) {
            out.push(Failure::ConstraintViolated {
                relation: edge.ty.clone(),
                from: edge.from.clone(),
                to: edge.to.clone(),
                constraint: schema.constraint.clone(),
            });
        }
    }
    out
}

pub fn eval_constraint(constraint: &str, from: &EffectInstance, to: &EffectInstance) -> bool {
    constraint
        .split("&&")
        .all(|clause| eval_clause(clause.trim(), from, to))
}

fn eval_clause(clause: &str, from: &EffectInstance, to: &EffectInstance) -> bool {
    let (lhs, op, rhs) = if let Some((l, r)) = clause.split_once("==") {
        (l.trim(), "==", r.trim())
    } else if let Some((l, r)) = clause.split_once("!=") {
        (l.trim(), "!=", r.trim())
    } else {
        return true;
    };
    let left = side_value(lhs, from, to);
    let right = side_value(rhs, from, to);
    match (left, right) {
        (Some(a), Some(b)) => {
            if op == "==" {
                a == b
            } else {
                a != b
            }
        }
        _ => false,
    }
}

fn side_value(side: &str, from: &EffectInstance, to: &EffectInstance) -> Option<String> {
    let side = side.trim();
    if let Some(stripped) = side.strip_prefix("from.") {
        return from.args.get(stripped).cloned();
    }
    if let Some(stripped) = side.strip_prefix("to.") {
        return to.args.get(stripped).cloned();
    }
    Some(side.trim_matches('"').to_string())
}

pub fn eval_guard(guard: &str, env: &Env) -> bool {
    guard.split("&&").all(|clause| {
        let clause = clause.trim();
        let (lhs, op, rhs) = if let Some((l, r)) = clause.split_once("==") {
            (l.trim(), "==", r.trim())
        } else if let Some((l, r)) = clause.split_once("!=") {
            (l.trim(), "!=", r.trim())
        } else {
            return true;
        };
        let left = guard_value(lhs, env);
        let right = guard_value(rhs, env);
        match (left, right) {
            (Some(a), Some(b)) => {
                if op == "==" {
                    a == b
                } else {
                    a != b
                }
            }
            _ => false,
        }
    })
}

fn guard_value(side: &str, env: &Env) -> Option<String> {
    match classify(side.trim()) {
        Pattern::Var(name) => env.get(&name).cloned(),
        Pattern::Lit(v) => Some(v.trim_matches('"').to_string()),
        Pattern::Glob(v) => Some(v),
    }
}
