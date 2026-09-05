use crate::model::{InvariantKind, Spec};
use indexmap::{IndexMap, IndexSet};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LintReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl LintReport {
    pub fn is_sound(&self) -> bool {
        !self.diagnostics.iter().any(|d| d.severity == Severity::Error)
    }

    pub fn errors(&self) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect()
    }

    fn error(&mut self, code: &'static str, message: String) {
        self.diagnostics.push(Diagnostic {
            severity: Severity::Error,
            code,
            message,
        });
    }

    fn warn(&mut self, code: &'static str, message: String) {
        self.diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code,
            message,
        });
    }
}

pub fn lint(spec: &Spec) -> LintReport {
    let mut report = LintReport::default();

    let mut place_ids: IndexSet<String> = IndexSet::new();
    for p in &spec.places {
        if !place_ids.insert(p.id.clone()) {
            report.error("W001", format!("duplicate place id `{}`", p.id));
        }
    }
    let mut transition_ids: IndexSet<String> = IndexSet::new();
    for t in &spec.transitions {
        if !transition_ids.insert(t.id.clone()) {
            report.error("W002", format!("duplicate transition id `{}`", t.id));
        }
    }

    for t in &spec.transitions {
        for p in t.consumes.iter().chain(t.produces.iter()) {
            if !place_ids.contains(p) {
                report.error(
                    "W003",
                    format!("transition `{}` references unknown place `{}`", t.id, p),
                );
            }
        }
        if !spec.principals.contains_key(&t.principal) {
            report.error(
                "W004",
                format!(
                    "transition `{}` references unknown principal `{}`",
                    t.id, t.principal
                ),
            );
        }
        if t.consumes.is_empty() && t.produces.is_empty() {
            report.error("W005", format!("transition `{}` is vacuous", t.id));
        }
    }

    if spec.final_places.is_empty() {
        report.error("W006", "specification declares no final places".to_string());
    }
    for f in &spec.final_places {
        if !place_ids.contains(f) {
            report.error("W007", format!("unknown final place `{}`", f));
        }
    }

    let initial: IndexSet<String> = spec
        .places
        .iter()
        .filter(|p| !p.tokens.is_empty())
        .map(|p| p.id.clone())
        .collect();
    if initial.is_empty() {
        report.error("W008", "initial marking is empty".to_string());
    }

    let (live, covered) = structural_coverability(spec, &initial);
    for t in &spec.transitions {
        if !live.contains(&t.id) {
            report.error(
                "W009",
                format!("transition `{}` is dead: never structurally enabled", t.id),
            );
        }
    }
    for f in &spec.final_places {
        if !covered.contains(f) {
            report.error(
                "W010",
                format!("improper completion: final place `{}` is unreachable", f),
            );
        }
    }

    for p in &spec.places {
        let produced = spec.transitions.iter().any(|t| t.produces.contains(&p.id));
        let consumed = spec.transitions.iter().any(|t| t.consumes.contains(&p.id));
        if !produced && !consumed {
            report.warn("W011", format!("place `{}` is isolated", p.id));
        }
        if !produced && !initial.contains(&p.id) {
            report.error(
                "W012",
                format!("place `{}` is never marked and never produced", p.id),
            );
        }
    }

    for (i, a) in spec.transitions.iter().enumerate() {
        for b in spec.transitions.iter().skip(i + 1) {
            let sa: IndexSet<&String> = a.consumes.iter().collect();
            let sb: IndexSet<&String> = b.consumes.iter().collect();
            if sa.intersection(&sb).count() > 0 && sa != sb {
                report.warn(
                    "W013",
                    format!(
                        "not free-choice: `{}` and `{}` share an input place with different preconditions; the general bounded procedure is used instead of the polynomial free-choice one",
                        a.id, b.id
                    ),
                );
            }
        }
    }

    let emitted: IndexSet<String> = spec
        .transitions
        .iter()
        .flat_map(|t| t.emits.iter().map(|e| e.effect.clone()))
        .collect();

    for (name, rel) in &spec.relations {
        if !emitted.contains(&rel.from) {
            report.error(
                "W014",
                format!(
                    "relation `{}` sources effect `{}` which no transition emits",
                    name, rel.from
                ),
            );
        }
        if !emitted.contains(&rel.to) {
            report.error(
                "W015",
                format!(
                    "relation `{}` targets effect `{}` which no transition emits",
                    name, rel.to
                ),
            );
        }
    }

    for t in &spec.transitions {
        for e in &t.emits {
            for obligation in &e.requires_relation {
                match spec.relations.get(&obligation.ty) {
                    None => report.error(
                        "W016",
                        format!(
                            "transition `{}` requires undeclared relation `{}`",
                            t.id, obligation.ty
                        ),
                    ),
                    Some(rel) => {
                        if rel.from != e.effect || rel.to != obligation.target {
                            report.error(
                                "W017",
                                format!(
                                    "obligation on `{}` is ill-typed: relation `{}` is {} -> {} but the obligation is {} -> {}",
                                    t.id, obligation.ty, rel.from, rel.to, e.effect, obligation.target
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    let place_vars = place_variables(spec, &initial);
    for t in &spec.transitions {
        let mut avail: IndexSet<String> = IndexSet::new();
        for c in &t.consumes {
            if let Some(v) = place_vars.get(c) {
                avail.extend(v.iter().cloned());
            }
        }
        avail.extend(t.binds.keys().cloned());
        for var in Spec::referenced_vars(t) {
            if !avail.contains(&var) {
                report.error(
                    "W018",
                    format!(
                        "transition `{}` references `${}` which no consumed token guarantees",
                        t.id, var
                    ),
                );
            }
        }
    }

    for inv in &spec.invariants {
        match &inv.kind {
            InvariantKind::EffectHasProducingTransition { effect, .. } => {
                if !emitted.contains(effect) {
                    report.error(
                        "W019",
                        format!(
                            "invariant `{}` names effect `{}` which no transition emits",
                            inv.id, effect
                        ),
                    );
                }
            }
            InvariantKind::TokenConsumedNotCopied { place } => {
                if !place_ids.contains(place) {
                    report.error(
                        "W020",
                        format!("invariant `{}` names unknown place `{}`", inv.id, place),
                    );
                }
                let copier = spec
                    .transitions
                    .iter()
                    .find(|t| t.consumes.contains(place) && t.produces.contains(place));
                if let Some(t) = copier {
                    report.error(
                        "W021",
                        format!(
                            "invariant `{}` fails statically: transition `{}` returns the `{}` token it consumes",
                            inv.id, t.id, place
                        ),
                    );
                }
            }
        }
    }

    report
}

fn structural_coverability(
    spec: &Spec,
    initial: &IndexSet<String>,
) -> (IndexSet<String>, IndexSet<String>) {
    let mut covered = initial.clone();
    let mut live: IndexSet<String> = IndexSet::new();
    loop {
        let mut changed = false;
        for t in &spec.transitions {
            if t.consumes.iter().all(|c| covered.contains(c)) {
                if live.insert(t.id.clone()) {
                    changed = true;
                }
                for p in &t.produces {
                    if covered.insert(p.clone()) {
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            return (live, covered);
        }
    }
}

fn place_variables(spec: &Spec, initial: &IndexSet<String>) -> IndexMap<String, IndexSet<String>> {
    let universe: IndexSet<String> = spec
        .transitions
        .iter()
        .flat_map(|t| t.binds.keys().cloned())
        .collect();
    let produced: IndexSet<String> = spec
        .transitions
        .iter()
        .flat_map(|t| t.produces.iter().cloned())
        .collect();

    let mut vars: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for p in &spec.places {
        let seed = if initial.contains(&p.id) || !produced.contains(&p.id) {
            IndexSet::new()
        } else {
            universe.clone()
        };
        vars.insert(p.id.clone(), seed);
    }

    loop {
        let mut next: IndexMap<String, Option<IndexSet<String>>> = IndexMap::new();
        for t in &spec.transitions {
            let mut avail: IndexSet<String> = IndexSet::new();
            for c in &t.consumes {
                if let Some(v) = vars.get(c) {
                    avail.extend(v.iter().cloned());
                }
            }
            avail.extend(t.binds.keys().cloned());
            for p in &t.produces {
                let slot = next.entry(p.clone()).or_insert(None);
                let merged = match slot.take() {
                    None => avail.clone(),
                    Some(prev) => prev.intersection(&avail).cloned().collect(),
                };
                *slot = Some(merged);
            }
        }
        let mut changed = false;
        for (p, v) in next {
            let Some(v) = v else { continue };
            if initial.contains(&p) {
                continue;
            }
            if let Some(cur) = vars.get_mut(&p) {
                if *cur != v {
                    *cur = v;
                    changed = true;
                }
            }
        }
        if !changed {
            return vars;
        }
    }
}
