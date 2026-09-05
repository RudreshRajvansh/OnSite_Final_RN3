use crate::model::{classify, Pattern, Spec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    DropObligation {
        transition: usize,
        emit: usize,
        obligation: usize,
    },
    LoosenArg {
        transition: usize,
        emit: usize,
        key: String,
    },
    WidenPrincipal {
        name: String,
    },
    RelaxRelation {
        name: String,
    },
    DropGuard {
        transition: usize,
    },
}

#[derive(Debug, Clone)]
pub struct Mutant {
    pub id: String,
    pub description: String,
    pub mutation: Mutation,
}

pub fn mutants(spec: &Spec) -> Vec<Mutant> {
    let mut out = Vec::new();

    for (ti, transition) in spec.transitions.iter().enumerate() {
        for (ei, emit) in transition.emits.iter().enumerate() {
            for (oi, obligation) in emit.requires_relation.iter().enumerate() {
                out.push(Mutant {
                    id: format!(
                        "drop-obligation:{}/{}/{}",
                        transition.id, emit.effect, obligation.ty
                    ),
                    description: format!(
                        "transition `{}` no longer requires {}({} -> {})",
                        transition.id, obligation.ty, emit.effect, obligation.target
                    ),
                    mutation: Mutation::DropObligation {
                        transition: ti,
                        emit: ei,
                        obligation: oi,
                    },
                });
            }
            for (key, raw) in emit.args.iter() {
                if classify(raw) == Pattern::Glob("*".to_string()) {
                    continue;
                }
                out.push(Mutant {
                    id: format!("loosen-arg:{}/{}/{}", transition.id, emit.effect, key),
                    description: format!(
                        "`{}` on {}.{} widened from `{}` to any value",
                        key, transition.id, emit.effect, raw
                    ),
                    mutation: Mutation::LoosenArg {
                        transition: ti,
                        emit: ei,
                        key: key.clone(),
                    },
                });
            }
        }
        if let Some(guard) = &transition.guard {
            out.push(Mutant {
                id: format!("drop-guard:{}", transition.id),
                description: format!("guard `{}` removed from `{}`", guard, transition.id),
                mutation: Mutation::DropGuard { transition: ti },
            });
        }
    }

    for (name, principal) in spec.principals.iter() {
        if principal.id_pattern == "*" {
            continue;
        }
        out.push(Mutant {
            id: format!("widen-principal:{}", name),
            description: format!(
                "principal class `{}` widened from `{}` to any identity",
                name, principal.id_pattern
            ),
            mutation: Mutation::WidenPrincipal { name: name.clone() },
        });
    }

    for (name, relation) in spec.relations.iter() {
        out.push(Mutant {
            id: format!("relax-relation:{}", name),
            description: format!(
                "relation `{}` no longer enforces `{}`",
                name, relation.constraint
            ),
            mutation: Mutation::RelaxRelation { name: name.clone() },
        });
    }

    out
}

pub fn apply(spec: &Spec, mutations: &[&Mutation]) -> Spec {
    let mut out = spec.clone();
    let mut removals: Vec<(usize, usize, usize)> = Vec::new();

    for mutation in mutations {
        match mutation {
            Mutation::DropObligation {
                transition,
                emit,
                obligation,
            } => removals.push((*transition, *emit, *obligation)),
            Mutation::LoosenArg {
                transition,
                emit,
                key,
            } => {
                if let Some(template) = out
                    .transitions
                    .get_mut(*transition)
                    .and_then(|t| t.emits.get_mut(*emit))
                {
                    template.args.insert(key.clone(), "*".to_string());
                }
            }
            Mutation::WidenPrincipal { name } => {
                if let Some(principal) = out.principals.get_mut(name) {
                    principal.id_pattern = "*".to_string();
                }
            }
            Mutation::RelaxRelation { name } => {
                if let Some(relation) = out.relations.get_mut(name) {
                    relation.constraint = String::new();
                }
            }
            Mutation::DropGuard { transition } => {
                if let Some(t) = out.transitions.get_mut(*transition) {
                    t.guard = None;
                }
            }
        }
    }

    removals.sort_unstable();
    removals.reverse();
    for (transition, emit, obligation) in removals {
        if let Some(template) = out
            .transitions
            .get_mut(transition)
            .and_then(|t| t.emits.get_mut(emit))
        {
            if obligation < template.requires_relation.len() {
                template.requires_relation.remove(obligation);
            }
        }
    }

    out
}
