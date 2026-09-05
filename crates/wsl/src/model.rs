use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    pub spec_version: u32,
    pub workflow: String,
    #[serde(default)]
    pub principals: IndexMap<String, Principal>,
    pub places: Vec<Place>,
    #[serde(rename = "final", default)]
    pub final_places: Vec<String>,
    pub transitions: Vec<Transition>,
    #[serde(default)]
    pub relations: IndexMap<String, RelationSchema>,
    #[serde(default)]
    pub invariants: Vec<Invariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub class: PrincipalClass,
    pub id_pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalClass {
    ServiceAccount,
    Human,
    Workload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Place {
    pub id: String,
    #[serde(default)]
    pub tokens: Vec<TokenSpec>,
    #[serde(default)]
    pub carries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSpec {
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub id: String,
    pub principal: String,
    #[serde(default)]
    pub consumes: Vec<String>,
    #[serde(default)]
    pub produces: Vec<String>,
    #[serde(default)]
    pub binds: IndexMap<String, BindMode>,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub emits: Vec<EffectTemplate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindMode {
    Fresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectTemplate {
    pub effect: String,
    #[serde(default)]
    pub requires_relation: Vec<RelationObligation>,
    #[serde(flatten)]
    pub args: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationObligation {
    #[serde(rename = "type")]
    pub ty: String,
    pub target: String,
    #[serde(default)]
    pub bind: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationSchema {
    pub from: String,
    pub to: String,
    pub constraint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub id: String,
    #[serde(flatten)]
    pub kind: InvariantKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvariantKind {
    EffectHasProducingTransition { effect: String, scope: String },
    TokenConsumedNotCopied { place: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Var(String),
    Glob(String),
    Lit(String),
}

pub fn classify(raw: &str) -> Pattern {
    if let Some(name) = raw.strip_prefix('$') {
        Pattern::Var(name.to_string())
    } else if raw.contains('*') {
        Pattern::Glob(raw.to_string())
    } else {
        Pattern::Lit(raw.to_string())
    }
}

pub fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    let mut pi = 0usize;
    let mut vi = 0usize;
    let mut star = usize::MAX;
    let mut mark = 0usize;
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = vi;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            vi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

impl Spec {
    pub fn transition(&self, id: &str) -> Option<&Transition> {
        self.transitions.iter().find(|t| t.id == id)
    }

    pub fn place(&self, id: &str) -> Option<&Place> {
        self.places.iter().find(|p| p.id == id)
    }

    pub fn principal_matches(&self, principal_key: &str, identity: &str) -> bool {
        match self.principals.get(principal_key) {
            Some(p) => glob_match(&p.id_pattern, identity),
            None => false,
        }
    }

    pub fn referenced_vars(t: &Transition) -> Vec<String> {
        let mut out = Vec::new();
        for e in &t.emits {
            for value in e.args.values() {
                if let Pattern::Var(name) = classify(value) {
                    out.push(name);
                }
            }
            for obligation in &e.requires_relation {
                for value in obligation.bind.values() {
                    if let Pattern::Var(name) = classify(value) {
                        out.push(name);
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}
