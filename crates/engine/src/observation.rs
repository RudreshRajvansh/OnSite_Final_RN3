use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub run_id: String,
    #[serde(default)]
    pub planes: BTreeMap<String, Plane>,
    pub records: Vec<Record>,
    #[serde(default)]
    pub edges: Vec<ObservedEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Plane {
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub carries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(default = "default_plane")]
    pub plane: String,
    pub principal: String,
    #[serde(default)]
    pub step: Option<String>,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub effects: Vec<EffectInstance>,
}

fn default_plane() -> String {
    "runner".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectInstance {
    pub id: String,
    pub kind: String,
    #[serde(flatten)]
    pub args: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedEdge {
    #[serde(rename = "type")]
    pub ty: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "fact", rename_all = "snake_case")]
pub enum Fact {
    Step {
        record: String,
        step: String,
        principal: String,
    },
    Effect {
        id: String,
        kind: String,
        args: BTreeMap<String, String>,
    },
    Edge {
        relation: String,
        from: String,
        to: String,
    },
}

impl Fact {
    pub fn render(&self) -> String {
        match self {
            Fact::Step {
                step, principal, ..
            } => format!("{} performed `{}`", principal, step),
            Fact::Effect { kind, args, .. } => {
                let rendered: Vec<String> =
                    args.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
                format!("{}({})", kind, rendered.join(", "))
            }
            Fact::Edge { relation, from, to } => format!("{}({} -> {})", relation, from, to),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    #[error("duplicate record id `{0}`")]
    DuplicateRecord(String),
    #[error("duplicate effect id `{0}`")]
    DuplicateEffect(String),
    #[error("edge `{relation}` references unknown effect `{id}`")]
    UnknownEffect { relation: String, id: String },
    #[error("observation contains a causal cycle involving record `{0}`")]
    CausalCycle(String),
    #[error("cannot parse observation: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("cannot read observation `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl Observation {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ObservationError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|source| ObservationError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let obs: Observation = serde_json::from_str(&raw)?;
        obs.validate()?;
        Ok(obs)
    }

    pub fn validate(&self) -> Result<(), ObservationError> {
        let mut records = BTreeSet::new();
        for r in &self.records {
            if !records.insert(r.id.clone()) {
                return Err(ObservationError::DuplicateRecord(r.id.clone()));
            }
        }
        let mut effects = BTreeSet::new();
        for e in self.effects() {
            if !effects.insert(e.id.clone()) {
                return Err(ObservationError::DuplicateEffect(e.id.clone()));
            }
        }
        for edge in &self.edges {
            for id in [&edge.from, &edge.to] {
                if !effects.contains(id) {
                    return Err(ObservationError::UnknownEffect {
                        relation: edge.ty.clone(),
                        id: id.clone(),
                    });
                }
            }
        }
        self.order()?;
        Ok(())
    }

    pub fn hash(&self) -> String {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(canonical);
        hex::encode(h.finalize())
    }

    pub fn effects(&self) -> impl Iterator<Item = &EffectInstance> {
        self.records.iter().flat_map(|r| r.effects.iter())
    }

    pub fn effect(&self, id: &str) -> Option<&EffectInstance> {
        self.effects().find(|e| e.id == id)
    }

    pub fn record_of_effect(&self, id: &str) -> Option<usize> {
        self.records
            .iter()
            .position(|r| r.effects.iter().any(|e| e.id == id))
    }

    pub fn step_records(&self) -> Vec<usize> {
        self.records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.step.is_some())
            .map(|(i, _)| i)
            .collect()
    }

    pub fn dangling_effects(&self) -> Vec<&EffectInstance> {
        self.records
            .iter()
            .filter(|r| r.step.is_none())
            .flat_map(|r| r.effects.iter())
            .collect()
    }

    pub fn value_domain(&self) -> BTreeSet<String> {
        self.effects()
            .flat_map(|e| e.args.values().cloned())
            .collect()
    }

    pub fn plane_carries(&self, kind: &str) -> bool {
        self.planes
            .values()
            .any(|p| p.complete && p.carries.iter().any(|c| c == kind))
    }

    pub fn order(&self) -> Result<Vec<Vec<usize>>, ObservationError> {
        let n = self.records.len();
        let mut preds: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];

        let mut planes: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (i, r) in self.records.iter().enumerate() {
            planes.entry(r.plane.as_str()).or_default().push(i);
        }
        for indices in planes.values() {
            let mut sorted = indices.clone();
            sorted.sort_by(|a, b| self.records[*a].ts.cmp(&self.records[*b].ts).then(a.cmp(b)));
            for w in sorted.windows(2) {
                preds[w[1]].insert(w[0]);
            }
        }

        for edge in &self.edges {
            let (Some(source), Some(target)) = (
                self.record_of_effect(&edge.from),
                self.record_of_effect(&edge.to),
            ) else {
                continue;
            };
            if source != target {
                preds[source].insert(target);
            }
        }

        let mut indegree: Vec<usize> = preds.iter().map(|p| p.len()).collect();
        let mut queue: Vec<usize> = (0..n).filter(|i| indegree[*i] == 0).collect();
        let mut visited = 0usize;
        while let Some(node) = queue.pop() {
            visited += 1;
            for (i, p) in preds.iter().enumerate() {
                if p.contains(&node) {
                    indegree[i] -= 1;
                    if indegree[i] == 0 {
                        queue.push(i);
                    }
                }
            }
        }
        if visited != n {
            let stuck = (0..n)
                .find(|i| indegree[*i] > 0)
                .map(|i| self.records[i].id.clone())
                .unwrap_or_default();
            return Err(ObservationError::CausalCycle(stuck));
        }

        Ok(preds
            .into_iter()
            .map(|p| p.into_iter().collect::<Vec<usize>>())
            .collect())
    }

    pub fn facts(&self) -> Vec<Fact> {
        let mut out = Vec::new();
        for r in &self.records {
            if let Some(step) = &r.step {
                out.push(Fact::Step {
                    record: r.id.clone(),
                    step: step.clone(),
                    principal: r.principal.clone(),
                });
            }
            for e in &r.effects {
                out.push(Fact::Effect {
                    id: e.id.clone(),
                    kind: e.kind.clone(),
                    args: e.args.clone(),
                });
            }
        }
        for edge in &self.edges {
            out.push(Fact::Edge {
                relation: edge.ty.clone(),
                from: edge.from.clone(),
                to: edge.to.clone(),
            });
        }
        out
    }

    pub fn restrict(&self, keep: &BTreeSet<Fact>) -> Observation {
        let kept_steps: BTreeSet<&str> = keep
            .iter()
            .filter_map(|f| match f {
                Fact::Step { record, .. } => Some(record.as_str()),
                _ => None,
            })
            .collect();
        let kept_effects: BTreeSet<&str> = keep
            .iter()
            .filter_map(|f| match f {
                Fact::Effect { id, .. } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        let kept_edges: BTreeSet<(&str, &str, &str)> = keep
            .iter()
            .filter_map(|f| match f {
                Fact::Edge { relation, from, to } => {
                    Some((relation.as_str(), from.as_str(), to.as_str()))
                }
                _ => None,
            })
            .collect();

        let mut records = Vec::new();
        for r in &self.records {
            let step = match &r.step {
                Some(_) if !kept_steps.contains(r.id.as_str()) => None,
                other => other.clone(),
            };
            let effects: Vec<EffectInstance> = r
                .effects
                .iter()
                .filter(|e| kept_effects.contains(e.id.as_str()))
                .cloned()
                .collect();
            if step.is_none() && effects.is_empty() {
                continue;
            }
            records.push(Record {
                id: r.id.clone(),
                plane: r.plane.clone(),
                principal: r.principal.clone(),
                step,
                ts: r.ts.clone(),
                effects,
            });
        }

        let live: BTreeSet<&str> = records
            .iter()
            .flat_map(|r| r.effects.iter().map(|e| e.id.as_str()))
            .collect();
        let edges = self
            .edges
            .iter()
            .filter(|e| {
                kept_edges.contains(&(e.ty.as_str(), e.from.as_str(), e.to.as_str()))
                    && live.contains(e.from.as_str())
                    && live.contains(e.to.as_str())
            })
            .cloned()
            .collect();

        Observation {
            run_id: self.run_id.clone(),
            planes: self.planes.clone(),
            records,
            edges,
        }
    }
}
